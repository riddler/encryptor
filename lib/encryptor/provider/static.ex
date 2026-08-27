defmodule Encryptor.Provider.Static do
  @moduledoc """
  A provider that holds its keys in configuration.

  The single-key vault, the root vault under the per-tenant envelope, and the
  test double. It resolves nothing from a store, which is exactly why the
  envelope's root vault uses it: a root vault configured with a store-backed
  provider would be a genuine cycle.

  It is deliberately not a tenancy solution. The selector is ignored, not
  rejected, so a `:single` vault resolves `:default` and a `:tenant` vault
  resolves every tenant to the same key.

  ## Two option shapes, mutually exclusive

  One key:

      provider: {Encryptor.Provider.Static,
        key: material, namespace: "myapp", name: "card/v1"}

  Or a candidate list, newest first:

      provider: {Encryptor.Provider.Static,
        keys: [
          [key: new_material, namespace: "myapp", name: "card/v2"],
          [key: old_material, namespace: "myapp", name: "card/v1"]
        ]}

  With `:keys`, `encryption_key/2` answers the head of the list and
  `decryption_keys/2` answers all of it. That is what makes a staged root
  rotation readable: writes go under the incoming key while reads still find
  the outgoing one, and the outgoing entry is removed in a later deploy.

  `:namespace` defaults to `"encryptor"` and `:name` to `"v1"`. Both defaults
  are ones a host will regret if it ever rotates, because a name is bound to
  its bytes forever - name the key for what it protects and version it.

  ## What it refuses at start

    * Both `:key` and `:keys` - `{:invalid_config, :provider, :key_and_keys}`.
      The two shapes answer the same question and there is no reading of the
      pair that is not a mistake.
    * Neither - `{:missing_config, [:provider, :key]}`.
    * An empty or malformed `:keys` list, or an entry with no `:key`.
    * Two entries sharing a `:name`. A candidate list is a list of *versions*,
      and two versions under one name is the failure mode the whole name
      contract exists to prevent - caught here, at start, rather than years
      later as an undecryptable row.
    * Material that is not a binary of 16, 24, or 32 bytes -
      `{:invalid_config, :provider, :key_size}`. The declared size is derived
      from the bytes rather than configured, so this is the one descriptor
      field this provider has to be sure of before it builds anything.

  Everything else about a descriptor - the reserved namespace prefix, the
  printability of a name - is the vault's to validate, immediately before it
  builds a keyring, and it is not repeated here.

  ## Rotating means restarting

  Configuration is resolved once and frozen into `:persistent_term`, so
  changing the candidate list means restarting the vault. For the root vault,
  which runs no cache, the restart costs nothing but the restart.

  Records: ADR-0002 decisions 1, 4 and 5; ADR-0005 decision 4.
  """

  @behaviour Encryptor.Provider

  alias Encryptor.Key.Aes
  alias Encryptor.Provider

  @default_namespace "encryptor"
  @default_name "v1"

  @typedoc """
  One entry in a candidate list. `:name` is the version identity that travels
  in the clear, and it must be distinct per entry.
  """
  @type entry :: [key: binary(), namespace: String.t(), name: String.t()]

  @typedoc "Exactly one of `:key` or `:keys`. `:keys` is newest first."
  @type opts ::
          [key: binary(), namespace: String.t(), name: String.t()]
          | [keys: [entry(), ...]]

  @typedoc """
  The frozen state: the descriptors, newest first, resolved once at start.
  """
  @type state :: %{keys: [Aes.t(), ...]}

  @doc """
  Resolves the configured key or candidate list into descriptors.

  The descriptors are built here, once, so that resolution is a lookup on
  every call afterwards.
  """
  @impl Provider
  @spec init(opts()) :: {:ok, state()} | {:error, Encryptor.Error.reason()}
  def init(opts) when is_list(opts) do
    with {:ok, entries} <- entries(opts),
         {:ok, keys} <- descriptors(entries),
         :ok <- distinct_names(keys) do
      {:ok, %{keys: keys}}
    end
  end

  @doc """
  The head of the candidate list, whatever the selector.
  """
  @impl Provider
  @spec encryption_key(state(), Provider.selector()) :: {:ok, Aes.t()}
  def encryption_key(%{keys: [key | _rest]}, _selector), do: {:ok, key}

  @doc """
  The whole candidate list, newest first, whatever the selector.
  """
  @impl Provider
  @spec decryption_keys(state(), Provider.selector()) :: {:ok, [Aes.t(), ...]}
  def decryption_keys(%{keys: keys}, _selector), do: {:ok, keys}

  @spec entries(keyword()) :: {:ok, [keyword(), ...]} | {:error, Encryptor.Error.reason()}
  defp entries(opts) do
    case {Keyword.has_key?(opts, :key), Keyword.fetch(opts, :keys)} do
      {true, {:ok, _keys}} -> {:error, {:invalid_config, :provider, :key_and_keys}}
      {true, :error} -> {:ok, [opts]}
      {false, {:ok, [_ | _] = keys}} -> candidate_entries(keys)
      {false, {:ok, []}} -> {:error, {:invalid_config, :provider, :empty_key_list}}
      {false, {:ok, _other}} -> {:error, {:invalid_config, :provider, :keys_not_a_list}}
      {false, :error} -> {:error, {:missing_config, [:provider, :key]}}
    end
  end

  @spec candidate_entries([term(), ...]) :: {:ok, [keyword(), ...]} | {:error, term()}
  defp candidate_entries(keys) do
    if Enum.all?(keys, &(Keyword.keyword?(&1) and Keyword.has_key?(&1, :key))) do
      {:ok, keys}
    else
      {:error, {:invalid_config, :provider, :malformed_key_entry}}
    end
  end

  # The size is derived from the material rather than configured: a declared
  # size that disagreed with the bytes would be a second place for the same
  # fact, and the vault would reject the descriptor anyway. Deriving it is
  # also why the byte count is checked here and not left to the vault - the
  # derivation has to produce one of three values or it produces nonsense.
  @spec descriptors([keyword(), ...]) :: {:ok, [Aes.t(), ...]} | {:error, term()}
  defp descriptors(entries) do
    entries
    |> Enum.reduce_while({:ok, []}, fn entry, {:ok, acc} ->
      case descriptor(entry, Keyword.fetch!(entry, :key)) do
        {:ok, descriptor} -> {:cont, {:ok, [descriptor | acc]}}
        {:error, reason} -> {:halt, {:error, reason}}
      end
    end)
    |> case do
      {:ok, reversed} -> {:ok, Enum.reverse(reversed)}
      {:error, reason} -> {:error, reason}
    end
  end

  @spec descriptor(keyword(), term()) :: {:ok, Aes.t()} | {:error, term()}
  defp descriptor(entry, material) when is_binary(material) do
    case byte_size(material) * 8 do
      bits when bits in [128, 192, 256] ->
        {:ok,
         %Aes{
           namespace: Keyword.get(entry, :namespace, @default_namespace),
           name: Keyword.get(entry, :name, @default_name),
           material: material,
           bits: bits
         }}

      _other ->
        {:error, {:invalid_config, :provider, :key_size}}
    end
  end

  defp descriptor(_entry, _material), do: {:error, {:invalid_config, :provider, :key_size}}

  @spec distinct_names([Aes.t(), ...]) :: :ok | {:error, term()}
  defp distinct_names(keys) do
    names = Enum.map(keys, & &1.name)

    if length(Enum.uniq(names)) == length(names) do
      :ok
    else
      {:error, {:invalid_config, :provider, :duplicate_key_names}}
    end
  end
end
