defmodule Encryptor.Provider.Function do
  @moduledoc """
  A provider built from a host-supplied pair of closures.

  The escape hatch. It exists so the per-tenant case is reachable on day one,
  before a storage-backed adapter exists, and so a host that already has a key
  store can use this package without writing a behaviour implementation.

      provider: {Encryptor.Provider.Function,
        encryption_key: fn merchant_id -> MyApp.Keys.current(merchant_id) end,
        decryption_keys: fn merchant_id -> MyApp.Keys.live(merchant_id) end}

  Both closures take one argument, the selector, and return
  `{:ok, descriptor}` / `{:ok, [descriptor, ...]}` or `{:error, reason}` with
  a reason from the provider vocabulary. Anything a closure needs beyond the
  selector it captures.

  ## It inherits every obligation and enforces none of them

  A closure pair is unreviewed code on the key path. Nothing here stops one
  from blocking for thirty seconds, reusing a name for different bytes, or
  caching unboundedly - the obligations in `Encryptor.Provider` are the
  contract, and this provider is the shape that makes breaking them easiest.
  Shipping it anyway is the deliberate trade: refusing a function-shaped
  provider would push hosts into forking the package, which is worse.

  ## What it does check, on the way back

  The two things a wrong answer would otherwise turn into a confusing failure
  somewhere else:

    * **The shape of the answer.** A closure that returns a bare descriptor, a
      map, `nil`, or an empty candidate list gets
      `{:invalid_key_descriptor, detail}` - a bug in the provider, named as
      one, rather than a `FunctionClauseError` from inside the vault.
    * **That descriptors are members of the closed set.** An engine keyring,
      or a host struct that looks like a descriptor, is refused here.

  Field-level validation - the reserved namespace prefix, printability, the
  material length against the declared size - stays the vault's, immediately
  before it builds a keyring. This is a membership check, not a second copy of
  that one.

  A closure's `{:error, reason}` passes through when the reason is one of the
  five in the provider vocabulary. Anything else becomes
  `{:invalid_key_descriptor, {:unrecognized_reason, tag}}`, carrying the
  leading tag and nothing else: the vocabulary is closed so that a `case` over
  it is exhaustive, and a term that escaped into it would arrive at a failure
  renderer that has no clause for it. The tag alone is carried because a
  reason term from a host closure can hold anything, including key material.

  ## The detail term never carries the answer

  Every `{:invalid_key_descriptor, detail}` here names the constraint that was
  violated and, at most, the struct module involved. The value that violated
  it is not carried: it came from a closure that resolves key material, and
  the error it lands in is one a host may well log.

  Records: ADR-0002 decisions 1, 3, 5 and 6.
  """

  @behaviour Encryptor.Provider

  alias Encryptor.Key.Aes
  alias Encryptor.Key.Kms
  alias Encryptor.Provider

  @typedoc "The two closures, both required."
  @type opts :: [
          encryption_key: (Provider.selector() -> {:ok, Provider.descriptor()} | {:error, term()}),
          decryption_keys: (Provider.selector() ->
                              {:ok, [Provider.descriptor(), ...]} | {:error, term()})
        ]

  @typedoc "The frozen state: the two closures, checked for arity at start."
  @type state :: %{
          encryption_key: (Provider.selector() -> term()),
          decryption_keys: (Provider.selector() -> term())
        }

  @doc """
  Holds the two closures, having checked that both are present and take one
  argument. A missing or wrong-arity closure fails the vault's start rather
  than the host's first encrypt.
  """
  @impl Provider
  @spec init(opts()) :: {:ok, state()} | {:error, Encryptor.Error.reason()}
  def init(opts) when is_list(opts) do
    with {:ok, encryption_key} <- closure(opts, :encryption_key),
         {:ok, decryption_keys} <- closure(opts, :decryption_keys) do
      {:ok, %{encryption_key: encryption_key, decryption_keys: decryption_keys}}
    end
  end

  @doc """
  Calls the host's encryption closure and validates its answer.
  """
  @impl Provider
  @spec encryption_key(state(), Provider.selector()) ::
          {:ok, Provider.descriptor()} | {:error, Provider.reason()}
  def encryption_key(%{encryption_key: fun}, selector) do
    case fun.(selector) do
      {:ok, descriptor} -> validate_one(descriptor)
      {:error, reason} -> {:error, translate(reason)}
      other -> {:error, {:invalid_key_descriptor, {:not_a_result, shape(other)}}}
    end
  end

  @doc """
  Calls the host's decryption closure and validates its answer: a non-empty
  list, every member a descriptor.
  """
  @impl Provider
  @spec decryption_keys(state(), Provider.selector()) ::
          {:ok, [Provider.descriptor(), ...]} | {:error, Provider.reason()}
  def decryption_keys(%{decryption_keys: fun}, selector) do
    case fun.(selector) do
      {:ok, [_ | _] = descriptors} -> validate_all(descriptors)
      {:ok, []} -> {:error, {:invalid_key_descriptor, :empty_candidate_list}}
      {:error, reason} -> {:error, translate(reason)}
      other -> {:error, {:invalid_key_descriptor, {:not_a_result, shape(other)}}}
    end
  end

  @spec closure(keyword(), atom()) :: {:ok, (term() -> term())} | {:error, term()}
  defp closure(opts, key) do
    case Keyword.fetch(opts, key) do
      {:ok, fun} when is_function(fun, 1) -> {:ok, fun}
      {:ok, _not_a_closure} -> {:error, {:invalid_config, :provider, {:not_a_closure, key}}}
      :error -> {:error, {:missing_config, [:provider, key]}}
    end
  end

  @spec validate_one(term()) :: {:ok, Provider.descriptor()} | {:error, Provider.reason()}
  defp validate_one(%Aes{} = descriptor), do: {:ok, descriptor}
  defp validate_one(%Kms{} = descriptor), do: {:ok, descriptor}

  defp validate_one(other),
    do: {:error, {:invalid_key_descriptor, {:not_a_descriptor, shape(other)}}}

  @spec validate_all([term(), ...]) ::
          {:ok, [Provider.descriptor(), ...]} | {:error, Provider.reason()}
  defp validate_all(descriptors) do
    Enum.reduce_while(descriptors, {:ok, []}, fn descriptor, {:ok, acc} ->
      case validate_one(descriptor) do
        {:ok, valid} -> {:cont, {:ok, [valid | acc]}}
        {:error, reason} -> {:halt, {:error, reason}}
      end
    end)
    |> case do
      {:ok, reversed} -> {:ok, Enum.reverse(reversed)}
      {:error, reason} -> {:error, reason}
    end
  end

  @spec translate(term()) :: Provider.reason()
  defp translate({:unknown_key, _selector} = reason), do: reason
  defp translate({:key_unavailable, _selector} = reason), do: reason
  defp translate({:invalid_key_descriptor, _detail} = reason), do: reason
  defp translate({:provider_not_started, _module} = reason), do: reason
  defp translate({:missing_optional_dependency, _dep} = reason), do: reason
  defp translate(other), do: {:invalid_key_descriptor, {:unrecognized_reason, shape(other)}}

  # Enough of an unrecognized term to debug with, and no more: a struct's
  # module, a tuple's leading tag when it is an atom, and otherwise nothing.
  @spec shape(term()) :: module() | atom()
  defp shape(%module{}), do: module
  defp shape(term) when is_tuple(term) and tuple_size(term) > 0, do: tag(elem(term, 0))
  defp shape(term) when is_atom(term), do: term
  defp shape(_term), do: :unnameable

  @spec tag(term()) :: atom()
  defp tag(first) when is_atom(first), do: first
  defp tag(_first), do: :unnameable
end
