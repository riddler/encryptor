defmodule Encryptor.Context do
  @moduledoc """
  The encryption context: the canonical vocabulary, the four-layer
  composition, and the bounds the engine does not check.

  The context is a flat map of `String.t()` to `String.t()` that rides every
  message **in the clear** and is covered by the header authentication tag. Two
  properties follow, and both are load-bearing:

    * every pair is public to anyone holding a ciphertext, so putting a key in
      the context is a disclosure decision, and
    * no pair can be edited without breaking the tag, which is what binds a
      message to the row, column and tenant it was written for.

  This module owns the vocabulary and the composition. It does not enforce the
  required set - that is the vault's `:required_context` plus the
  required-context CMM (ADR-0004 decisions 3 and 5) - and it does not compare a
  reproduced context against a stored one, which is the decrypt path's
  (decision 6).

  ## The canonical vocabulary

  Six host-facing keys, spelled bare and in `snake_case`, and two reserved
  prefixes. `canonical_keys/0` and `reserved_prefixes/0` are the one place the
  strings live, so a sibling package matches against this module rather than
  against a copy of a literal.

  | Key | Value | Supplied by |
  |---|---|---|
  | `tenant_ref` | the keyed reference derived from the `:key` selector | the vault, never the caller |
  | `table` | logical relation name, frozen at declaration | the caller |
  | `column` | logical field name, frozen at declaration | the caller |
  | `blob` | logical name for a payload with no table | the caller |
  | `purpose` | coarse classification of the value (`"pii"`, `"oauth_token"`) | vault configuration |
  | `app` | the host application's own name | vault configuration |

  The vocabulary is **open at the edges and closed in the middle**: a host adds
  its own keys freely, and it may neither redefine one of the six nor write
  under `aws-crypto-` (the engine's, and it may grow) or `encryptor-` (this
  package's). Adding a key to the table above is an ADR, not a call site.

  ## The four layers

  `compose/3` merges them, lowest precedence first, and refuses rather than
  silently overriding:

  | Layer | Source | Precedence |
  |---|---|---|
  | Static | `:static_encryption_context` from vault configuration | above nothing |
  | Per-call | the caller's `:encryption_context` option | merged over static |
  | Vault-supplied | keys the vault derives from the call's own arguments | above config, refuses a caller conflict |
  | Package-reserved | `encryptor-*` pairs this package sets | highest, never overridable |

  The refusals, in the order they are checked:

    * a non-string, empty, or non-UTF-8 key or value is
      `{:invalid_context_value, key}`, before the engine is called - the
      engine's serializer would otherwise either raise deep inside a `Format`
      module or accept something whose serialization a reader cannot reproduce;
    * a per-call or static key that is reserved, or that collides with a
      vault-supplied or package-reserved key, is `{:reserved_context_key, key}`;
    * a per-call key that collides with a static key at a **different** value is
      `{:encryption_context_conflict, key}`. The same value is not a conflict,
      so a call site that spells out what configuration already says is
      redundant rather than broken.

  On a `:tenant` vault the tenant pair is the vault's alone: `tenant_ref` and
  `tenant_id` are both refused from a caller, because `:key` is the whole of
  per-tenant routing and a tenant named twice is a tenant that can disagree
  with itself. `tenant_ref` is refused on a `:single` vault too, where there is
  no tenant to name at all.

  ## The bounds

  The engine performs no size validation, and the context is written into every
  message, so its serialized size is a per-row storage cost paid forever. This
  module refuses, per call:

    * more than 32 pairs, as `{:invalid_context_value, :count}`,
    * a serialized context over 4 KiB, as `{:invalid_context_value, :too_large}`,
    * a key or value that is empty or not valid UTF-8.

  The static half is bounded once, at start, by `Encryptor.Vault.Config`, which
  reads its numbers from `max_pairs/0` and `max_bytes/0` here. The numbers are
  conservative and are stated rather than measured (ADR-0004 open question 4).

  ## Nothing that varies per row may go in the context

  A primary key, a row id, a timestamp, a request id, or a user id does not
  belong in a context. This is a correctness-adjacent rule rather than a style
  preference: the serialized context is hashed into the materials cache id, so
  **each distinct context is its own cache entry and its own cold-cache
  provider round trip** - a key-store read plus a root-vault decrypt, per row,
  forever.

  `table` and `column` are per-column, which is bounded by the schema. A host
  with 200 tenants and 40 encrypted columns holds up to 8,000 cache entries;
  the same host with a row id in the context holds one per row.

  The vault cannot enforce this - it cannot tell a column name from a row id -
  so it is a documented rule, and the size cap above is the only mechanical
  backstop it has.

  Records: ADR-0004 decisions 1, 2, 7 and 9, with decision 4's refusal of a
  caller-supplied tenant pair.
  """

  alias Encryptor.Error
  alias Encryptor.Vault.Config

  @tenant_ref "tenant_ref"
  @tenant_id "tenant_id"
  @table "table"
  @column "column"
  @blob "blob"
  @purpose "purpose"
  @app "app"

  @canonical_keys [@tenant_ref, @table, @column, @blob, @purpose, @app]
  @reserved_prefixes ["aws-crypto-", "encryptor-"]

  @max_pairs 32
  @max_bytes 4096

  @typedoc "An encryption context: a flat map of string to string."
  @type context :: %{optional(String.t()) => String.t()}

  @typedoc "A context, or the pair list an already-decomposed one arrives as."
  @type pairs :: context() | [{String.t(), String.t()}]

  @doc """
  The six canonical host-facing keys, in the order ADR-0004 decision 2 tables
  them.

      iex> Encryptor.Context.canonical_keys()
      ["tenant_ref", "table", "column", "blob", "purpose", "app"]
  """
  @spec canonical_keys() :: [String.t()]
  def canonical_keys, do: @canonical_keys

  @doc """
  The prefixes no host key may start with.

  `aws-crypto-` is the engine's, and the engine is of two minds about it:
  `Format.EncryptionContext.validate/1` refuses the whole prefix, while
  `Cmm.Behaviour.validate_encryption_context_for_encrypt/1` refuses exactly
  `"aws-crypto-public-key"`, the one key it uses today. This package refuses
  the prefix, on the stricter of the two readings, because a later engine
  version may put another reserved key under it and a host that has been
  writing one is then unable to encrypt.

      iex> Encryptor.Context.reserved_prefixes()
      ["aws-crypto-", "encryptor-"]
  """
  @spec reserved_prefixes() :: [String.t()]
  def reserved_prefixes, do: @reserved_prefixes

  @doc """
  The key the vault writes a tenant reference under.

      iex> Encryptor.Context.tenant_ref_key()
      "tenant_ref"
  """
  @spec tenant_ref_key() :: String.t()
  def tenant_ref_key, do: @tenant_ref

  @doc """
  The most pairs a composed context may carry.

      iex> Encryptor.Context.max_pairs()
      32
  """
  @spec max_pairs() :: pos_integer()
  def max_pairs, do: @max_pairs

  @doc """
  The most bytes a composed context may serialize to.

      iex> Encryptor.Context.max_bytes()
      4096
  """
  @spec max_bytes() :: pos_integer()
  def max_bytes, do: @max_bytes

  @doc """
  Whether a term is usable as a context key or value: a non-empty binary that
  is valid UTF-8.

      iex> Encryptor.Context.valid_string?("customers")
      true

      iex> Encryptor.Context.valid_string?("")
      false

      iex> Encryptor.Context.valid_string?(:customers)
      false
  """
  @spec valid_string?(term()) :: boolean()
  def valid_string?(value), do: is_binary(value) and value != "" and String.valid?(value)

  @doc """
  Whether a key is refused from a caller or from static configuration on a
  vault of this profile.

  Both reserved prefixes are refused on either profile. The tenant pair is
  profile-sensitive: `tenant_ref` is the vault's on a `:tenant` vault and
  meaningless on a `:single` one, so it is refused on both; `tenant_id` is
  refused only where a tenant exists to be named twice.

      iex> Encryptor.Context.reserved_key?("aws-crypto-public-key", :single)
      true

      iex> Encryptor.Context.reserved_key?("tenant_ref", :single)
      true

      iex> Encryptor.Context.reserved_key?("tenant_id", :tenant)
      true

      iex> Encryptor.Context.reserved_key?("tenant_id", :single)
      false

      iex> Encryptor.Context.reserved_key?("table", :tenant)
      false
  """
  @spec reserved_key?(String.t(), Config.profile()) :: boolean()
  def reserved_key?(key, profile) when is_binary(key) do
    Enum.any?(@reserved_prefixes, &String.starts_with?(key, &1)) or
      key == @tenant_ref or
      (profile == :tenant and key == @tenant_id)
  end

  @doc """
  The size the engine serializes a context to, in bytes.

  A non-empty context is a 16-bit pair count followed by one entry per pair,
  each a 16-bit length prefix and the bytes of the key then the same for the
  value. An **empty context serializes to nothing at all** - not to a
  zero-valued count - which is `Format.EncryptionContext.serialize/1`'s own
  first clause and the reason this is not simply `2 + entries`.

  Computed arithmetically rather than by calling the engine's serializer, so a
  size check does not become a second place this package depends on the
  message format.

      iex> Encryptor.Context.serialized_size(%{})
      0

      iex> Encryptor.Context.serialized_size(%{"app" => "my_app"})
      15
  """
  @spec serialized_size(pairs()) :: non_neg_integer()
  def serialized_size(pairs) do
    case Enum.reduce(pairs, 0, &entry_size/2) do
      0 -> 0
      entries -> 2 + entries
    end
  end

  defp entry_size({key, value}, total) do
    total + 2 + byte_size(key) + 2 + byte_size(value)
  end

  @doc """
  Composes the four layers into the context a message will carry.

  `config` supplies the static layer and the profile. `per_call` is the
  caller's `:encryption_context`. The two upper layers arrive as options,
  because both are the vault's own and neither is ever a caller's to pass:

    * `:supplied` - keys the vault derives from the call's own arguments, which
      today is `tenant_ref` on a `:tenant` vault. Defaults to `%{}`.
    * `:reserved` - `encryptor-*` pairs this package sets on its own messages,
      which is how `Encryptor.Envelope` marks a wrapped key. Defaults to `%{}`.
    * `:operation` - what to record on a failure. Defaults to `:encrypt`.

  A caller key that collides with either upper layer is refused rather than
  overridden, which is the whole reason they are separate arguments and not a
  pre-merged map.

      iex> config = %Encryptor.Vault.Config{
      ...>   vault: MyApp.Vault,
      ...>   context_profile: :single,
      ...>   static_encryption_context: %{"app" => "my_app"}
      ...> }
      iex> Encryptor.Context.compose(config, %{"table" => "customers"})
      {:ok, %{"app" => "my_app", "table" => "customers"}}

      iex> config = %Encryptor.Vault.Config{
      ...>   vault: MyApp.Vault,
      ...>   context_profile: :tenant,
      ...>   static_encryption_context: %{}
      ...> }
      iex> {:error, error} = Encryptor.Context.compose(config, %{"tenant_ref" => "mine"})
      iex> error.reason
      {:reserved_context_key, "tenant_ref"}
  """
  @spec compose(Config.t(), term(), keyword()) :: {:ok, context()} | {:error, Error.t()}
  def compose(config, per_call, opts \\ [])

  def compose(%Config{} = config, per_call, opts) when is_map(per_call) do
    supplied = Keyword.get(opts, :supplied, %{})
    reserved = Keyword.get(opts, :reserved, %{})
    operation = Keyword.get(opts, :operation, :encrypt)
    above = Map.merge(supplied, reserved)

    with :ok <- validate_pairs(config, operation, per_call),
         :ok <- refuse_reserved(config, operation, per_call, above),
         :ok <- refuse_conflicts(config, operation, per_call),
         :ok <- refuse_reserved(config, operation, config.static_encryption_context, above),
         composed = merge(config, per_call, supplied, reserved),
         :ok <- within_bounds(config, operation, composed) do
      {:ok, composed}
    end
  end

  # A non-map `:encryption_context` has no term of its own in the closed reason
  # vocabulary, and inventing one is an ADR rather than a call site's
  # (ADR-0001 decision 10). It is reported as an invalid value under the
  # option's own name, which is the only part of it safe to render.
  def compose(%Config{} = config, _per_call, opts) do
    operation = Keyword.get(opts, :operation, :encrypt)
    {:error, error(config, operation, {:invalid_context_value, "encryption_context"})}
  end

  # The static-to-per-call step of this order is unobservable, and deliberately
  # so: `refuse_conflicts/3` has already refused every key the two layers hold
  # at different values, so by the time they meet they agree. The two steps
  # above it are the ones that decide anything.
  defp merge(%Config{static_encryption_context: static}, per_call, supplied, reserved) do
    static
    |> Map.merge(per_call)
    |> Map.merge(supplied)
    |> Map.merge(reserved)
  end

  # Every scan below sorts before it reports, so a map with two faults names the
  # same key on every run. An unordered `Enum.find/2` over a map would make a
  # refusal depend on term ordering inside the runtime.
  defp validate_pairs(config, operation, per_call) do
    per_call
    |> Enum.sort_by(fn {key, _value} -> inspect(key) end)
    |> Enum.find(fn {key, value} -> not (valid_string?(key) and valid_string?(value)) end)
    |> case do
      nil -> :ok
      {key, _value} -> {:error, error(config, operation, {:invalid_context_value, render(key)})}
    end
  end

  defp refuse_reserved(config, operation, map, above) do
    profile = config.context_profile

    map
    |> Map.keys()
    |> Enum.sort()
    |> Enum.find(&(is_binary(&1) and (reserved_key?(&1, profile) or Map.has_key?(above, &1))))
    |> case do
      nil -> :ok
      key -> {:error, error(config, operation, {:reserved_context_key, key})}
    end
  end

  defp refuse_conflicts(config, operation, per_call) do
    static = config.static_encryption_context

    per_call
    |> Enum.sort()
    |> Enum.find(fn {key, value} -> Map.get(static, key, value) != value end)
    |> case do
      nil -> :ok
      {key, _value} -> {:error, error(config, operation, {:encryption_context_conflict, key})}
    end
  end

  defp within_bounds(config, operation, composed) do
    cond do
      map_size(composed) > @max_pairs ->
        {:error, error(config, operation, {:invalid_context_value, :count})}

      serialized_size(composed) > @max_bytes ->
        {:error, error(config, operation, {:invalid_context_value, :too_large})}

      true ->
        :ok
    end
  end

  # A key is the only part of a rejected pair that reaches a message. A value
  # never does: it can be anything the caller passed, and this package does not
  # render caller data into a failure report.
  defp render(key) when is_binary(key) do
    if String.valid?(key), do: key, else: inspect(key)
  end

  defp render(key), do: inspect(key)

  # The spec is what makes the funnel worth having: dialyzer rejects a reason
  # that is not in `Encryptor.Error.reason/0`, so this module cannot invent a
  # near-miss term without the gate saying so.
  @spec error(Config.t(), Error.operation(), Error.reason()) :: Error.t()
  defp error(%Config{vault: vault}, operation, reason) do
    %Error{reason: reason, vault: vault, operation: operation, engine: nil}
  end
end
