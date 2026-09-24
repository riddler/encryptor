defmodule Encryptor.Provider.Kms do
  @moduledoc """
  A keyring-backed provider: the scope's key *is* an AWS KMS key.

  ADR-0008. This is the only adapter that answers `Encryptor.Key.Kms`
  descriptors, and AWS KMS is the only key manager that ever will - every
  other one is a *material source* that produces the bytes of an
  `Encryptor.Key.Aes` (ADR-0002 decision 5).

  What that buys, and what it costs, is one table:

  | | a material-source provider | this one |
  |---|---|---|
  | version identity | `:name`, minted by the provider | the KMS key ARN, assigned by AWS |
  | who holds the wrapping key | the host's key store, as a wrapped blob | AWS KMS; nothing is stored |
  | the data key is generated | by the engine, locally | inside KMS, by `GenerateDataKey` |
  | the two-level envelope | yes | **no** - there is no scope master key to wrap |
  | `Encryptor.Vault.derive/3` | available | refused, `{:invalid_key_descriptor, :not_derivable}` |
  | dropping a version from the candidate list | **is** the crypto-shred | is **not** the shred |
  | the shred | `DELETE` the wrapping from the key store | `ScheduleKeyDeletion` on the scope's KMS key |

  ## The row that destroys data if it is skimmed

  **Removing a key from what this provider answers is not a crypto-shred.** It
  hides the scope's data from this vault; KMS can still decrypt it for anyone
  holding `kms:Decrypt` on the key, including from a backup of the ciphertext.
  The shred on this path is `ScheduleKeyDeletion` on the key itself, it is not
  complete until the pending-deletion window elapses, and `CancelKeyDeletion`
  works inside that window. ADR-0005 P3 step 2 reads differently per shape and
  ADR-0008 decision 4's table is where the two are reconciled.

  What the shred gains in exchange: it survives backups, because the wrapping
  key was never in one.

  ## Configuration

      config :my_app, MyApp.ScopedVault,
        provider:
          {Encryptor.Provider.Kms,
           region: "us-east-1",
           keys: %{
             "acme" => "arn:aws:kms:us-east-1:111122223333:key/abcd1234",
             "globex" => [
               "arn:aws:kms:us-east-1:111122223333:key/ef567890",
               "arn:aws:kms:us-east-1:111122223333:key/0b1c2d3e"
             ]
           }}

    * `:keys` - a map from selector to the key ids that selector's stored
      messages may have been written under, **newest first**, or a
      one-argument function taking the selector and answering
      `{:ok, entries}` / `{:error, reason}`. A bare string is the one-entry
      shape. A selector the map does not hold is `{:unknown_key, selector}`.
    * `:key_id` - the selector-ignoring shape, for a `:single` vault or a host
      that puts every scope on one key. Mutually exclusive with `:keys`.
    * `:client` - the engine's KMS client struct, built by the host. Mutually
      exclusive with `:region`.
    * `:region` - builds the engine's shipped `ExAws` client, which is what
      requires the optional dependencies below.
    * `:config` - passed to the shipped client alongside `:region`. It is
      where `ex_aws` conventionally takes a static access key id and secret,
      so prefer an instance role and leave it out.
    * `:mrk` - whether the keys are multi-region keys. Defaults to `false`,
      and an entry may override it: `[key_id: "mrk-abcd1234", mrk: true]`.

  At engine v1.0.0 the multi-region keyring is the same code path as the
  single-region one. `:mrk` selects the engine struct and this package asserts
  nothing else about it (ADR-0008 decision 8).

  ## What KMS sees, and what CloudTrail records

  **The vault's composed encryption context is sent to the AWS KMS API.** On
  this path there is one context object and it serves the message header and
  the API call both: `GenerateDataKey`, `Encrypt` and `Decrypt` each carry it,
  and a KMS encryption context is recorded *unencrypted* in CloudTrail. Every
  key ADR-0004 decision 2's table names - `tenant_ref` included, along with
  whatever `:static_encryption_context` and a per-call `:encryption_context`
  add - is therefore readable by whoever holds CloudTrail read in the host's
  AWS account, and not only by whoever holds the ciphertext bytes. ADR-0004
  decision 2 is the list; ADR-0004 decision 7 is the rule that keeps per-row
  values out of it - no primary key, row id, timestamp, request id or user id -
  which is what keeps a per-operation log from becoming a per-subject one. A
  host that judges a context key of its own inappropriate for its audit log
  configures it away at the vault: this adapter runs no narrower profile, and
  the composed context here is byte-for-byte the one every other provider
  shape composes (ADR-0004 Amendment A).
  Under a signing algorithm suite - which `0x0578`, the default
  `:algorithm_suite_id`, is - the engine adds its own reserved
  `aws-crypto-public-key` pair, the ECDSA verification key it generates for
  the write, to that context before the keyring wraps, so what the API call
  and its CloudTrail record carry is the composed context plus that one
  engine-owned pair; under `0x0478` it is exactly the composed context
  (ADR-0004, the 2026-09-13 Note on the signing suite).

  ## The AWS dependencies are the host's

  This package declares none of them. The engine's AWS client stack is
  *its* optional dependency, and a dependency's optional dependencies do not
  flow into a dependent's build - adding them here would make every consumer
  of this package carry an AWS HTTP stack it did not ask for. A host that
  wants the shipped client adds `:ex_aws` and `:ex_aws_kms` itself; without
  them `c:Encryptor.Provider.init/1` refuses `:region` at vault start with
  `{:missing_optional_dependency, :ex_aws_kms}` - at start, so a misconfigured
  deploy fails to boot rather than failing on a customer's first write
  (ADR-0002 decision 5, ADR-0008 decision 9).

  A host supplying its own `AwsEncryptionSdk.Keyring.KmsClient` implementation
  passes it as `:client` and needs none of them.

  ## What it never does

    * **It creates no keys.** The KMS key, its key policy, its alias and the
      application role's `kms:GenerateDataKey` and `kms:Decrypt` grants are
      the operator's infrastructure. `c:Encryptor.Provider.provision/2` is not
      implemented, and a caller reaching for it gets
      `{:not_provisionable, Encryptor.Provider.Kms}` - `provisioned()` is
      shaped around a wrapped master key and none of its fields has a value
      here (ADR-0008 decision 7).
    * **It stores nothing.** There is no row, so there is nothing to read
      back and nothing to migrate.
    * **It never asks KMS to export a key**, which is why
      `Encryptor.Vault.derive/3` and every blind index built on it need the
      material-source shape instead.

  ## Migrating a scope from raw keys to KMS

  An ordinary rotation window (ADR-0005 decision 2), because a candidate list
  may hold both shapes at once: answer the `Encryptor.Key.Kms` descriptor
  first and the live `Encryptor.Key.Aes` versions after it, flip
  `c:Encryptor.Provider.encryption_key/2` to the KMS one, re-encrypt at the
  host's pace, then retire the AES versions - and *that* retire is a shred,
  because the retired shape is the material-source one.

  Nothing can be confused for anything else while it runs: a `RawAes` child
  accepts an encrypted data key only when the header's provider id equals its
  namespace, an `AwsKms` child only when it is exactly `"aws-kms"`, and this
  package refuses that prefix as a namespace before it builds anything. A
  provider mixing the two shapes for one selector is the host's to write -
  this adapter answers KMS keys only - and `Encryptor.Provider.Function` is
  the shape that composes them without one.

  Records: ADR-0002 decisions 1, 3, 4, 5 and 6; ADR-0004 Amendment A decision
  A5; ADR-0005 decisions 2 and 3; ADR-0008 decisions 1, 3, 4, 6, 7, 8 and 9.
  """

  @behaviour Encryptor.Provider

  alias Encryptor.Key.Kms
  alias Encryptor.Provider

  # The engine compiles this module only when the host's own `ExAws.KMS` is
  # present, so it is absent from every build of this package and is excluded
  # in `mix.exs`'s `:xref` list beside `Goth` and `Argon2.Base`, for the reason
  # ADR-0003 amendment B decision 5 gives: a compile warning about an optional
  # module is the warning that trains a reader to ignore warnings. Presence is
  # checked at run time instead, in `init/1`.
  @ex_aws_client AwsEncryptionSdk.Keyring.KmsClient.ExAws

  # `t:Encryptor.Provider.reason/0`, as leading tags. A closure's failure
  # passes through only when it is already a member.
  @vocabulary [
    :unknown_key,
    :key_unavailable,
    :invalid_key_descriptor,
    :provider_not_started,
    :missing_optional_dependency,
    :not_provisionable
  ]

  @typedoc """
  One candidate: a key id, or a key id with its own `:mrk`.
  """
  @type entry :: String.t() | [key_id: String.t(), mrk: boolean()]

  @typedoc "Exactly one of `:keys` or `:key_id`, and at most one of `:client` or `:region`."
  @type opts :: keyword()

  @typedoc """
  The frozen state: the client, and either the resolved descriptors or the
  host's closure.
  """
  @type state :: %{
          client: struct(),
          mrk: boolean(),
          keys: %{Provider.selector() => [Kms.t(), ...]} | [Kms.t(), ...] | (term() -> term())
        }

  @doc """
  Builds the client once, resolves the configured keys, and freezes both.

  The optional-dependency check runs here rather than at first use, and the
  descriptors are built here so that resolution is a lookup afterwards.
  """
  @impl Provider
  @spec init(opts()) :: {:ok, state()} | {:error, Encryptor.Error.reason()}
  def init(opts) when is_list(opts) do
    with {:ok, mrk} <- default_mrk(opts),
         {:ok, client} <- client(opts),
         {:ok, keys} <- keys(opts, client, mrk) do
      {:ok, %{client: client, mrk: mrk, keys: keys}}
    end
  end

  @doc """
  The head of the selector's candidate list: the key new writes go under.
  """
  @impl Provider
  @spec encryption_key(state(), Provider.selector()) ::
          {:ok, Kms.t()} | {:error, Provider.reason()}
  def encryption_key(state, selector) do
    with {:ok, [head | _older]} <- candidates(state, selector) do
      {:ok, head}
    end
  end

  @doc """
  Every key the selector's stored messages may have been written under,
  newest first.

  A walk down this list on the decrypt path costs one KMS `Decrypt` per wrong
  candidate, so the head is where the write key belongs.
  """
  @impl Provider
  @spec decryption_keys(state(), Provider.selector()) ::
          {:ok, [Kms.t(), ...]} | {:error, Provider.reason()}
  def decryption_keys(state, selector), do: candidates(state, selector)

  @spec candidates(state(), Provider.selector()) ::
          {:ok, [Kms.t(), ...]} | {:error, Provider.reason()}
  defp candidates(%{keys: keys}, _selector) when is_list(keys), do: {:ok, keys}

  defp candidates(%{keys: keys}, selector) when is_map(keys) do
    case Map.fetch(keys, selector) do
      {:ok, descriptors} -> {:ok, descriptors}
      :error -> {:error, {:unknown_key, selector}}
    end
  end

  defp candidates(%{keys: fun} = state, selector), do: from_closure(fun.(selector), state)

  # The same membership discipline `Encryptor.Provider.Function` applies to a
  # host closure: a shape that is not a candidate list is a bug in the
  # provider, named as one, and a reason outside the closed vocabulary is
  # carried by its leading tag alone - a reason term from a host closure can
  # hold anything, including a key id.
  @spec from_closure(term(), state()) :: {:ok, [Kms.t(), ...]} | {:error, Provider.reason()}
  defp from_closure({:ok, entries}, state) do
    case descriptors(entries, state.client, state.mrk) do
      {:ok, descriptors} ->
        {:ok, descriptors}

      {:error, {:invalid_config, :provider, detail}} ->
        {:error, {:invalid_key_descriptor, detail}}
    end
  end

  defp from_closure({:error, reason}, _state) when is_tuple(reason) and tuple_size(reason) > 0 do
    if elem(reason, 0) in @vocabulary do
      {:error, reason}
    else
      {:error, {:invalid_key_descriptor, {:unrecognized_reason, tag(elem(reason, 0))}}}
    end
  end

  defp from_closure({:error, reason}, _state) when is_atom(reason),
    do: {:error, {:invalid_key_descriptor, {:unrecognized_reason, reason}}}

  defp from_closure(_other, _state),
    do: {:error, {:invalid_key_descriptor, :not_a_candidate_list}}

  @spec tag(term()) :: atom()
  defp tag(first) when is_atom(first), do: first
  defp tag(_first), do: :unnameable

  @spec default_mrk(keyword()) :: {:ok, boolean()} | {:error, Encryptor.Error.reason()}
  defp default_mrk(opts) do
    case Keyword.get(opts, :mrk, false) do
      mrk when is_boolean(mrk) -> {:ok, mrk}
      _other -> {:error, {:invalid_config, :provider, :mrk}}
    end
  end

  # ADR-0008 decision 9's at-start check, in the term ADR-0002 decision 5
  # already put in the closed vocabulary. A host-supplied client skips it: the
  # check is about the shipped adapter's dependency, not about clients in
  # general.
  @spec client(keyword()) :: {:ok, struct()} | {:error, Encryptor.Error.reason()}
  defp client(opts) do
    case {Keyword.fetch(opts, :client), Keyword.has_key?(opts, :region)} do
      {{:ok, _client}, true} ->
        {:error, {:invalid_config, :provider, :client_and_region}}

      {{:ok, %_struct{} = client}, false} ->
        {:ok, client}

      {{:ok, _other}, false} ->
        {:error, {:invalid_config, :provider, :client_not_a_struct}}

      {:error, true} ->
        shipped_client(opts)

      {:error, false} ->
        {:error, {:missing_config, [:provider, :client]}}
    end
  end

  @spec shipped_client(keyword()) :: {:ok, struct()} | {:error, Encryptor.Error.reason()}
  defp shipped_client(opts) do
    module = @ex_aws_client

    if Code.ensure_loaded?(module) do
      module.new(Keyword.take(opts, [:region, :config]))
    else
      {:error, {:missing_optional_dependency, :ex_aws_kms}}
    end
  end

  @spec keys(keyword(), struct(), boolean()) :: {:ok, term()} | {:error, Encryptor.Error.reason()}
  defp keys(opts, client, mrk) do
    case {Keyword.fetch(opts, :keys), Keyword.fetch(opts, :key_id)} do
      {{:ok, _keys}, {:ok, _key_id}} -> {:error, {:invalid_config, :provider, :keys_and_key_id}}
      {{:ok, fun}, :error} when is_function(fun, 1) -> {:ok, fun}
      {{:ok, map}, :error} when is_map(map) -> key_map(map, client, mrk)
      {{:ok, _other}, :error} -> {:error, {:invalid_config, :provider, :keys_not_a_map}}
      {:error, {:ok, entries}} -> descriptors(entries, client, mrk)
      {:error, :error} -> {:error, {:missing_config, [:provider, :keys]}}
    end
  end

  @spec key_map(map(), struct(), boolean()) ::
          {:ok, %{Provider.selector() => [Kms.t(), ...]}} | {:error, Encryptor.Error.reason()}
  defp key_map(map, client, mrk) do
    Enum.reduce_while(map, {:ok, %{}}, fn {selector, entries}, {:ok, acc} ->
      case descriptors(entries, client, mrk) do
        {:ok, descriptors} -> {:cont, {:ok, Map.put(acc, selector, descriptors)}}
        {:error, reason} -> {:halt, {:error, reason}}
      end
    end)
  end

  # A bare entry is the one-key shape. The candidate list is a list of
  # *versions*, so two entries sharing a key id is refused here, at start, for
  # the reason `Encryptor.Provider.Static` refuses two entries sharing a name:
  # on this path the ARN is the version identity (ADR-0008 decision 3).
  @spec descriptors(term(), struct(), boolean()) ::
          {:ok, [Kms.t(), ...]} | {:error, Encryptor.Error.reason()}
  defp descriptors(entries, client, mrk) when is_list(entries) and entries != [] do
    entries
    |> Enum.reduce_while({:ok, []}, fn entry, {:ok, acc} ->
      case descriptor(entry, client, mrk) do
        {:ok, descriptor} -> {:cont, {:ok, [descriptor | acc]}}
        {:error, reason} -> {:halt, {:error, reason}}
      end
    end)
    |> case do
      {:ok, reversed} -> distinct_key_ids(Enum.reverse(reversed))
      {:error, reason} -> {:error, reason}
    end
  end

  defp descriptors(entry, client, mrk) when is_binary(entry),
    do: descriptors([entry], client, mrk)

  defp descriptors([], _client, _mrk), do: {:error, {:invalid_config, :provider, :empty_key_list}}

  defp descriptors(_other, _client, _mrk),
    do: {:error, {:invalid_config, :provider, :malformed_key_entry}}

  @spec descriptor(term(), struct(), boolean()) :: {:ok, Kms.t()} | {:error, term()}
  defp descriptor(key_id, client, mrk) when is_binary(key_id) and key_id != "",
    do: {:ok, %Kms{key_id: key_id, mrk: mrk, client: client}}

  defp descriptor(entry, client, mrk) when is_list(entry) do
    with true <- Keyword.keyword?(entry),
         {:ok, key_id} when is_binary(key_id) and key_id != "" <- Keyword.fetch(entry, :key_id),
         entry_mrk when is_boolean(entry_mrk) <- Keyword.get(entry, :mrk, mrk) do
      {:ok, %Kms{key_id: key_id, mrk: entry_mrk, client: client}}
    else
      _other -> {:error, {:invalid_config, :provider, :malformed_key_entry}}
    end
  end

  defp descriptor(_other, _client, _mrk),
    do: {:error, {:invalid_config, :provider, :malformed_key_entry}}

  @spec distinct_key_ids([Kms.t(), ...]) :: {:ok, [Kms.t(), ...]} | {:error, term()}
  defp distinct_key_ids(descriptors) do
    key_ids = Enum.map(descriptors, & &1.key_id)

    if length(Enum.uniq(key_ids)) == length(key_ids) do
      {:ok, descriptors}
    else
      {:error, {:invalid_config, :provider, :duplicate_key_ids}}
    end
  end
end
