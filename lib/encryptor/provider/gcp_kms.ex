defmodule Encryptor.Provider.GcpKms do
  @moduledoc """
  A wrap-provider: the tenant master key is wrapped and unwrapped by a GCP
  Cloud KMS `CryptoKey`, and the vault is handed ordinary AES material.

  ADR-0007 decision 1. This is a *material source* in ADR-0002 decision 5's
  sense, exactly as that record classified GCP KMS: it introduces no
  descriptor, no keyring and no engine change. Where ADR-0003 decision 2 wraps
  the tenant master key with a root `Encryptor` vault into an engine message,
  this provider wraps it with a GCP `CryptoKey` into a GCP KMS ciphertext.

  | | ADR-0003 root-vault envelope | this provider |
  |---|---|---|
  | what holds the wrapping key | a root `Encryptor` vault | a GCP `CryptoKey` |
  | the stored blob | an AWS ESDK message | a GCP KMS ciphertext |
  | binding | encryption context (ADR-0003 decision 4) | GCP additional authenticated data, same fields |
  | unwrap | `Encryptor.Envelope.unwrap/2`, local | `Decrypt`, one network round trip |
  | application ciphertext | unchanged AWS ESDK message | unchanged AWS ESDK message |

  The last row is the point: two hosts running the two shapes write
  byte-compatible application data and differ only in one small blob per
  tenant per version.

  **The wrapping root moves and nothing else does.** The reference subkey of
  ADR-0003 decision 6 stays local and stays configured on the tenant vault
  (ADR-0004 decision 4 as amended), because `tenant_ref` travels in the clear
  in every message header and must not depend on a remote service that could
  be unreachable on the read path.

  ## Configuration

      config :my_app, MyApp.TenantVault,
        provider:
          {Encryptor.Provider.GcpKms,
           project: "myapp-prod",
           location: "us-east1",
           key_ring: "encryptor-tenant-keys",
           reference_subkey: {:system, "ENCRYPTOR_REFERENCE_SUBKEY"},
           http_client: MyApp.KmsHttp,
           goth: MyApp.Goth,
           store: &MyApp.TenantKeys.live/1},
        store: MyApp.TenantKeys,
        max_age: :timer.minutes(5)

    * `:project`, `:location`, `:key_ring` - required. The ring exists
      already: this package never creates one (see "What it never does").
    * `:reference_subkey` - required, 32 bytes. ADR-0003 decision 6's
      `"encryptor/v1/tenant-ref"` subkey, local and not replaced by GCP.
    * `:http_client` - required. The host's module, described below.
    * `:goth` - required. A running `Goth` server's name, or `{module, name}`
      for any token server exporting `fetch/1` with Goth's return shape.
    * `:store` - required. A one-argument function taking a `tenant_ref` and
      answering `{:ok, rows}` newest first, where a row is what
      `c:Encryptor.Provider.provision/2` returned. This package owns no
      storage (ADR-0003 decision 9), so the read is the host's.
    * `:namespace` - the key namespace carried in the binding and in every
      row. Defaults to `"encryptor-tenant"`, ADR-0003 decision 5's default.
    * `:protection_level` - `:software` (default) or `:hsm`. A configuration
      change, never a code change.
    * `:key_id_prefix` - defaults to `"t-"`.
    * `:key_id_fun` - a one-argument escape hatch replacing the derivation
      below, with the same warning `Encryptor.Provider.Function` carries:
      everything the derivation guarantees becomes the host's obligation.
    * `:timeout` - per call, milliseconds, default `5_000`. This is the bound
      ADR-0002's roadmap line asked for on a provider that does network I/O.

  ### The HTTP client contract

  The configured module must export `request/5`:

      request(:post, url, headers, body, opts) ::
        {:ok, %{status: non_neg_integer(), body: binary()}} | {:error, term()}

  where `headers` is a list of `{name, value}` string pairs and `opts` carries
  `:timeout`. It is a five-line wrapper over whichever client the host already
  runs, which is the point: ADR-0007 decision 9 refuses to pick between
  `finch`, `req` and `hackney` on a host's behalf. Absence of either module at
  start is `{:missing_optional_dependency, module}`, checked at start and not
  at first use, so a misconfigured deploy fails to boot rather than failing on
  a customer's first write.

  ## The `CryptoKey` id

  ADR-0007 decision 4. The id is an unkeyed, collision-free derivation of the
  selector and never the selector itself - a GCP resource name is visible in
  IAM policies, audit logs and every client error, and a raw tenant identifier
  there discloses the host's tenant list:

      key_id = prefix <> Base.encode32(
        :crypto.hash(:sha256, [namespace, 0, selector]),
        case: :lower, padding: false
      )

  The full digest, never truncated, because an undeletable resource that
  collides is unrecoverable. Base32 lower-case because the GCP id charset
  excludes `=` and base32 survives copy-paste and case-folding search. It is
  deliberately *not* ADR-0003 decision 5's keyed `tenant_ref`: a keyed id
  would rename every tenant's key on a root rotation, and GCP keys cannot be
  renamed or deleted.

  ## Provisioning

  `c:Encryptor.Provider.provision/2`, reached through the vault as
  `MyApp.TenantVault.provision(tenant.id)`, creates the tenant's `CryptoKey`,
  generates 32 bytes, wraps them, and returns everything a store needs -
  keyed by `tenant_ref`, with the raw selector nowhere in it, and without the
  plaintext.

  **It is not safe to call concurrently for one selector, and this package
  does not make it so.** Two concurrent calls both pass the create step and
  both mint fresh material at the same version; whichever row loses the store
  write leaves anything encrypted under the winner unreadable. This is the
  race ADR-0003 open question 1 owns. Single-flight is the host's onboarding
  transaction, or a unique index on `(tenant_ref, version)` in the store.

  **Resolution never provisions.** `c:Encryptor.Provider.encryption_key/2` and
  `c:Encryptor.Provider.decryption_keys/2` never call `provision/2`, never
  call `CreateCryptoKey`, and answer a selector with no rows with
  `{:unknown_key, selector}` (ADR-0003 decision 8). There is no path from a
  read to a create, which matters more here than it did before: a typo'd
  tenant identifier that reaches `provision/2` mints a GCP `CryptoKey` that
  will exist for the life of the project.

  ## What it never does

    * **Never `CreateKeyRing`.** A key ring cannot be deleted. A package that
      created one would permanently enlarge a host's GCP project from inside
      a library call. The ring is the operator's Terraform, once per
      environment - and it is a destroy-time hazard there, not a create-time
      one: `google_kms_key_ring` accepts a destroy and removes only the state
      entry, so a re-apply hits `ALREADY_EXISTS` on a resource no destroy can
      clear. `prevent_destroy`, or keeping the ring out of the application's
      state entirely, is the mitigation.
    * **Never any IAM write.** The service account needs
      `cloudkms.cryptoKeyVersions.useToEncrypt` and `useToDecrypt` on the
      ring, plus `cloudkms.cryptoKeys.create` if it mints. Granting itself
      those is a privilege-escalation surface with no upside; a deployment
      whose IAM is wrong fails loudly at the first call.
    * **Never an automatic rotation schedule.** GCP's automatic rotation moves
      the primary version and leaves existing ciphertexts decryptable under
      their original version, so it accumulates live versions nobody is
      tracking - which is not what ADR-0005's runbook means by a rotation with
      a verifiable end.

  ## Two vocabularies of "version"

  ADR-0007 decision 7. Conflating them is the failure this table exists to
  prevent:

  | | tenant master key version | GCP `CryptoKeyVersion` |
  |---|---|---|
  | what it is | ADR-0003's `version`, one per minting of 32 fresh bytes | GCP's version of the wrapping key |
  | where it lives | the host's store, and the AAD | GCP |
  | rotating it | ADR-0005 R2, level 2: re-encrypt every ciphertext for the tenant | ADR-0005 R1, level 1: re-encrypt one blob per tenant per live version |
  | cost | a walk over user tables | a walk over the key store |
  | who walks | `encryptor_ecto` / the host | the key store's package |
  | destroying it | deletes one wrapping (ADR-0005 P4) | `DestroyCryptoKeyVersion` |

  They rotate on their own schedules and neither implies the other. An
  operator who reads "rotate the key" and rotates the GCP `CryptoKeyVersion`
  has done a level-1 rotation that touches no application data; one who mints
  a new tenant master key version has committed to a level-2 re-encrypt.

  ## The shred, and why it is not a function here

  ADR-0007 decision 8. Destroying every `CryptoKeyVersion` of a tenant's
  `CryptoKey` renders every wrapping of that tenant's master key
  undecryptable **including every backup copy of the store**, because the
  wrapping key is not in the backup. That is ADR-0005 P3 step 2a, and it runs
  as the operator's own call against `projects/<project>/locations/<location>/
  keyRings/<ring>/cryptoKeys/t-<digest>/cryptoKeyVersions/<n>`, once per live
  version:

      gcloud kms keys versions destroy <n> \\
        --location <location> --keyring <ring> --key t-<digest>

  This package ships no verb for it, for the reason ADR-0005 decision 10
  declined to ship `shred/2`: the store delete is still the host's and the
  destroy is still a call the host's runbook makes. ADR-0007 open question 5
  leaves whether it should ever offer one open.

  Two things the destroy does not do. **It is not full erasure**: the tenant's
  permanent pseudonym, the `tenant_ref`, sits in every message header and
  every retained backup, so P3 step 4's row deletion stays as
  compliance-mandatory as ADR-0005 made it. And **the scheduled destruction
  window is a delay, not a reprieve to design around**: a version is
  `DESTROY_SCHEDULED` for the key's configured duration, 24 hours by default,
  and restoring it works during that window. The window exists; do not rely
  on it.

  Records: ADR-0007 decisions 1 through 10; ADR-0002 decisions 1, 5 and 6;
  ADR-0003 decisions 1, 4, 5, 6 and 8; ADR-0004 decisions 3, 4 and 7;
  ADR-0005 decision 10 and procedure P3.
  """

  @behaviour Encryptor.Provider

  alias Encryptor.Envelope
  alias Encryptor.Key.Aes
  alias Encryptor.Provider
  alias Encryptor.Provider.GcpKms.Aad
  alias Encryptor.Provider.GcpKms.Api
  alias Encryptor.Vault.Reference

  # ADR-0003 decision 1: 32 bytes from the CSPRNG.
  @material_bytes 32
  @bits 256

  # ADR-0007's worked example mints at version 1. A later version is a
  # level-2 rotation (decision 7), which is a procedure over the store rather
  # than a second call to this one.
  @mint_version 1

  @default_namespace "encryptor-tenant"
  @default_prefix "t-"
  @default_timeout 5_000

  @required [:project, :location, :key_ring, :reference_subkey, :http_client, :goth, :store]
  @reference_subkey_bytes 32

  @typedoc "The frozen state: every option resolved and checked at start."
  @type state :: %{
          project: String.t(),
          location: String.t(),
          key_ring: String.t(),
          reference_subkey: binary(),
          http_client: module(),
          goth: term(),
          store: (String.t() -> {:ok, [Provider.provisioned()]} | {:error, term()}),
          namespace: String.t(),
          protection_level: :software | :hsm,
          key_id_prefix: String.t(),
          key_id_fun: (Provider.selector() -> String.t()) | nil,
          timeout: pos_integer()
        }

  @doc """
  Resolves and checks every option, once, at vault start.

  The transport modules are checked for presence here rather than at first
  use, which is ADR-0002 decision 5's at-start principle: a misconfigured
  deploy fails to boot rather than failing on a customer's first write.
  """
  @impl Provider
  @spec init(keyword()) :: {:ok, state()} | {:error, Encryptor.Error.reason()}
  def init(opts) when is_list(opts) do
    with :ok <- required(opts),
         :ok <- reference_subkey(opts),
         :ok <- store_fun(opts),
         :ok <- loaded(Keyword.fetch!(opts, :http_client), :request, 5),
         :ok <- token_server(Keyword.fetch!(opts, :goth)),
         {:ok, protection_level} <- protection_level(opts),
         {:ok, key_id_fun} <- key_id_fun(opts) do
      {:ok,
       %{
         project: Keyword.fetch!(opts, :project),
         location: Keyword.fetch!(opts, :location),
         key_ring: Keyword.fetch!(opts, :key_ring),
         reference_subkey: Keyword.fetch!(opts, :reference_subkey),
         http_client: Keyword.fetch!(opts, :http_client),
         goth: Keyword.fetch!(opts, :goth),
         store: Keyword.fetch!(opts, :store),
         namespace: Keyword.get(opts, :namespace, @default_namespace),
         protection_level: protection_level,
         key_id_prefix: Keyword.get(opts, :key_id_prefix, @default_prefix),
         key_id_fun: key_id_fun,
         timeout: Keyword.get(opts, :timeout, @default_timeout)
       }}
    end
  end

  @doc """
  The tenant's current master key, unwrapped through GCP `Decrypt`.

  The store's newest row, decrypted under the binding rebuilt from that row's
  own `tenant_ref`, `version` and `namespace`. A row moved between tenants or
  versions fails closed here rather than unwrapping silently, which is the
  property ADR-0003 decision 4 bought with the encryption context and
  ADR-0007 decision 5 carries into GCP's byte-string AAD.
  """
  @impl Provider
  @spec encryption_key(state(), Provider.selector()) ::
          {:ok, Aes.t()} | {:error, Provider.reason()}
  def encryption_key(state, selector) do
    with {:ok, [row | _older]} <- rows(state, selector) do
      unwrap(state, row, selector)
    end
  end

  @doc """
  Every live master key for the tenant, newest first.

  One `Decrypt` per row, on every call. The vault's materials cache sits in
  front of the CMM rather than in front of the provider, so it does not reduce
  that count, whatever `max_age` is set to (ADR-0002 Amendment A's A1,
  ADR-0007 Amendment A's A1).
  """
  @impl Provider
  @spec decryption_keys(state(), Provider.selector()) ::
          {:ok, [Aes.t(), ...]} | {:error, Provider.reason()}
  def decryption_keys(state, selector) do
    with {:ok, rows} <- rows(state, selector) do
      unwrap_all(state, rows, selector)
    end
  end

  @doc """
  Creates this tenant's `CryptoKey`, then mints and wraps its master key.

  ADR-0007 decisions 3 and 6, in order: `CreateCryptoKey` with the derived id,
  `ENCRYPT_DECRYPT` and no rotation schedule; 32 bytes from the CSPRNG;
  `Encrypt` under the four-field AAD; the row. `ALREADY_EXISTS` on the create
  is success for that step - the id is a pure function of the selector, so an
  existing key is always *this* tenant's - which is what makes a provision
  that half-succeeded retryable.

  The plaintext's whole lifetime is one function body. It is never returned,
  never logged and never put in the row.

  Not to be confused with `Encryptor.Envelope.provision/3`, which wraps under
  a root vault and takes a vault module as its first argument.
  """
  @impl Provider
  @spec provision(state(), Provider.selector()) ::
          {:ok, Provider.provisioned()} | {:error, Provider.reason()}
  def provision(state, selector) when is_binary(selector) and selector != "" do
    key_id = key_id(state, selector)

    case Api.create_crypto_key(state, key_id) do
      {:ok, _created_or_existing} ->
        mint(state, Reference.derive(state.reference_subkey, selector), key_id, selector)

      {:error, _failure} ->
        {:error, {:key_unavailable, selector}}
    end
  end

  def provision(_state, selector), do: {:error, {:unknown_key, selector}}

  # The plaintext exists here and nowhere else.
  @spec mint(state(), String.t(), String.t(), Provider.selector()) ::
          {:ok, Provider.provisioned()} | {:error, Provider.reason()}
  defp mint(state, tenant_ref, key_id, selector) do
    material = :crypto.strong_rand_bytes(@material_bytes)
    aad = aad(tenant_ref, @mint_version, state.namespace)

    case Api.encrypt(state, key_id, material, aad) do
      {:ok, wrapped} ->
        {:ok,
         %{
           tenant_ref: tenant_ref,
           version: @mint_version,
           namespace: state.namespace,
           name: Envelope.key_name(tenant_ref, @mint_version),
           bits: @bits,
           wrapped: wrapped,
           key_id: key_id
         }}

      {:error, _failure} ->
        {:error, {:key_unavailable, selector}}
    end
  end

  @doc """
  The GCP resource name of a tenant's `CryptoKey`, for an operator's runbook.

  Pure, and it calls nothing: ADR-0007 decision 8 leaves
  `DestroyCryptoKeyVersion` to the host's runbook, so what this package owes
  an operator running ADR-0005 P3 step 2a is the name to run it against:

      projects/<project>/locations/<location>/keyRings/<ring>/cryptoKeys/t-<digest>

  """
  @spec crypto_key_name(state(), Provider.selector()) :: String.t()
  def crypto_key_name(state, selector) when is_binary(selector),
    do: Api.key_name(state, key_id(state, selector))

  # ADR-0007 decision 4.
  @spec key_id(state(), Provider.selector()) :: String.t()
  defp key_id(%{key_id_fun: fun}, selector) when is_function(fun, 1), do: fun.(selector)

  defp key_id(state, selector) do
    digest = :crypto.hash(:sha256, [state.namespace, 0, encoded(selector)])

    state.key_id_prefix <> Base.encode32(digest, case: :lower, padding: false)
  end

  # ADR-0004 decision 3 narrowed the selector to a `String.t()` on a `:tenant`
  # vault, so the encoding is the identity on every selector this provider can
  # see. It is spelled out anyway: the value must be byte-stable for the life
  # of a resource that cannot be deleted, and "the string" is not a byte
  # specification.
  @spec encoded(Provider.selector()) :: binary()
  defp encoded(selector) when is_binary(selector), do: selector

  @spec aad(String.t(), pos_integer(), String.t()) :: binary()
  defp aad(tenant_ref, version, namespace) do
    tenant_ref
    |> Envelope.binding(version, namespace)
    |> Aad.encode()
  end

  @spec rows(state(), Provider.selector()) ::
          {:ok, [Provider.provisioned(), ...]} | {:error, Provider.reason()}
  defp rows(state, selector) when is_binary(selector) and selector != "" do
    tenant_ref = Reference.derive(state.reference_subkey, selector)

    case state.store.(tenant_ref) do
      {:ok, [_first | _rest] = rows} -> validate_rows(rows, selector)
      {:ok, []} -> {:error, {:unknown_key, selector}}
      {:error, reason} -> {:error, translate(reason, selector)}
      other -> {:error, {:invalid_key_descriptor, {:store_off_contract, shape(other)}}}
    end
  end

  defp rows(_state, selector), do: {:error, {:unknown_key, selector}}

  @spec validate_rows([term(), ...], Provider.selector()) ::
          {:ok, [Provider.provisioned(), ...]} | {:error, Provider.reason()}
  defp validate_rows(rows, _selector) do
    Enum.reduce_while(rows, {:ok, []}, fn row, {:ok, acc} ->
      case validate_row(row) do
        :ok -> {:cont, {:ok, [row | acc]}}
        {:error, reason} -> {:halt, {:error, reason}}
      end
    end)
    |> case do
      {:ok, reversed} -> {:ok, Enum.reverse(reversed)}
      {:error, reason} -> {:error, reason}
    end
  end

  # Every field a row must carry to rebuild both the binding and the
  # descriptor. The detail names the field and never its value: a hand-edited
  # row can hold anything at all in any column.
  #
  # `bits` is matched against the one width this provider provisions rather
  # than the three the engine's raw keyrings accept: ADR-0007 decision 6 fixes
  # `Encryptor.Provider.provisioned/0` at `bits: 256`, so a row claiming
  # another width is a row this provider never wrote, and accepting it would
  # surface as a material-size failure one call later instead of as the
  # refused row it is.
  @spec validate_row(term()) :: :ok | {:error, Provider.reason()}
  defp validate_row(%{
         tenant_ref: tenant_ref,
         version: version,
         namespace: namespace,
         name: name,
         bits: bits,
         wrapped: wrapped,
         key_id: key_id
       })
       when is_binary(tenant_ref) and is_integer(version) and version > 0 and
              is_binary(namespace) and is_binary(name) and bits == @bits and
              is_binary(wrapped) and is_binary(key_id),
       do: :ok

  defp validate_row(%{}), do: {:error, {:invalid_key_descriptor, :invalid_row}}
  defp validate_row(other), do: {:error, {:invalid_key_descriptor, {:not_a_row, shape(other)}}}

  @spec unwrap_all(state(), [Provider.provisioned(), ...], Provider.selector()) ::
          {:ok, [Aes.t(), ...]} | {:error, Provider.reason()}
  defp unwrap_all(state, rows, selector) do
    Enum.reduce_while(rows, {:ok, []}, fn row, {:ok, acc} ->
      case unwrap(state, row, selector) do
        {:ok, descriptor} -> {:cont, {:ok, [descriptor | acc]}}
        {:error, reason} -> {:halt, {:error, reason}}
      end
    end)
    |> case do
      {:ok, reversed} -> {:ok, Enum.reverse(reversed)}
      {:error, reason} -> {:error, reason}
    end
  end

  @spec unwrap(state(), Provider.provisioned(), Provider.selector()) ::
          {:ok, Aes.t()} | {:error, Provider.reason()}
  defp unwrap(state, row, selector) do
    aad = aad(row.tenant_ref, row.version, row.namespace)

    case Api.decrypt(state, row.key_id, row.wrapped, aad) do
      {:ok, material} when byte_size(material) * 8 == row.bits ->
        {:ok,
         %Aes{
           namespace: row.namespace,
           name: row.name,
           material: material,
           bits: row.bits
         }}

      {:ok, _wrong_size} ->
        {:error, {:invalid_key_descriptor, :material_size}}

      {:error, _failure} ->
        {:error, {:key_unavailable, selector}}
    end
  end

  @spec required(keyword()) :: :ok | {:error, Encryptor.Error.reason()}
  defp required(opts) do
    case Enum.reject(@required, &Keyword.has_key?(opts, &1)) do
      [] -> :ok
      [missing | _rest] -> {:error, {:missing_config, [:provider, missing]}}
    end
  end

  @spec reference_subkey(keyword()) :: :ok | {:error, Encryptor.Error.reason()}
  defp reference_subkey(opts) do
    case Keyword.fetch!(opts, :reference_subkey) do
      subkey when is_binary(subkey) and byte_size(subkey) == @reference_subkey_bytes -> :ok
      _other -> {:error, {:invalid_config, :reference_subkey, :invalid_length}}
    end
  end

  @spec store_fun(keyword()) :: :ok | {:error, Encryptor.Error.reason()}
  defp store_fun(opts) do
    if is_function(Keyword.fetch!(opts, :store), 1) do
      :ok
    else
      {:error, {:invalid_config, :provider, {:not_a_closure, :store}}}
    end
  end

  # ADR-0007 decision 9's at-start check, in the term ADR-0002 decision 5
  # already put in the closed vocabulary.
  @spec loaded(term(), atom(), arity()) :: :ok | {:error, Encryptor.Error.reason()}
  defp loaded(module, function, arity) when is_atom(module) do
    if Code.ensure_loaded?(module) and function_exported?(module, function, arity) do
      :ok
    else
      {:error, {:missing_optional_dependency, module}}
    end
  end

  defp loaded(_other, _function, _arity),
    do: {:error, {:invalid_config, :provider, :http_client}}

  # The module is guarded here rather than left to `loaded/3`, whose own
  # catch-all names `:http_client`: a `{term, name}` pair whose first element
  # is not a module is a bad `:goth`, and the detail an operator reads has to
  # name the option they set.
  @spec token_server(term()) :: :ok | {:error, Encryptor.Error.reason()}
  defp token_server({module, _name}) when is_atom(module), do: loaded(module, :fetch, 1)

  defp token_server(name) when is_atom(name) do
    if Code.ensure_loaded?(Goth), do: :ok, else: {:error, {:missing_optional_dependency, :goth}}
  end

  defp token_server(_other), do: {:error, {:invalid_config, :provider, :goth}}

  @spec protection_level(keyword()) ::
          {:ok, :software | :hsm} | {:error, Encryptor.Error.reason()}
  defp protection_level(opts) do
    case Keyword.get(opts, :protection_level, :software) do
      level when level in [:software, :hsm] -> {:ok, level}
      _other -> {:error, {:invalid_config, :provider, :protection_level}}
    end
  end

  @spec key_id_fun(keyword()) ::
          {:ok, (Provider.selector() -> String.t()) | nil} | {:error, Encryptor.Error.reason()}
  defp key_id_fun(opts) do
    case Keyword.get(opts, :key_id_fun) do
      nil -> {:ok, nil}
      fun when is_function(fun, 1) -> {:ok, fun}
      _other -> {:error, {:invalid_config, :provider, {:not_a_closure, :key_id_fun}}}
    end
  end

  @spec translate(term(), Provider.selector()) :: Provider.reason()
  defp translate({:unknown_key, _key} = reason, _selector), do: reason
  defp translate({:key_unavailable, _key} = reason, _selector), do: reason
  defp translate({:invalid_key_descriptor, _detail} = reason, _selector), do: reason
  defp translate(_other, selector), do: {:key_unavailable, selector}

  # Enough of an unrecognized term to debug with, and no more.
  @spec shape(term()) :: module() | atom()
  defp shape(%module{}), do: module
  defp shape(term) when is_tuple(term) and tuple_size(term) > 0, do: tag(elem(term, 0))
  defp shape(term) when is_atom(term), do: term
  defp shape(_term), do: :unnameable

  @spec tag(term()) :: atom()
  defp tag(first) when is_atom(first), do: first
  defp tag(_first), do: :unnameable
end
