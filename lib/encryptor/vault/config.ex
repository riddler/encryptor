defmodule Encryptor.Vault.Config do
  @moduledoc """
  A vault's resolved configuration: the five-layer precedence chain, every
  check that runs at start, and the `:persistent_term` freeze the hot path
  reads.

  Configuration is resolved **once**, when the vault starts, and frozen into
  this struct under the `:persistent_term` key `{Encryptor.Vault, vault}`.
  Per-call reads are then lock-free and allocate nothing, which is what makes
  a check on every encrypted-column read affordable. Changing configuration
  under a running vault means restarting it, deliberately: configuration that
  changes key selection silently underneath in-flight operations is worse
  than an explicit restart (ADR-0001 decision 5).

  ## The precedence chain

  Lowest to highest, exactly as ADR-0001 decision 5 fixes it:

    1. `defaults/0`, declared by this package,
    2. options passed to `use Encryptor.Vault`,
    3. `Application.get_env(otp_app, vault)`,
    4. options passed to `start_link/1`,
    5. the return of the vault's optional `init/1` callback.

  Layers merge **by top-level key**. A layer that supplies `:cache` replaces
  the whole cache setting rather than deep-merging into the layer below it,
  because a host that inherits half a bound it never wrote has no way to read
  its own configuration off the page. Sub-defaults for the cache are applied
  once, during validation, to whichever layer won.

  `init/1` receives the merged keyword list and returns `{:ok, config}`; its
  return replaces the merge rather than being merged over it. It is the
  runtime escape hatch and the intended place to read key material out of the
  environment or a secrets manager.

  Layer 1 is the one exception to "replaces". The package defaults are applied
  a second time, underneath whatever `init/1` returned, so a callback that
  builds a fresh keyword list rather than adding to the one it was handed does
  not silently drop the commitment policy floor and the EDK limit on its way
  past. Every default is stated once, in `defaults/0`, and nowhere else -
  a validator that carried its own copy of a default would be a second place
  for it to drift.

  ## Key material is never a compile-time option

  `validate_use_opts!/2` raises at compile time when a `use` option, or a
  `:provider` option nested inside one, names key material: `:key`, `:keys`,
  `:root_key`, `:private_key`, `:passphrase`, or `:reference_subkey`. A secret
  in `use` options is a secret compiled into a `.beam` file and committed to
  the host's build artifacts, and the vault refuses to be the reason that
  happens (ADR-0001 decision 5; ADR-0004 decision 4 for the reference subkey).

  That list is closed and is extended by an ADR, not by a call site.

  ## What is checked at start

  Every check below produces an `Encryptor.Error` with `operation: :start` and
  a reason from the closed vocabulary. None of them is deferred to the first
  encrypt: a vault that cannot be configured correctly does not start.

    * `:provider` is required, is a `{module, opts}` pair, and may not carry
      both `:key` and `:keys` (ADR-0005 decision 4).
    * `:commitment_policy` defaults to `:require_encrypt_require_decrypt` and
      may be relaxed to `:require_encrypt_allow_decrypt`.
      `:forbid_encrypt_allow_decrypt` is refused outright: that policy exists
      to write non-committed messages, this package has never written one, and
      a key that can turn key commitment off will eventually be turned off by
      someone who does not know what it does (ADR-0001 decision 8).
    * `:max_encrypted_data_keys` defaults to `10` and may never be `nil`. The
      engine reads `nil` as unlimited, and an unlimited EDK count on the
      decrypt path is a work-amplification lever handed to whoever supplies
      the ciphertext.
    * `:algorithm_suite_id` defaults to `0x0578` and accepts `0x0478`. See
      "Choosing an algorithm suite" below.
    * `:cache` is `false` or a keyword list. `:max_age` is required with no
      default; `:max_messages` defaults to `100`, `:max_bytes` to 1 GiB, and
      `:recycle_after` to `20 * max_age` (ADR-0001 decision 6).
    * `:context_profile` is `:single` or `:tenant`, and `:required_context` is
      a list of context keys (ADR-0004 decision 3).
    * On a `:tenant` vault `:reference_subkey` is required, and when the
      deployment has pinned a `:reference_check` value the subkey must
      reproduce it (ADR-0004 decision 4).
    * `:static_encryption_context` is validated and bounded here: at most 32
      pairs, at most 4 KiB serialized, non-empty UTF-8 strings throughout, and
      no reserved key (ADR-0004 decisions 1, 2 and 9).

  ## Choosing an algorithm suite

  The default `0x0578` is the engine's own default: AES-256-GCM, HKDF-SHA512,
  key commitment, and ECDSA P-384 signing. A wrapper should not silently
  weaken what the engine chose, so that is what a host gets without saying
  anything.

  A host should configure `0x0478` - which keeps key commitment and drops the
  signature - when **the writer and the reader are the same trust domain**.
  The encrypted-column case `encryptor_ecto` serves is exactly that shape:
  signing exists so a reader can verify a writer it does not trust, and paying
  an ECDSA P-384 sign per column write, a verify per read, and the signature's
  bytes per row buys nothing when one application is both parties
  (ADR-0001 decision 9).

  ## The profile is start-time, not compile-time

  `:context_profile` arrives through the same five layers as everything else,
  and three of those layers do not exist when the vault module - or any module
  downstream of it - is compiled. A downstream layer that needs to know
  whether a vault is `:single` or `:tenant` reads it from the frozen struct at
  runtime, through `fetch/1`, and never from the `use` options.

      case Encryptor.Vault.Config.fetch(MyApp.TenantVault) do
        {:ok, %{context_profile: :tenant}} -> :ok
        {:ok, %{context_profile: :single}} -> {:error, :vault_is_single_profile}
        {:error, error} -> {:error, error}
      end

  Records: ADR-0001 decisions 5, 6, 8 and 9; ADR-0004 decisions 3, 4 and 9;
  ADR-0005 decision 4.
  """

  alias Encryptor.Error

  @default_commitment_policy :require_encrypt_require_decrypt
  @allowed_commitment_policies [:require_encrypt_require_decrypt, :require_encrypt_allow_decrypt]
  @forbidden_commitment_policy :forbid_encrypt_allow_decrypt

  @default_max_encrypted_data_keys 10
  @default_algorithm_suite_id 0x0578
  @allowed_algorithm_suite_ids [0x0578, 0x0478]

  @default_max_messages 100
  @default_max_bytes 1_073_741_824
  @recycle_after_multiplier 20
  @cache_bounds [:max_age, :max_messages, :max_bytes, :recycle_after]

  @max_context_pairs 32
  @max_context_bytes 4096
  @reserved_context_prefixes ["aws-crypto-", "encryptor-"]
  @tenant_context_keys ["tenant_ref", "tenant_id"]

  @key_material_options [:key, :keys, :root_key, :private_key, :passphrase, :reference_subkey]
  @reference_subkey_bytes 32

  # The probe the known-answer check derives against. It is a package
  # constant rather than configuration because ADR-0004 decision 4 describes
  # configuration as carrying one pinned value, not a pair, which only closes
  # if both sides derive against the same fixed probe. It is shaped so it
  # cannot collide with a real tenant identifier.
  @known_answer_probe "encryptor/v1/known-answer-probe"

  @typedoc "Which shape of vault this is, and therefore which selector and required keys it takes."
  @type profile :: :single | :tenant

  @typedoc "An encryption context: a flat map of string to string."
  @type context :: %{optional(String.t()) => String.t()}

  @typedoc "The resolved cache bounds, or `false` when the vault runs no cache."
  @type cache ::
          false
          | %{
              max_age: pos_integer(),
              max_messages: pos_integer(),
              max_bytes: pos_integer(),
              recycle_after: pos_integer()
            }

  @type t :: %__MODULE__{
          vault: module(),
          otp_app: atom(),
          provider: {module(), term()},
          cache: cache(),
          commitment_policy: :require_encrypt_require_decrypt | :require_encrypt_allow_decrypt,
          algorithm_suite_id: 0x0578 | 0x0478,
          max_encrypted_data_keys: pos_integer(),
          static_encryption_context: context(),
          context_profile: profile(),
          required_context: [String.t()],
          required_keys: [String.t()],
          reference_subkey: binary() | nil,
          reference_check: String.t() | nil
        }

  defstruct [
    :vault,
    :otp_app,
    :provider,
    :cache,
    :commitment_policy,
    :algorithm_suite_id,
    :max_encrypted_data_keys,
    :static_encryption_context,
    :context_profile,
    :required_context,
    :required_keys,
    :reference_subkey,
    :reference_check
  ]

  @doc """
  The package defaults - layer 1 of the precedence chain.

  Three keys are deliberately absent. `:provider` and `:context_profile` are
  required, because there is no defensible default for where key material
  comes from or for whether a vault is per-tenant, and a wrong guess at either
  changes what goes into a message. `:reference_subkey` is key material and
  arrives through `init/1`.

      iex> Keyword.fetch(Encryptor.Vault.Config.defaults(), :commitment_policy)
      {:ok, :require_encrypt_require_decrypt}

      iex> Keyword.fetch(Encryptor.Vault.Config.defaults(), :context_profile)
      :error
  """
  @spec defaults() :: keyword()
  def defaults do
    [
      cache: false,
      commitment_policy: @default_commitment_policy,
      algorithm_suite_id: @default_algorithm_suite_id,
      max_encrypted_data_keys: @default_max_encrypted_data_keys,
      static_encryption_context: %{},
      required_context: []
    ]
  end

  @doc """
  Refuses key material in `use` options, at compile time.

  Called by the `use Encryptor.Vault` macro while it expands, so the failure
  is a compilation failure rather than a start-time error: by the time a vault
  starts, the secret is already in the `.beam` file.

  It raises `ArgumentError` rather than returning an `Encryptor.Error`,
  because this is a misuse of a macro rather than an operation on a vault, and
  because `Encryptor.Error.message/1` deliberately never renders the detail of
  an `{:invalid_config, key, detail}` - the one thing an operator needs to see
  here is which option was refused.

  Returns the options unchanged when they are clean, so the macro can thread
  it.
  """
  @spec validate_use_opts!(module(), keyword()) :: keyword()
  def validate_use_opts!(vault, opts) do
    Enum.each(opts, &refuse_key_material!(vault, &1))
    opts
  end

  defp refuse_key_material!(vault, {:provider, {_module, provider_opts}}) do
    provider_opts
    |> nested_keys()
    |> Enum.each(&refuse_nested_key_material!(vault, &1))
  end

  defp refuse_key_material!(vault, {key, _value}) do
    if key in @key_material_options, do: raise_key_material!(vault, "option :#{key}")
  end

  defp nested_keys(provider_opts) do
    if Keyword.keyword?(provider_opts), do: Keyword.keys(provider_opts), else: []
  end

  defp refuse_nested_key_material!(vault, key) do
    if key in @key_material_options, do: raise_key_material!(vault, "provider option :#{key}")
  end

  defp raise_key_material!(vault, what) do
    raise ArgumentError, """
    #{inspect(vault)}: #{what} is key material and may not be passed to \
    `use Encryptor.Vault`.

    Options given to `use` are compiled into the module's .beam file and \
    committed to the host's build artifacts. Key material belongs in the \
    vault's `init/1` callback, read from the environment or a secrets \
    manager at start (ADR-0001 decision 5).
    """
  end

  @doc """
  Resolves the five layers and validates the result.

  `use_opts` is layer 2 and `start_opts` is layer 4; layers 3 and 5 are read
  here, from `Application.get_env/3` and from the vault's `init/1` when it
  exports one.

  Returns the validated struct. It is **not** frozen - `freeze/1` is a
  separate step so a caller can resolve and inspect a configuration without
  publishing it.
  """
  @spec resolve(module(), atom(), keyword(), keyword()) :: {:ok, t()} | {:error, Error.t()}
  def resolve(vault, otp_app, use_opts, start_opts \\ []) do
    with {:ok, merged} <- merge_layers(vault, otp_app, use_opts, start_opts) do
      build(vault, otp_app, merged)
    end
  end

  defp merge_layers(vault, otp_app, use_opts, start_opts) do
    layers = [
      {:use, use_opts},
      {:app_env, Application.get_env(otp_app, vault, [])},
      {:start_link, start_opts}
    ]

    Enum.reduce_while(layers, {:ok, defaults()}, fn {name, layer}, {:ok, merged} ->
      if Keyword.keyword?(layer),
        do: {:cont, {:ok, Keyword.merge(merged, layer)}},
        else: {:halt, {:error, error(vault, {:invalid_config, name, :not_a_keyword_list})}}
    end)
    |> case do
      {:ok, merged} -> under_defaults(apply_init(merged, vault))
      {:error, _error} = failure -> failure
    end
  end

  # Layer 1 is applied twice: once as the seed, so `init/1` sees the defaults
  # it is entitled to read, and once underneath whatever `init/1` returned, so
  # a callback that builds a fresh list rather than adding to the one it was
  # handed does not silently drop every package default on its way past.
  defp under_defaults({:ok, config}), do: {:ok, Keyword.merge(defaults(), config)}
  defp under_defaults({:error, _error} = failure), do: failure

  defp apply_init(merged, vault) do
    if Code.ensure_loaded?(vault) and function_exported?(vault, :init, 1) do
      case vault.init(merged) do
        {:ok, config} when is_list(config) -> {:ok, config}
        _other -> {:error, error(vault, {:invalid_config, :init, :bad_return})}
      end
    else
      {:ok, merged}
    end
  end

  defp build(vault, otp_app, opts) do
    with {:ok, provider} <- provider(vault, opts),
         {:ok, policy} <- commitment_policy(vault, opts),
         {:ok, suite} <- algorithm_suite_id(vault, opts),
         {:ok, edks} <- max_encrypted_data_keys(vault, opts),
         {:ok, cache} <- cache(vault, opts),
         {:ok, profile} <- context_profile(vault, opts),
         {:ok, required} <- required_context(vault, profile, opts),
         {:ok, static} <- static_encryption_context(vault, profile, opts),
         {:ok, subkey} <- reference_subkey(vault, profile, opts),
         {:ok, check} <- reference_check(vault, profile, subkey, opts) do
      {:ok,
       %__MODULE__{
         vault: vault,
         otp_app: otp_app,
         provider: provider,
         cache: cache,
         commitment_policy: policy,
         algorithm_suite_id: suite,
         max_encrypted_data_keys: edks,
         static_encryption_context: static,
         context_profile: profile,
         required_context: required,
         required_keys: required_keys(profile, required),
         reference_subkey: subkey,
         reference_check: check
       }}
    end
  end

  # ADR-0004 decision 3: the profile contributes its own required keys ahead
  # of the host's, and the effective set is frozen so the hot path reads it
  # rather than recomputing it.
  defp required_keys(:tenant, required), do: Enum.uniq(["tenant_ref" | required])
  defp required_keys(:single, required), do: Enum.uniq(required)

  defp provider(vault, opts) do
    case Keyword.fetch(opts, :provider) do
      {:ok, {module, provider_opts}} when is_atom(module) ->
        provider_options(vault, module, provider_opts)

      {:ok, _other} ->
        {:error, error(vault, {:invalid_config, :provider, :shape})}

      :error ->
        {:error, error(vault, {:missing_config, [:provider]})}
    end
  end

  # ADR-0005 decision 4: `:key` and `:keys` are mutually exclusive on the
  # provider, and passing both is refused at start rather than resolved by
  # precedence.
  defp provider_options(vault, module, provider_opts) do
    if Keyword.keyword?(provider_opts) and Keyword.has_key?(provider_opts, :key) and
         Keyword.has_key?(provider_opts, :keys) do
      {:error, error(vault, {:invalid_config, :provider, :key_and_keys})}
    else
      {:ok, {module, provider_opts}}
    end
  end

  defp commitment_policy(vault, opts) do
    case Keyword.get(opts, :commitment_policy) do
      policy when policy in @allowed_commitment_policies ->
        {:ok, policy}

      @forbidden_commitment_policy ->
        {:error, error(vault, {:invalid_config, :commitment_policy, :forbidden})}

      _other ->
        {:error, error(vault, {:invalid_config, :commitment_policy, :unknown})}
    end
  end

  defp algorithm_suite_id(vault, opts) do
    case Keyword.get(opts, :algorithm_suite_id) do
      id when id in @allowed_algorithm_suite_ids -> {:ok, id}
      _other -> {:error, error(vault, {:invalid_config, :algorithm_suite_id, :unsupported})}
    end
  end

  defp max_encrypted_data_keys(vault, opts) do
    case Keyword.get(opts, :max_encrypted_data_keys) do
      nil ->
        {:error, error(vault, {:invalid_config, :max_encrypted_data_keys, :unlimited})}

      count when is_integer(count) and count > 0 ->
        {:ok, count}

      _other ->
        {:error,
         error(vault, {:invalid_config, :max_encrypted_data_keys, :not_a_positive_integer})}
    end
  end

  defp cache(vault, opts) do
    case Keyword.get(opts, :cache) do
      false ->
        {:ok, false}

      bounds when is_list(bounds) ->
        if Keyword.keyword?(bounds),
          do: cache_bounds(vault, bounds),
          else: {:error, error(vault, {:invalid_config, :cache, :not_false_or_keyword_list})}

      _other ->
        {:error, error(vault, {:invalid_config, :cache, :not_false_or_keyword_list})}
    end
  end

  defp cache_bounds(vault, bounds) do
    with :ok <- known_cache_bounds(vault, bounds),
         {:ok, max_age} <- cache_bound(vault, bounds, :max_age, :required),
         {:ok, max_messages} <- cache_bound(vault, bounds, :max_messages, @default_max_messages),
         {:ok, max_bytes} <- cache_bound(vault, bounds, :max_bytes, @default_max_bytes),
         default_recycle = @recycle_after_multiplier * max_age,
         {:ok, recycle_after} <- cache_bound(vault, bounds, :recycle_after, default_recycle) do
      {:ok,
       %{
         max_age: max_age,
         max_messages: max_messages,
         max_bytes: max_bytes,
         recycle_after: recycle_after
       }}
    end
  end

  # The cache bounds are a closed set (ADR-0001 decision 6), so a misspelled
  # bound is refused rather than silently taking the default it was meant to
  # replace.
  defp known_cache_bounds(vault, bounds) do
    case Keyword.keys(bounds) -- @cache_bounds do
      [] -> :ok
      unknown -> {:error, error(vault, {:invalid_config, :cache, {:unknown_bounds, unknown}})}
    end
  end

  defp cache_bound(vault, bounds, key, default) do
    case {Keyword.fetch(bounds, key), default} do
      {{:ok, value}, _default} when is_integer(value) and value > 0 ->
        {:ok, value}

      {{:ok, _value}, _default} ->
        {:error, error(vault, {:invalid_config, :cache, {key, :not_a_positive_integer}})}

      {:error, :required} ->
        {:error, error(vault, {:missing_config, [:cache, key]})}

      {:error, default} ->
        {:ok, default}
    end
  end

  defp context_profile(vault, opts) do
    case Keyword.fetch(opts, :context_profile) do
      {:ok, profile} when profile in [:single, :tenant] ->
        {:ok, profile}

      {:ok, _other} ->
        {:error, error(vault, {:invalid_config, :context_profile, :unknown})}

      :error ->
        {:error, error(vault, {:missing_config, [:context_profile]})}
    end
  end

  defp required_context(vault, profile, opts) do
    case Keyword.get(opts, :required_context) do
      keys when is_list(keys) -> required_context_keys(vault, profile, keys)
      _other -> {:error, error(vault, {:invalid_config, :required_context, :not_a_list})}
    end
  end

  defp required_context_keys(vault, profile, keys) do
    cond do
      invalid = Enum.find(keys, &(not context_key?(&1))) ->
        {:error, error(vault, {:invalid_config, :required_context, {:invalid_key, invalid}})}

      profile == :single and "tenant_ref" in keys ->
        # ADR-0004 decision 2: `tenant_ref` is refused on a `:single` vault, so
        # requiring it there is a vault that can never encrypt.
        {:error,
         error(vault, {:invalid_config, :required_context, {:reserved_key, "tenant_ref"}})}

      true ->
        {:ok, keys}
    end
  end

  defp static_encryption_context(vault, profile, opts) do
    case Keyword.get(opts, :static_encryption_context) do
      static when is_map(static) -> validate_static_context(vault, profile, static)
      _other -> {:error, error(vault, {:invalid_config, :encryption_context, :not_a_map})}
    end
  end

  defp validate_static_context(vault, profile, static) do
    pairs = Map.to_list(static)

    cond do
      invalid = Enum.find(pairs, fn {k, v} -> not (context_key?(k) and context_key?(v)) end) ->
        {:error,
         error(vault, {:invalid_config, :encryption_context, {:invalid_pair, elem(invalid, 0)}})}

      reserved = Enum.find(Map.keys(static), &reserved_context_key?(&1, profile)) ->
        {:error, error(vault, {:reserved_context_key, reserved})}

      length(pairs) > @max_context_pairs ->
        {:error, error(vault, {:invalid_config, :encryption_context, :too_many_pairs})}

      serialized_context_size(pairs) > @max_context_bytes ->
        {:error, error(vault, {:invalid_config, :encryption_context, :too_large})}

      true ->
        {:ok, static}
    end
  end

  # ADR-0004 decision 9 bounds the *serialized* context, and the engine's
  # serialization is a 16-bit pair count followed by a 16-bit length prefix on
  # every key and value. Computed arithmetically so this stays a size check
  # rather than a second dependency on the message format.
  defp serialized_context_size(pairs) do
    Enum.reduce(pairs, 2, fn {key, value}, total ->
      total + 2 + byte_size(key) + 2 + byte_size(value)
    end)
  end

  defp reserved_context_key?(key, profile) do
    Enum.any?(@reserved_context_prefixes, &String.starts_with?(key, &1)) or
      (profile == :tenant and key in @tenant_context_keys)
  end

  defp context_key?(value), do: is_binary(value) and value != "" and String.valid?(value)

  defp reference_subkey(vault, :tenant, opts) do
    case Keyword.fetch(opts, :reference_subkey) do
      {:ok, subkey} when is_binary(subkey) and byte_size(subkey) == @reference_subkey_bytes ->
        {:ok, subkey}

      {:ok, _other} ->
        {:error, error(vault, {:invalid_config, :reference_subkey, :invalid_length})}

      :error ->
        {:error, error(vault, {:missing_config, [:reference_subkey]})}
    end
  end

  defp reference_subkey(vault, :single, opts) do
    if Keyword.has_key?(opts, :reference_subkey) do
      # A reference subkey on a `:single` vault means the host believes this is
      # a tenant vault. Refusing here catches a mistyped profile at start
      # rather than at the first string selector.
      {:error, error(vault, {:invalid_config, :reference_subkey, :single_profile})}
    else
      {:ok, nil}
    end
  end

  defp reference_check(vault, :tenant, subkey, opts) do
    case Keyword.fetch(opts, :reference_check) do
      {:ok, pinned} when is_binary(pinned) ->
        # The reference is a published value - it travels in the clear in
        # every message header (ADR-0003 decision 5) - so there is nothing
        # here for a timing attack to learn.
        if pinned == known_answer(subkey),
          do: {:ok, pinned},
          else:
            {:error, error(vault, {:invalid_config, :reference_subkey, :known_answer_mismatch})}

      {:ok, _other} ->
        {:error, error(vault, {:invalid_config, :reference_check, :not_a_string})}

      :error ->
        {:ok, nil}
    end
  end

  defp reference_check(vault, :single, _subkey, opts) do
    if Keyword.has_key?(opts, :reference_check),
      do: {:error, error(vault, {:invalid_config, :reference_check, :single_profile})},
      else: {:ok, nil}
  end

  @doc """
  Computes the known-answer value a deployment pins as `:reference_check`.

  The value is the reference this package derives for a fixed probe selector,
  by ADR-0003 decision 5's keyed derivation. An operator runs this once,
  against the reference subkey the deployment was provisioned with, and writes
  the result into the tenant vault's configuration. Every node then refuses to
  start unless its subkey reproduces it.

  The check exists because the alternative failure is silent and fleet-wide: a
  node deployed with a wrong reference subkey writes messages no correct
  reader can open, and fails every correct message as `:decrypt_failed` -
  corruption-shaped, and discovered at decrypt time, when the reference subkey
  is already permanent (ADR-0004 decision 4).

  The returned value is not secret. It is the same shape as a `tenant_ref`,
  which travels in the clear in every message header.
  """
  @spec known_answer(binary()) :: String.t()
  def known_answer(reference_subkey) when is_binary(reference_subkey) do
    :hmac
    |> :crypto.mac(:sha256, reference_subkey, @known_answer_probe)
    |> binary_part(0, 16)
    |> Base.url_encode64(padding: false)
  end

  @doc """
  Publishes a resolved configuration under `{Encryptor.Vault, vault}`.

  Called once, by the vault's supervisor, at start. Returns the config so it
  can be threaded.
  """
  @spec freeze(t()) :: t()
  def freeze(%__MODULE__{vault: vault} = config) do
    :persistent_term.put(term_key(vault), config)
    config
  end

  @doc """
  Reads a vault's frozen configuration.

  A vault that has not been started has no entry, and that is a typed error
  rather than a raise: `{:vault_not_started, vault}` is the check ADR-0001
  decision 2 requires at every entry point.

      iex> Encryptor.Vault.Config.fetch(MyApp.UnstartedVault)
      {:error,
       %Encryptor.Error{
         reason: {:vault_not_started, MyApp.UnstartedVault},
         vault: MyApp.UnstartedVault,
         operation: :start,
         engine: nil
       }}
  """
  @spec fetch(module()) :: {:ok, t()} | {:error, Error.t()}
  def fetch(vault) do
    case :persistent_term.get(term_key(vault), :__not_started__) do
      :__not_started__ -> {:error, error(vault, {:vault_not_started, vault})}
      %__MODULE__{} = config -> {:ok, config}
    end
  end

  @doc """
  Removes a vault's frozen configuration.

  Called when a vault stops. `:persistent_term.erase/1` triggers a global
  scan, which is why this happens on a vault's lifecycle boundary and never on
  a call path.
  """
  @spec erase(module()) :: :ok
  def erase(vault) do
    :persistent_term.erase(term_key(vault))
    :ok
  end

  defp term_key(vault), do: {Encryptor.Vault, vault}

  # Every refusal in this module funnels through here, and the spec is what
  # makes that funnel worth having: dialyzer rejects a reason that is not in
  # `Encryptor.Error.reason/0`, so a validator cannot invent a near-miss term
  # without the gate saying so.
  @spec error(module(), Error.reason()) :: Error.t()
  defp error(vault, reason) do
    %Error{reason: reason, vault: vault, operation: :start, engine: nil}
  end

  defimpl Inspect do
    import Inspect.Algebra

    @redacted "[redacted]"

    def inspect(config, opts) do
      fields =
        config
        |> Map.from_struct()
        |> Map.put(:reference_subkey, redact(config.reference_subkey))
        |> Map.put(:provider, redact_provider(config.provider))

      concat(["#Encryptor.Vault.Config<", to_doc(fields, opts), ">"])
    end

    defp redact(nil), do: nil
    defp redact(_binary), do: @redacted

    defp redact_provider({module, _opts}), do: {module, @redacted}
    defp redact_provider(other), do: other
  end
end
