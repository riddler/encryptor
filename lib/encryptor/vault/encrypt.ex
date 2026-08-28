defmodule Encryptor.Vault.Encrypt do
  @moduledoc false

  # The encrypt path: one call, in a fixed order, ending in the complete
  # self-describing engine message and nothing else.
  #
  # `Encryptor.Vault.encrypt/3` is the door; this module is the body behind
  # it. It is internal, and it is separate from `Encryptor.Vault` because the
  # order below is the security-relevant part of ADR-0004 decision 5 and
  # deserves to be readable in one screen rather than interleaved with the
  # lifecycle surface.
  #
  # ## The order, and why it is this order
  #
  #   1. `Encryptor.Vault.ready/2` - the vault is running and its provider, if
  #      it has a process, is alive (ADR-0001 decision 2).
  #   2. The **selector profile check**. A `:tenant` vault refuses `:default`
  #      and a `:single` vault refuses a string, both as
  #      `{:invalid_selector, selector}`, and both **before the provider is
  #      consulted** (ADR-0004 decision 3). A per-tenant provider handed
  #      `:default` by mistake is the failure this catches one layer above the
  #      provider.
  #   3. The provider resolves the selector to one descriptor.
  #   4. `Encryptor.Vault.Keyring` validates the descriptor and maps it to an
  #      engine keyring. Only the vault does this (ADR-0002 decision 3).
  #   5. `Encryptor.Context` composes the four layers, with `tenant_ref`
  #      injected by the vault on a `:tenant` vault and refused from a caller
  #      (ADR-0004 decision 4).
  #
  # Steps 2, 3 and 5 are `Encryptor.Vault.Resolve`'s, because the decrypt path
  # takes them identically and a check that ran on one side only would not be
  # a check at all. What is this module's alone is step 4's single descriptor,
  # the stack below, and the engine call.
  #   6. `Encryptor.Vault.Partition` derives the cache partition id from the
  #      same selector that chose the key, which is what keeps one tenant's
  #      data key out of another tenant's cache lookup (ADR-0001 decision 7).
  #   7. The CMM stack, then the client, then the engine call.
  #
  # ## The CMM stack order is a security property, not a style choice
  #
  #     Cmm.Default.new(keyring)
  #     |> maybe_wrap_in_caching(config.cache, partition_id)
  #     |> then(&Cmm.RequiredEncryptionContext.new(required_keys, &1))
  #
  # The engine permits either arrangement and the wrong one is silently
  # unsafe. With caching on the outside, a decryption cache hit returns the
  # stored materials directly and the wrapped CMM is never called, so the
  # reproduced-context presence check is skipped for exactly the messages that
  # are read often. Required on the outside runs the check before the cache is
  # consulted, every time. The vault builds this order and **does not make it
  # configurable** (ADR-0004 decision 5).
  #
  # When the required set is empty the outer wrap is skipped: a
  # required-context CMM over an empty list is an extra struct and an extra
  # dispatch for nothing.
  #
  # ## Flagged, not settled: the provider is consulted on every call
  #
  # Two accepted records describe provider resolution differently, and this
  # module is the first code that has to take a position.
  #
  #   * ADR-0001 decision 2: encrypt and decrypt "build the engine's keyring,
  #     CMM, and `Client` structs per call". A keyring needs a descriptor, and
  #     a descriptor comes from the provider, so read literally the provider
  #     answers once per call.
  #   * ADR-0002 decision 2: the materials cache "collapses provider round
  #     trips to one per partition per `max_age`". Read literally, a warm
  #     partition does not reach the provider at all.
  #
  # The implementation follows the first, because `enc-50m` fixes the order in
  # its own words - the vault "resolves the selector through the provider,
  # validates and maps the descriptor to a keyring, composes the context,
  # derives the partition id, builds the CMM stack and the client" - and the
  # B3 graph doc says the beads win where they and the doc disagree. So the
  # keyring is built before the caching CMM is consulted, and what a warm
  # cache saves is the data key generation and the EDK wrap, not the
  # provider lookup.
  #
  # That is cheap for `Static` and for a `Function` provider closing over
  # material already in memory, and it is not cheap for a store-backed
  # provider, which is the case ADR-0002's sentence was written about. The
  # tension is recorded here and in `enc-50m`'s notes rather than resolved:
  # narrowing it is an amendment to one of the two records, and an
  # implementation bead does not amend an accepted record.
  #
  # ## What is deliberately not an option
  #
  # `:algorithm_suite`, `:commitment_policy`, `:frame_length` and
  # `:max_encrypted_data_keys` are configuration, never per call (ADR-0001
  # decision 4). A per-call suite is the shape of an algorithm downgrade and a
  # per-call commitment policy is the shape of an attacker choosing to be
  # trusted. The two the vault passes to the engine come from the frozen
  # configuration and from nowhere else.

  alias AwsEncryptionSdk.AlgorithmSuite
  alias AwsEncryptionSdk.Client
  alias AwsEncryptionSdk.Cmm.Caching
  alias AwsEncryptionSdk.Cmm.Default
  alias AwsEncryptionSdk.Cmm.RequiredEncryptionContext
  alias Encryptor.Context
  alias Encryptor.Error
  alias Encryptor.Vault
  alias Encryptor.Vault.Config
  alias Encryptor.Vault.Keyring
  alias Encryptor.Vault.Partition
  alias Encryptor.Vault.Resolve

  @doc false
  @spec call(module(), binary(), keyword()) :: {:ok, binary()} | {:error, Error.t()}
  def call(vault, plaintext, opts) when is_binary(plaintext) and is_list(opts) do
    with {:ok, config} <- Vault.ready(vault, :encrypt),
         {:ok, selector} <- Resolve.selector(config, opts, :encrypt),
         {:ok, descriptor} <- Resolve.encryption_key(config, selector, :encrypt),
         {:ok, keyring} <- Keyring.build(vault, :encrypt, descriptor),
         {:ok, context} <- Resolve.context(config, selector, opts, :encrypt) do
      config
      |> client(keyring, selector)
      |> engine_encrypt(config, plaintext, context)
    end
  end

  @typedoc false
  @type cmm :: Default.t() | Caching.t() | RequiredEncryptionContext.t()

  @doc false
  # Public so the nesting can be asserted directly. The order below is the
  # security property this bead exists to fix, and a test that could only
  # observe it through a successful round trip would pass just as happily
  # with the unsafe arrangement.
  @spec stack(Config.t(), Keyring.t(), Error.selector()) :: cmm()
  def stack(config, keyring, selector) do
    keyring
    |> Default.new()
    |> maybe_caching(config, selector)
    |> maybe_required(config)
  end

  @doc false
  # Public for the same reason `stack/3` is: the commitment policy and the EDK
  # limit the client carries are configuration the vault is not allowed to
  # take from a caller, and a test that could only observe them through a
  # successful encrypt could not tell a dropped limit from a present one.
  @spec client(Config.t(), Keyring.t(), Error.selector()) :: Client.t()
  def client(config, keyring, selector) do
    config
    |> stack(keyring, selector)
    |> Client.new(
      commitment_policy: config.commitment_policy,
      max_encrypted_data_keys: config.max_encrypted_data_keys
    )
  end

  # A vault with `cache: false` runs a bare Default CMM and starts no cache
  # process, so there is nothing to wrap (ADR-0001 decision 6).
  @spec maybe_caching(Default.t(), Config.t(), Error.selector()) :: Default.t() | Caching.t()
  defp maybe_caching(cmm, %Config{cache: false}, _selector), do: cmm

  defp maybe_caching(cmm, %Config{vault: vault, cache: bounds}, selector) do
    Caching.new(cmm, Vault.cache_name(vault),
      max_age: bounds.max_age,
      max_messages: bounds.max_messages,
      max_bytes: bounds.max_bytes,
      partition_id: Partition.id(vault, selector)
    )
  end

  @spec maybe_required(Default.t() | Caching.t(), Config.t()) ::
          Default.t() | Caching.t() | RequiredEncryptionContext.t()
  defp maybe_required(cmm, %Config{required_keys: []}), do: cmm

  defp maybe_required(cmm, %Config{required_keys: keys}),
    do: RequiredEncryptionContext.new(keys, cmm)

  # The suite is matched over the closed set `Encryptor.Vault.Config` admits
  # rather than looked up by id, so a suite this package has never validated
  # cannot reach the engine through a widened configuration.
  @spec suite(Config.t()) :: AlgorithmSuite.t()
  defp suite(%Config{algorithm_suite_id: 0x0578}),
    do: AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key_ecdsa_p384()

  defp suite(%Config{algorithm_suite_id: 0x0478}),
    do: AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()

  # ADR-0001 decision 4: the vault returns the ciphertext binary and nothing
  # else. The engine's result also carries the header, the context and the
  # suite, and returning them would invite callers to persist a second copy of
  # facts the message already carries authenticated.
  @spec engine_encrypt(Client.t(), Config.t(), binary(), Context.context()) ::
          {:ok, binary()} | {:error, Error.t()}
  defp engine_encrypt(client, config, plaintext, context) do
    case Client.encrypt(client, plaintext,
           encryption_context: context,
           algorithm_suite: suite(config)
         ) do
      {:ok, %{ciphertext: ciphertext}} ->
        {:ok, ciphertext}

      # The required-context CMM's refusal, and the one encrypt-side failure a
      # caller can act on: a call site that omitted a key the host configured
      # as required. It depends on the caller's own arguments and the vault's
      # own configuration, so it stays distinct (ADR-0004 decision 8).
      {:error, {:missing_required_encryption_context_keys, keys} = engine} ->
        {:error, error(config, {:missing_required_context_keys, keys}, engine)}

      # Everything else the engine can refuse at encrypt is a disagreement
      # between validated configuration and the message being built - a suite
      # the commitment policy will not write, an EDK limit the materials
      # exceed. The context, the descriptor and every configuration key were
      # checked above, so reaching here means one of those checks is wrong.
      # The engine's term is carried for the operator; it is never matched on.
      {:error, engine} ->
        {:error, error(config, {:invalid_config, :encrypt, :engine_refused}, engine)}
    end
  end

  @spec error(Config.t(), Error.reason(), term()) :: Error.t()
  defp error(%Config{vault: vault}, reason, engine) do
    %Error{reason: reason, vault: vault, operation: :encrypt, engine: engine}
  end
end
