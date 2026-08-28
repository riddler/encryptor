defmodule Encryptor.Vault.Decrypt do
  @moduledoc false

  # The decrypt path: one call, in a fixed order, ending in plaintext and
  # nothing else - and, one step before the engine, the value comparison this
  # package performs itself because the engine's own is bypassed by its cache.
  #
  # `Encryptor.Vault.decrypt/3` is the door; this module is the body behind
  # it, as `Encryptor.Vault.Encrypt` is for the write half.
  #
  # ## The order, and why it is this order
  #
  #   1. `Encryptor.Vault.ready/2` - the vault is running and its provider, if
  #      it has a process, is alive (ADR-0001 decision 2).
  #   2. The selector profile check, before the provider is consulted
  #      (ADR-0004 decision 3). Identical to the write half's, and shared with
  #      it: a `:tenant` vault that refused `:default` at encrypt and accepted
  #      it at decrypt would accept a read no write could have produced.
  #   3. `c:Encryptor.Provider.decryption_keys/2` resolves the selector to
  #      **every** key a stored message might have been written under, newest
  #      first.
  #   4. `Encryptor.Vault.Keyring.build_all/3` turns that candidate list into
  #      one keyring: a plain `RawAes` for a single candidate, a `Multi` with
  #      `generator: nil` for more. The `Multi` walk is the whole rotation
  #      mechanism - a message written under an older name still decrypts, and
  #      a name dropped from the list is a message nobody can read again
  #      (ADR-0002 decision 7).
  #   5. `Encryptor.Context` composes the reproduced context, from the same
  #      four layers the writer composed the stored one from, with `tenant_ref`
  #      injected by the vault on a `:tenant` vault and refused from a caller
  #      (ADR-0004 decision 4).
  #   6. **The value comparison** (ADR-0004 decision 6), below.
  #   7. The CMM stack, then the client, then the engine call.
  #
  # ## The value comparison is ours, and it is not an optimization
  #
  # `Cmm.Behaviour.validate_reproduced_context/2` - the engine's own check that
  # a reader's claim about the context agrees with the message - lives in
  # `Cmm.Default.get_decryption_materials/2`, which sits **below**
  # `Cmm.Caching`. On a decryption cache hit the Default CMM is never called,
  # so the comparison does not happen. The decryption cache id is computed from
  # the partition, the suite, the EDKs and the *message's own* stored context,
  # never from the reproduced one, so a second read of the same ciphertext
  # within `max_age` hits the entry a legitimate first read populated - and a
  # reader supplying a disagreeing value gets a plaintext.
  #
  # ADR-0004 decision 5's stack ordering does not save this. Required-context
  # on the outside buys *presence*, and presence is satisfied by a wrong value.
  #
  # So this module parses the header itself and compares, above the engine and
  # above the cache, before `Client.decrypt/3` is called at all. That is what
  # makes anti-substitution this package's guarantee rather than an engine
  # behaviour it happens to inherit: it holds identically on a cold cache, a
  # warm cache, and with caching switched off.
  #
  # **This is a workaround for an open upstream defect**
  # (riddler/aws-encryption-sdk-elixir issue #96) and it may not be simplified
  # away by a reader who notices the engine "already does that". The engine
  # does it in the cold-cache case only, and the warm case is the one that
  # dominates real traffic. Even if upstream moves, this package has to work
  # against v1.0.0.
  #
  # The reach of the comparison is deliberately the engine's, not tighter:
  # only keys present in **both** maps are compared. A reader may claim a key
  # the message does not carry, and it is ignored; a reader may omit a key the
  # message does carry, and that is ignored too. Requiring the reproduced
  # context to cover the stored one would make every message unreadable the
  # moment a host added an advisory key to a vault's static configuration.
  # Required keys are what close the gap for the keys that matter, and on a
  # `:tenant` vault `tenant_ref` is always in the required set.
  #
  # ## The reader's stack is the writer's stack
  #
  # `Encryptor.Vault.Encrypt.client/3` builds it, and this module calls that
  # function rather than assembling a second one. The reason is not tidiness:
  # this engine appends the serialization of the *required subset* of the
  # context to the header AAD (`Crypto.HeaderAuth.compute_header_auth_tag/4`,
  # `Map.take(full_encryption_context, required_ec_keys)`), so a reader that
  # does not know which keys were required computes a different tag and fails
  # header authentication rather than a context comparison. A second spelling
  # of the stack that drifted from the first would not fail loudly; it would
  # make correct messages unreadable.
  #
  # ## What comes back
  #
  # `{:ok, plaintext}` and nothing else (ADR-0001 decision 4). The engine's
  # `decrypt_result` also carries the header, the verified context and the
  # suite; a caller that wants the context reads it from
  # `Encryptor.Message.describe/1`, which is honest about being unverified,
  # rather than from a decrypt return that would be half-trusted.
  #
  # ## The failure mapping
  #
  # ADR-0004 decision 8's table, and it is the oracle rule (ADR-0001 decision
  # 10) applied to the context. Everything that depends on what is *in* the
  # message collapses to `:decrypt_failed` with the detail in `:engine`, for
  # logs only. `{:missing_required_context_keys, keys}` stays distinct because
  # it depends only on the reproduced context the caller passed and on the
  # vault's own configuration - both of which the caller already knows, and it
  # is the one context failure a caller can actually fix.
  #
  # The vault's own `{:encryption_context_mismatch, key}` goes into `:engine`
  # shaped exactly as the engine's, so an operator's log line reads the same
  # whether the check fired above the engine or below it.

  alias AwsEncryptionSdk.Client
  alias Encryptor.Context
  alias Encryptor.Error
  alias Encryptor.Message
  alias Encryptor.Message.Info
  alias Encryptor.Vault
  alias Encryptor.Vault.Config
  alias Encryptor.Vault.Encrypt
  alias Encryptor.Vault.Keyring
  alias Encryptor.Vault.Resolve

  @doc false
  @spec call(module(), binary(), keyword()) :: {:ok, binary()} | {:error, Error.t()}
  def call(vault, ciphertext, opts) when is_binary(ciphertext) and is_list(opts) do
    with {:ok, config} <- Vault.ready(vault, :decrypt),
         {:ok, selector} <- Resolve.selector(config, opts, :decrypt),
         {:ok, candidates} <- Resolve.decryption_keys(config, selector, :decrypt),
         {:ok, keyring} <- Keyring.build_all(vault, :decrypt, candidates),
         {:ok, context} <- Resolve.context(config, selector, opts, :decrypt),
         :ok <- agree(config, ciphertext, context) do
      config
      |> Encrypt.client(keyring, selector)
      |> engine_decrypt(config, ciphertext, context)
    end
  end

  @doc false
  # ADR-0004 decision 6, and the module's reason for existing. Public so a
  # test can reach it on a message the vault would refuse for another reason
  # first, and so `rekey/2` (`enc-gsd`) has one comparison to call rather than
  # a second copy to write.
  #
  # `operation` is threaded rather than fixed at `:decrypt` because a rekey
  # reports `:rekey` on both halves: what failed is the operation the caller
  # asked for, not the half of it the failure landed in.
  @spec agree(Config.t(), binary(), Context.context(), Error.operation()) ::
          :ok | {:error, Error.t()}
  def agree(config, ciphertext, reproduced, operation \\ :decrypt) do
    case Message.describe(ciphertext) do
      {:ok, %Info{encryption_context: stored}} ->
        compare(config, stored, reproduced, operation)

      # A header this package cannot parse is not a message it can compare
      # against. It depends on the bytes, so it collapses like every other
      # message-dependent failure, and the engine's own parse error is
      # carried. `Encryptor.Message` reports the same reason with no vault and
      # no operation, because it has neither; here both are known.
      {:error, %Error{engine: engine}} ->
        {:error, Error.decrypt_failed(config.vault, operation, engine)}
    end
  end

  # Sorted before it reports, so a reproduced context disagreeing on two keys
  # names the same one on every run. `Map.get(stored, key, value)` is what
  # makes "only keys present in both" literal: a key the message does not
  # carry compares equal to itself and is skipped.
  @spec compare(Config.t(), Context.context(), Context.context(), Error.operation()) ::
          :ok | {:error, Error.t()}
  defp compare(config, stored, reproduced, operation) do
    reproduced
    |> Enum.sort()
    |> Enum.find(fn {key, value} -> Map.get(stored, key, value) != value end)
    |> case do
      nil ->
        :ok

      {key, _value} ->
        {:error,
         Error.decrypt_failed(config.vault, operation, {:encryption_context_mismatch, key})}
    end
  end

  @spec engine_decrypt(Client.t(), Config.t(), binary(), Context.context()) ::
          {:ok, binary()} | {:error, Error.t()}
  defp engine_decrypt(client, config, ciphertext, context) do
    case Client.decrypt(client, ciphertext, encryption_context: context) do
      {:ok, %{plaintext: plaintext}} ->
        {:ok, plaintext}

      # The required-context CMM's refusal, and the one decrypt-side failure
      # that is not an oracle: the reader omitted a key the host configured as
      # required. It is answerable from the caller's own arguments and the
      # vault's own configuration and discloses nothing about the ciphertext
      # (ADR-0004 decision 8).
      {:error, {:missing_required_encryption_context_keys, keys} = engine} ->
        {:error,
         %Error{
           reason: {:missing_required_context_keys, keys},
           vault: config.vault,
           operation: :decrypt,
           engine: engine
         }}

      # Everything else: a wrong key, a failed authentication tag, a required
      # key the *message* lacks, a commitment policy rejection, a context
      # mismatch the engine caught underneath us on a cache miss. A caller who
      # could tell these apart would hold an oracle over the header, and could
      # not act differently on the distinctions anyway.
      {:error, engine} ->
        {:error, Error.decrypt_failed(config.vault, :decrypt, engine)}
    end
  end
end
