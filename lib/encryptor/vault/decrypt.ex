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
  #      it: a `:scoped` vault that refused `:default` at encrypt and accepted
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
  #      four layers the writer composed the stored one from, with `"scope_ref"`
  #      injected by the vault on a `:scoped` vault and refused from a caller
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
  # `:scoped` vault `"scope_ref"` is always in the required set.
  #
  # ## One stored key a reader may not omit: a package pair
  #
  # The one exception to "a key the claim omits is ignored" is a key under
  # this package's own prefix, `Encryptor.Context.package_key?/1`. No host
  # can write one, so a message carrying one was written by this package for
  # itself - today, a scope-key wrapping, whose binding is four such pairs -
  # and only the reader that reproduces the pair may open it. A reader that
  # does not is refused with `:decrypt_failed`, before the engine is called,
  # carrying `{:encryption_context_mismatch, key}` in `:engine` like any
  # other disagreement.
  #
  # The public doors reproduce no package pair: `Encryptor.Vault.decrypt/3`
  # passes no reserved layer and `Encryptor.Context` refuses the prefix from
  # a caller. So a root vault's own `decrypt/2` refuses a wrapping, where
  # without this it opened the wrapping and returned the bare scope master
  # key, which ADR-0003 decision 3 says no function in this package returns.
  # `Encryptor.Envelope.unwrap/2` is the reader that reproduces the binding,
  # through `call/4` below; the rekey path applies the same rule, and
  # `Encryptor.Envelope.rewrap/2` reproduces the binding there likewise.
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
  #
  # An engine return that is neither `{:ok, %{plaintext: _}}` nor
  # `{:error, _}` - a message followed by trailing bytes is one today - also
  # collapses to `:decrypt_failed`, carrying `:unexpected_engine_result` in
  # `:engine` rather than the term, which would hold the parsed message.

  alias AwsEncryptionSdk.Client
  alias Encryptor.Context
  alias Encryptor.Error
  alias Encryptor.Message
  alias Encryptor.Message.Info
  alias Encryptor.Telemetry
  alias Encryptor.Vault.Config
  alias Encryptor.Vault.Encrypt
  alias Encryptor.Vault.Keyring
  alias Encryptor.Vault.Resolve

  @doc false
  # `reserved` is the package-reserved context layer the reader reproduces,
  # positional for the reason `Encryptor.Vault.Resolve.context/5` gives. Its
  # only caller is `Encryptor.Envelope.unwrap/2`, reproducing ADR-0003
  # decision 4's binding; `Encryptor.Vault.decrypt/3` passes none, which is
  # what makes `agree/4` refuse a wrapping on the public door. Note that
  # reproducing it here is not the same as *requiring* it: `agree/4` compares
  # only keys present in both maps, so the envelope performs its own presence
  # check before calling in.
  @spec call(module(), binary(), keyword(), Context.context()) ::
          {:ok, binary()} | {:error, Error.t()}
  def call(vault, ciphertext, opts, reserved \\ %{})
      when is_binary(ciphertext) and is_list(opts) and is_map(reserved) do
    opened = Resolve.open(vault, opts, :decrypt)
    scope_ref = Resolve.telemetry_reference(opened)
    span = Telemetry.operation_start(vault, :decrypt, scope_ref)

    result =
      with {:ok, config, selector, reference} <- opened do
        decrypt(config, selector, reference, ciphertext, opts, reserved, scope_ref)
      end

    # ADR-0006 decision 4 puts `size` on this half rather than on the start:
    # what a decrypt measures is the plaintext it produced, and a failure
    # produced none. Decision 7 is why the metadata stops at `reason_tag`.
    Telemetry.operation_stop(vault, :decrypt, span, scope_ref, result, %{size: size(result)})

    result
  end

  defp size({:ok, plaintext}), do: byte_size(plaintext)
  defp size({:error, _error}), do: 0

  defp decrypt(config, selector, reference, ciphertext, opts, reserved, scope_ref) do
    with {:ok, candidates} <-
           Telemetry.provider_span(config, :decryption_keys, :decrypt, scope_ref, fn ->
             Resolve.decryption_keys(config, selector, :decrypt)
           end),
         {:ok, keyring} <- Keyring.build_all(config.vault, :decrypt, candidates),
         {:ok, context} <- Resolve.context(config, reference, opts, :decrypt, reserved),
         :ok <- agree(config, ciphertext, context) do
      config
      |> Encrypt.client(keyring, selector)
      |> engine_decrypt(config, ciphertext, context, :decrypt)
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

  # Two scans, each sorted before it reports, so a message failing on two
  # keys names the same one on every run. The first is the package pair the
  # reader did not reproduce ("One stored key a reader may not omit", above).
  # The second is the value comparison, where `Map.get(stored, key, value)` is
  # what makes "only keys present in both" literal: a key the message does not
  # carry compares equal to itself and is skipped.
  @spec compare(Config.t(), Context.context(), Context.context(), Error.operation()) ::
          :ok | {:error, Error.t()}
  defp compare(config, stored, reproduced, operation) do
    case unreproduced_package_key(stored, reproduced) || disagreeing_key(stored, reproduced) do
      nil ->
        :ok

      key ->
        {:error,
         Error.decrypt_failed(config.vault, operation, {:encryption_context_mismatch, key})}
    end
  end

  @spec unreproduced_package_key(Context.context(), Context.context()) :: String.t() | nil
  defp unreproduced_package_key(stored, reproduced) do
    stored
    |> Map.keys()
    |> Enum.sort()
    |> Enum.find(&(Context.package_key?(&1) and not Map.has_key?(reproduced, &1)))
  end

  @spec disagreeing_key(Context.context(), Context.context()) :: String.t() | nil
  defp disagreeing_key(stored, reproduced) do
    reproduced
    |> Enum.sort()
    |> Enum.find_value(fn {key, value} -> if Map.get(stored, key, value) != value, do: key end)
  end

  @doc false
  # Public for the same reason `agree/4` is: `rekey/2` (`enc-gsd`) has a
  # decrypt half, and this failure mapping - the oracle collapse and the one
  # carve-out from it - is the part of it that must not be spelled twice.
  # `operation` is threaded so a rekey reports `:rekey` here too.
  @spec engine_decrypt(
          Client.t(),
          Config.t(),
          binary(),
          Context.context(),
          Error.operation()
        ) :: {:ok, binary()} | {:error, Error.t()}
  def engine_decrypt(client, config, ciphertext, context, operation) do
    client
    |> Client.decrypt(ciphertext, encryption_context: context)
    |> engine_result(config, operation)
  end

  @doc false
  # The failure mapping itself, taking `term()` rather than the engine's
  # `@spec` on purpose. `Client.decrypt/3` is specified to return
  # `{:ok, decrypt_result}` or `{:error, term}`, and it does not: a message
  # followed by trailing bytes comes back as `{:ok, parsed_message, rest}`.
  # Matched inside `engine_decrypt/5` against the spec, the last clause
  # below is one a type checker calls unreachable; matched here, against
  # what the engine actually returns, it is the clause that keeps a decrypt
  # from raising. Public only so the type of its argument is its own.
  @spec engine_result(term(), Config.t(), Error.operation()) ::
          {:ok, binary()} | {:error, Error.t()}
  def engine_result(result, config, operation) do
    case result do
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
           operation: operation,
           engine: engine
         }}

      # Everything else: a wrong key, a failed authentication tag, a required
      # key the *message* lacks, a commitment policy rejection, a context
      # mismatch the engine caught underneath us on a cache miss. A caller who
      # could tell these apart would hold an oracle over the header, and could
      # not act differently on the distinctions anyway.
      {:error, engine} ->
        {:error, Error.decrypt_failed(config.vault, operation, engine)}

      # Any return outside the engine's documented pair. The engine answers a
      # message followed by trailing bytes with `{:ok, parsed_message, rest}`,
      # and a future engine may answer something else again. It depends on the
      # message, so it collapses like every other message-dependent failure; and
      # the term itself is NOT carried, because a parsed message holds the header,
      # the wrapped data keys and the body ciphertext, and `:engine` is printed
      # wherever an error struct is inspected. Without this clause the `case`
      # raises a `CaseClauseError` whose text renders that whole term.
      _unexpected ->
        {:error, Error.decrypt_failed(config.vault, operation, :unexpected_engine_result)}
    end
  end
end
