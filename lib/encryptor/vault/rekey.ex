defmodule Encryptor.Vault.Rekey do
  @moduledoc false

  # The rekey path: a decrypt and an encrypt, in that order, with the message's
  # own encryption context carried across untouched - less the one pair the
  # engine owns, which the encrypt writes afresh.
  #
  # `Encryptor.Vault.rekey/3` is the door; this module is the body behind it,
  # as `Encryptor.Vault.Encrypt` and `Encryptor.Vault.Decrypt` are for the two
  # halves it is built out of. It is the last item in the vault core and it is
  # deliberately the smallest: every step below is a function one of those two
  # modules already exports, and the value of this module is the order and the
  # one refusal, not new machinery.
  #
  # ## The context comes from the message, then the vault, then the row
  #
  # ADR-0001 decision 4 requires a rekey to preserve the context, which ADR-0004
  # Amendment B reads as the authenticated map: the same pairs are bound to the
  # rekeyed message. ADR-0004 decision 5 requires every decrypt to reproduce the
  # required keys. A rekey caller holds a ciphertext, not a row.
  #
  # Where the header stores a pair, the header is the copy: a message the 1.0.x
  # engine wrote stores its whole context, `Encryptor.Message.describe/1`
  # recovers it, and such a message rekeys with nothing from the caller, as
  # ADR-0004 decision 11 has it. The 1.1 engine this package requires follows
  # the specification and stores no required pair in a message it writes; the
  # pairs are bound into the encrypted data key and the header authentication
  # instead. For such a message the decrypt half reproduces, per Amendment B's
  # B1:
  #
  #   * the stored context, as before;
  #   * each required key the header does not store that the vault composes
  #     itself - the static layer, and `"scope_ref"` from `:key` on a `:scoped`
  #     vault (`reproduce/3`);
  #   * each required key the header does not store that the caller passes in
  #     `:encryption_context`, which is what the option is for now.
  #
  # The re-encrypt writes under that same map, so what is bound to the new
  # message is what was bound to the old one. A value that disagrees with the
  # one the message was written under fails the unwrap in the engine, which is
  # `:decrypt_failed`, and nothing is rebound. A required key nobody supplies is
  # the required-context CMM's `{:missing_required_context_keys, keys}`.
  #
  # ## Why the option still refuses almost everything
  #
  # Where the message already says what a pair is, a second copy buys nothing
  # and risks everything: a rotation job that passes a context rewrites what a
  # million rows are bound to while believing it is rotating keys. Changing the
  # context is an encrypt of new data - ADR-0005 decision 1's R3 - and a
  # context-preserving rekey is by definition the wrong operation for it. So the
  # option accepts a key only when the vault requires it, the header does not
  # store it, the vault does not compose it, and it is under no reserved prefix
  # (`accept_pairs/4`); every other key is `{:reserved_context_key, key}`
  # (ADR-0004 decision 11 as Amendment B replaces its second paragraph). The
  # check runs before the provider is consulted, because it depends on the
  # caller's arguments, the vault's configuration and the header, and on no key
  # material.
  #
  # ## The vault-side comparison still runs, and it is not redundant
  #
  # Reproducing the context from the message would make a comparison of the two
  # trivially true, so this module does not compare the stored context against
  # itself. It compares the stored context against the one **the vault composes
  # from the call's own arguments** - the static layer, plus `"scope_ref"`
  # derived from the `:key` selector on a `:scoped` vault - through the same
  # `Encryptor.Vault.Decrypt.agree/4` a read goes through, reporting `:rekey`.
  #
  # That is what stops a rekey being a way around ADR-0004 decision 6. Without
  # it, a caller naming scope A could hand this function scope B's ciphertext
  # and, wherever the two selectors resolve to overlapping key material, get
  # back a message re-encrypted under A's current key with B's binding still
  # inside it. For a message whose header does not store `"scope_ref"`, the
  # composed pair is reproduced into the decrypt instead, and the engine's
  # unwrap refuses a scope the message was not bound to. The comparison is one
  # call, and it is the same call the decrypt
  # path makes, on purpose: a second copy of it would be a second thing to keep
  # in step with upstream issue #96.
  #
  # The same call is what refuses a scope-key wrapping on the public door. A
  # stored pair under this package's own prefix that the composed context
  # does not reproduce is `:decrypt_failed` there (`Encryptor.Vault.Decrypt`,
  # "One stored key a reader may not omit"), and `Encryptor.Vault.rekey/3`
  # composes no package pair. So a root vault's own `rekey/2` cannot open a
  # wrapping, and `Encryptor.Envelope.rewrap/2` - which reproduces the binding
  # as the `reserved` layer of `call/4` - is the one caller that can.
  #
  # ## The order
  #
  #   1. `Encryptor.Vault.ready/2`, stamped `:rekey`.
  #   2. The selector profile check (ADR-0004 decision 3).
  #   3. The vault-composed context, with the `reserved` layer when the
  #      caller is `Encryptor.Envelope.rewrap/2`.
  #   4. The `:encryption_context` check (Amendment B's B1), and the accepted
  #      pairs validated over the composed context.
  #   5. `decryption_keys/2` and the `Multi` keyring: the read half resolves to
  #      **every** key the message might have been written under, which is what
  #      makes a rekey the mechanism that moves a message off a retired key
  #      (ADR-0002 decision 7, ADR-0005 decision 1's R2).
  #   6. The stored context, parsed from the header, and the value comparison
  #      of it against the composed context described above.
  #   7. The decrypt, reproducing the stored context plus the required pairs
  #      the header does not store.
  #   8. `encryption_key/2` and its single keyring: the write half goes under
  #      the vault's **currently** resolved materials, which is the whole point.
  #   9. The re-encrypt, under the reproduced context less the engine's own
  #      pair.
  #
  # Steps 5 and 8 are two different provider callbacks answering two different
  # questions, and their independence is the rotation window itself
  # (ADR-0005 decision 2): minting a new version changes step 8 immediately and
  # changes step 4 not at all, so a rekey pass can run for as long as it takes.
  #
  # ## The engine's own pair is not carried
  #
  # Under a signing suite (`0x0578`, the default) the engine adds a pair of its
  # own to every message it writes: the verification key for that message's
  # signature, under the key `Cmm.Behaviour.reserved_encryption_context_key/0`
  # names. The header stores it, so the stored context carries it, and the
  # engine refuses that key from a caller on encrypt
  # (`:reserved_encryption_context_key`). Writing the stored context back
  # unchanged would fail every rekey, and every `rewrap/2` built on it, on the
  # default suite.
  #
  # So the write half drops that one key and nothing else, and the engine adds
  # a fresh pair for the fresh signing key it generates for the write. The
  # read half keeps it: it is part of what the message is, and the decrypt
  # reads the verification key from it. The key is the engine's own constant,
  # not a spelling kept here, so this cannot drift from the refusal it
  # answers. Every other key is carried as it was; `Encryptor.Context` refuses
  # the whole `aws-crypto-` prefix from a host, so no host pair is dropped.
  #
  # ## What it does not do
  #
  # It touches no storage and it is a pure binary-to-binary function: the batch
  # that walks rows belongs to whatever owns them. Its canonical caller is
  # `Encryptor.Envelope.rewrap/2` (ADR-0005 decision 7). It is **not** the
  # downstream migrator's tool - that one must be uniform across a rekey-shaped
  # rotation and a format or context change, and this function is by definition
  # wrong for the second.

  alias AwsEncryptionSdk.Cmm.Behaviour, as: CmmBehaviour
  alias Encryptor.Context
  alias Encryptor.Error
  alias Encryptor.Message
  alias Encryptor.Message.Info
  alias Encryptor.Telemetry
  alias Encryptor.Vault.Config
  alias Encryptor.Vault.Decrypt
  alias Encryptor.Vault.Encrypt
  alias Encryptor.Vault.Keyring
  alias Encryptor.Vault.Resolve

  @doc false
  # `reserved` is the package-reserved layer the composed context reproduces,
  # positional for the reason `Encryptor.Vault.Resolve.context/5` gives, as on
  # `Encryptor.Vault.Decrypt.call/4`. Its only caller is
  # `Encryptor.Envelope.rewrap/2`, reproducing ADR-0003 decision 4's binding;
  # `Encryptor.Vault.rekey/3` passes none.
  @spec call(module(), binary(), keyword(), Context.context()) ::
          {:ok, binary()} | {:error, Error.t()}
  def call(vault, ciphertext, opts, reserved \\ %{})
      when is_binary(ciphertext) and is_list(opts) and is_map(reserved) do
    opened = Resolve.open(vault, opts, :rekey)
    scope_ref = Resolve.telemetry_reference(opened)
    span = Telemetry.operation_start(vault, :rekey, scope_ref)

    result =
      with {:ok, config, selector, reference} <- opened do
        rekey(config, selector, reference, ciphertext, opts, reserved, scope_ref)
      end

    Telemetry.operation_stop(vault, :rekey, span, scope_ref, result)

    result
  end

  # Two provider round trips, so two nested provider spans: a rekey reads
  # under every candidate and writes under the current one, and an operator
  # watching a `key_unavailable` rate wants both.
  defp rekey(config, selector, reference, ciphertext, opts, reserved, scope_ref) do
    vault = config.vault

    with {:ok, composed} <- Resolve.context(config, reference, [], :rekey, reserved),
         {:ok, accepted} <- accept_context(config, opts, composed, ciphertext),
         {:ok, supplied} <- supplied(config, reference, accepted, reserved),
         {:ok, candidates} <-
           Telemetry.provider_span(config, :decryption_keys, :rekey, scope_ref, fn ->
             Resolve.decryption_keys(config, selector, :rekey)
           end),
         {:ok, readers} <- Keyring.build_all(vault, :rekey, candidates),
         {:ok, stored} <- Decrypt.agreed_stored(config, ciphertext, composed, :rekey),
         reproduced = reproduce(config, stored, supplied),
         {:ok, plaintext} <-
           open(config, {readers, candidates}, selector, ciphertext, reproduced),
         {:ok, descriptor} <-
           Telemetry.provider_span(config, :encryption_key, :rekey, scope_ref, fn ->
             Resolve.encryption_key(config, selector, :rekey)
           end),
         {:ok, writer} <- Keyring.build(vault, :rekey, descriptor) do
      # The write-side client, partitioned by the key it writes under as well
      # as the selector, so a rewrite after a mint never finds a warm entry
      # wrapped under the version before it (ADR-0001 Amendments B and C).
      config
      |> Encrypt.client(writer, selector, descriptor)
      |> Encrypt.engine_encrypt(config, plaintext, writable(reproduced), :rekey)
    end
  end

  # ADR-0004 Amendment B, B1: the decrypt half reproduces the stored context,
  # plus each required key the header does not store, from what the vault
  # composes or the caller supplied. A required key absent from both stays
  # absent, and the required-context CMM reports it as
  # `{:missing_required_context_keys, keys}`. A message the 1.0.x engine
  # wrote stores every required key, so for it this is the stored context.
  # Every pair here is stored or required, so the decrypt's B3 filter
  # (`Encryptor.Vault.Decrypt`) would keep all of it.
  @spec reproduce(Config.t(), Context.context(), Context.context()) :: Context.context()
  defp reproduce(%Config{required_keys: required}, stored, supplied) do
    unstored = Enum.reject(required, &Map.has_key?(stored, &1))

    Map.merge(stored, Map.take(supplied, unstored))
  end

  # What the vault composes, with the accepted option pairs as the per-call
  # layer, so the values are validated as any caller's are. The accepted keys
  # are none of the composed context's, so the layers cannot conflict; with
  # no accepted pair this is the composed context again.
  @spec supplied(Config.t(), String.t() | nil, Context.context(), Context.context()) ::
          {:ok, Context.context()} | {:error, Error.t()}
  defp supplied(config, reference, accepted, reserved) do
    Resolve.context(config, reference, [encryption_context: accepted], :rekey, reserved)
  end

  # The context the write half writes: the reproduced one less the engine's
  # own verification-key pair, which the engine refuses from a caller and
  # writes afresh for the new message's signing key ("The engine's own pair is
  # not carried", above). A message written under `0x0478` has no such pair,
  # and there this is the identity.
  @spec writable(Context.context()) :: Context.context()
  defp writable(reproduced),
    do: Map.delete(reproduced, CmmBehaviour.reserved_encryption_context_key())

  # The read half. The stack is the writer's stack, built by
  # `Encryptor.Vault.Encrypt.client/4`, for the reason that module records: the
  # engine mixes the serialization of the required subset of the context into
  # the header AAD, so a reader that does not know which keys were required
  # fails header authentication rather than anything more legible.
  @spec open(
          Config.t(),
          {Keyring.t(), [Encryptor.Key.t(), ...]},
          Error.selector(),
          binary(),
          Context.context()
        ) :: {:ok, binary()} | {:error, Error.t()}
  defp open(config, {readers, candidates}, selector, ciphertext, reproduced) do
    config
    |> Encrypt.client(readers, selector, candidates)
    |> Decrypt.engine_decrypt(config, ciphertext, reproduced, :rekey)
  end

  # ADR-0004 Amendment B, B1. An empty map is accepted, as decision 11 had
  # it: it supplies nothing and there is no key in it to name. A value that is
  # not a map is reported the way `Encryptor.Context.compose/3` reports one,
  # under the option's own name, because that is the only part of it safe to
  # render. A non-empty map is checked against the header, which is parsed
  # here only then, so a rekey with no option parses it once, in
  # `Decrypt.agreed_stored/4`.
  @spec accept_context(Config.t(), keyword(), Context.context(), binary()) ::
          {:ok, Context.context()} | {:error, Error.t()}
  defp accept_context(config, opts, composed, ciphertext) do
    case Keyword.fetch(opts, :encryption_context) do
      :error ->
        {:ok, %{}}

      {:ok, per_call} when is_map(per_call) and map_size(per_call) == 0 ->
        {:ok, %{}}

      {:ok, per_call} when is_map(per_call) ->
        with {:ok, stored} <- stored_context(config, ciphertext) do
          accept_pairs(config, per_call, composed, stored)
        end

      {:ok, _other} ->
        {:error, error(config, {:invalid_context_value, "encryption_context"})}
    end
  end

  # B1's table. A key is accepted only when the vault requires it, the header
  # does not store it, the vault does not compose it, and it is not under a
  # prefix this package or the engine reserves; every other key is
  # `{:reserved_context_key, key}`. Sorted before it reports, as every scan in
  # `Encryptor.Context` is, so a caller passing two refused keys is told about
  # the same one on every run.
  @spec accept_pairs(Config.t(), map(), Context.context(), Context.context()) ::
          {:ok, Context.context()} | {:error, Error.t()}
  defp accept_pairs(config, per_call, composed, stored) do
    per_call
    |> Map.keys()
    |> Enum.sort_by(&inspect/1)
    |> Enum.find(&(not acceptable?(config, &1, composed, stored)))
    |> case do
      nil -> {:ok, per_call}
      key -> {:error, error(config, {:reserved_context_key, render(key)})}
    end
  end

  @spec acceptable?(Config.t(), term(), Context.context(), Context.context()) :: boolean()
  defp acceptable?(
         %Config{required_keys: required, context_profile: profile},
         key,
         composed,
         stored
       )
       when is_binary(key) do
    key in required and not Map.has_key?(stored, key) and not Map.has_key?(composed, key) and
      not Context.reserved_key?(key, profile)
  end

  defp acceptable?(_config, _key, _composed, _stored), do: false

  # The header parse the option check needs. A header this package cannot
  # parse depends on the bytes, so it collapses like every other
  # message-dependent failure, carrying the engine's own parse term.
  # `Encryptor.Message` reports the same reason with no vault and no
  # operation, because it has neither; here both are known.
  @spec stored_context(Config.t(), binary()) :: {:ok, Context.context()} | {:error, Error.t()}
  defp stored_context(config, ciphertext) do
    case Message.describe(ciphertext) do
      {:ok, %Info{encryption_context: stored}} ->
        {:ok, stored}

      {:error, %Error{engine: engine}} ->
        {:error, Error.decrypt_failed(config.vault, :rekey, engine)}
    end
  end

  # A key is the only part of a rejected pair that reaches a failure report. A
  # value never does: it is caller-supplied and unvalidated here, so it could
  # hold anything, including key-shaped bytes.
  @spec render(term()) :: String.t()
  defp render(key) when is_binary(key) do
    if String.valid?(key), do: key, else: inspect(key)
  end

  defp render(key), do: inspect(key)

  @spec error(Config.t(), Error.reason()) :: Error.t()
  defp error(%Config{vault: vault}, reason) do
    %Error{reason: reason, vault: vault, operation: :rekey, engine: nil}
  end
end
