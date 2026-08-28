defmodule Encryptor.Vault.Rekey do
  @moduledoc false

  # The rekey path: a decrypt and an encrypt, in that order, with the message's
  # own encryption context carried across untouched.
  #
  # `Encryptor.Vault.rekey/3` is the door; this module is the body behind it,
  # as `Encryptor.Vault.Encrypt` and `Encryptor.Vault.Decrypt` are for the two
  # halves it is built out of. It is the last item in the vault core and it is
  # deliberately the smallest: every step below is a function one of those two
  # modules already exports, and the value of this module is the order and the
  # one refusal, not new machinery.
  #
  # ## The context comes from the message, and only from the message
  #
  # ADR-0001 decision 4 requires a rekey to preserve the context byte for byte,
  # and ADR-0004 decision 5 requires every decrypt to reproduce the required
  # keys. A rekey caller cannot satisfy both: it holds a ciphertext, not a row,
  # so it has no independent copy of what the message was bound to.
  #
  # It does not need one. This engine stores the **full** context in the header
  # - `Crypto.HeaderAuth.build_header/4` copies `materials.encryption_context`
  # into it whole - so `Encryptor.Message.describe/1` recovers
  # it, and that map is used twice: as the reproduced context for the decrypt
  # half, and as the context the re-encrypt writes. That is ADR-0004 decision
  # 11, and it is the one decision in the family that depends on the engine
  # deviating from the specification, which has required keys stripped from the
  # header instead. ADR-0004 open question 5 records the remedy if the engine is
  # ever corrected: `rekey/2` would take the context as an argument, supplied by
  # whatever owns the row. Until then, this module is the only place that
  # assumption is made, and `Encryptor.Message` is the only place the header is
  # read.
  #
  # ## Why `:encryption_context` is refused rather than merged
  #
  # The only correct value is the one already in the message, so accepting a
  # second copy buys nothing and risks everything: a rotation job that passes a
  # context rewrites what a million rows are bound to while believing it is
  # rotating keys. Changing the context is an encrypt of new data - ADR-0005
  # decision 1's R3 - and a context-preserving rekey is by definition the wrong
  # operation for it. So the option is `{:reserved_context_key, key}`
  # (ADR-0004 decision 11), refused before the provider is consulted, because
  # like the selector check it depends on the caller's own arguments and on
  # nothing else.
  #
  # ## The vault-side comparison still runs, and it is not redundant
  #
  # Reproducing the context from the message would make a comparison of the two
  # trivially true, so this module does not compare the stored context against
  # itself. It compares the stored context against the one **the vault composes
  # from the call's own arguments** - the static layer, plus `tenant_ref`
  # derived from the `:key` selector on a `:tenant` vault - through the same
  # `Encryptor.Vault.Decrypt.agree/4` a read goes through, reporting `:rekey`.
  #
  # That is what stops a rekey being a way around ADR-0004 decision 6. Without
  # it, a caller naming tenant A could hand this function tenant B's ciphertext
  # and, wherever the two selectors resolve to overlapping key material, get
  # back a message re-encrypted under A's current key with B's binding still
  # inside it. The comparison is one call, and it is the same call the decrypt
  # path makes, on purpose: a second copy of it would be a second thing to keep
  # in step with upstream issue #96.
  #
  # ## The order
  #
  #   1. `Encryptor.Vault.ready/2`, stamped `:rekey`.
  #   2. The selector profile check (ADR-0004 decision 3).
  #   3. The `:encryption_context` refusal (ADR-0004 decision 11).
  #   4. `decryption_keys/2` and the `Multi` keyring: the read half resolves to
  #      **every** key the message might have been written under, which is what
  #      makes a rekey the mechanism that moves a message off a retired key
  #      (ADR-0002 decision 7, ADR-0005 decision 1's R2).
  #   5. The vault-composed context.
  #   6. The stored context, parsed from the header, and the value comparison
  #      of the two described above.
  #   7. The decrypt, reproducing the stored context.
  #   8. `encryption_key/2` and its single keyring: the write half goes under
  #      the vault's **currently** resolved materials, which is the whole point.
  #   9. The re-encrypt, under the stored context.
  #
  # Steps 4 and 8 are two different provider callbacks answering two different
  # questions, and their independence is the rotation window itself
  # (ADR-0005 decision 2): minting a new version changes step 8 immediately and
  # changes step 4 not at all, so a rekey pass can run for as long as it takes.
  #
  # ## What it does not do
  #
  # It touches no storage and it is a pure binary-to-binary function: the batch
  # that walks rows belongs to whatever owns them. Its canonical caller is
  # `Encryptor.Envelope.rewrap/2` (ADR-0005 decision 7). It is **not** the
  # downstream migrator's tool - that one must be uniform across a rekey-shaped
  # rotation and a format or context change, and this function is by definition
  # wrong for the second.

  alias Encryptor.Context
  alias Encryptor.Error
  alias Encryptor.Message
  alias Encryptor.Message.Info
  alias Encryptor.Vault
  alias Encryptor.Vault.Config
  alias Encryptor.Vault.Decrypt
  alias Encryptor.Vault.Encrypt
  alias Encryptor.Vault.Keyring
  alias Encryptor.Vault.Resolve

  @doc false
  @spec call(module(), binary(), keyword()) :: {:ok, binary()} | {:error, Error.t()}
  def call(vault, ciphertext, opts) when is_binary(ciphertext) and is_list(opts) do
    with {:ok, config} <- Vault.ready(vault, :rekey),
         {:ok, selector} <- Resolve.selector(config, opts, :rekey),
         :ok <- refuse_context(config, opts),
         {:ok, candidates} <- Resolve.decryption_keys(config, selector, :rekey),
         {:ok, readers} <- Keyring.build_all(vault, :rekey, candidates),
         {:ok, composed} <- Resolve.context(config, selector, [], :rekey),
         {:ok, stored} <- stored_context(config, ciphertext),
         :ok <- Decrypt.agree(config, ciphertext, composed, :rekey),
         {:ok, plaintext} <- open(config, readers, selector, ciphertext, stored),
         {:ok, descriptor} <- Resolve.encryption_key(config, selector, :rekey),
         {:ok, writer} <- Keyring.build(vault, :rekey, descriptor) do
      config
      |> Encrypt.client(writer, selector)
      |> Encrypt.engine_encrypt(config, plaintext, stored, :rekey)
    end
  end

  # The header is parsed twice on a rekey: once here, which owns the
  # reproduction, and once inside `agree/4`, which owns the comparison. The
  # duplicated work is a header parse with no key material and no vault state,
  # and the alternative is a second spelling of one of the two - which is
  # exactly what this package avoids by having one module read the engine's
  # message format at all.
  #
  # It runs *before* `agree/4` rather than after, so that a header this package
  # cannot parse is reported from the step that needed it, and neither branch
  # of either function is a branch no call can reach.
  @spec stored_context(Config.t(), binary()) :: {:ok, Context.context()} | {:error, Error.t()}
  defp stored_context(config, ciphertext) do
    case Message.describe(ciphertext) do
      {:ok, %Info{encryption_context: stored}} ->
        {:ok, stored}

      # It depends on the bytes, so it collapses like every other
      # message-dependent failure, carrying the engine's own parse term.
      # `Encryptor.Message` reports the same reason with no vault and no
      # operation, because it has neither; here both are known.
      {:error, %Error{engine: engine}} ->
        {:error, Error.decrypt_failed(config.vault, :rekey, engine)}
    end
  end

  # The read half. The stack is the writer's stack, built by
  # `Encryptor.Vault.Encrypt.client/3`, for the reason that module records: this
  # engine mixes the serialization of the required subset of the context into
  # the header AAD, so a reader that does not know which keys were required
  # fails header authentication rather than anything more legible.
  @spec open(Config.t(), Keyring.t(), Error.selector(), binary(), Context.context()) ::
          {:ok, binary()} | {:error, Error.t()}
  defp open(config, readers, selector, ciphertext, stored) do
    config
    |> Encrypt.client(readers, selector)
    |> Decrypt.engine_decrypt(config, ciphertext, stored, :rekey)
  end

  # ADR-0004 decision 11. An empty map is accepted rather than refused: the
  # refusal exists to stop a caller *rewriting* a binding, an empty map rewrites
  # nothing, and there is no key in it to name. A value that is not a map is
  # reported the way `Encryptor.Context.compose/3` reports one, under the
  # option's own name, because that is the only part of it safe to render.
  @spec refuse_context(Config.t(), keyword()) :: :ok | {:error, Error.t()}
  defp refuse_context(config, opts) do
    case Keyword.fetch(opts, :encryption_context) do
      :error ->
        :ok

      {:ok, per_call} when is_map(per_call) ->
        refuse_pairs(config, per_call)

      {:ok, _other} ->
        {:error, error(config, {:invalid_context_value, "encryption_context"})}
    end
  end

  @spec refuse_pairs(Config.t(), Context.context()) :: :ok | {:error, Error.t()}
  defp refuse_pairs(_config, per_call) when map_size(per_call) == 0, do: :ok

  # Sorted before it reports, as every scan in `Encryptor.Context` is, so a
  # caller passing two keys is told about the same one on every run.
  defp refuse_pairs(config, per_call) do
    key =
      per_call
      |> Map.keys()
      |> Enum.sort_by(&inspect/1)
      |> hd()
      |> render()

    {:error, error(config, {:reserved_context_key, key})}
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
