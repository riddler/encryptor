defmodule Encryptor.Vault.Docs do
  @moduledoc false

  # The documentation of the three entry points `use Encryptor.Vault` defines
  # on a host's module.
  #
  # It lives outside the `quote` block rather than inside it because the three
  # docstrings are longer than every generated function put together, and a
  # macro body whose bulk is prose is a macro body nobody reads for its
  # behaviour. `@doc Encryptor.Vault.Docs.rekey()` is evaluated while the
  # host's module compiles, so the host's own documentation is byte for byte
  # what it would have been with the string written inline.
  #
  # It is `@moduledoc false` because it documents nothing of its own: every
  # string below appears in the generated documentation of each host vault,
  # which is the only place a reader should meet it.

  @doc false
  @spec encrypt() :: String.t()
  def encrypt do
    """
    Encrypts a value under this vault's currently resolved materials.

    Returns `{:ok, ciphertext}`, where `ciphertext` is the complete
    self-describing engine message and nothing else: the header, the
    encryption context and the algorithm suite the engine also reports are
    already inside it, authenticated, and a second stored copy of them is a
    copy that can disagree with the message.

    ## Options

      * `:key` - the selector handed to the key provider. A `:tenant` vault
        takes a non-empty `String.t()` and refuses `:default`; a `:single`
        vault takes `:default`, which is also what an absent `:key` means,
        and refuses a string. Either refusal is
        `{:invalid_selector, selector}`, raised before the provider is
        consulted.

      * `:encryption_context` - a map of `String.t()` to `String.t()`,
        merged over the vault's configured static context.
        `Encryptor.Context` owns the canonical vocabulary, the reserved
        prefixes, the conflict rules and the size bounds, and is the place
        to read before choosing a key. Two rules are worth carrying here:
        **nothing that varies per row** may go in a context - a row id
        multiplies the materials cache by the size of the table - and on a
        `:tenant` vault the tenant pair is the vault's, derived from `:key`,
        so `"tenant_ref"` and `"tenant_id"` are refused from a caller.

    `:algorithm_suite`, `:commitment_policy`, `:frame_length` and
    `:max_encrypted_data_keys` are deliberately not options. All four are
    configuration, never per call.
    """
  end

  @doc false
  @spec decrypt() :: String.t()
  def decrypt do
    """
    Decrypts a message written under this vault's key material.

    Returns `{:ok, plaintext}` and nothing else: the verified encryption
    context the engine also reports is deliberately not returned, because a
    caller that wants it has `Encryptor.Message.describe/1`, which is honest
    about being an unverified claim.

    Every failure that depends on what is *in* the message - a wrong key, a
    failed authentication tag, a context value that disagrees with the
    stored one - is the single reason `:decrypt_failed`, with the detail in
    the error's `:engine` field for an operator's log line and not for a
    `case`. Distinguishable decrypt failures are a decryption oracle.

    ## Options

      * `:key` - the selector handed to the key provider, typed by the
        vault's profile exactly as `encrypt/2` types it. The provider
        answers with **every** key a stored message might have been written
        under, so a message written before a rotation still opens.

      * `:encryption_context` - the **reproduced** context: the caller's
        claim about what the message was bound to, merged over the vault's
        configured static context the same way the writer's was. For every
        key present in both the claim and the message, the values must
        agree, or the read fails - and that comparison is this vault's, run
        before the engine and before any cache, so it holds on the first
        read of a row and on the thousandth alike.

        A key the message does not carry is ignored, and a key the message
        carries that the claim omits is ignored too. What closes that gap is
        the vault's configured `:required_context`: omitting one of those is
        `{:missing_required_context_keys, keys}`, which is the one context
        failure a caller can act on. On a `:tenant` vault the tenant pair is
        the vault's, derived from `:key`, so `"tenant_ref"` and
        `"tenant_id"` are refused from a caller here as they are at encrypt.
    """
  end

  @doc false
  @spec rekey() :: String.t()
  def rekey do
    """
    Re-encrypts one message under this vault's current materials.

    Decrypts with whatever this vault's provider says the message's own
    encrypted data keys might resolve to, then encrypts the result under the
    one key the provider currently writes with, **preserving the message's
    encryption context byte for byte**. Returns `{:ok, new_ciphertext}`.

    A rekey never changes the context. Changing what a ciphertext is bound
    to is an encrypt of new data, not a rotation of old data, and conflating
    the two is how a rotation job silently unbinds a million rows.

    The context is reproduced from the message's own header rather than from
    the caller, because a rekey caller holds a ciphertext and not a row.
    `:encryption_context` is therefore **not** an option: passing one is
    `{:reserved_context_key, key}`, since the only correct value is the one
    already in the message.

    This behaviour depends on the engine storing the full encryption context
    in the message header, which is a deviation from the AWS Encryption SDK
    specification in this package's favour. If the engine is ever corrected
    to strip required keys from the header, `rekey/2` will need the context
    as an argument from whatever owns the row.

    ## What this is for, and what it is not for

    It re-encrypts one message under current materials, and it touches no
    storage: it is a pure binary-to-binary function, and the batch that walks
    rows belongs to whatever owns them. Its canonical caller in this family
    is `Encryptor.Envelope.rewrap/2`, and it is available to a host that
    stores ciphertext outside Ecto and wants a key rotation rewritten without
    a migrator.

    It is **not** the downstream migrator's tool. A migrator has to be
    uniform across a rotation of the kind above and a change of format,
    algorithm, or context - and for the second, a context-preserving rekey is
    by definition the wrong operation.

    ## Options

      * `:key` - the selector handed to the key provider, typed by the
        vault's profile exactly as `encrypt/2` and `decrypt/2` type it. On a
        `:tenant` vault the pair the vault derives from it is compared
        against the message's own before anything is decrypted, so a rekey
        cannot move a message between tenants.

    ## When a rekey changes nothing

    Rekeying a message already written under the current key succeeds and
    returns a *different* binary carrying the same plaintext and the same
    context: a fresh data key, a fresh IV. There is no no-op detection, and
    a caller that wants one compares `Encryptor.Message.describe/1`'s key
    names before calling.
    """
  end
end
