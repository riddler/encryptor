defmodule Encryptor.Key.Aes do
  @moduledoc """
  A raw AES wrapping key, named.

  This is the descriptor every material-source provider returns: config, an
  environment variable, a database of wrapped keys, a remote key manager that
  is not AWS KMS. The bytes arrive by whatever means the provider owns, and
  the engine never learns where they came from.

      %Encryptor.Key.Aes{
        namespace: "myapp",
        name: "t/9f2c/v3",
        material: material,
        bits: 256
      }

  ## The four fields

    * `:namespace` - the key provider id. It is written into the message
      header and `RawAes.unwrap_key/3` accepts an EDK only when the header's
      provider id equals the keyring's namespace, so it is part of what a
      decrypt years from now has to reproduce exactly. It may not begin with
      `"aws-kms"`; the engine reserves that prefix.
    * `:name` - the key's version identity. Also written into the header, also
      compared on unwrap.
    * `:material` - the wrapping key bytes. Never logged, never inspected,
      never rendered into an exception message or a failure report.
    * `:bits` - `128`, `192`, or `256`. `byte_size(material) * 8` must equal
      it, which is the check the engine's `RawAes.new/4` performs and which
      this package fails on with a reason of its own.

  ## `name` is public, and it is append-only

  Three obligations follow from the engine's behaviour, and they belong to the
  provider that mints names rather than to the vault, which treats `name` as
  opaque:

    * **A name is bound to bytes, forever.** Reusing a name for different
      material makes previously written messages undecryptable, silently, at
      some later date. A provider that rotates a key mints a new name. The
      recommended grammar is an opaque reference plus a monotonic version -
      `"t/<derived>/v<n>"` - recommended, not enforced.
    * **A name travels in the clear.** It lands in the encrypted data key's
      provider info, inside a header that is authenticated but not encrypted.
      Anyone holding a ciphertext can read it. A provider that puts a raw
      tenant identifier there has published that identifier in every row, so
      a derived reference is the recommendation for the same reason the cache
      partition id is derived rather than used directly.
    * **Every name that may still appear in stored ciphertext stays in
      `decryption_keys/2`, newest first.** Dropping one is what makes the
      messages written under it undecryptable, which is precisely the
      crypto-shred mechanism. Ordering is a performance property: a
      wrong-name keyring fails a cheap comparison, not a decryption.

  ## `:material` is redacted from `inspect/2`

  The struct derives `Inspect` with `:material` excluded, so the bytes cannot
  reach a log line, a crash report, an `IO.inspect/2` left in a call site, or
  the `:engine` field of an `Encryptor.Error` rendered by a logger backend.
  The repo rule against printing key-shaped values is a rule; this is the part
  of it a reviewer does not have to remember.

  It is redaction, not secrecy: `descriptor.material` still returns the bytes,
  because the vault needs them. Nothing here defends against a caller that
  goes and prints the field itself.

  Records: ADR-0002 decisions 3 and 4.
  """

  @typedoc "The AES wrapping key sizes the engine's `RawAes` keyring accepts."
  @type bits :: 128 | 192 | 256

  @type t :: %__MODULE__{
          namespace: String.t(),
          name: String.t(),
          material: binary(),
          bits: bits()
        }

  @derive {Inspect, except: [:material]}
  @enforce_keys [:namespace, :name, :material, :bits]
  defstruct @enforce_keys
end
