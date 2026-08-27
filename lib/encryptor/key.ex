defmodule Encryptor.Key do
  @moduledoc """
  The closed, package-owned set of key descriptors.

  A key provider answers a selector with a *descriptor*: a struct that says
  **which key**, not a keyring. The vault, and only the vault, turns a
  descriptor into an engine keyring. That split is ADR-0002 decision 3, and it
  exists because the engine dispatches on keyring struct type over a closed
  set of its own - a provider returning an engine keyring would be a provider
  that has to know the engine's internals to be written at all.

  ## The set has two members and a host cannot add one

    * `Encryptor.Key.Aes` - raw AES wrapping material. Maps to the engine's
      `RawAes` keyring.
    * `Encryptor.Key.Kms` - an AWS KMS key id. Reserved for the KMS adapter,
      which is where its keyring mapping is specified and where it ships.

  The set being closed is the engine's closed dispatch reappearing one layer
  up. Publishing an open behaviour that would reject most implementations of
  itself would be worse than saying so plainly. Adding a member is a release
  of this package, not a host-side extension, and a descriptor the vault does
  not recognize is `{:invalid_key_descriptor, detail}`.

  Every external key manager other than AWS KMS is a *material source*, not a
  keyring: it produces the bytes of an `Encryptor.Key.Aes` by some means the
  engine never learns about. So is a database of wrapped keys, and so is an
  environment variable. None of them needs a new member here.

  ## Validation is the vault's, not the struct's

  These structs are data. They enforce their keys and nothing else. The checks
  that a namespace is usable, that the material length matches the declared
  size, and that the pair is something a keyring can be built from all run in
  the vault, immediately before it constructs the keyring, in the vault-internal
  keyring builder.

  Records: ADR-0002 decisions 3, 4, and 5.
  """

  @typedoc """
  Any member of the descriptor set.

  The key-provider behaviour's callbacks are specified in terms of this union.
  """
  @type t :: Encryptor.Key.Aes.t() | Encryptor.Key.Kms.t()
end
