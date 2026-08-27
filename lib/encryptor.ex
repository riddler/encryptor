defmodule Encryptor do
  @moduledoc """
  Ergonomic envelope encryption for Elixir - a vault module, pluggable key
  providers, and per-tenant keys - on the
  [aws_encryption_sdk](https://hex.pm/packages/aws_encryption_sdk) engine.

  The engine already does the cryptography correctly. What it does not do is
  make the everyday shape of the job pleasant: standing up a client, holding
  a keyring, deciding which key a given tenant's data belongs to, rotating
  that key without rewriting call sites. This package is that layer - a
  supervised vault a host configures once and then calls, with key material
  resolved through a provider rather than hard-wired at the call site.

  Ciphertexts carry the AWS Encryption SDK message format, so anything written
  here is readable by the official ESDKs in any language.

  The contracts are decided and implementation is under way. This module
  exists so the package has a root; the vault surface, the key-provider
  behaviour, the per-tenant envelope, the encryption-context convention and
  the rotation model each have an accepted decision record behind them.

  `Encryptor.Error` is the first of those contracts in code: the one error
  struct every entry point returns, and the closed vocabulary of reasons it
  carries. `Encryptor.Kdf` is the second: HKDF-SHA256 expansion into the
  labelled subkeys the key hierarchy is built from. `Encryptor.Key` is the
  third: the closed set of key descriptors a provider answers a selector with,
  and which the vault alone turns into an engine keyring.
  """
end
