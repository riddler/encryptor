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

  Nothing is implemented yet. This module exists so the package has a root;
  the vault surface, the key-provider behaviour, and the per-tenant key record
  are each being decided in an ADR before any of them is built.
  """
end
