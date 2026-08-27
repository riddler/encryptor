# Encryptor

[![CI](https://github.com/riddler/encryptor/actions/workflows/ci.yml/badge.svg)](https://github.com/riddler/encryptor/actions/workflows/ci.yml)
[![Hex.pm Version](https://img.shields.io/hexpm/v/encryptor.svg)](https://hex.pm/packages/encryptor)
[![Hex Downloads](https://img.shields.io/hexpm/dt/encryptor.svg)](https://hex.pm/packages/encryptor)
[![Hex Docs](https://img.shields.io/badge/hex-docs-lightgreen.svg)](https://hexdocs.pm/encryptor/)
[![License](https://img.shields.io/hexpm/l/encryptor.svg)](https://github.com/riddler/encryptor/blob/main/LICENSE)

Ergonomic envelope encryption for Elixir - a vault module, pluggable key
providers, and per-tenant keys - on the
[aws_encryption_sdk](https://hex.pm/packages/aws_encryption_sdk) engine.

**Status: scaffold.** Nothing is implemented yet. The package skeleton is in
place; the contracts below are being decided in ADRs before any of them is
built.

## The charter

Application-level encryption in Elixir usually arrives as one of two things: a
thin wrapper over `:crypto` that leaves key management to the caller, or a
full ESDK client whose surface is shaped for the cryptography rather than for
the application. Neither answers the questions a real application asks - which
key does this tenant's data use, how does that key rotate without a migration,
where does the key material actually come from. This package is the layer that
answers them:

- **A vault module.** `use Encryptor.Vault, otp_app: :my_app` gives a
  supervised client, configured from app config, with `encrypt/decrypt`
  entry points a call site can use without naming a keyring, a client, or a
  cryptographic materials manager. One place to configure, one surface to
  call.

- **Pluggable key providers.** Where key material comes from is a behaviour,
  not a hard-coded choice. A static key in config, a key column in the
  database, a KMS call - each is an adapter behind the same contract, so the
  call sites do not change when the source does.

- **Per-tenant keys and rotation.** A multi-tenant host app needs each
  tenant's data encrypted under that tenant's own key, and needs to roll that
  key on its own schedule. Key identity and key version are first-class here:
  ciphertext records which key encrypted it, decryption resolves the key it
  names, and rotation is re-encryption against a new version rather than a
  flag day.

- **AWS Encryption SDK message format** - ciphertexts are interoperable with
  the official ESDKs, so data written from Elixir is readable from Java,
  Python, JavaScript, or the AWS CLI, and vice versa.

The engine stays `aws_encryption_sdk`. The vault wraps it fully, so consumers
never type the engine's namespace. Raw-keyring usage pulls no AWS, HTTP, or
XML libraries - the AWS client stack is optional in the engine, and only
KMS-backed providers will bring it in.

## Installation

```elixir
def deps do
  [
    {:encryptor, "~> 0.1"}
  ]
end
```

Not yet published to Hex.

## License

MIT - see
[LICENSE](https://github.com/riddler/encryptor/blob/main/LICENSE).
