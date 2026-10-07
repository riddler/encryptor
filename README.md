# Encryptor

[![CI](https://github.com/riddler/encryptor/actions/workflows/ci.yml/badge.svg)](https://github.com/riddler/encryptor/actions/workflows/ci.yml)
[![Hex.pm Version](https://img.shields.io/hexpm/v/encryptor.svg)](https://hex.pm/packages/encryptor)
[![Hex Downloads](https://img.shields.io/hexpm/dt/encryptor.svg)](https://hex.pm/packages/encryptor)
[![Hex Docs](https://img.shields.io/badge/hex-docs-lightgreen.svg)](https://hexdocs.pm/encryptor/)
[![License](https://img.shields.io/hexpm/l/encryptor.svg)](https://github.com/riddler/encryptor/blob/main/LICENSE)

Application-layer encryption for Elixir: a vault module your code calls,
pluggable key providers, per-scope keys in envelopes, and rotation. It runs on
the [aws_encryption_sdk](https://hex.pm/packages/aws_encryption_sdk) engine,
so every ciphertext is a standard AWS Encryption SDK message.

## Why encryptor

Encrypting data before it reaches the database usually means choosing between
a thin wrapper over `:crypto` that leaves every key question to you, and a full
encryption SDK client whose surface is shaped for the cryptography rather than
for your application. Either way the questions a real application asks stay
open: which key does this record use, where does the key material come from,
and how does a key rotate without a migration. With this package your call
sites name one vault module and nothing else; where key material comes from is
an adapter behind one behaviour, so the source can change without the call
sites changing; each scope you key by (an account, a workspace) gets its own
key, which a ciphertext names, so rotation is re-encryption against a new
version and a crypto-shred destroys one scope's key; and the messages stay in
the AWS Encryption SDK's format, which the official SDKs in other languages
read, with two exceptions today that [Compatibility](#compatibility) names.

## Install

Add `encryptor` to the dependencies in your `mix.exs`:

```elixir
def deps do
  [
    {:encryptor, "~> 0.7.0"}
  ]
end
```

Raw-keyring use pulls in no AWS, HTTP or XML library; only the KMS-backed
providers bring that stack in. Two dependencies are optional:
`{:argon2_elixir, "~> 4.0"}` for `Encryptor.Kdf.slow_hash/3`, and
`{:goth, "~> 1.4"}` for `Encryptor.Provider.GcpKms`.

## Basic usage

A single-key vault encrypting one column. The key is 32 random bytes, Base64
in the environment, and it reaches the vault through `init/1` at start: a `use`
option such as `:key` fails compilation.

```elixir
defmodule MyApp.Vault do
  use Encryptor.Vault,
    otp_app: :my_app,
    context_profile: :single,
    required_context: ["table", "column"]

  @impl true
  def init(config) do
    key = Base.decode64!(System.fetch_env!("MY_APP_VAULT_KEY"))
    provider = {Encryptor.Provider.Static, key: key, namespace: "my_app", name: "data/v1"}
    {:ok, Keyword.put(config, :provider, provider)}
  end
end

# With MyApp.Vault in your supervision tree:
context = %{"table" => "notes", "column" => "body"}

{:ok, ciphertext} = MyApp.Vault.encrypt("a private note", encryption_context: context)
{:ok, "a private note"} = MyApp.Vault.decrypt(ciphertext, encryption_context: context)

# A write that leaves out a required context key is refused, not written unbound.
{:error, %Encryptor.Error{reason: {:missing_required_context_keys, ["column"]}}} =
  MyApp.Vault.encrypt("a private note", encryption_context: %{"table" => "notes"})

# A decrypt under any other context fails, and every such failure looks the same.
{:error, %Encryptor.Error{reason: :decrypt_failed}} =
  MyApp.Vault.decrypt(ciphertext, encryption_context: %{"table" => "t", "column" => "c"})
```

`ciphertext` is the whole self-describing message: you store that one binary,
and there is no second column to keep in step with it.

## Documentation

- Learn
  - [Getting started](guides/getting-started.md): a single-key vault, then a scoped vault with one key per scope, and the two root secrets a deployment provisions on day one.
- Do
  - [How to source secrets at start](guides/secrets-at-start.md): read key material from the environment or a secrets manager in `init/1`, and what each mistake looks like at start.
  - [How to rotate, retire, shred and suspend keys](guides/rotation-runbook.md): the five operator procedures, what each step destroys, and the GCP operator section.
  - [Encrypt Ecto schema columns](https://hexdocs.pm/encryptor_ecto): `encryptor_ecto`, the companion package with the Ecto types, the wrapped-key storage and the re-encryption migrator.
- Look up
  - [The vault](https://hexdocs.pm/encryptor/Encryptor.Vault.html): the functions `use Encryptor.Vault` generates, the lifecycle checks, `derive/3`, `suspend/2` and `reinstate/2`.
  - [Vault configuration](https://hexdocs.pm/encryptor/Encryptor.Vault.Config.html): the five-layer precedence chain, each option and what is checked at start, and choosing an algorithm suite.
  - [Key providers](https://hexdocs.pm/encryptor/Encryptor.Provider.html): the behaviour, its conformance suite, and the `Static`, `Function`, `Kms` and `GcpKms` adapters.
  - [Key derivation](https://hexdocs.pm/encryptor/Encryptor.Kdf.html): the HKDF trees, the label grammar, derived subkeys and the Argon2id slow hash.
  - [The materials cache bound](https://hexdocs.pm/encryptor/Encryptor.Vault.CacheRecycler.html): how `:recycle_after` bounds the engine's cache, and why dropping the table is safe.
  - [Telemetry events](https://hexdocs.pm/encryptor/Encryptor.Telemetry.html): the closed event set, its measurements and its allow-listed metadata.
  - [Errors](https://hexdocs.pm/encryptor/Encryptor.Error.html): the one error struct and its closed reason vocabulary.
  - [The changelog](https://github.com/riddler/encryptor/blob/main/CHANGELOG.md): what changed in each version, and what to do about each breaking change.
- Understand
  - [The security model: keys, scopes and envelopes](docs/explanation/security-model.md): the three levels of keys, why a scope's key is random and stored rather than derived, what the encryption context binds, why decrypt failures look alike, and what the model does not protect against.
  - [The threat model: what is protected, from whom, and how we know](docs/explanation/threat-model.md): the assets, the adversaries and the trust boundaries, the test or record behind each claim, the limits of AES-GCM, the known engine defects, and what the evidence was tested against.
  - [Choosing the scope](guides/choosing-the-scope.md): what a scope is, where to draw its boundary, the rotate, suspend and shred verbs, and what cryptographic erasure honestly achieves.
  - [The decision records](https://github.com/riddler/encryptor/tree/main/docs/adr): the record behind every cryptographic choice here, with an index of what each one decides.

## Compatibility

The package needs Elixir 1.18 or later (`elixir: "~> 1.18"` in `mix.exs`). Its
runtime dependencies are `aws_encryption_sdk ~> 1.0` and `telemetry ~> 1.3`;
`argon2_elixir ~> 4.0` and `goth ~> 1.4` are optional. CI runs the full
gate on Erlang/OTP 27 and the test suite on Erlang/OTP 26, both with Elixir
1.18. Ciphertexts are in the AWS Encryption SDK's message format, and a CI job
([python-interop](https://github.com/riddler/encryptor/blob/main/.github/workflows/ci.yml)) checks them against the official SDK for Python
([the test](https://github.com/riddler/encryptor/blob/main/test/encryptor/interop/python_interop_test.exs)). Today a single-key vault's messages cross both ways
at suite 0x0478, and Python's messages reach a single-key vault at 0x0578.
Two defects in the engine keep the rest from crossing. A per-scope vault's
messages store the scope reference in the header, where the specification
says a required context key must not be stored, so neither SDK reads the
other's per-scope messages. And at 0x0578, the default suite, the engine
writes the signature verification key as an uncompressed point, which the
Python SDK cannot decode. The test asserts each failure exactly, so a fix
in the engine shows up as a change rather than passing unnoticed.

Two open engine issues are worked round here until they move:
[#95](https://github.com/riddler/aws-encryption-sdk-elixir/issues/95), an
unbounded materials cache, which the vault bounds by recycling it, and
[#96](https://github.com/riddler/aws-encryption-sdk-elixir/issues/96), a warm
decryption cache that skips context validation, which the vault replaces with
its own comparison.

Until 1.0, the public surface may change between minor releases: a release may
rename modules, callbacks, telemetry events or error vocabulary with no
compatibility shim. Every such change is recorded in the
[changelog](https://github.com/riddler/encryptor/blob/main/CHANGELOG.md) under
a bold **Breaking** heading that says what to do about it, and pinning to an
exact minor, `~> X.Y.0`, is the recommended way to take the package until
then. Do not depend on `encryptor 0.1.0`: it is a name reservation with no
code in it.

## License

Apache-2.0 - see
[LICENSE](https://github.com/riddler/encryptor/blob/main/LICENSE).
