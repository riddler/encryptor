# Encryptor

[![CI](https://github.com/riddler/encryptor/actions/workflows/ci.yml/badge.svg)](https://github.com/riddler/encryptor/actions/workflows/ci.yml)
[![Hex.pm Version](https://img.shields.io/hexpm/v/encryptor.svg)](https://hex.pm/packages/encryptor)
[![Hex Downloads](https://img.shields.io/hexpm/dt/encryptor.svg)](https://hex.pm/packages/encryptor)
[![Hex Docs](https://img.shields.io/badge/hex-docs-lightgreen.svg)](https://hexdocs.pm/encryptor/)
[![License](https://img.shields.io/hexpm/l/encryptor.svg)](https://github.com/riddler/encryptor/blob/main/LICENSE)

Ergonomic envelope encryption for Elixir - a vault module, pluggable key
providers, and per-tenant keys - on the
[aws_encryption_sdk](https://hex.pm/packages/aws_encryption_sdk) engine.

## Status: built, not released

The five founding architecture decision records were **accepted on
2026-08-27**. They fix the contracts this package is made of, and the vault
core and the per-tenant envelope are implemented against them: the `use
Encryptor.Vault` macro and its supervision tree, the configuration freeze,
`encrypt/2`, `decrypt/2`, `rekey/2`, the key-provider behaviour with its
`Static` and `Function` adapters, `Encryptor.Envelope`'s
`provision/3`/`unwrap/2`/`rewrap/2`, and `Encryptor.Message.describe/1`.

**Nothing is released.** The package is not published to Hex - the reserved
`encryptor 0.1.0` there is a name reservation holding no implementation - so
consume it as a git dependency until the first real release. See
[Installation](#installation).

Start with the **[getting-started guide](guides/getting-started.md)** and the
**[rotation runbook](guides/rotation-runbook.md)**.

| Record | Decides |
|---|---|
| [ADR-0001](docs/adr/0001-vault-layer.md) | The vault layer: one host-owned module that wraps the engine completely, what it supervises, how it is configured, how its cache is bounded, and its error vocabulary |
| [ADR-0002](docs/adr/0002-key-providers.md) | The key-provider behaviour: a provider resolves a selector to a key descriptor, and only the vault turns a descriptor into a keyring |
| [ADR-0003](docs/adr/0003-per-tenant-envelope.md) | The per-tenant envelope: a tenant key is 32 random bytes wrapped into an ordinary message, and the host stores the wrapping |
| [ADR-0004](docs/adr/0004-encryption-context.md) | The encryption-context convention: the canonical keys, who supplies each, and how a vault enforces them |
| [ADR-0005](docs/adr/0005-rotation-and-crypto-shred.md) | Rotation and crypto-shred: three independent lifecycles, four operator procedures, and the one step that cannot be undone |

The implementation graph derived from them is
[`docs/plans/260827-enc-2y3-b3-implementation-graph.md`](docs/plans/260827-enc-2y3-b3-implementation-graph.md).
Work is tracked in this repository's own beads database, under the epic
"Implement the vault core".

Read the records before writing code here. Until a contract is fixed by an
accepted record, it is open - and a cryptographic choice made inline in an
implementation is a defect even when the choice happens to be a good one,
because the record is what makes it reviewable.

## The charter

Application-level encryption in Elixir usually arrives as one of two things: a
thin wrapper over `:crypto` that leaves key management to the caller, or a
full ESDK client whose surface is shaped for the cryptography rather than for
the application. Neither answers the questions a real application asks - which
key does this tenant's data use, how does that key rotate without a migration,
where does the key material actually come from. This package is the layer that
answers them:

- **A vault module.** `use Encryptor.Vault, otp_app: :my_app` gives a
  supervised client, configured from app config, with `encrypt`/`decrypt`
  entry points a call site can use without naming a keyring, a client, or a
  cryptographic materials manager. One place to configure, one surface to
  call, and consumers never type the engine's namespace.

- **Pluggable key providers.** Where key material comes from is a behaviour,
  not a hard-coded choice. A static key resolved at boot, a wrapped key column
  in the database, a KMS call - each is an adapter behind the same contract,
  so the call sites do not change when the source does.

- **Per-tenant keys and rotation.** A multi-tenant host app needs each
  tenant's data encrypted under that tenant's own key, and needs to roll that
  key on its own schedule. Key identity and key version are first-class:
  a ciphertext records which key encrypted it, decryption resolves the key it
  names, and rotation is re-encryption against a new version rather than a
  flag day. Because a tenant key is random rather than derived, destroying its
  wrapping destroys the key, so a crypto-shred is honest.

- **AWS Encryption SDK message format** - ciphertexts are interoperable with
  the official ESDKs, so data written from Elixir is readable from Java,
  Python, JavaScript, or the AWS CLI, and vice versa.

The engine stays `aws_encryption_sdk`. Raw-keyring usage pulls no AWS, HTTP,
or XML libraries - that client stack is optional in the engine, and only
KMS-backed providers will bring it in.

## The family

| Package | Owns |
|---|---|
| `encryptor` (here) | The vault surface, the key-provider behaviour, the envelope and key-derivation scheme, the encryption-context convention, the rotation model |
| [`encryptor_ecto`](https://github.com/riddler/encryptor_ecto) | The Ecto types, the schema conventions, the wrapped-key storage and its migration, the re-encryption migrator |

The split is deliberate and it is a boundary, not a layering convenience: no
function in this package takes a repo, a query, a table, or a batch size, and
this package defines no storage schema at all.

## Engine notes

The design is written against `aws_encryption_sdk` v1.0.0 as published, with
module paths cited so every claim can be re-checked. Two upstream issues are
open and the design works around both until they move:

- [#95](https://github.com/riddler/aws-encryption-sdk-elixir/issues/95) - the
  materials cache is unbounded and is not substitutable through the cache
  behaviour, so this package bounds it by recycling the cache process.
- [#96](https://github.com/riddler/aws-encryption-sdk-elixir/issues/96) - a
  warm decryption cache bypasses reproduced-context validation, so this
  package performs the value comparison itself, above the engine. That is what
  makes anti-substitution a property of this package rather than one it
  happens to inherit.

## Installation

The package is **not published to Hex**. `encryptor 0.1.0` on Hex is a name
reservation and holds no implementation; do not depend on it. Until the first
real release, consume this package as a git dependency pinned to a full SHA:

```elixir
def deps do
  [
    {:encryptor, github: "riddler/encryptor", ref: "<full 40-character sha>"}
  ]
end
```

Pin a SHA rather than a branch. A moving dependency on a package that decides
ciphertext layout is a package that can change what your stored rows mean
between two `mix deps.get` runs.

## Guides

- **[Getting started](guides/getting-started.md)** - a single-key vault and a
  per-tenant vault, where key material is allowed to come from, why a host
  chooses `0x0478`, why `max_age` has no default, and the two root secrets a
  deployment provisions on day one.
- **[Rotation runbook](guides/rotation-runbook.md)** - the four operator
  procedures, what each step destroys, which steps this package ships as
  functions and which are actions on a store it does not own, and what a
  crypto-shred does and does not achieve.

## License

Apache-2.0 - see
[LICENSE](https://github.com/riddler/encryptor/blob/main/LICENSE).
