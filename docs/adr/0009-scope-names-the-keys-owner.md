# ADR-0009: Scope names the key's owner, and the v1 wire spellings stay constants behind it

Status: proposed (2026-09-24)

## Context

The records call the thing a per-owner key belongs to a *tenant*, and the Elixir surface follows: the `:tenant` context profile
(`Encryptor.Vault.Config`'s `@type profile`), `Encryptor.Context.tenant_ref_key/0`,
`Encryptor.Envelope.tenant_ref/2`, the `tenant_ref` field of
`%Encryptor.Envelope.WrappedKey{}` and of `Encryptor.Provider`'s `provisioned`
type, the `:telemetry_tenant_ref` vault option and the `tenant_ref` telemetry
metadata key. All cites in this record were read at `5e532aa`.

The word is narrower than the package. Nothing in the vault, the envelope or a
provider knows what a tenant is: ADR-0004's open question 1 answer says
"Tenant identity itself is the **host's** - the package never mints,
validates, or interprets a tenant identifier; it requires only that it be a
non-empty string (decision 3) and treats it as opaque thereafter."
(`docs/adr/0004-encryption-context.md`, "Open questions", item 1). A host can
want a key per something that is not a customer account: an entitlement,
a workspace, a region. Calling that owner a tenant in the API
misleads the host's reader into a hierarchy the package does not have.

The same word is also inside strings the package writes into every
ciphertext and every wrapped key: the context key `tenant_ref`, the
wrapping-context key `encryptor-tenant-ref`, the HKDF label
`encryptor/v1/tenant-ref`, and others tabled below. Those strings are
authenticated data. A build that spells any of them differently cannot open
what an earlier build wrote. The envelope's own comment on its binding says
so: "a typo in any of them is a wrapped-key population that a corrected build
can no longer open" (`lib/encryptor/envelope.ex`, the comment above `@purpose_key`).

So a rename of the owner noun has two halves with opposite costs. The Elixir
half is a breaking API change a host absorbs at an upgrade. The wire half is a
re-encrypt of every stored row, which ADR-0005 decision 1's table names R3:
"Format or context change | R3 | none in this package | every ciphertext in
scope" (`docs/adr/0005-rotation-and-crypto-shred.md`, decision 1).

## Decision

**1. The key's owner is named *Scope*.** A scope is whatever the host keys
by: one opaque, non-empty string selector per key owner, exactly as ADR-0004
decision 3 types the selector today. The package still never mints,
validates or interprets it, and a scope has no parent and no children: this
record renames the noun and adds no hierarchy.

**2. The profile `:tenant` becomes `:scoped`.** `:single` is unchanged. The
profile's behaviour is unchanged: a `:scoped` vault requires a selector,
derives the reference from it, injects that reference into the context, and
refuses a caller-supplied reference, as ADR-0004 decisions 3 and 4 say of
`:tenant`.

**3. The Elixir surfaces take the Scope name.** The rename is scheduled work
that follows this record, not code this record lands. Its scope is:

| Today (at `5e532aa`) | After the rename |
|---|---|
| profile `:tenant` | `:scoped` |
| `Encryptor.Context.tenant_ref_key/0` | `Encryptor.Context.scope_ref_key/0` |
| `Encryptor.Envelope.tenant_ref/2` | `Encryptor.Envelope.scope_ref/2` |
| `%Encryptor.Envelope.WrappedKey{tenant_ref: _}` | `%Encryptor.Envelope.WrappedKey{scope_ref: _}` |
| `Encryptor.Provider.provisioned()`'s `tenant_ref` key | `scope_ref` |
| vault option `:telemetry_tenant_ref` | `:telemetry_scope_ref` |
| telemetry metadata key `:tenant_ref` | `:scope_ref` |
| error terms naming an Elixir field or option, such as `{:invalid_config, :telemetry_tenant_ref, _}` and the `:tenant_ref` field of an invalid wrapped key | the same terms with the Scope name |
| reserved caller context key `tenant_id` on a `:tenant` vault | `tenant_id` stays reserved on a `:scoped` vault, and `scope_id` is reserved beside it |

An error term that quotes a *wire* key keeps the wire spelling, because the
term reports the string the host sent: `{:reserved_context_key, "tenant_ref"}`
is unchanged. `tenant_id` stays reserved because a host that followed today's
docs may already send it, and un-reserving it would let that pair reach the
context unrefused.

**4. The v1 wire spellings are constants, and they are not renamed.** Each
stays byte for byte what 0.4.1 writes, behind the Scope-named surface that
reaches it. `Context.scope_ref_key/0` returns `"tenant_ref"`;
`Envelope.scope_ref/2` returns the same value `tenant_ref/2` returns for the
same subkey and selector. The owner-noun-bearing wire spellings, re-counted at
`5e532aa`:

| # | Spelling | What it is | Where it is written (anchor at `5e532aa`) | Record |
|---|---|---|---|---|
| 1 | `"tenant_ref"` | the application-data context key the vault injects | `lib/encryptor/context.ex`, `@tenant_ref`, returned by `tenant_ref_key/0` | ADR-0004 decision 4 |
| 2 | `"t/<ref>/v<n>"` | the key name: the EDK provider info in every message header | `lib/encryptor/envelope.ex`, `key_name/2` | ADR-0002 decision 4, ADR-0003 decision 5 |
| 3 | `"encryptor-tenant-ref"` | the wrapping-context key carrying the reference | `lib/encryptor/envelope.ex`, `@tenant_ref_key`, applied by `binding/3` | ADR-0003 decision 4 |
| 4 | `"tenant-key-wrap"` | the wrapping-context value of `"encryptor-purpose"` | `lib/encryptor/envelope.ex`, `@wrap_purpose`, applied by `binding/3` | ADR-0003 decision 4 |
| 5 | `"encryptor-tenant"` | the default key namespace, persisted in every wrapped key's binding and carried by the descriptor its keyring is built from | `lib/encryptor/envelope.ex`, `@default_namespace`; spelled a second time in `lib/encryptor/provider/gcp_kms.ex`, `@default_namespace` | ADR-0003 decision 5 |
| 6 | `"tenant-ref"` | the root purpose the reference subkey is derived under | `lib/encryptor/envelope.ex`, `@tenant_ref_purpose` (the refusal in `subkey/2`); the host passes it to `root_subkey/2` (`guides/getting-started.md`, "Onboarding a merchant") | ADR-0003 decision 6 |
| 7 | `"encryptor/v1/tenant-ref"` | the HKDF label of that subkey | `lib/encryptor/kdf.ex`, `label/1`, which composes `@label_namespace`, `@label_version` and the purpose; its moduledoc's label table | ADR-0003 decision 6 |

Rows 3 and 4 reach a second wire through the same function: the GCP KMS
provider's AAD is `binding/3`'s map, encoded (`lib/encryptor/provider/gcp_kms.ex`,
`aad/3`). Row 1's value, the reference itself, is fixed by
`Encryptor.Vault.Reference.derive/2` (`lib/encryptor/vault/reference.ex`):
the derivation carries no owner noun, but it is persisted in every row, so it
is pinned by the same rule and the rename does not touch it.

The binding's other spellings, `"encryptor-purpose"`, `"encryptor-key-version"`,
`"encryptor-key-namespace"`, the `"root-wrap"` purpose and the
`"encryptor/v1/"` label prefix, carry no owner noun and are outside the
rename by construction; they are wire constants all the same.

**5. Renaming a wire constant is R3.** Any change to a spelling in decision
4's table changes what the engine authenticates, so every ciphertext and
wrapped key written under the old spelling must be re-encrypted under the new
one: ADR-0005 decision 1's R3, owned downstream, which `rekey/2` cannot
express because it preserves the context byte for byte. Row 7 is the widest
case: a new label means a new reference subkey, so every reference changes,
and with it rows 1, 2 and 3 in every stored message. A v2 wire format, if
there is ever one, is an R3 and is recorded as one; none is scheduled.

**6. Comments beside a pinned constant say it is pinned.** After the rename
the only `tenant` spellings left in `lib/` are decision 4's constants and the
comments that explain them, so a later reader who sees `tenant` next to
`scope` finds the reason on the spot rather than filing a rename.

## Consequences

- The rename is a **breaking** change to the Elixir API and ships in a minor
  release with a Breaking changelog entry; a host changes its vault
  configuration (`context_profile: :scoped`), its calls to
  `Envelope.tenant_ref/2`, its pattern matches on `WrappedKey` and on
  telemetry metadata, and nothing it has stored.
- Every ciphertext and wrapped key written by 0.4.1 decrypts and unwraps
  under the renamed build with no migration. The rename's acceptance should
  pin that with a fixture of each produced by 0.4.1, because a green suite
  that only round-trips its own output cannot see a changed constant.
- `describe/1` keeps reporting the context key as `"tenant_ref"`, so a host's
  support tooling reads the wire name, not the Elixir name. The docs say so
  once, where the scope is introduced.
- `encryptor_ecto`'s key store finds a wrapped key by its reference, which
  its docs define as `Envelope.tenant_ref/2` of the host's selector; its
  surfaces follow its own records, and the reference values it has stored
  are pinned for the same reason as row 1.
- Two spellings of one noun sit side by side in the source indefinitely.
  That is the cost of not re-encrypting, and decision 6 is how it stays
  legible.

## The contract as typespecs

As the rename is to spell them; a proposal, not landed code.

```elixir
# Encryptor.Vault.Config
@type profile :: :single | :scoped

# Encryptor.Context
@spec scope_ref_key() :: String.t()   # always "tenant_ref", a v1 wire constant

# Encryptor.Envelope
@spec scope_ref(binary(), selector()) :: {:ok, String.t()} | {:error, Error.t()}

# Encryptor.Envelope.WrappedKey
@type t :: %__MODULE__{
        scope_ref: String.t(),
        version: pos_integer(),
        namespace: String.t(),
        name: String.t(),
        bits: pos_integer(),
        wrapped: binary()
      }
```

## Worked example: a 0.4.1 row read after the rename

A host provisioned a key for selector `"workspace-7"` under 0.4.1 and stored one
encrypted column value. It upgrades, changes `context_profile: :tenant` to
`context_profile: :scoped`, and changes nothing else.

```elixir
{:ok, ref} = Encryptor.Envelope.scope_ref(reference_subkey, "workspace-7")
# ref is byte-identical to what tenant_ref/2 returned under 0.4.1

wrapped.scope_ref == ref
# the row's stored reference column is read into the renamed field

wrapped.name == "t/" <> ref <> "/v1"
# decision 4 row 2: the header name is unchanged

{:ok, info} = Encryptor.Message.describe(ciphertext)
info.encryption_context["tenant_ref"] == ref
# decision 4 row 1: the authenticated context still spells the v1 key

{:ok, plaintext} = MyApp.ScopedVault.decrypt(ciphertext, key: "workspace-7")
# decrypts, because nothing the engine authenticates has changed
```

Had the rename also respelled row 1 as `"scope_ref"`, the last call would fail
with a context mismatch on every row written before the upgrade, and the only
recovery would be an R3 pass.

## Open questions

1. **Do the old Elixir names survive one release as deprecated aliases?**
   This record decides the new names and that the change is breaking; whether
   `:tenant` is still accepted by the profile validator with a warning, and
   whether `tenant_ref/2` delegates to `scope_ref/2` for a release, is the
   rename's call to make and record in its changelog entry.
