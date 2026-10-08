# ADR-0009: Scope names the key's owner, and the v1 wire spellings stay constants behind it

Status: accepted (2026-09-24)

**Amendment A (2026-10-06) is proposed, not accepted.** It is appended at the
end of this record, it replaces decisions 4 and 5, and decisions 1 to 3 and 6
are unchanged. Read the decisions as accepted and the amendment as a proposal
awaiting the operator's acceptance reading.

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

## Note (2026-09-24): accepted; what was verified, where the anchors now resolve, and open question 1's answer

This record is accepted on 2026-09-24. Its code shipped in encryptor 0.5.0,
published on Hex from the `v0.5.0` tag at `9ad74e2`. Every claim below was
re-read by anchor at `e84b648`, the tip of `main` when this Note was written;
`lib/` is byte-identical between the two, and the only files that differ are
`mix.exs` and `mix.lock`. This Note changes no decision, and it carries the
record's status rather than one of its own.

### 1. Decisions 1 to 4 are implemented as written

- Decision 1: on a `:scoped` vault, `Encryptor.Vault.Resolve.selector/3`
  accepts any non-empty binary as the selector and interprets it no further,
  and nothing in `lib/` gives a scope a parent or a child.
- Decision 2: `Encryptor.Vault.Config`'s `@type profile` is `:single | :scoped`,
  and the private `context_profile/2` accepts those two values and nothing
  else.
- Decision 3: every row of the rename table is the code's name.
  `Encryptor.Context.scope_ref_key/0`, `Encryptor.Envelope.scope_ref/2`, the
  `scope_ref` field of `%Encryptor.Envelope.WrappedKey{}`, the `scope_ref` key
  of `Encryptor.Provider`'s `provisioned` type, the `:telemetry_scope_ref`
  option (the private `telemetry_scope_ref/3` in `Encryptor.Vault.Config`) and
  the `scope_ref` metadata key (`Encryptor.Telemetry`'s metadata table). The
  invalid wrapped-key field is reported as `:scope_ref` (the private
  `invalid_field/3` call in `Encryptor.Envelope`). `Encryptor.Context`'s
  `@owner_ids` reserves `"scope_id"` and `"tenant_id"` together, and
  `compose/3`'s doctest still returns `{:reserved_context_key, "tenant_ref"}`.
- Decision 4: each of the seven spellings is the byte string 0.4.1 wrote,
  checked against the `v0.4.1` tag attribute by attribute. The table's
  anchors were given at `5e532aa`, before the rename; three module attributes
  were renamed with it and resolve under their new names:

| Row | Cited at `5e532aa` | Resolves at `e84b648` |
|---|---|---|
| 1 | `lib/encryptor/context.ex`, `@tenant_ref`, returned by `tenant_ref_key/0` | `@scope_ref`, returned by `scope_ref_key/0` |
| 3 | `lib/encryptor/envelope.ex`, `@tenant_ref_key` | `@scope_ref_key`, still applied by `binding/3` |
| 6 | `lib/encryptor/envelope.ex`, `@tenant_ref_purpose` | `@scope_ref_purpose`, still the refusal in `subkey/2` |

Rows 2, 4, 5 and 7 resolve at the anchors the table names: `key_name/2`,
`@wrap_purpose`, both `@default_namespace` attributes, and
`Encryptor.Kdf.label/1` over `@label_namespace` and `@label_version`. The
GCP KMS provider's `aad/3` still encodes `binding/3`'s map, and
`Encryptor.Vault.Reference.derive/2` has no code change since `v0.4.1`. The
getting-started guide's "Onboarding a merchant" step still passes
`"tenant-ref"` to `root_subkey/2`. The comment above `@purpose_key` still
says "a typo in any of them is a wrapped-key population that a corrected
build can no longer open".

### 2. Decision 6, read with decision 3

Decision 6 says "After the rename the only `tenant` spellings left in `lib/`
are decision 4's constants and the comments that explain them". Every
`tenant` spelling in `lib/` at `e84b648` is one of decision 4's seven, prose
that quotes one of them, a comment that says why one is pinned, or the
reserved caller key `"tenant_id"`. The last is not in decision 4's table: it
is decision 3's, whose last row keeps it reserved on a `:scoped` vault. Read
decision 6's "decision 4's constants" as including that one reserved key,
which the record keeps on purpose; it is explained where it is declared, at
`Encryptor.Context`'s `@owner_ids`.

### 3. The Consequences hold

- The rename shipped in a minor release, 0.5.0, whose changelog opens with
  a `**Breaking**` section naming every renamed surface.
- The acceptance fixture the second bullet asked for is
  `test/encryptor/wire_fixture_test.exs`: a wrapped key and a ciphertext
  written by 0.4.1, unwrapped, rewrapped, decrypted and rekeyed by the renamed
  build.
- `describe/1` still reports the context key as `"tenant_ref"`. The docs say
  so where a scoped vault is introduced, in the getting-started guide's
  "Part 2: a scoped vault", and again in the guide whose subject is the
  scope, `guides/choosing-the-scope.md`'s "Scope, and the spellings that
  stay", which the first links to. The bullet says "once"; two places is
  one mention per entry point, not a claim that fails.

### 4. The sentences that named the record as unlanded are met, not reworded

Decision 3's "The rename is scheduled work that follows this record, not
code this record lands" and the typespec section's "As the rename is to
spell them; a proposal, not landed code" were true when written. They are
left as they stand. The rename has landed, and the typespecs match the code:
`@type profile`, `scope_ref_key/0`'s and `scope_ref/2`'s specs, and
`WrappedKey`'s `@type t`.

### 5. Open question 1 is answered: a clean break

The 0.5.0 release kept no deprecated aliases. The profile validator refuses
`:tenant` as `{:invalid_config, :context_profile, :unknown}`, and
`Encryptor.Envelope` has no `tenant_ref/2`. The 0.5.0 changelog's first
Breaking entry records it in the words "renamed with no deprecated aliases",
which is where the question said the answer would be recorded.

## Note (2026-09-29): the key store's reference is `scope_ref/2` of the selector

One reading of the Consequences' fourth bullet, which changes no decision.
The bullet says `encryptor_ecto`'s key store finds a wrapped key by "its
reference, which its docs define as `Envelope.tenant_ref/2` of the host's
selector". That was true when this record was written; the function it
names was renamed by decision 3 and shipped in 0.5.0 with no alias (the
2026-09-24 Note, section 5).

**Read the bullet as naming `Envelope.scope_ref/2`.** In `encryptor_ecto`
(read at `4722b05`), `Encryptor.Ecto.KeyStore`'s moduledoc, section "The
table", defines the `tenant_ref` column as "`Encryptor.Envelope.scope_ref/2`
of the host's selector", and the store's private `scope_ref/2` computes the
lookup key by calling `Envelope.scope_ref/2`. That package's own record of
the rename is its ADR-0006. The rest of the bullet holds as written: the
column keeps the name `tenant_ref`, and the values it holds are still
found, because decision 4 keeps `scope_ref/2`'s answer equal to what
`tenant_ref/2` returned for the same subkey and selector.

The bullet is left as written - a merged record's body is not rewritten by a
Note - and this Note carries no status of its own.

## Amendment A (2026-10-06): a v2 wire format spells the owner noun scope

Status: accepted (2026-10-06, encryptor 0.7.0), proposed 2026-10-06. This amendment replaces decisions 4 and 5
above. Decisions 1 to 3 and 6 are unchanged; A4 tables the reserved caller
keys under the v2 spellings, and A5 restates which spellings decision 6's
sentence now covers. No line above is edited except the header note under
the record's Status line. Every `lib/`, `guides/` and `test/` cite in this
amendment was read at `32880c7`.

### Why now

Decision 5 rests on one premise: a respelled wire constant forces a
re-encrypt of every row already written under the old spelling, ADR-0005
decision 1's R3 ("Format or context change | R3 | none in this package |
every ciphertext in scope", `docs/adr/0005-rotation-and-crypto-shred.md`,
decision 1). That premise is about stored rows, not about the strings, and
today there are none to re-encrypt:

- **No package depends on encryptor except encryptor_ecto.** Hex lists
  encryptor_ecto as encryptor's only dependent, and encryptor_ecto pins an
  exact version, so it moves when this package moves; its key-store column
  follows in its own record.
- **No host has stored a ciphertext or a wrapped key.** No host has run
  encryptor_ecto's key-store migration, so no wrapped-key table holds a row,
  and no ciphertext written by this package is held anywhere a host has to
  read it back.

The cost comparison follows from that. With zero stored rows, the
respelling costs one minor release of each package and this amendment.
After a host writes its first row, the same respelling costs that host an
R3 re-encrypt rather than a rotation, and every later host the same. The
original Consequences accepted the price of not respelling ("Two spellings
of one noun sit side by side in the source indefinitely") only because the
re-encrypt was assumed to be owed; with nothing stored, that price buys
nothing.

The v2 wire format, its spelling set, the label rule of A2, the absence of
v1 compatibility (A3), the reserved keys of A4 and the respelled Cloud KMS
defaults were ruled by the operator, 2026-10-06.

"Wire format v2" names the spelling set in A1's table. It is not a label
prefix: the HKDF label space stays `encryptor/v1/` (A2).

### A1. Decision 4 is replaced: the v2 wire spellings

Decision 4's rule stands with new values. Each spelling in the v2 column is
a constant, written byte for byte by every build from encryptor 0.7.0 on,
behind the Scope-named surface that reaches it. `Context.scope_ref_key/0`
returns `"scope_ref"`. The anchors name where each spelling is written
today, under its v1 value, at `32880c7`:

| # | v1 (decision 4, through 0.6.x) | v2 (from 0.7.0) | What it is | Where it is written (anchor at `32880c7`) | Record |
|---|---|---|---|---|---|
| 1 | `"tenant_ref"` | `"scope_ref"` | the application-data context key the vault injects | `lib/encryptor/context.ex:120`, `@scope_ref`, returned by `scope_ref_key/0` (`:181`) | ADR-0004 decision 4 |
| 2 | `"t/<ref>/v<n>"` | `"s/<ref>/v<n>"` | the key name: the EDK provider info in every message header | `lib/encryptor/envelope.ex:586`, `key_name/2` | ADR-0002 decision 4, ADR-0003 decision 5 |
| 3 | `"encryptor-tenant-ref"` | `"encryptor-scope-ref"` | the wrapping-context key carrying the reference | `lib/encryptor/envelope.ex:191`, `@scope_ref_key`, applied by `binding/3` (`:594`) | ADR-0003 decision 4 |
| 4 | `"tenant-key-wrap"` | `"scope-key-wrap"` | the wrapping-context value of `"encryptor-purpose"` | `lib/encryptor/envelope.ex:194`, `@wrap_purpose`, applied by `binding/3` (`:594`) | ADR-0003 decision 4 |
| 5 | `"encryptor-tenant"` | `"encryptor-scope"` | the default key namespace, persisted in every wrapped key's binding and carried by the descriptor its keyring is built from | `lib/encryptor/envelope.ex:207`, `@default_namespace`; spelled a second time at `lib/encryptor/provider/gcp_kms.ex:261`, `@default_namespace` | ADR-0003 decision 5, ADR-0007 decision 4 |
| 6 | `"tenant-ref"` | `"scope-ref"` | the root purpose the reference subkey is derived under | `lib/encryptor/envelope.ex:202`, `@scope_ref_purpose`, the refusal in `subkey/2` (`:569-574`); the host passes it to `root_subkey/2` (`guides/getting-started.md:415`, "Onboarding a merchant") | ADR-0003 decision 6 |
| 7 | `"encryptor/v1/tenant-ref"` | `"encryptor/v1/scope-ref"` | the HKDF label of that subkey | `lib/encryptor/kdf.ex:243`, `label/1`, which composes `@label_namespace` and `@label_version` (`:187-188`) with the purpose; its moduledoc's label table (`:100`) | ADR-0003 decision 6, ADR-0005 decision 5 |
| 8 | `"t-"` | `"s-"` | the default `:key_id_prefix`, the start of every default Cloud KMS `CryptoKey` id | `lib/encryptor/provider/gcp_kms.ex:262`, `@default_prefix`, the option's default (`:315`), used by `key_id/2` (`:433-436`) | ADR-0007 decision 4 |

Each v2 spelling is its v1 spelling with the owner noun swapped and nothing
else, so a reader maps one to the other on sight.

Row 8 is new to the table. Decision 4 did not list it because it is not
authenticated data, but a host lives with it all the same: `key_id/2` starts
every default `CryptoKey` id with it, and a `CryptoKey` can be neither
renamed nor deleted (`lib/encryptor/provider/gcp_kms.ex`, the moduledoc
section "The `CryptoKey` id").

Rows 6 and 7 are one choice: the purpose names the label. Row 7 is a new
label, so a new reference subkey, so every reference value changes, and with
it row 1's value, the `<ref>` in row 2 and row 3's value in every message
and wrapped key written from 0.7.0 on. The derivation itself,
`Encryptor.Vault.Reference.derive/2` (`lib/encryptor/vault/reference.ex:49`),
carries no owner noun and does not change.

**Second wires.** Three groups of these spellings leave the message:

- Rows 3, 4 and 5 are `binding/3`'s map, which the GCP KMS provider encodes
  as the Cloud KMS additional authenticated data
  (`lib/encryptor/provider/gcp_kms.ex:448`, `aad/3`). A wrapping written
  under the v1 spellings fails the Cloud KMS `Decrypt` under v2.
- Row 1 is in the composed context, which on the AWS KMS keyring path the
  engine passes to KMS as the KMS encryption context, recorded in
  CloudTrail (ADR-0008 decision 7). From 0.7.0 the pair there is
  `scope_ref`; a key policy or an audit query conditioned on the v1 key is
  the host's to change.
- Rows 5 and 8 together make the default `CryptoKey` id: `key_id/2` is the
  prefix followed by the base32 digest of the namespace, a zero byte and the
  selector (`lib/encryptor/provider/gcp_kms.ex:433-436`), so every default
  id changes under v2. A deployment holding a `CryptoKey` created under the
  v1 defaults could still name it by passing `namespace: "encryptor-tenant"`
  and `key_id_prefix: "t-"` in its provider config, but the wrappings in it
  would carry v1 bindings and would not unwrap (A3). The defaults are
  respelled because no real `CryptoKey` was created through this provider
  under them.

The binding's other spellings, `"encryptor-purpose"`,
`"encryptor-key-version"`, `"encryptor-key-namespace"`, the `"root-wrap"`
purpose and the `"encryptor/v1/"` label prefix, carry no owner noun and are
unchanged; they are wire constants as before.

### A2. Decision 5 is replaced: a respelling is still a re-encrypt, and v2 is the one made while none is owed

- A change to a spelling in A1's table changes what the engine, or Cloud
  KMS, authenticates, so every ciphertext and wrapped key written under the
  old spelling would have to be re-encrypted under the new one: ADR-0005
  decision 1's R3, owned downstream, which `rekey/2` cannot express because
  it preserves the context byte for byte. That half of decision 5 stands.
- v2 is that respelling, made while no stored row exists to re-encrypt.
- From 0.7.0 on, A1's table is pinned as decision 4's was. A later
  respelling of any row is an R3 and is recorded as one.

**The label rule.** The label version stays `v1`, and only the purpose
changes. `"encryptor/v1/scope-ref"` is a new label in the existing label
space, which is what the one-way reservation prescribes for a new key: "Any
future purpose-separated key takes a *new* `"encryptor/v<n>/<purpose>"`
label and never reuses an existing one" (`lib/encryptor/kdf.ex:103-105`;
ADR-0003 decision 6). And `@label_version` "moves only when a record says a
new version of the whole label space exists; it is never bumped to re-mint
one purpose" (`lib/encryptor/kdf.ex:184-186`). A `v2` prefix on every label
would re-key the root-wrap and blind-index trees for nothing.
`"encryptor/v1/tenant-ref"` is retired and stays reserved: no later purpose
takes it, and `subkey/2` refuses `"tenant-ref"` beside `"root-wrap"` and
`"scope-ref"`.

### A3. No v1 compatibility

0.7.0 reads the v2 spellings only. No fallback decrypt, no dual-spelling
binding, no alias and no migration helper for a v1 spelling enters `lib/`.
A wrapped key written by 0.6.x or earlier does not unwrap under 0.7.0,
because its binding spells rows 3, 4 and 5 in v1; a ciphertext written by
0.6.x or earlier does not decrypt, because its context spells row 1 in v1
and its reference was derived under the retired label.

A host holding v1 rows would have two courses. It can stay on encryptor
0.6.x (and encryptor_ecto 0.7.x). Or it can run an R3 re-encrypt, which this
package does not ship (ADR-0005 decision 1: "none in this package"); one Mix
build cannot load two encryptor versions, so that re-encrypt would need a v1
read path, which 0.7.0 deliberately omits. If such a host appears, a v1 read
path is its own record.

### A4. Reserved caller context keys

| Key | `:single` vault | `:scoped` vault | Why |
|---|---|---|---|
| `"scope_ref"` | refused | refused | A1 row 1: the vault injects it on a `:scoped` vault, and on a `:single` vault there is no scope for a caller to name |
| `"tenant_ref"` | refused | refused | the retired v1 spelling of row 1: un-reserving it would let a caller put a pair spelled like the v1 scope reference into a v2 context, where support tooling reading `describe/1` could take it for the vault's |
| `"scope_id"` | accepted | refused | decision 3 |
| `"tenant_id"` | accepted | refused | decision 3: a host that followed older docs may still send it |

At `32880c7`, `reserved_key?/2` refuses row 1's key on both profiles and
`@owner_ids` on a `:scoped` vault (`lib/encryptor/context.ex:248-251`); the
`aws-crypto-` and `encryptor-` prefixes stay refused on both
(`@reserved_prefixes`, `:132`). Decision 3's rule that an error term quoting
a wire key reports the string the host sent still holds: a caller sending
`"tenant_ref"` gets `{:reserved_context_key, "tenant_ref"}`, and one sending
`"scope_ref"` gets `{:reserved_context_key, "scope_ref"}`.

### A5. Decision 6 now reads

After the respelling, the only `tenant` spellings left in `lib/` are the
retired, reserved keys `"tenant_ref"` and `"tenant_id"` and the retired
purpose `"tenant-ref"` (with its label, where the label table lists it as
retired), each beside a comment saying why it stays. Decision 6's rule, that
a comment beside such a spelling says why it is there, is unchanged.

### Consequences

- The respelling is a **breaking** change to what the package writes and
  reads. It ships in a minor release, 0.7.0, whose changelog carries a
  **Breaking** entry naming every respelled string, saying that nothing
  written by 0.6.x or earlier opens under 0.7.0, and saying that a later
  respelling is an R3 re-encrypt rather than a rotation.
- encryptor_ecto's key-store column and its index follow in that package's
  own record, its ADR-0006 Amendment A. The reference values it stores
  change with row 7.
- The first Consequences bullet's "and nothing it has stored", the second
  bullet (every 0.4.1 row opens under the renamed build), the third
  (`describe/1` keeps reporting `"tenant_ref"`), the fifth (two spellings
  side by side indefinitely) and the worked example "a 0.4.1 row read after
  the rename" describe encryptor 0.5.0 through 0.6.x. They are left as
  written, not edited, and read as history from 0.7.0 on; this amendment
  records that reading.
- The 0.4.1 wire fixture (`test/encryptor/wire_fixture_test.exs`) changes
  role: from 0.7.0 it pins that a v1 row is refused, and a v2 fixture pins
  A1's table, for the second Consequences bullet's reason: a suite that only
  round-trips its own output cannot see a changed constant.
- ADR-0003, ADR-0004, ADR-0005, ADR-0007 and ADR-0008 quote v1 spellings.
  Each carries a dated Note pointing here; none of their decisions changes.

### The contract as typespecs

No signature changes. Two return values do:

```elixir
# Encryptor.Context
@spec scope_ref_key() :: String.t()   # always "scope_ref", a v2 wire constant

# Encryptor.Envelope
@spec scope_ref(binary(), selector()) :: {:ok, String.t()} | {:error, Error.t()}
@spec key_name(String.t(), pos_integer()) :: String.t()
# key_name(ref, n) == "s/" <> ref <> "/v" <> Integer.to_string(n)

# Encryptor.Kdf
@spec label(purpose()) :: String.t()
# label("scope-ref") == "encryptor/v1/scope-ref"
```

### Worked example: a fresh scoped vault on 0.7.0

A host adopts encryptor 0.7.0 with nothing stored. Its root vault is
`MyApp.RootVault` and its scoped vault `MyApp.ScopedVault`, built from the
same reference subkey.

```elixir
reference_subkey = Encryptor.Envelope.root_subkey(reference_root, "scope-ref")
# A1 rows 6 and 7: the purpose, and so the label "encryptor/v1/scope-ref"

{:ok, wrapped} =
  Encryptor.Envelope.provision(MyApp.RootVault, "workspace-7",
    reference_subkey: reference_subkey
  )

{:ok, ref} = Encryptor.Envelope.scope_ref(reference_subkey, "workspace-7")
wrapped.scope_ref == ref
wrapped.namespace == "encryptor-scope"
# A1 row 5: the default namespace
wrapped.name == "s/" <> ref <> "/v1"
# A1 row 2: the key name starts s/

{:ok, ciphertext} = MyApp.ScopedVault.encrypt("a value", key: "workspace-7")
{:ok, info} = Encryptor.Message.describe(ciphertext)
info.encryption_context["scope_ref"] == ref
# A1 row 1: describe/1 shows "scope_ref", and no "tenant_ref" pair

{:error, _} = Encryptor.Envelope.unwrap(MyApp.RootVault, row_written_by_0_4_1)
# A3: the 0.4.1 fixture row's binding spells rows 3, 4 and 5 in v1, so it is refused
```

### Open questions

None.

Provenance: bead `enc-q9ke`.

## Note (2026-10-06): Amendment A is accepted

Amendment A's Status line now reads `accepted (2026-10-06, encryptor
0.7.0)`. The record's own Status line, `accepted (2026-09-24)`, does not
change, and its index row now reads `accepted (2026-09-24, amended)`. The
amendment decides something cryptographic - a new HKDF label for the
reference subkey, and the strings the engine and Cloud KMS authenticate - so
it is accepted by the operator's own reading, not by this repository's flip
rule.

The amendment's code shipped in encryptor 0.7.0: the commit tagged `v0.7.0`
(`cb379b5`), published on Hex by the release workflow's run
https://github.com/riddler/encryptor/actions/runs/37490975248, which
succeeded. Every claim below was re-verified at `cb379b5`, which was also the
tip of `main` when this Note was written, so no later commit touches a claim.
The amendment gave its anchors at `32880c7`, under the v1 values, and each
resolves there as cited; the table below gives where each A1 row resolves at
`cb379b5`, now holding its v2 value.

| Row | v2 value | Where it is written at `cb379b5` |
|---|---|---|
| 1 | `"scope_ref"` | `lib/encryptor/context.ex:123`, `@scope_ref`, returned by `scope_ref_key/0` (`:189`) |
| 2 | `"s/<ref>/v<n>"` | `lib/encryptor/envelope.ex:593`, `key_name/2` |
| 3 | `"encryptor-scope-ref"` | `lib/encryptor/envelope.ex:192`, `@scope_ref_key`, applied by `binding/3` (`:601`) |
| 4 | `"scope-key-wrap"` | `lib/encryptor/envelope.ex:195`, `@wrap_purpose`, applied by `binding/3` |
| 5 | `"encryptor-scope"` | `lib/encryptor/envelope.ex:212`, `@default_namespace`, and `lib/encryptor/provider/gcp_kms.ex:263`, `@default_namespace` |
| 6 | `"scope-ref"` | `lib/encryptor/envelope.ex:203`, `@scope_ref_purpose`, refused by `subkey/2` (`:575-580`); `guides/getting-started.md:415`, "Onboarding a merchant" |
| 7 | `"encryptor/v1/scope-ref"` | `lib/encryptor/kdf.ex:235`, `label/1`, composing `@label_namespace` and `@label_version` (`:188-189`) with the purpose at `:244`; the moduledoc's label table at `:100` |
| 8 | `"s-"` | `lib/encryptor/provider/gcp_kms.ex:267`, `@default_prefix`, the option's default (`:320`), used by `key_id/2` (`:438-442`) |

- **A1.** Each v2 value is its v1 value with the owner noun swapped and
  nothing else. Row 8's reason holds: the GCP KMS provider's moduledoc
  section "The `CryptoKey` id" says the provider's keys cannot be renamed or
  deleted. `Encryptor.Vault.Reference.derive/2`
  (`lib/encryptor/vault/reference.ex:49`) carries no owner noun, and between
  `v0.6.1` and `v0.7.0` only a comment in its file changed. The second wires:
  `aad/3` (`lib/encryptor/provider/gcp_kms.ex:453`) encodes `binding/3`'s
  map; the AWS KMS context lists in `test/encryptor/provider/kms_test.exs`
  pin `"scope_ref"` as the pair KMS receives; `key_id/2` is the prefix and
  the base32 of the SHA-256 of the namespace, a zero byte and the selector.
  The binding's other spellings are unchanged: `@purpose_key`,
  `@version_key` and `@namespace_key` (`lib/encryptor/envelope.ex:191-194`),
  `@root_wrap`, and the `"encryptor/v1/"` prefix of `label/1`.
- **A2.** The two sentences the label rule quotes still read as quoted, at
  `lib/encryptor/kdf.ex:104-106` and `:185-187`; `@label_version` is still
  `"v1"`. `subkey/2` refuses `"root-wrap"`, `"scope-ref"` and the retired
  `"tenant-ref"` (`lib/encryptor/envelope.ex:576`), and the label table lists
  `"encryptor/v1/tenant-ref"` as retired and reserved
  (`lib/encryptor/kdf.ex:102`).
- **A3.** No v1 spelling is written or read anywhere in `lib/` except the
  retired, reserved keys A4 and A5 name; there is no fallback decrypt, dual
  binding, alias or migration helper. `test/encryptor/wire_fixture_test.exs`
  pins the refusal: its 0.4.1 wrapped key "does not unwrap under the root
  vault" and its 0.4.1 ciphertext "does not decrypt on a :scoped vault, even
  holding the key it was written under".
- **A4.** `reserved_key?/2` (`lib/encryptor/context.ex:263-268`) refuses the
  `@reserved_prefixes` (`:140`), `"scope_ref"` and `"tenant_ref"` on both
  profiles, and `@owner_ids`, `"scope_id"` and `"tenant_id"` (`:132`), on a
  `:scoped` vault. `test/encryptor/context_test.exs` asserts
  `{:reserved_context_key, "tenant_ref"}` and `{:reserved_context_key,
  "scope_ref"}` on both profiles.
- **A5.** Every `tenant` spelling in `lib/` at `cb379b5` is `"tenant_ref"`
  (`lib/encryptor/context.ex:128`), `"tenant_id"` (`:132`), `"tenant-ref"`
  (`lib/encryptor/envelope.ex:207` and the refusal message in `subkey/2`),
  the retired label's row in the label table, or prose and comments that
  quote one of them; one comment in `Encryptor.Vault.Reference` names the
  function's earlier name, `tenant_ref/2`, as history. Each of the three
  constants sits beside a comment saying why it stays.
- **Consequences.** The 0.7.0 changelog opens with a **Breaking** section
  whose first entry names every respelled string and says a later respelling
  is a re-encrypt rather than a rotation, and whose second says nothing
  written by 0.6.x or earlier opens under 0.7.0. encryptor_ecto's ADR-0006
  Amendment A is on that repository's `main` (read at `34ebbc5`). ADR-0003,
  ADR-0004, ADR-0005, ADR-0007 and ADR-0008 each carry a Note of 2026-10-06
  pointing here. `test/encryptor/wire_fixture_v2_test.exs` pins A1's table
  with a v2 wrapped key and ciphertext.
- **The contract as typespecs.** The specs of `scope_ref_key/0`,
  `Envelope.scope_ref/2`, `key_name/2` and `Kdf.label/1` read as the
  amendment gives them, and the doctest of `label/1` returns
  `"encryptor/v1/scope-ref"` for `"scope-ref"`.
- **The worked example.** `Envelope.provision/3` and `Envelope.unwrap/2`
  take the arguments the example passes; the v2 fixture test "is the row the
  current build provisions for the same selector" and "carries the reference
  under the v2 context key and the v2 key name".
- **Why now.** The Hex API lists encryptor_ecto as the only package that
  depends on encryptor, and encryptor_ecto's `mix.exs` (read at `34ebbc5`)
  pins `== 0.7.0`. The two facts about stored rows - that no host has stored
  a ciphertext or a wrapped key, and that no real `CryptoKey` was created
  through this provider under the v1 defaults - are not in any source this
  repository or Hex can show; they rest on the operator's report, and the
  operator's acceptance of this amendment is the reading that covers them.

**Sentences that name the amendment as proposed.** The header note under
this record's Status line says "**Amendment A (2026-10-06) is proposed, not
accepted.**" and asks the reader to read the amendment "as a proposal
awaiting the operator's acceptance reading". From this Note on, Amendment A
is accepted, and the header note's other sentences (where the amendment
sits, and which decisions it replaces) hold as written. The 2026-10-06 Notes
on ADR-0003, ADR-0004, ADR-0005, ADR-0007 and ADR-0008 each name "ADR-0009
Amendment A (2026-10-06, proposed)", which still states the date it was
proposed. `guides/choosing-the-scope.md`'s list of records marks the
amendment "(proposed)"; the guide is not a record and follows on its own.
None of these is edited.

Provenance: bead `enc-a9ah`.

No decision changes, no line above is edited other than Amendment A's Status
line, and this Note carries no status of its own.

## Note (2026-10-07): Amendment A's worked example reads `scope_ref` from a header the 1.0.x engine wrote

One reading, which changes no decision. Amendment A's worked example, "a
fresh scoped vault on 0.7.0", reads the scope reference back through
`Encryptor.Message.describe/1`:

    info.encryption_context["scope_ref"] == ref

That line describes a message written on `aws_encryption_sdk` 1.0.x, which
stored every pair of the context in the header, and it holds for every
message encryptor 0.7.0 wrote. From the encryptor release that requires
`aws_encryption_sdk` 1.1, the engine follows the AWS Encryption SDK
specification and stores no required pair in the header it writes
(ADR-0004 Amendment B). A `:scoped` vault always requires `"scope_ref"`, so
for a message that release writes `describe/1` returns no `"scope_ref"` pair
and the line above reads `nil`. ADR-0004 Amendment B's consequence that
`describe/1` returns fewer pairs for such a message says the same.

A1 row 1 still pins the spelling: the pair is authenticated in the header
and bound into the encrypted data key under the key `"scope_ref"`, and a
reader reproduces it under that key, so a respelling still leaves every
stored message unreadable. The reference also still travels in the clear in
the key name, `"s/" <> ref <> "/v1"` (A1 row 2), which the example's
`wrapped.name` line shows and which a header of either engine carries.

What pins the earlier form: `test/encryptor/wire_fixture_v2_test.exs`, "carries
the reference under the v2 context key and the v2 key name", reads
`"scope_ref"` from the header of a ciphertext encryptor 0.7.0 wrote.

Provenance: beads `enc-wqbc` and `enc-3bbw`.

No decision changes, no line above is edited, and this Note carries no
status of its own.
