# ADR-0004: The encryption context is a vault-composed, profile-enforced set of identifying keys

Status: accepted (2026-08-27, with amendments)

## Acceptance amendments (2026-08-27)

Two substantive changes were made at acceptance, after an adversarial
review of open question 1; the decision text below is already amended.

1. **The application-data context carries the derived `tenant_ref`, not the
   raw tenant identifier.** As proposed, decision 4 published the raw
   selector in every message header - beside the EDK key name
   `"t/<tenant_ref>/v<n>"`, which meant every ciphertext published an
   authenticated (identifier, reference) pair and voided ADR-0003
   decision 5's keying for every tenant that had ever written a row. The
   vault now derives the reference from the `:key` selector and injects
   `"tenant_ref"` instead. Riders bundled with the amendment: the reference
   subkey is tenant-vault configuration (the store-backed provider computes
   references from selectors with the same subkey, so the wrapped-key store
   is keyed by reference only); the vault performs a start-time known-answer
   check on the subkey against a pinned check value, because a node holding
   a wrong reference subkey would otherwise fail every decrypt as
   `:decrypt_failed` shaped like corruption; and the shred consequences in
   ADR-0005 carry the honest wording - a header carries a permanent
   pseudonym that the subkey holder can re-identify by guess-and-confirm.

2. **`table` and `column` are frozen at declaration, not re-derived at
   read time.** As proposed, `encryptor_ecto` derived both from the live
   schema on every operation, so an ordinary table or column rename made
   every existing row's reproduced context disagree with its stored context
   and fail as `:decrypt_failed`, recoverable only by an R3 re-encrypt.
   The Ecto layer now freezes the derived names as explicit, overridable
   declared values at type-declaration time (its ADR-0001 owns the
   mechanics, including a uniqueness check across declarations); renaming
   the physical source while pinning the declared value is free, and
   changing the declared value remains an R3.

## Context

ADR-0001 fixed the vault, ADR-0002 the provider contract, ADR-0003 the tenant
key hierarchy. All three deferred the same thing to this record, in the same
words: what the encryption context says, which of its keys are required, and
who supplies each one. ADR-0001 decision 4 recognized `:encryption_context` as
an option and explicitly labelled its own worked example's `tenant_id`,
`table`, `column` as "illustrative". ADR-0003 decision 4 fixed a package-owned
context for the wrapped-key blob and said "whether these exact key names are
the canonical vocabulary is enc-cvw's to ratify". This record ratifies, and in
three places it tightens rather than ratifies.

It also has a consumer already building against it. `encryptor_ecto`'s
ADR-0001 (`ece-alx-adr-0001-ecto-types`) derives table and column context
automatically and reads a tenant out of a process scope, and rests that design
on seven numbered assumptions about this package's contract. Those assumptions
are reviewed, one by one, in a section of their own below, because the
operator reads both records at acceptance and the assumptions are the seam.

Seven findings from `aws_encryption_sdk` v1.0.0 shape everything that
follows. Each is against the source, with a path, because several of them
contradict what the AWS specification says the mechanism does.

**The context rides the message in the clear, and it is authenticated.**
`Crypto.HeaderAuth.build_header/4` puts `materials.encryption_context` into the
header struct, `Header.serialize_body/1` serializes it, and the header auth tag
is computed over that serialized body
(`lib/aws_encryption_sdk/crypto/header_auth.ex`). So every context pair is
public to anyone holding a ciphertext, and no context pair can be edited
without breaking the tag. Both halves matter: the second is the anti-
substitution property, the first is the reason a context key is a disclosure
decision.

**Reproduced context is checked by value comparison, not by the AAD.**
`Cmm.Behaviour.validate_reproduced_context/2`
(`lib/aws_encryption_sdk/cmm/behaviour.ex:508`) walks the reproduced map, and
for each key that is *also in the stored header context*, returns
`{:error, {:encryption_context_mismatch, key}}` when the values differ. This is
an ordinary Elixir comparison in the CMM, before the keyring is consulted. The
bead's phrasing - "auth-tagged, so a moved ciphertext fails authentication" -
is very nearly right and worth stating precisely: the stored context is
authenticated, and the reader's claim about it is compared against that
authenticated copy. A wrong reproduced value fails a comparison; it does not
fail an AES-GCM tag.

**A key the reader supplies that the message does not carry is not an error.**
Same function, the `:error -> false` arm: a reproduced key absent from the
stored context is skipped. So decrypting a context-less message while claiming
`%{"tenant_id" => "B"}` succeeds.

**A key the message carries that the reader omits is not an error either.**
Nothing in `Default.get_decryption_materials/2` requires the reproduced context
to cover the stored one. A caller passing no context at all decrypts every
message the keyring can open. **This is the important one.** It means the
anti-substitution property is not a property of the ciphertext; it is a
property of readers who reproduce the context. A convention that only tells
writers what to put in is worth nothing.

**`Cmm.RequiredEncryptionContext` is the presence check that closes that
hole - and only the presence check.**
`validate_required_keys_in_reproduced_context/2`
(`lib/aws_encryption_sdk/cmm/required_encryption_context.ex`) returns
`{:error, {:missing_required_encryption_context_keys, keys}}` when the reader
omits a required key. It never compares values; the value comparison is the
Default CMM's, one layer down. The two compose exactly: *required* buys
presence, *Default* buys agreement, and only both together bind a message to a
tenant. It also composes with caching - `call_underlying_cmm_encrypt/2`
dispatches over `Default`, `Caching`, and itself - so a vault can wrap a
caching CMM in a required-context CMM and lose nothing.

**This engine does not implement the required-context privacy behaviour, and
that is load-bearing in our favour.** The specification has required keys
*removed* from the stored header and mixed into the AAD instead, so their
values are not published. v1.0.0 stores the full context in the header
(`build_header/4`) *and* appends the serialization of the required subset to
the AAD (`compute_header_auth_tag/4`, `Map.take(full_encryption_context,
required_ec_keys)`). Two consequences. Marking a key required hides nothing:
its value is in the header regardless. And because the header carries
everything, a message is self-sufficient for reproduction - which is what makes
decision 11's `rekey/2` behaviour possible at all. This is a deviation from the
specification, and if the engine is ever corrected, decision 11 breaks. Open
question 5 records it.

**The encryption context is an input to the materials cache id.**
`Caching.compute_encryption_cache_id/3` hashes
`partition_id || suite_id || serialize(encryption_context)`
(`lib/aws_encryption_sdk/cmm/caching.ex:201`). So the cache is partitioned not
by tenant, as ADR-0001 decision 7 implies, but by *tenant and exact context*. A
per-column context multiplies the entry count by the number of encrypted
columns, and every distinct context is its own provider round trip on a cold
cache. That is a real cost, it lands on ADR-0003's already-noted thundering
herd, and it puts a hard rule on what may go into the context (decision 7).

This record owns the vocabulary, the enforcement mechanism, the failure
mapping, and the shape of `describe/1`. It does not own the rotation and
shredding procedures (enc-53a), the storage schema (`encryptor_ecto`), or the
blind index. It settles three open questions its siblings assigned to it and
opens five narrower ones.

## Decision

**1. The context is a flat map of `String.t()` to `String.t()`, composed by the
vault in four layers, and the layers do not silently override each other.**

| Layer | Source | Precedence |
|---|---|---|
| Package-reserved | `encryptor-*` pairs this package sets (ADR-0003 decision 4) | highest, never overridable |
| Vault-supplied | keys the vault derives from the call's own arguments (decision 4) | above config, refuses a caller conflict |
| Static | `:static_encryption_context` from vault configuration | above nothing |
| Per-call | the caller's `:encryption_context` option | merged over static |

Nesting, lists, atoms, integers, and `nil` are not context values. A non-string
key or value is `{:error, {:invalid_context_value, key}}` before the engine is
called, because the engine's serializer would either raise deep inside a
`Format` module or, worse, accept something whose serialization the reader
cannot reproduce.

Conflicts are errors, not overrides, exactly as ADR-0001 decision 4 already
specified: a per-call key that collides with a static key with a different
value is `{:error, {:encryption_context_conflict, key}}`, and a per-call or
static key that collides with a vault-supplied or package-reserved key is
`{:error, {:reserved_context_key, key}}`. No new mechanism; this record only
says which keys fall in which layer.

**2. The canonical vocabulary is six host-facing keys and one reserved
prefix.** This is the convention the bead asks for, stated as a table. "Class"
is decision 5's enforcement class; "supplied by" is who is expected to put the
pair in, and is a contract, not a suggestion.

| Key | Value | Supplied by | Class |
|---|---|---|---|
| `tenant_ref` | the keyed reference derived from the `:key` selector (ADR-0003 decision 5) | **the vault**, from `:key` (decision 4) | required on a `:tenant` profile; refused on `:single` |
| `table` | logical relation name, frozen at declaration (defaults to the physical source name at declaration time) | the caller, or `encryptor_ecto` from its frozen declared value | required when configured; advisory otherwise |
| `column` | logical field name, frozen at declaration (defaults to the field name at declaration time) | the caller, or `encryptor_ecto` from its frozen declared value | required when configured; advisory otherwise |
| `blob` | logical name for a payload with no table (a file, an export, a queue message) | the caller | advisory |
| `purpose` | coarse classification of what the value is (`"pii"`, `"oauth_token"`) | vault configuration, static | advisory |
| `app` | the host application's own name, for messages that outlive one deployment | vault configuration, static | advisory |
| `encryptor-*` | package-owned pairs (ADR-0003 decision 4) | this package | required, refused from callers |

Rules that go with the table:

- **Host-facing keys are bare `snake_case`; package-owned keys carry the
  `encryptor-` prefix.** The prefix is a namespace marker whose job is to be
  un-typable by accident, and ADR-0003 already spent it; changing its
  punctuation now would churn a decided format for symmetry. The bare keys are
  what a host migrating from `cloak_ecto` and what `encryptor_ecto` both
  already write, and matching them is worth more than internal consistency in
  a string.
- **`aws-crypto-` is refused as a prefix**, not merely as the one key the
  engine checks. `Cmm.Behaviour.validate_encryption_context_for_encrypt/1`
  rejects exactly `"aws-crypto-public-key"`; ADR-0001 decision 4 refuses the
  whole prefix, and this record confirms that tightening. The engine may add
  reserved keys under it in a later version, and a host that has been writing
  one is then unable to encrypt.
- **The vocabulary is open at the edges and closed in the middle.** A host may
  add its own keys freely; it may not redefine one of the seven above, and it
  may not use the reserved prefixes. Adding a key to this table is a
  subsequent ADR, in the same way ADR-0001 decision 10 fixed the extension
  mechanism for the error vocabulary.

**3. A vault has a context profile, and the profile fixes both the required key
set and the selector type.** Configuration gains one key, `:context_profile`,
whose value is `:single` or `:tenant`, and one list, `:required_context`.

| Profile | Selector | Vault-supplied keys | Required set |
|---|---|---|---|
| `:single` | the atom `:default`, and nothing else | none | `:required_context` as configured |
| `:tenant` | a non-empty `String.t()` | `tenant_ref` | `["tenant_ref"]` ++ `:required_context` |

A `:tenant` vault handed `:default` is `{:error, {:invalid_selector, :default}}`.
A `:single` vault handed a string is `{:error, {:invalid_selector, selector}}`.
Both are caller-argument failures, both are checked in the vault before the
provider is consulted, and neither depends on any ciphertext.

This is the answer to ADR-0002 open question 5, and the answer is that the
`:default` selector does not want a distinguished *type* - it wants a
distinguished *vault*. A per-tenant provider handed `:default` by mistake is
the failure that question worried about, and a profile catches it one layer
above the provider, without a wrapper struct that every host implementation
would have to learn. It also tightens ADR-0001's `@type selector :: term()` to
`String.t() | :default` in practice, which is what makes decision 4 possible:
a term that has to be serialized into a context has to be a string.

`:required_context` is where a host names the keys it wants enforced beyond the
profile's own - `["table", "column"]` for a vault behind `encryptor_ecto`,
`["purpose"]` for an application-secrets vault. It is configuration, resolved
at start and frozen with the rest (ADR-0001 decision 5), never per call. A
per-call required set is a caller choosing how strictly to be checked.

**4. `tenant_ref` is supplied by the vault, derived from the `:key` selector,
and a caller that supplies a tenant pair is refused.** On a `:tenant` vault,
every `encrypt/2`, `decrypt/2`, and `rekey/2` gets
`"tenant_ref" => tenant_ref(reference_subkey, selector)` injected, using
ADR-0003 decision 5's keyed derivation. A caller passing `"tenant_ref"` or
`"tenant_id"` in `:encryption_context` gets
`{:error, {:reserved_context_key, key}}`, with generated documentation that
says to pass `key:` instead.

The reason is ADR-0001 decision 4's own goal, taken literally: *`:key` is the
whole of per-tenant routing, and there is no second place to get tenancy
wrong*. If the tenant appears in two arguments, they can disagree, and the
interesting disagreement is silent: encrypting under tenant A's key with
tenant B's context produces a row that decrypts for nobody and looks like
corruption a year later. Deriving the context pair from the routing argument
makes the two incapable of disagreeing. The derived reference preserves that
property - it is a pure function of `:key` - conditional on one new input
being right: the reference subkey.

Two mechanics come with the derivation, and both are part of this decision:

- **The reference subkey is tenant-vault configuration**, resolved at start
  like every other key-material input (through `init/1`, never `use`
  options), frozen into the vault's `Config`. The store-backed provider
  holds the same subkey and computes references from selectors for its row
  lookups, so the wrapped-key store is keyed by reference only and never
  stores a raw tenant identifier. The cost is that a hot-path secret now
  sits in every tenant vault that was previously reachable only from
  provisioning; the derivation itself is one HMAC-SHA256 per call, and no
  per-selector memo of it may be added without honoring ADR-0002
  decision 2's bounded-cache rule.
- **The vault performs a start-time known-answer check on the reference
  subkey.** Configuration carries a pinned check value (the reference
  derived for a fixed probe selector at first provisioning); a vault whose
  subkey does not reproduce it refuses to start with
  `{:error, {:invalid_config, :reference_subkey, :known_answer_mismatch}}`.
  Without the check, a node deployed with a wrong reference subkey writes
  messages no correct reader can open and fails every correct message as
  `:decrypt_failed` - corruption-shaped, fleet-wide, and silent. The
  reference subkey is permanent (ADR-0003 consequence four, as corrected at
  acceptance), so this is the one misconfiguration this design cannot
  afford to discover at decrypt time.

It also removes the pair from the surface a host can forget: a caller writes
`key: tenant.id` and the pair appears anyway. And it keeps the raw tenant
identifier out of the message header entirely, which is what makes ADR-0003
decision 5's keying worth its cost - the EDK key name already carries the
reference, so the context adds a second copy of a published string rather
than publishing its preimage beside it. The examples in this record show the
shape.

**5. Enforcement is `Cmm.RequiredEncryptionContext` wrapping the caching CMM,
and the vault always builds it.** ADR-0001 decision 2 builds the keyring, CMM,
and client per call. This record fixes what that construction is:

```
Cmm.Default.new(keyring)
  |> maybe_wrap_in_caching(config.cache, partition_id)
  |> then(&Cmm.RequiredEncryptionContext.new(required_keys, &1))
```

with `required_keys` from decision 3. When the required set is empty the outer
wrap is skipped, because a required-context CMM over an empty list is an extra
struct and an extra dispatch for nothing.

**The nesting order is a security property, not a style choice.** The engine
permits either arrangement - `Caching.call_underlying_cmm_decrypt/2` dispatches
over `RequiredEncryptionContext` and vice versa - and the wrong one is silently
unsafe. With caching on the outside, a cache hit returns `entry.materials`
directly (`handle_decryption_cache_lookup/2`) and the wrapped CMM is never
called, so the reproduced-context presence check is skipped for exactly the
messages that are read often. Required on the outside runs the check before the
cache is consulted, every time. The vault builds this order and does not make
it configurable.

Cached materials survive the arrangement: `CacheEntry.new/2` stores the whole
materials struct, `required_encryption_context_keys` included, so a hit returns
them intact and `validate_required_keys_in_materials/2` is satisfied.

What "required" buys, precisely, and what it does not:

- **At encrypt**: the operation fails if a required key is missing from the
  composed context. Since decision 4 supplies `tenant_ref` itself, the realistic
  failure is a host that configured `required_context: ["table", "column"]` and
  a call site that forgot one. That is the failure it is for.
- **At decrypt**: the operation fails if the reader omits a required key from
  the reproduced context. This is the hole in the fourth Context finding, and
  closing it is the entire reason the required-context CMM appears in this
  design.
- **It does not compare values.** Agreement is the Default CMM's comparison
  (decision 6).
- **It does not hide values.** In v1.0.0 the header carries the full context
  regardless (sixth Context finding). A host must not read "required" as
  "private".

**6. Value agreement is checked by the vault, above the engine, because the
engine's own check is bypassed by its cache.** `validate_reproduced_context/2`
lives in `Cmm.Default.get_decryption_materials/2`, which sits *below*
`Cmm.Caching`. On a decryption cache hit the Default CMM is not called, so the
value comparison does not happen. The decryption cache id is computed from the
partition, the suite, the EDKs, and the *message's own* stored context - never
from the reproduced context - so a second read of the same ciphertext within
`max_age` hits the entry a legitimate first read populated, and a reader who
supplies a disagreeing value gets a plaintext. Decision 5's ordering does not
save this: it buys presence, and presence is satisfied by a wrong value.

That is not a property this package can ship. So the vault performs the
comparison itself, before it calls `Client.decrypt/3`: it parses the header
(the same pure parse decision 12 exposes), and for every key present in both
the reproduced context and the stored context, requires the values to be equal.
A disagreement is `:decrypt_failed` and the engine is never called.

Three things follow, and the first is the point:

- **Anti-substitution becomes this package's guarantee rather than an engine
  behaviour we happen to inherit.** It holds identically on a cold cache, a
  warm cache, and with caching disabled, which is the only version of the claim
  worth writing in a README.
- The engine's own comparison still runs underneath on a cache miss. Two checks
  of the same predicate is not a cost worth removing; the vault's is the one
  that is always reached.
- The parse is a header deserialization on every decrypt, which the engine
  performs anyway inside `Client.decrypt/3`. It is the one place this package
  reads the message format, and it is the dependency ADR-0002 open question 1
  hesitated to take on for a different reason. Here it is unavoidable, so it
  is taken deliberately and named.

The reach of the comparison, once it is ours:

- It covers only keys present in *both* maps, which is deliberate and matches
  the engine's semantics rather than tightening them silently. A reader may
  supply a key the message does not carry, and it is ignored. Under this design
  that cannot silently pass a tenant check, because `tenant_ref` is in the
  required set on a `:tenant` vault, so a message written without it is
  rejected for missing the key rather than accepted for the wrong reason.
- A reader may omit a key the message does carry, and that is ignored too.
  Required keys close it for the keys that matter; advisory keys stay advisory,
  and the table in decision 2 is where a host sees which is which. Requiring
  the reproduced context to cover the stored one instead would make every
  message unreadable the moment a host adds an advisory key to a vault's static
  configuration, which is a migration hazard bought for very little.

**7. Nothing that varies per row may go in the context.** The seventh Context
finding makes this a correctness-adjacent rule rather than a style
preference: the serialized context is hashed into the materials cache id, so
each distinct context is its own cache entry and its own cold-cache provider
round trip - a store read plus a root-vault decrypt, per ADR-0003.

A primary key, a row id, a timestamp, a request id, or a user id therefore
does not belong in the context, and the generated documentation says so at the
option. `table` and `column` are per-column, which is bounded by the schema. A
host with 200 tenants and 40 encrypted columns holds up to 8,000 cache entries
where ADR-0001 decision 7's reasoning assumed 200, and its recycler empties all
of them at once. The bound is the schema's size, and it is a bound; a row id
is not.

The vault does not and cannot enforce this - it cannot tell a column name from
a row id - so it is a documented rule with a numbered cost, and decision 9's
size cap is the only mechanical backstop.

**8. Mismatch at decrypt maps to exactly two reasons, split on whether the
failure depends on the message.** This is the "what happens on context
mismatch" the bead asks for, and it keeps ADR-0001 decision 10's oracle rule
intact.

| Condition | Engine term | `Encryptor.Error.reason` |
|---|---|---|
| Reader omits a required key | `{:missing_required_encryption_context_keys, keys}` | `{:missing_required_context_keys, keys}` |
| Reader supplies a value that disagrees with the message | `{:encryption_context_mismatch, key}`, from the vault's own check (decision 6) or from the engine on a cache miss | `:decrypt_failed` |
| Message lacks a key the vault requires | `{:required_keys_not_in_decryption_context, keys}` | `:decrypt_failed` |
| Caller supplies a reserved or conflicting key | none (vault-side check) | `{:reserved_context_key, key}` / `{:encryption_context_conflict, key}` |
| Caller supplies a non-string key or value | none (vault-side check) | `{:invalid_context_value, key}` |
| Wrong key material for the message | keyring mismatch | `:decrypt_failed` |

The split is the same one ADR-0002 decision 6 drew for provider failures.
`{:missing_required_context_keys, keys}` depends only on the reproduced context
the caller passed and on the vault's own configuration, both of which the
caller already knows; it discloses nothing about the ciphertext and it is the
one context failure a caller can actually fix. Everything that depends on what
is *in* the message collapses to `:decrypt_failed`, because a caller who can
distinguish "wrong tenant" from "wrong column" from "wrong key" holds an
oracle over the header.

The engine's own term is carried unchanged in the `Encryptor.Error` struct's
`:engine` field, per ADR-0001 decision 10. The one place this record stretches
that field is the context comparison: because decision 6 moves the check above
the engine, the vault puts its own `{:encryption_context_mismatch, key}` there,
shaped exactly as the engine's, so that an operator's log line and
`encryptor_ecto`'s message read the same whether the check fired above the
engine or below it. That is stated here rather than left for someone to
discover that the field is sometimes ours. An operator reading a log line sees
`{:encryption_context_mismatch, "column"}`; a `case` in application code sees
`:decrypt_failed`. This record adds exactly two terms to the vocabulary,
`{:missing_required_context_keys, [String.t()]}` and
`{:invalid_context_value, String.t()}`, plus `{:invalid_selector, term()}` from
decision 3.

**9. The context is bounded, and the bound is checked by the vault.** The
engine serializes the context with a 16-bit pair count
(`Format.EncryptionContext.serialize/1`) and performs no size validation at
all. The context is written into every message, so its serialized size is a
per-row storage cost paid forever, and an unbounded one is a way to double the
size of a table of short encrypted strings.

The vault refuses, before the engine is called:

- more than 32 pairs, `{:invalid_config, :encryption_context, :too_many_pairs}`
  at start for the static part, `{:invalid_context_value, :count}` per call,
- a serialized context over 4 KiB, `{:invalid_context_value, :too_large}`,
- a key or value that is not valid UTF-8, or that is empty.

The numbers are conservative and, like ADR-0001 decision 6's cache bounds,
they are stated rather than measured; open question 6 says so plainly instead
of dressing them up.

**10. `encryptor_ecto` supplies `table` and `column` and enforces nothing.**
The division of labour, stated from this side so both records agree:

- The Ecto layer resolves a tenant and passes it as `key:`. It does **not** put
  a tenant pair in `:encryption_context` - decision 4 refuses that pair - and
  its `MissingTenantError` fires before this package is called at all, which is
  the right place for it.
- The Ecto layer supplies `table` and `column` from its frozen declared
  values - derived once from `Ecto.ParameterizedType.init/1`'s `:schema` and
  `:field` at declaration time, made explicit and overridable there
  (acceptance amendment 2; the mechanics are its ADR-0001's) - and merges
  the host's static `:context` option. Renaming a physical table or column
  while keeping the declared value pinned does not invalidate stored rows;
  changing the declared value is an R3 re-encrypt.
- The host's vault configuration is what makes them required
  (`required_context: ["table", "column"]`), and the generated documentation of
  both packages recommends it. Enforcement lives here because it is a property
  of the vault, not of one type module: two schemas sharing a vault must not be
  able to disagree about how strictly their rows are bound.

**11. `rekey/2` reproduces the context from the message.** ADR-0001 decision 4
requires `rekey/2` to preserve the context byte for byte, and decision 5 of
this record requires every decrypt to reproduce the required keys. A rekey
caller therefore has to supply a context it has no independent copy of - it
holds a ciphertext, not a row.

It does not have to. Because this engine stores the full context in the header
(sixth Context finding), `rekey/2` parses the header, uses the stored context
as the reproduced context for its decrypt, and re-encrypts under exactly that
map. A `:encryption_context` option passed to `rekey/2` is
`{:error, {:reserved_context_key, key}}`, because the only correct value is the
one already in the message and accepting a second copy invites a rotation job
to rewrite a million bindings.

This is the one decision in the family that depends on the engine's deviation
from the specification. Open question 5 records what to do if that deviation is
corrected.

**12. `describe/1` is the read-only context surface, and it authenticates
nothing.** `Encryptor.Vault.describe(ciphertext)` parses the message header -
`Format.Header.deserialize/1` is pure parsing, needs no key material, and
touches no provider - and returns the stored encryption context, the algorithm
suite id, whether the suite commits, and the `{provider_id, key_name}` pair of
each EDK.

Three properties make this safe to offer:

- **It discloses nothing that the ciphertext did not already disclose.**
  Everything it returns is in the clear in the header to anyone holding the
  bytes. It is therefore not a decryption oracle, and it is exempt from
  ADR-0001 decision 10's collapse rule for that reason and no other.
- **Its return is unauthenticated.** The header auth tag is not checked,
  because checking it requires the data key. A caller must not make an
  authorization or routing decision on `describe/1`'s output; it is for support
  tooling, for a migration that needs to know which key version wrote a row,
  and for an operator holding a row they cannot explain. The generated
  documentation says this in the first line of the docstring, and the return is
  a struct named `Encryptor.Message.Info` rather than a bare map so that it
  reads as a claim rather than as a fact.
- **It is not `decrypt/2` widened.** `decrypt/2` returns plaintext only, as
  ADR-0001 decision 4 fixed.

This answers ADR-0001 open question 1, and the answer is the separate
read-only function rather than a wider `decrypt/2`. The deciding argument is
that the two have different trust levels: `decrypt/2`'s output is
authenticated and `describe/1`'s is not, and a single return value carrying
both would be a value half of which a caller may trust. The name is
`describe/1` and not `inspect/1` because a generated vault module defining
`inspect/1` shadows `Kernel.inspect/1` inside its own body, which is a papercut
this package should not hand to every host.

## Consequences

**The convention is only as good as the required set, and the required set is
the host's.** A host that configures no `:required_context` on a `:single`
vault gets a context that is advisory end to end: written into every message,
compared when reproduced, ignored when not. That is a legitimate configuration
- an application-secrets vault with one key and one reader has little to bind
against - and it is also the configuration a host ends up in by not thinking
about it. The profile mechanism gives `:tenant` vaults a non-empty required set
by construction, which is the case where the omission is dangerous, and the
documentation leads with `required_context: ["table", "column"]` for anything
storing columns.

**Per-column context multiplies cache entries and cold-cache provider load.**
Decision 7 states the rule; the cost lands on ADR-0001 decision 6's recycler
and ADR-0003's thundering-herd consequence, and it multiplies both by the
number of encrypted columns rather than leaving them per tenant. A host with a
wide encrypted schema and a short `recycle_after` should expect the recycle to
be followed by a burst proportional to tenants times columns. ADR-0001 open
question 2's unmeasured cache bounds are now unmeasured against a larger
number, and open question 6 carries that forward rather than quietly
re-defaulting them here.

**The tenant attribution of a message is a permanent pseudonym, not an
identity - and not an erasure.** As amended at acceptance, decision 4 puts
the derived `tenant_ref` in the header rather than the raw selector, so a
stolen ciphertext discloses that two messages belong to the same tenant
without disclosing which tenant that is - the same property ADR-0003
decision 5 bought for the key names, now holding for the context too, which
is what makes the keying investment coherent. Two honest limits remain. The
reference is permanent: it cannot be rotated (ADR-0003 consequence four),
so the pseudonym in every header and every backup is forever, and the
holder of the reference subkey can re-identify it by guess-and-confirm at
any time, including after a crypto-shred. And the anti-disagreement
property of decision 4 is now conditional on the reference subkey being
correct on every node, which is why the start-time known-answer check is
part of the decision rather than an implementation nicety.

**This package now reads the message header on every decrypt, and owns a
security check the engine appeared to provide.** Decision 6 is the largest
structural consequence of this record. It adds a header parse to the decrypt
path, it puts this package in a dependency on the engine's message format that
ADR-0002 open question 1 was reluctant to take, and it means the sentence "the
engine validates the reproduced context" is false for this stack in the warm-
cache case that dominates real traffic. The alternative - documenting that
anti-substitution holds only on a cold cache - is not a thing to ship, and
turning the decryption cache off costs the entire per-tenant resolution story
ADR-0003 is built on. Filing the defect upstream (open question 7) does not
remove the check, since this package has to work against v1.0.0 either way.

**Two more error terms, and one more configuration key, for a mechanism most
hosts will configure once.** `:context_profile` and `:required_context` are
start-time configuration in a package that has been careful to keep options
few. The justification is decision 5's asymmetry: without the required set,
the whole convention is advice to writers, and the readers are where the
substitution attack lands.

**A host can still write a context nobody can reproduce.** Decision 7's rule is
documentation. A host that puts a row id in the context gets rows that decrypt
only when the reader knows the row id, which they usually do, plus a cache
entry per row, which nobody notices until the provider load does. The vault's
size cap catches the pathological version and nothing catches the merely
wasteful one.

**`rekey/2` now depends on an engine deviation from the specification.**
Decision 11 is correct against v1.0.0 and would break against a
specification-conformant engine that strips required keys from the header. The
dependency is recorded, is narrow, and has an obvious remedy (rekey takes the
context as an argument, supplied by the caller that owns the row), so it is a
watch item rather than a design risk.

**`describe/1` is a new surface with a new way to be misused.** It returns
unauthenticated data by design, and the mitigation is a name, a struct, and a
docstring. A host that routes on it - "this row's context says tenant A, so
show it to tenant A" - has built an authorization check out of an attacker-
editable claim. There is no way to offer header inspection without offering
that mistake; the alternative is to not offer it, and ADR-0001 open question 1
exists because tooling genuinely needs it.

## The contract as typespecs

```elixir
defmodule Encryptor.Vault do
  @type selector :: String.t() | :default
  @type context :: %{optional(String.t()) => String.t()}
  @type context_profile :: :single | :tenant

  @callback describe(ciphertext()) ::
              {:ok, Encryptor.Message.Info.t()} | {:error, Encryptor.Error.t()}
end
```

```elixir
defmodule Encryptor.Message.Info do
  @moduledoc """
  What a message says about itself.

  Every field is read from the message header without verifying the header
  authentication tag, because verification needs the data key. Treat this as
  an unverified claim. It is for support tooling and migrations; it is never
  an authorization input.
  """

  @type edk :: %{provider_id: String.t(), key_name: String.t()}

  @type t :: %__MODULE__{
          encryption_context: Encryptor.Vault.context(),
          algorithm_suite_id: non_neg_integer(),
          committed?: boolean(),
          encrypted_data_keys: [edk()]
        }

  @enforce_keys [:encryption_context, :algorithm_suite_id, :committed?, :encrypted_data_keys]
  defstruct @enforce_keys
end
```

Additions to `Encryptor.Vault.Config` from ADR-0001 decision 5:

```elixir
  @type t :: %__MODULE__{
          # ... every field from ADR-0001 ...
          context_profile: Encryptor.Vault.context_profile(),
          required_context: [String.t()]
        }
```

Additions to `Encryptor.Error.reason/0` from ADR-0001 decision 10, as extended
by ADR-0002 decision 6:

```elixir
  @type reason ::
          # ... every term from ADR-0001 and ADR-0002 ...
          | {:missing_required_context_keys, [String.t()]}
          | {:invalid_context_value, String.t() | :count | :too_large}
          | {:invalid_selector, term()}
```

The canonical key names as a module attribute, so that the vocabulary is one
place in the code and not a string repeated across three packages:

```elixir
defmodule Encryptor.Context do
  @tenant_ref "tenant_ref"
  @table "table"
  @column "column"
  @blob "blob"
  @purpose "purpose"
  @app "app"

  @spec canonical_keys() :: [String.t()]
  @spec reserved_prefixes() :: [String.t()]   # ["aws-crypto-", "encryptor-"]
end
```

## Worked example: a cross-tenant substitution failing

The bead's acceptance criterion. A multi-tenant host app, two tenants, one
encrypted column, and an attacker - or a bad migration - that copies one
tenant's stored bytes into another tenant's row.

```elixir
config :my_app, MyApp.TenantVault,
  algorithm_suite_id: 0x0478,
  context_profile: :tenant,
  required_context: ["table", "column"],
  static_encryption_context: %{"app" => "my_app"},
  max_encrypted_data_keys: 2,
  cache: [max_age: 300]
```

Tenant A writes a row. Note what the call site does *not* say:

```elixir
{:ok, ct} =
  MyApp.TenantVault.encrypt(customer.tax_id,
    key: "acct_A",
    encryption_context: %{"table" => "customers", "column" => "tax_id"}
  )
```

The message that lands in the column carries this context, all of it in the
clear, all of it authenticated by the header tag:

```elixir
%{
  "tenant_ref" => "6Qk2_1xZ...",  # vault-derived from :key, decision 4
  "table"      => "customers",
  "column"     => "tax_id",
  "app"        => "my_app"        # static, from configuration
}
```

Now the four ways to be wrong, and what each one returns.

```elixir
# 1. The bytes are moved into tenant B's row and read in tenant B's scope.
#    The EDK names tenant A's key, so tenant B's keyring cannot even unwrap it.
MyApp.TenantVault.decrypt(ct,
  key: "acct_B",
  encryption_context: %{"table" => "customers", "column" => "tax_id"})
#=> {:error, %Encryptor.Error{reason: :decrypt_failed, operation: :decrypt}}
#   engine: {:key_name_mismatch, _}

# 2. The attacker also has tenant A's key - a compromised tenant - and reads
#    the row while claiming to be tenant B. The context comparison catches it
#    before the keyring is consulted.
MyApp.TenantVault.decrypt(ct,
  key: "acct_A",
  encryption_context: %{"tenant_ref" => "...", ...})
#=> {:error, %Encryptor.Error{reason: {:reserved_context_key, "tenant_ref"}}}
#   There is no way to claim a tenant other than through :key, which is
#   decision 4's whole point.

# 3. The bytes are moved between columns inside one tenant - tax_id into
#    notes - where the key is identical and only the context differs.
MyApp.TenantVault.decrypt(ct,
  key: "acct_A",
  encryption_context: %{"table" => "customers", "column" => "notes"})
#=> {:error, %Encryptor.Error{reason: :decrypt_failed, operation: :decrypt}}
#   engine: {:encryption_context_mismatch, "column"}
#
#   This is the case decision 6 exists for. The engine's own comparison is
#   below the materials cache, so on a second read of this row within
#   max_age it would not run at all and the swap would succeed. The vault
#   compares above the cache, so this fails on the first read and the
#   thousandth alike.

# 4. A reader that supplies no context at all. Without decision 5 this
#    succeeds - the engine requires nothing of a reader (fourth Context
#    finding). With the required-context CMM it is a loud, fixable error.
MyApp.TenantVault.decrypt(ct, key: "acct_A")
#=> {:error, %Encryptor.Error{
#     reason: {:missing_required_context_keys, ["table", "column"]},
#     operation: :decrypt}}
```

And the operator's view of the same row, with no key material anywhere:

```elixir
{:ok, info} = MyApp.TenantVault.describe(ct)

info.encryption_context
#=> %{"tenant_ref" => "6Qk2_1xZ...", "table" => "customers",
#     "column" => "tax_id", "app" => "my_app"}

info.encrypted_data_keys
#=> [%{provider_id: "acme-tenant", key_name: "t/6Qk2_1xZ.../v3"}]

info.committed?
#=> true
```

What this example is chosen to demonstrate:

- **Case 4 is the one that matters, and it is the one the engine does not
  give you.** Cases 1 and 3 are properties of the message. Case 4 is a
  property of the vault's configuration, and it is why decision 5 exists.
- **Case 2 has no failure mode to demonstrate**, which is the strongest form
  of the argument for decision 4: the wrong-tenant claim is unrepresentable,
  so there is no code path in which it is checked.
- **Case 1 and case 3 return the same reason and different `:engine` terms.**
  A caller cannot tell them apart; an operator reading a log can. That is
  ADR-0001 decision 10 applied to context, exactly.
- **`describe/1` needs no key**, which is why it is safe to expose and why its
  output is not to be trusted.

## Worked example: the same vault behind `encryptor_ecto`

Nothing in the type declaration changes from that package's own record. What
changes is that the tenant is routing, not context:

```elixir
defmodule MyApp.Encrypted.Binary do
  use Encryptor.Ecto.Binary, vault: MyApp.TenantVault
end

defmodule MyApp.Accounts.Customer do
  use Ecto.Schema

  schema "customers" do
    field :tax_id, MyApp.Encrypted.Binary
  end
end
```

On `dump/3`, that layer resolves the tenant from its process scope and calls:

```elixir
MyApp.TenantVault.encrypt(value,
  key: tenant_id,
  encryption_context: %{"table" => "customers", "column" => "tax_id"})
```

Three things follow that are worth naming because they are the seam between
the two records:

- **`Encryptor.Ecto.MissingTenantError` still fires first**, in the Ecto layer,
  before this package sees the call. A context-less encrypt is never performed,
  as that record's decision 4 requires, and the `{:invalid_selector, _}` of
  decision 3 is the backstop for a resolver that returns something that is not
  a string.
- **`tenant: :none` fields need a different vault.** A field declared global
  has no tenant to route with, and a `:tenant` profile refuses `:default`. The
  host declares those fields against a `:single` vault - which is the shape
  ADR-0001 decision 3 already expects a host to run - rather than against a
  tenant vault with the tenant pair omitted. This is a real change to that
  record's decision 5e and it is listed in the assumption review below.
- **The AAD-mismatch message that record wants to print** is available from the
  `Encryptor.Error` struct's `:engine` field, not from `:reason`. See A5.

## Review of `encryptor_ecto` ADR-0001's upstream assumptions

That record lists seven assumptions about this package and asks for each to be
a review item at acceptance. Taken in order, against the decisions above.

| # | Assumed | Verdict |
|---|---|---|
| A1 | Vault exports `encrypt(plaintext, context)` / `decrypt(message, context)` returning `{:ok, binary}` / `{:error, reason}` | **Confirmed, with the second argument named** |
| A2 | `context` is a flat map of string keys to string values | **Confirmed** |
| A3 | Canonical keys include `tenant_id`, `table`, `column` | **Confirmed in shape; the tenant pair is `tenant_ref` and vault-supplied** |
| A4 | Required-vs-advisory enforcement lives upstream, so the Ecto layer supplies and never enforces | **Confirmed** |
| A5 | Decrypt reports AAD mismatch as a distinguishable error reason | **Denied in `:reason`; available in `:engine`** |
| A6 | The message is self-describing, so the column needs no framing | **Confirmed** |
| A7 | Tenant key material is addressed by an opaque tenant identifier the host already has as a string | **Confirmed, and now required to be a string** |

**A1 - confirmed, with a naming correction.** ADR-0001 decision 4 fixes
`encrypt(plaintext, opts)` and `decrypt(ciphertext, opts)` where `opts` is a
keyword list carrying `:key` and `:encryption_context`, not a bare context map
as a positional second argument. The returns are exactly as assumed:
`{:ok, binary()}` or `{:error, %Encryptor.Error{}}`. That record's decision 6
table maps vault errors onto its own exceptions and is unaffected; the call
sites in its worked example need the keyword form.

**A2 - confirmed.** Decision 1. Flat, `String.t()` to `String.t()`, and
anything else is refused before the engine is called.

**A3 - confirmed in shape, corrected in two particulars.** `table` and
`column` are canonical and spelled as assumed. The tenant pair is
vault-supplied from the `:key` selector and *refused* from a caller
(decision 4), so the Ecto layer passes the tenant as `key:` rather than as a
context pair - and as amended at acceptance, the pair written is
`"tenant_ref"` (the keyed derivation), never the raw identifier, which
changes nothing further on the Ecto side since it never supplied the pair
anyway. This is a small mechanical change to that record's decision 5
and 5f - the `TenantContext` behaviour, the process scope, `wrap/2`, the
`MissingTenantError`, and the option table are all unaffected; only the shape
of the call in `dump/3` and `load/3` changes. Its decision 5e (`tenant: :none`)
is the one substantive consequence: a global field cannot be a tenant vault
with the pair omitted, because a `:tenant` profile has `tenant_ref` in its
required set. Such fields declare a `:single` vault. That is a change to that
record, not a change here, and it is flagged for its author rather than made
by this record.

**A4 - confirmed, and made concrete.** Enforcement is decision 3's
`:required_context` on the vault plus decision 5's CMM, both upstream of the
Ecto layer, which supplies `table` and `column` and enforces nothing. Decision
10 states the division from this side. The recommended host configuration is
`required_context: ["table", "column"]` and both packages' documentation should
say so.

**A5 - denied as stated; the affordance exists in a different field.** ADR-0001
decision 10 collapses every message-dependent decrypt failure to
`:decrypt_failed` precisely so that a caller cannot distinguish an AAD mismatch
from a wrong key, and decision 8 above keeps that. So
`Encryptor.Ecto.DecryptError` cannot branch on `:reason` to know it was a
context mismatch. What it can do is carry `error.engine` -
`{:encryption_context_mismatch, "column"}` - into its message for an operator,
which is what that record's worked example actually prints. Two constraints
come with it: the `:engine` term is not part of this package's versioned
contract and must not be matched on for control flow, and its own decision 6
prohibition on plaintext in exception messages applies to it. The one context
failure that *is* distinguishable in `:reason` is
`{:missing_required_context_keys, keys}`, which is a host misconfiguration
rather than an integrity event, and is worth its own exception on that side.

**A6 - confirmed.** ADR-0001 decision 4 returns the complete self-describing
engine message and nothing else; decision 12 above adds `describe/1` for
reading what the message says about itself without a key, which is the tool
that record's decision 11 gestures at when it notes "a host cannot tell from
the column alone which key version wrote a row". It can, with `describe/1`, and
it should be told in the same breath that the answer is unauthenticated.

**A7 - confirmed and tightened.** ADR-0001 typed the selector `term()`;
decision 3 above narrows it to `String.t()` on a `:tenant` vault, which is what
that record already assumed. It also means an integer tenant id must be
stringified by the host at the boundary, once, rather than being coerced
silently by this package, since a silent `to_string/1` is a second way for two
tenants to collide.

## Open questions

Recorded rather than guessed. Each names who should settle it. The first three
are inherited; the rest are opened by this record.

1. **Should the application-data context carry a derived `tenant_ref` instead
   of the raw `tenant_id`?** *(Inherited: ADR-0003 open question 2, ADR-0002
   open question 5's other half. This record answers the question as asked and
   opens this narrower successor.)*

   The answer to ADR-0003 open question 2 is **yes, keep the derivation keyed**.
   Decision 5 of that record stands. Keying costs the reference subkey's
   effective unrotatability, which ADR-0003 decision 6 already isolated onto
   the cheap half of the root; unkeying it is not reversible once names are in
   headers, and an unkeyed hash of a short tenant slug is confirmable by anyone
   who can guess the slug. The support-tooling argument for an unkeyed
   reference is answered by `describe/1` plus the store, not by weakening the
   derivation. Tenant identity itself is the **host's** - the package never
   mints, validates, or interprets a tenant identifier; it requires only that
   it be a non-empty string (decision 3) and treats it as opaque thereafter.

   What is *not* settled is the consequence that decision 4 publishes the raw
   identifier in every application message's header anyway, which makes the
   keying protect the key store and the key names but not the tenant
   attribution of application rows. Putting `tenant_ref` in the context instead
   would restore the property, and it requires the tenant vault to be able to
   compute the reference, which today it cannot: the derivation lives in
   `Encryptor.Envelope` and needs the reference subkey, while the tenant vault
   holds only a store-backed provider. ADR-0003's own
   `tenant_ref(root_vault, selector)` typespec has the same gap, since the root
   vault holds the `root-wrap` subkey rather than the root key material. The
   fix is plumbing, not cryptography, and it is a change to ADR-0003's surface.
   The operator should settle it at acceptance of these two records together;
   this record chose the ergonomic contract the sibling packages are already
   built against, and stated the leak rather than hiding it.

   *Resolved at acceptance (2026-08-27): settled in favour of `tenant_ref`,
   after an adversarial review found the proposed shape published the
   (identifier, reference) mapping in every header - the EDK key name
   carries the reference, so the raw id beside it was the preimage of a
   keyed derivation the family pays real cost for. Decision 4 above is
   amended, with the reference subkey as tenant-vault configuration, the
   store keyed by reference only, and a start-time known-answer check. See
   the acceptance amendments section at the top of this record.*

2. **Answered: `decrypt/2` does not return the context; `describe/1` does.**
   *(Inherited: ADR-0001 open question 1.)* Decision 12. Recorded here so the
   question is visibly closed rather than dropped. The residual is a naming
   question - whether `describe/1` should also exist as a `Encryptor.Message`
   function that takes no vault, since it needs no vault state - which is an
   API-shape call and not worth an ADR.

3. **Answered: the `:default` selector gets a distinguished vault, not a
   distinguished type.** *(Inherited: ADR-0002 open question 5.)* Decision 3.
   The residual is whether `:single` should also refuse a `:key` option
   entirely rather than requiring it to be `:default`, which would make
   ADR-0001's "`:key` is absent" ergonomics the only spelling. That is a small
   compatibility call for the implementation bead.

4. **The 32-pair and 4 KiB context bounds are stated, not measured.**
   Decision 9. They are chosen to be obviously above a canonical context and
   obviously below a per-row storage problem. They belong with ADR-0001 open
   question 2's cache bounds and ADR-0003 open question 7's key size in a
   single measurement pass against a real workload.

5. **Decision 11 depends on the engine storing required-context keys in the
   header, which the specification says it should not.** If the engine is
   corrected to strip them, `rekey/2` can no longer reproduce a required
   context from the message and would need the context as an argument, supplied
   by whatever owns the row. The correction would also change what "required"
   means for privacy, since values would stop being published. This is an
   engine-side record like ADR-0001 open question 4, and this package should
   file it upstream and watch it.

6. **Per-column context multiplies materials-cache entries, and nobody has
   measured the result.** The seventh Context finding is new information that
   ADR-0001 decision 6's bounds and ADR-0003's herd analysis did not have.
   Whether `max_messages: 100` and `recycle_after: 20 * max_age` are still
   sensible when the entry count is tenants times columns is a question for the
   same measurement pass as open question 4. This record deliberately does not
   re-default them, since re-guessing a sibling record's numbers from a new
   qualitative argument would be worse than saying they need measuring.

7. **The caching CMM bypasses reproduced-context validation, and that should be
   filed upstream.** `Cmm.Caching.handle_decryption_cache_lookup/2` returns
   cached materials without calling the underlying CMM, and the Default CMM is
   where `validate_reproduced_context/2` lives, so a warm decryption cache
   skips the check entirely. The decryption cache id is derived from the
   message's own context and its EDKs, never from the reproduced context, so
   the bypass is reachable by re-reading any recently-read ciphertext with a
   false claim about it. Decision 6 works around it locally. The durable fix is
   the engine's - either validate the reproduced context in `Caching` before
   serving an entry, or include it in the cache id - and this package should
   report it with the reproduction above. Like ADR-0001 open questions 3 and 4,
   it is an engine-side record, not this one; unlike them, it is a security
   defect rather than an ergonomic gap, and it should be filed first.

8. **Whether an advisory key is worth having at all.** Decision 2 marks
   `blob`, `purpose`, and `app` advisory, meaning they are written, ignored
   when a reader omits them, and compared when a reader supplies them. A key
   that is sometimes checked is a key whose guarantee nobody can state in one
   sentence. The alternative is that every canonical key is required and the
   host's `:required_context` is the only knob, which is simpler to explain and
   harder to adopt incrementally. Worth revisiting after the first host
   configures one.

## Amendment A (2026-09-13; accepted 2026-09-13): the composed context on a KMS-backed vault

Status: **accepted (2026-09-13)**, by the operator's reading. This amendment
only adds. Decisions 1 to 12 and the two acceptance amendments at the top of
this record are unchanged, and nothing below reverses, narrows, or re-words
any of them.

A note on labels, because this record already uses the letter. The assumption
review of `encryptor_ecto` ADR-0001 above numbers its rows A1 to A7 (the table
at `:831-837` and the prose that follows), and a bare "A5" elsewhere in this
record - the cross-reference at `:822`, for one - means that table's row.
**This amendment's decisions are written `A1` to `A5` under the house
convention ADR-0003 and ADR-0005 use for lettered amendments, and a reference
to one from outside this section should be spelled "Amendment A's A5".** The
older table is not renumbered; renaming a set that other records cite would be
a worse cure than a sentence.

### Why now

ADR-0008 open question 5 asks whether a KMS-backed vault should run a narrower
encryption-context profile, and hands the question here rather than deciding
it:

> **Should a KMS-backed vault run a narrower encryption-context profile?**
> Decision 7 records that ADR-0004's composed context reaches CloudTrail
> unencrypted on this path. ADR-0004 fixed the profile against a threat model
> in which the context travels in the message header only, and this record does
> not reopen it, because narrowing the context would change what a message
> binds - an ADR-0004 decision, taken in an ADR-0004 amendment [...]
> (`docs/adr/0008-aws-kms-keyring-backed.md:931-939`, read at `2a84a04`)

The premise is correct and it is this record's to answer. The question is
answered **no**: there is no KMS-specific profile, and the composed context on
a KMS-backed vault is byte-for-byte the context decision 1 composes on every
other path. The rest of this amendment is why, what a host is owed instead,
and the one thing that changes in `lib/`.

### What is true today, per path

The disclosure surface is not uniform across the three provider shapes this
package ships, and the difference is mechanical rather than a matter of
policy. Read at `2a84a04` (this package) and `aws_encryption_sdk` v1.0.0.

| Path | What composes the context | Where the composed context goes | Reaches a third-party log? |
|---|---|---|---|
| Material source (`Encryptor.Provider.Static`, store-backed) | `Resolve.context/5` (`lib/encryptor/vault/resolve.ex:198`), `tenant_ref` from `Resolve.vault_supplied/2` (`:214`) | the message header, and the local `RawAes` keyring's AAD | no - it never leaves the host process |
| GCP wrap (`Encryptor.Provider.GcpKms`, ADR-0007) | the same `Resolve.context/5` for the message; the provider composes its **own** wrap AAD from `tenant_ref`, version and namespace (`lib/encryptor/provider/gcp_kms.ex:396-401`, sent at `:344-346` and `:472-474`) | the message header; the wrap AAD, separately, to the Cloud KMS API | the wrap AAD does, and it is three fields this package chose - **not** ADR-0004's context |
| AWS KMS keyring (`Encryptor.Provider.Kms`, ADR-0008) | the same `Resolve.context/5` | the message header **and**, wholesale, the KMS API: `materials.encryption_context` is passed to `GenerateDataKey`, `Encrypt` and `Decrypt` (`aws_encryption_sdk` v1.0.0, `lib/aws_encryption_sdk/keyring/aws_kms.ex:266`, `:291`, `:400`) | yes - a KMS encryption context is recorded unencrypted in CloudTrail |

Two facts in that table decide the rest. The GCP path shows that a provider
*can* carry a binding of its own choosing to a third-party API without
touching ADR-0004's context, because it composes its own. The KMS path shows
that `Encryptor.Provider.Kms` has no such seam: it and `Encryptor.Key.Kms`
carry no context argument at all (`lib/encryptor/provider/kms.ex`,
`lib/encryptor/key/kms.ex`, read at `2a84a04`), because the engine's keyring
reads `materials.encryption_context` directly. On this path there is exactly
one context object, and it serves the message and the API call both.

### Decisions

**A1. The context profile is unchanged on a KMS-backed vault, and this package
ships no per-provider context narrowing.** `:context_profile` keeps the two
values decision 3 gave it, the canonical vocabulary is decision 2's table
unaltered, and `Resolve.context/5` composes the same map whatever the
provider answers. A KMS-backed message binds exactly what every other message
binds.

**A2. The deciding reason is that a narrowed KMS context is a narrowed
message, not a quieter log.** Because there is one context object on this path
(the table above), "send KMS less" and "bind the message to less" are the same
edit. The property that would be spent is the one decision 6 calls this
package's own guarantee: the anti-substitution comparison covers the keys
present in both the reproduced and the stored context, so dropping `table` and
`column` from a KMS-backed vault's context re-opens the cross-column swap this
record's third worked example exists to fail (`:727-739`), and dropping
`tenant_ref` re-opens the second (`:717-724`). Trading a decided integrity
property for the quietness of an audit log the host owns is the wrong
direction, and it is a trade a host could not undo later without re-encrypting
every row.

The alternative shape - compose two contexts, a full one for the header and a
narrow one for the KMS calls - is not available, and the reason is the
engine's **closed dispatch**, not the byte-for-byte rule. KMS requires the
context on `Decrypt` to equal the context on `GenerateDataKey`, not to equal
the header's, so a narrowing applied deterministically on both calls would
satisfy `aws_kms.ex:400` perfectly well. What forbids it is that there is
nowhere to apply it: the engine dispatches on its own structs and rejects
everything else - `Cmm.Default.call_wrap_key/2` and `call_unwrap_key/3` fall
through to `{:error, {:unsupported_keyring_type, _}}` (`aws_encryption_sdk`
v1.0.0, `lib/aws_encryption_sdk/cmm/default.ex:119-121` and `:154-156`), and
`Client`'s CMM dispatch does the same with `{:error, {:unsupported_cmm_type,
_}}` (`lib/aws_encryption_sdk/client.ex:368-370` and `:431-433`). No decorator
keyring and no decorator CMM can sit between this package's vault and `AwsKms`
to rewrite `materials.encryption_context` on the way out. The only remaining
place to narrow is `Resolve.context/5` itself, and that composes the one map
the header gets.

The shape that *would* be reachable - a context argument on the provider
behaviour, so `Encryptor.Provider.Kms` could hand the engine something narrower
than the vault composed - is new public surface bought to make a guarantee
weaker, which is the wrong trade in both directions at once.

**A3. The profile is publishable because its vocabulary is already published
and already pseudonymous.** This is the half of the threat model ADR-0008
correctly declined to assume. Decision 12 states the message property
directly - `describe/1` "discloses nothing that the ciphertext did not already
disclose", because the whole context is in the clear in the header to anyone
holding the bytes. The canonical vocabulary is therefore designed as non-secret
material end to end:

- `tenant_ref` is the **keyed** derivation of ADR-0003 decision 5, and the
  first acceptance amendment at the top of this record exists precisely to
  keep the raw tenant identifier out of the published pair. What CloudTrail
  records is the same pseudonymous reference the EDK key name
  `"t/<tenant_ref>/v<n>"` already carries - and on this path the EDK's key
  name is the KMS key ARN, which CloudTrail records regardless.
- `table` and `column` are logical names frozen at declaration (decisions 2
  and 10), so they name a schema, not a row.
- `blob`, `purpose` and `app` are static vault configuration (decision 2),
  written by the host about itself.
- Decision 7 already forbids anything that varies per row - no primary key, row
  id, timestamp, request id or user id - which is what would make a
  per-operation log a per-subject log. That rule was taken for a cache-cost
  reason; it is load-bearing for disclosure too, and this amendment says so.

What genuinely widens is the **audience**, as ADR-0008 decision 7's bullet
says in as many words (`docs/adr/0008-aws-kms-keyring-backed.md:610-614`):
from whoever holds the ciphertext bytes to whoever holds CloudTrail read in
the host's AWS account. Both populations
are inside the host's own trust boundary, and a host that has granted
`kms:Decrypt` to a principal has already granted it more than the context.

**A4. A host that judges its own context inappropriate for CloudTrail already
has the knob, and it is configuration, not a profile.** The keys beyond the
required set are the host's: `:static_encryption_context` and the per-call
`:encryption_context` are what a host puts in, `:required_context` is what it
makes binding (decisions 1, 3 and 10). A host running a KMS-backed vault that
does not want `purpose: "oauth_token"` in its audit log configures it away,
once, at the vault. This package adds no second mechanism for the same
sentence.

**A5. What this package owes instead is disclosure at the point of
configuration.** The hazard is not that the context is published; it is that a
host reads ADR-0004, reads "message header", configures a static context
accordingly, and discovers the CloudTrail copy from its own audit log. So:
`Encryptor.Provider.Kms`'s generated documentation **must** state that the
vault's composed encryption context - every key decision 2's table names,
`tenant_ref` included - is sent to the AWS KMS API on `GenerateDataKey`,
`Encrypt` and `Decrypt` and is recorded unencrypted in CloudTrail, and must
point at decision 2 for the list and decision 7 for the rule that keeps per-row
values out of it.

This is an obligation, not a description: the module carries no such sentence
today (`lib/encryptor/provider/kms.ex`, read at `2a84a04`; `CloudTrail` appears
nowhere in `lib/`), and writing it is the whole of this amendment's code half,
`enc-8nr`. It is a moduledoc sentence in the one module a host is reading when
it makes the choice. It adds no option, no function, and no configuration key,
and there is no per-provider context seam for that bead to build.

### Consequences

- ADR-0008 open question 5 is closed by A1: the profile stands as fixed, and
  the threat model is widened in this record rather than in that one.
- A KMS-backed vault and a material-source vault under the same host write
  interchangeable contexts, so a host that migrates a tenant between provider
  shapes (ADR-0002 decision 5's two rows) does not have to re-encrypt for a
  context reason.
- The disclosure is now a documented property rather than an inference, which
  means a host can be told in review that granting CloudTrail read is granting
  the context, and can price that once.
- Nothing here applies to the GCP wrap path: its third-party AAD is the
  provider's own three fields (`gcp_kms.ex:396-401`), and ADR-0004's context
  never reaches Cloud KMS.

### Open question this amendment adds

**A-1. Whether the reserved `encryptor-*` pairs deserve their own sentence in
the disclosure.** ADR-0003 decision 4's package-owned pairs are composed as the
`reserved` layer of `Resolve.context/5` (`resolve.ex:198`) and travel with
everything else, so they reach CloudTrail too. They are package-chosen binding
material rather than host-chosen description, and A5's sentence names decision
2's table, which is the host-facing half. Whether a host needs to be told
separately about the pairs it did not write is a documentation call for
whoever writes the security section, with ADR-0005 open question 7, which
names the same unwritten section
(`docs/adr/0005-rotation-and-crypto-shred.md:894-901`).

*Answered (2026-09-13): yes. The section is written, as a foot Note on
ADR-0005 - "the security section, and the reserved `encryptor-*` pairs in the
KMS disclosure" - which names the four pairs, the `reserved` layer they
compose into, what a CloudTrail reader sees of them and what it does not.*

## Note (2026-09-13): case 1 of the worked example names the wrong refusal term

The worked example "a cross-tenant substitution failing" shows four ways to be
wrong. Case 1 - tenant A's bytes moved into tenant B's row and read in tenant
B's scope - is annotated `engine: {:key_name_mismatch, _}`, on the reasoning
that "the EDK names tenant A's key, so tenant B's keyring cannot even unwrap
it". That reasoning is sound about the keyring and wrong about which guard
fires. **On a `:tenant` vault the read is refused as
`{:encryption_context_mismatch, "tenant_ref"}`, and the engine is never
called.** Two guards apply to case 1; this Note records which one fires first
and why. The `reason` in the example's `%Encryptor.Error{}` - `:decrypt_failed`
- is right either way, and no decision changes: decision 6's comparison and the
key-name check are both real, and decision 8's oracle collapse gives them the
same caller-visible term.

The order is fixed by `Encryptor.Vault.Decrypt.decrypt/7`
(`lib/encryptor/vault/decrypt.ex:148-160`, read at enc `ec6a84d`). Its `with`
chain resolves candidates, builds the keyring, composes the reproduced context
through `Resolve.context/5`, and then calls `agree/4` - all before
`engine_decrypt/5` is reached. So the keyring for tenant B is *built*, but the
engine that would have found the key-name mismatch is never handed it.

What `agree/4` finds is decision 4's own doing. On a `:tenant` vault
`Resolve.reference/2` derives `tenant_ref` from the `:key` selector rather than
accepting it from the caller (`lib/encryptor/vault/resolve.ex:206-209`, same
SHA), and `Resolve.context/5` injects that derived value as the vault-supplied
layer (`resolve.ex:248-267`). A reader passing `key: "acct_B"` therefore
reproduces tenant B's `tenant_ref` against a message carrying tenant A's, and
`compare/4` (`decrypt.ex:192-206`) returns
`Error.decrypt_failed(vault, :decrypt, {:encryption_context_mismatch,
"tenant_ref"})`. Case 2's annotation already says the context comparison
catches a cross-tenant claim "before the keyring is consulted"; case 1 is the
same mechanism, reached by a different route.

**Worth recording for the security section this record keeps deferring.**
Because the context guard alone refuses the read, case 1 is not on its own
evidence of key separation. It would refuse identically against a key store
that handed every tenant one shared key. The key-name mismatch the example
describes is a second, independent line of defence - it is simply not the one
the caller observes, and a reader who took case 1 as a demonstration that the
keyring is doing the work would be taking the wrong lesson from it.

Nothing above changes. No decision is amended, no error vocabulary is added or
removed, and this Note carries the record's status rather than one of its own.

## Note (2026-09-13): Amendment A accepted; A5 discharged, and where its cites resolve today

The operator accepted Amendment A on 2026-09-13. This Note records that
acceptance, records that A5's obligation has since been met, and re-locates
the amendment's cites against `main` at `6acefff`. It changes no decision:
decisions 1 to 12, the two acceptance amendments at the top, and A1 to A5
stand exactly as written, and it carries the record's status rather than one
of its own.

### 1. What the flip touched

Two sites: this amendment's heading and its `Status` line. Unlike ADR-0003 and
ADR-0005, this record carries no per-amendment pointer paragraph under its own
`Status` line to flip - its top line has read "accepted (2026-08-27, with
amendments)" since acceptance - and the ADR index and README rows have marked
it amended since then too. Nothing else in the record's words changed.

No sentence in Amendment A's body names its own proposed status, so there is
none to meet here.

### 2. A5 is discharged

A5 states an obligation and says so: "the module carries no such sentence
today (`lib/encryptor/provider/kms.ex`, read at `2a84a04`; `CloudTrail`
appears nowhere in `lib/`), and writing it is the whole of this amendment's
code half, `enc-8nr`". That sentence is anchored to `2a84a04` and was true
there. It is no longer the state of the tree, because the obligation was met:
`Encryptor.Provider.Kms`'s moduledoc now carries the section "What KMS sees,
and what CloudTrail records" (`lib/encryptor/provider/kms.ex:70-86`, read at
`6acefff`), which states that the vault's composed context is sent on
`GenerateDataKey`, `Encrypt` and `Decrypt` and recorded unencrypted in
CloudTrail, names ADR-0004 decision 2 as the list and decision 7 as the rule
that keeps per-row values out of it, and adds no option, function or
configuration key. Read A5's "today" as the state at `2a84a04`, and A5 itself
as met.

### 3. Where Amendment A's cites resolve at `6acefff`

Amendment A labels its cites `read at 2a84a04`, and ADR-0006 Amendment A's
implementation has moved two of them since. Every cite below was re-read by
anchor at `6acefff`. **Every claim holds**; what follows is re-location, not
correction.

| Cited in Amendment A | Resolves at `6acefff` |
|---|---|
| `lib/encryptor/vault/resolve.ex:198`, `Resolve.context/5` (the per-path table, and A-1) | `lib/encryptor/vault/resolve.ex:248` |
| `lib/encryptor/vault/resolve.ex:214`, `tenant_ref` from `Resolve.vault_supplied/2` | the derivation is `Resolve.reference/2` (`lib/encryptor/vault/resolve.ex:206-209`) and `vault_supplied/1` (`:263-267`) receives the derived string; the arity changed when ADR-0006 Amendment A's A3 fixed one derivation per operation. What the table asserts - that the vault supplies `tenant_ref` into the composed context - is unchanged |
| `lib/encryptor/provider/gcp_kms.ex:396-401`, `:344-346`, `:472-474` | unchanged, at those anchors |
| `lib/encryptor/provider/kms.ex` and `lib/encryptor/key/kms.ex` carry no context argument | still true: neither module takes or forwards an encryption context, which is A2's "no such seam" |
| `aws_encryption_sdk` v1.0.0 `keyring/aws_kms.ex:266`, `:291`, `:400`; `cmm/default.ex:119-121`, `:154-156`; `client.ex:368-370`, `:431-433` | the dependency is version-pinned, so these are unmoved |
| this record's own `:717-724`, `:727-739`, `:822`, `:831-837` | unchanged, at those anchors |
| `docs/adr/0008-aws-kms-keyring-backed.md:931-939` and `:610-614`; `docs/adr/0005-rotation-and-crypto-shred.md:894-901` | unchanged, at those anchors |

### 4. ADR-0008 open question 5's answer line still reads proposed

This amendment's consequences say "ADR-0008 open question 5 is closed by A1".
That record already carries an answer line saying so, and the line is labelled
with this amendment's pre-acceptance status: "*Answered (2026-09-13, proposed):
no. ADR-0004 Amendment A [...] Merged at proposed*"
(`docs/adr/0008-aws-kms-keyring-backed.md:940-948`, read at `6acefff`, under
question 5 at `:931-939`). With the acceptance the closure is no longer
provisional, so that line and its "Merged at proposed" clause want flipping,
and so does the heading ADR-0008's own Note quotes at `:998`. That Note
(`:994-1007`) already anticipates it, recording that "the parenthetical it
quotes is the half that changes when the operator flips that amendment's
acceptance" and directing a reader to the unadorned section name instead.
Both edits belong to ADR-0008 and not to this flip. Recorded here so the
pending edit is not lost between the two records.

### 5. A-1 stays open

The open question this amendment added - whether the reserved `encryptor-*`
pairs deserve their own sentence in the disclosure - is not settled by the
acceptance. It stays open, with ADR-0005 open question 7, for whoever writes
the security section.

### 6. What the pass-1 direction review corrected in this Note

The cold direction review of this flip found section 4 wrong: it said ADR-0008
carried no answer line under open question 5, when that record carries one
labelled proposed and a Note subsection anticipating this very flip. Section 4
above is corrected, and the deferral it makes - that the edit is ADR-0008's -
is unchanged, because what is owed there is a flip of an existing line rather
than the writing of a new one.

## Note (2026-09-13): under a signing suite the KMS API receives the composed context plus the engine's reserved `aws-crypto-public-key` pair

Amendment A's per-path table and A5 say what the AWS KMS keyring path sends to
the KMS API, and therefore what CloudTrail records: the map `Resolve.context/5`
composes. Measured against `main` at `60610df`, that is a strict subset of what
is actually sent under this package's default algorithm suite, by one
engine-owned pair. This Note records the fact. It decides nothing: decisions 1
to 12, the two acceptance amendments at the top, and A1 to A5 stand exactly as
written; the default suite is unchanged; nothing is removed from the context.
It carries the record's status rather than one of its own. Recorded for
`enc-msh`, the record half of `enc-dzf`, campaign RF045.

### 1. The rule

Read at `60610df`, with `aws_encryption_sdk` at the version `mix.lock` pins
(`1.0.0`, `mix.lock:3`):

- **Under a signing algorithm suite the KMS client receives the composed
  context plus exactly one further pair, `aws-crypto-public-key`.** The
  engine's Default CMM generates an ECDSA `:secp384r1` keypair for the write
  and puts the encoded public key into the context under its reserved key before
  any keyring wraps - `maybe_add_signing_context/2`, guarded by
  `AlgorithmSuite.signed?/1`
  (`aws_encryption_sdk` v1.0.0, `lib/aws_encryption_sdk/cmm/default.ex:195-205`,
  called at `:173`) - and the keyring then hands
  `materials.encryption_context` to `GenerateDataKey`, `Encrypt` and `Decrypt`
  unaltered (`lib/aws_encryption_sdk/keyring/aws_kms.ex:266`, `:291`, `:400`,
  the anchors the per-path table already names). Both the message header and
  the API call carry it, which is A2's single context object doing exactly what
  A2 says it does.
- **This package's default suite is a signing one.** `:algorithm_suite_id`
  defaults to `0x0578` and accepts `0x0478` (`@default_algorithm_suite_id` and
  `@allowed_algorithm_suite_ids`, `lib/encryptor/vault/config.ex:177-178`, read
  at `60610df`), and that module's "Choosing an algorithm suite" section
  (`:131-144`) names ECDSA P-384 signing as part of `0x0578` and `0x0478` as
  the value that drops the signature. A vault that says nothing about the suite
  is therefore a signing vault.
- **Under `0x0478` the KMS client receives exactly the composed context.** The
  extra pair belongs to the signing branch, and without signing the branch does
  not run. This is why no context assertion in the suite had seen the pair: the
  one end-to-end path that asserted on a context ran the unsigned suite.

### 2. The pair carries no secret, and decision 7 is not breached

The value is a signature *verification* key, and the message header already
carries it in the clear to anyone holding the ciphertext bytes - which is
decision 12's property (`:489`), stated for the header and true here for the
same reason. The private half is returned to the engine as signing material
and never enters the context at all (`cmm/default.ex:200-201`).

Decision 7 (`:369-386`) forbids anything that varies per row, and it takes
that rule for a cache-cost reason: "the serialized context is hashed into the
materials cache id, so each distinct context is its own cache entry and its
own cold-cache provider round trip". A pair whose value changes from one wrap
to the next looks, on that reading, like exactly what the rule forbids. It is
not - but the engine computes two different cache ids, the pair reaches only
one of them, and the claim therefore has to be made twice.

On **encrypt** the pair is not in the cache id at all, because of an ordering
the engine fixes: the Caching CMM computes its cache id from
`request.encryption_context` and does its lookup (`aws_encryption_sdk` v1.0.0,
`lib/aws_encryption_sdk/cmm/caching.ex:160`, `:174`, `:176`) **before** it
delegates to the Default CMM that inserts the pair (`:309-311`). The
encryption cache id is composed from the context the vault handed in, and the
pair never reaches it.

On **decrypt** the pair *is* in the cache id, and decision 7's bound survives
for a different reason. `get_decryption_materials/2` takes the request's
context (`caching.ex:183`) and hands it to `compute_decryption_cache_id/4`
(`:191`), which serializes it into the hash input (`:232`); the decrypt
request's context is the *message header's*
(`lib/aws_encryption_sdk/client.ex:410`, dispatched to the Caching CMM at
`:427-428`), and under a signing suite the header carries the pair. What keeps
that off decision 7's ledger is the other term in the same hash: the id also
carries the message's sorted encrypted data keys (`caching.ex:226-230`), which
are unique per data key. A decryption cache entry is already per-message
before its context is considered at all, so the decrypt-side entry count is
data-key shaped rather than context shaped, and adding a per-write context
pair to a per-message id changes nothing about what decision 7 prices.
Decision 7's own arithmetic - 200 tenants times 40 columns - is the encryption
cache id's, and this Note leaves the rule and its cost sentence exactly as
written: whether the record should price the decrypt side separately is a
question for whoever revisits decision 7, and not something this pair settles.

Its lifetime is worth stating precisely for the same reason. The keypair is
generated inside the Default CMM, and the Caching CMM reaches that CMM on a
cache miss only, so one encoded public key is reused across every message a
cached entry serves: "per message" is right for a cache-off vault and "per
cache entry" for a cache-on one. Either way it is per-write-burst rather than
per-subject, and every KMS call a CloudTrail reader sees is a cache miss by
construction, so what that reader gains from the pair is one opaque per-call
string and not a correlation handle for a subject or a row.

What this Note widens is not the secrecy of the context but the accuracy of
its enumeration.

### 3. What it means for A5 and the per-path table

A5's obligation stands, and stays discharged: the moduledoc section it requires
exists and says what A5 told it to say. What is now known is that the *set* both
A5 and the per-path table name - "every key decision 2's table names,
`tenant_ref` included" - is a **strict subset** of what the KMS API and
CloudTrail see under the default suite, by that one engine-owned pair. The
disclosure section in `Encryptor.Provider.Kms`'s moduledoc ("What KMS sees, and
what CloudTrail records", `lib/encryptor/provider/kms.ex:70-86`, read at
`60610df`) gains one sentence saying so, in the same commit as this Note. A5's
own words are unchanged: this is a widening of the enumeration a host reads, not
a new obligation and not a new option, function or configuration key.

Decision 2's rule about the reserved prefix is untouched and stays true as
written. It refuses `aws-crypto-` *from a host* (`:186-191`), and this pair is
not written by a host: it is added by the engine below the vault, after the
vault has composed the host's context and after the engine has validated that
the host did not supply the key itself. A host still cannot write it; the engine
still can, and under a signing suite does.

### 4. What is to pin it

The enumeration belongs in a test rather than in this record, and that test is
not in the tree yet: `test/encryptor/provider/kms_test.exs` at `60610df`
carries no encryption-context assertion and no recording client, which is the
gap the regression test this Note unblocks exists to close. That test half's
obligation is to pin both halves of the rule above - the composed map plus the
engine's reserved pair on the `0x0578` path, and exact equality with the
composed map on the `0x0478` path, on the calls the keyring makes. Until it
lands, this Note is the only place the fact is written down; once it lands, a
key added to or removed from either path goes red rather than ageing quietly
here.

### 5. Where Amendment A's `Resolve.context/5` cite resolves at `60610df`

One row for the re-location table of this record's previous Note: the per-path
table's and A-1's `lib/encryptor/vault/resolve.ex:198` (labelled read at
`2a84a04`) is the `def context(` clause head, and at `60610df` that head is
`lib/encryptor/vault/resolve.ex:248` - the same anchor the previous Note recorded
at `6acefff`, unmoved since. Every other cite in that table stands where that
Note put it.

## Note (2026-09-14): decision 7's cost arithmetic is the encryption cache id's, the Caching CMM has two encryption-side bypasses, and three clauses of the signing-suite Note are read more precisely

The 2026-09-13 signing-suite Note above settled, in passing, which of the
engine's two cache ids decision 7's arithmetic prices. It did not name the two
places where the Caching CMM computes no cache id at all, and three of its
supporting sentences are narrower or looser than the code they cite. This Note
records the bypasses, records a deliberate decision to leave the encryption
path as this record's only priced case, and reads those three sentences
precisely.

It decides nothing that changes a rule. Decisions 1 to 12, the two acceptance
amendments at the top, A1 to A5, and every Note above stand exactly as
written; decision 7's cost sentence is unchanged; nothing is removed. It
carries the record's status rather than one of its own. Recorded for
`enc-obf`, folding `enc-509` and `enc-ert`, campaign RF048.

Everything below was read at `4c8fbe9` (= `v0.4.1`), with
`aws_encryption_sdk` at the version `mix.lock` pins (`1.0.0`, `mix.lock:3`).

### 1. What the Note above already settled, and is not restated here

The decrypt-side half of `enc-509`'s question is already written, in the
signing-suite Note's section 2 (`:1397-1413`, read at `4c8fbe9`): that the
decryption cache id also hashes "the message's sorted encrypted data keys
(`caching.ex:226-230`), which are unique per data key", that "the decrypt-side
entry count is data-key shaped rather than context shaped", and that
"Decision 7's own arithmetic - 200 tenants times 40 columns - is the
encryption cache id's". Those three claims hold at `4c8fbe9`; this Note cites
them rather than repeating them. The EDK serialization and sort they name are
`compute_decryption_cache_id/4`'s first step
(`aws_encryption_sdk` v1.0.0, `lib/aws_encryption_sdk/cmm/caching.ex:224-231`,
the `sorted_edks` pipeline, with the serialized context appended at `:232`).

What that Note did not name is section 2 below.

### 2. The Caching CMM's two encryption-side bypasses

`get_encryption_materials/2` is a three-branch `cond`
(`caching.ex:158-179`). Two of its branches call the underlying CMM directly
and never compute a cache id, never look an entry up, and never store one:

- **An identity-KDF suite.** `identity_kdf?/1` (`caching.ex:252-254`, true for
  `%AlgorithmSuite{kdf_type: :identity}`) short-circuits to
  `call_underlying_cmm_encrypt/2` (`caching.ex:164-165`). The decryption side
  carries the same bypass (`caching.ex:187-188`).
- **A non-integer `:max_plaintext_length`.** When the request carries no
  declared plaintext length the byte limit cannot be enforced, so the result
  is not cached (`caching.ex:169-170`). There is no counterpart on the
  decryption side.

Only the third branch reaches `compute_encryption_cache_id/3`
(`caching.ex:174`) and the lookup (`caching.ex:176`).

**Neither bypass is reachable from a vault this package configures, at
`1.0.0`.** `:algorithm_suite_id` accepts `0x0578` and `0x0478`
(`@default_algorithm_suite_id` and `@allowed_algorithm_suite_ids`,
`lib/encryptor/vault/config.ex:177-178`, read at `4c8fbe9`) and both suites
are `kdf_type: :hkdf`
(`aws_encryption_sdk` v1.0.0, `lib/aws_encryption_sdk/algorithm_suite.ex:144`
and `:173`); and the client sets `:max_plaintext_length` to
`byte_size(plaintext)` on every write
(`lib/aws_encryption_sdk/client.ex:179`, passed through at `:343-348`), which
is always an integer. So both bypasses are engine-general facts about the
Caching CMM rather than paths a host of this package can take today.

### 3. The encryption path stays this record's only priced case

This is the decision `enc-509` asks for, and it is the second of the two
options that bead offers: decision 7's cost sentence is **not** amended to
name the bypasses or the decrypt-side id shape.

The reasoning: decision 7's number is exact for the case it prices, and every
term this Note adds moves the real count in the same direction. The two
bypasses of section 2 remove entries rather than adding them, and are
unreachable from a configured vault besides. The decrypt-side count is
data-key shaped, which is a different quantity in a different cache and is
already recorded above. A second number in decision 7 would price a bound no
host can exceed by configuring this package, at the cost of making a
correctness-adjacent rule read as a capacity table.

What decision 7 forbids, and why, is unchanged: a context that varies per row
is one cache entry per row on the encryption side, and that is the cost the
rule exists to refuse.

### 4. Three clauses of the signing-suite Note, read precisely

Added here rather than edited there, so the Note above stays as it was
reviewed. Each clause below names the sentence it reads, by anchor.

**(a) "already per-message" is, strictly, per data key.** Section 2's sentence
at `:1406-1407` - "A decryption cache entry is already per-message before its
context is considered at all" - is exact for a cache-off writer and loose for
a cache-on one. The decryption cache id hashes the *sorted EDK set*
(`caching.ex:224-231`), not a message id, so every message written from one
cached encryption entry shares one decryption entry. Read the sentence as
*per data key*. The operative clause it supports - "data-key shaped rather
than context shaped" (`:1407-1408`) - is exact as written, and nothing in
section 2's conclusion depends on the looser reading.

**(b) "on a cache miss only" is narrower than the code.** The lifetime
sentence at `:1416-1417` - "the Caching CMM reaches that CMM on a cache miss
only" - names one of three ways the underlying CMM is reached on the
encryption side. `handle_encryption_cache_lookup/3` (`caching.ex:256-272`)
refetches through `fetch_and_cache_encryption_materials/4` both on
`{:error, :cache_miss}` (`:270-271`) and when a *present* entry fails
`CacheEntry.can_serve?/4` (`:261`, else-branch at `:266-267`) because the
message or byte limit would be exceeded; and the two bypasses of section 2
reach it without a lookup at all. Read the sentence as *on anything other
than a servable cache hit*. What it is offered for - that one encoded public
key is reused across every message a cached entry serves - is unaffected: a
refetch on a failed `can_serve?/4` replaces the entry and the new key, exactly
as a miss does.

**(c) "the one end-to-end path" is a singular that undercounts.** The sentence
at `:1370-1371` - "the one end-to-end path that asserted on a context ran the
unsigned suite" - is true of the suite and wrong about the count. Several
end-to-end paths assert on a message's encryption context at `4c8fbe9`.

What kept every one of them from seeing the engine's reserved pair is a
property of the fixtures rather than of the count, and that property is the
durable claim: **every vault whose written context is asserted is configured
`algorithm_suite_id: 0x0478`, and the one path that builds its messages
without a vault chooses the same unsigned committed suite deliberately**
(`test/encryptor/message_test.exs:217-235`, with the comment at `:223-227`
saying why). A signing vault would break that property, and no fixture is
one.

Sites, as the set stood at `4c8fbe9` - cited to make the claim checkable, not
as a list this record undertakes to keep exhaustive:

- `test/encryptor/message_test.exs:43` and `:124`, through the helpers at
  `:211-215` and `:217-235` (no vault; the suite is chosen in the helper).
- `test/encryptor/envelope_test.exs`'s `context/1` helper (`:46-49`) feeding
  `:99`, `:114`, `:149`, `:452`, `:530` and `:628`, against
  `EnvelopeVaults.Root`, `Staged` and `Contextual`
  (`test/support/envelope_vaults.ex:74`, `:100`, `:147`) and
  `EncryptVaults.Merchant` (`test/support/encrypt_vaults.ex:201`).
- `test/encryptor/vault/rekey_test.exs`'s own `context/1` (`:23-26`) feeding
  `:88`, `:89`, `:102`, `:116`, `:188` and `:292-293`, against
  `DecryptVaults.Retired` (`test/support/decrypt_vaults.ex:33`),
  `EncryptVaults.Bound` (`test/support/encrypt_vaults.ex:186`) and
  `EncryptVaults.Merchant` (`:201`).
- `test/guides_test.exs:135-137` and `:236`, against `GuideVaults.Vault`
  (`test/support/guide_vaults.ex:83`) and `GuideVaults.MerchantVault`
  (`:302`).

Read the sentence as *every end-to-end path that asserted on a context*. Its
point stands for all of them: none had seen the engine's reserved pair,
because none ran a signing suite.
