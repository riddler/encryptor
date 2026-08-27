# ADR-0004: The encryption context is a vault-composed, profile-enforced set of identifying keys

Status: proposed (2026-08-26)

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
| `tenant_id` | the `:key` selector, verbatim | **the vault**, from `:key` (decision 4) | required on a `:tenant` profile; refused on `:single` |
| `table` | storage relation name, unqualified | the caller, or `encryptor_ecto` from `schema.__schema__(:source)` | required when configured; advisory otherwise |
| `column` | field name | the caller, or `encryptor_ecto` from `:field` | required when configured; advisory otherwise |
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
| `:tenant` | a non-empty `String.t()` | `tenant_id` | `["tenant_id"]` ++ `:required_context` |

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

**4. `tenant_id` is supplied by the vault from the `:key` selector, and a
caller that supplies it is refused.** On a `:tenant` vault, every `encrypt/2`,
`decrypt/2`, and `rekey/2` gets `"tenant_id" => selector` injected. A caller
passing `"tenant_id"` in `:encryption_context` gets
`{:error, {:reserved_context_key, "tenant_id"}}`, with generated documentation
that says to pass `key:` instead.

The reason is ADR-0001 decision 4's own goal, taken literally: *`:key` is the
whole of per-tenant routing, and there is no second place to get tenancy
wrong*. If the tenant appears in two arguments, they can disagree, and the
interesting disagreement is silent: encrypting under tenant A's key with
tenant B's context produces a row that decrypts for nobody and looks like
corruption a year later. Deriving the context pair from the routing argument
makes the two incapable of disagreeing.

It also removes the pair from the surface a host can forget. ADR-0001's and
ADR-0003's worked examples both write
`encryption_context: %{"tenant_id" => tenant.id, ...}` by hand; under this
decision they write `key: tenant.id` and the pair appears anyway. The examples
in this record show the shape.

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
  composed context. Since decision 4 supplies `tenant_id` itself, the realistic
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
  that cannot silently pass a tenant check, because `tenant_id` is in the
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
- The Ecto layer supplies `table` and `column`, derived from
  `Ecto.ParameterizedType.init/1`'s `:schema` and `:field`, and merges the
  host's static `:context` option.
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

**The tenant identifier is published in every application message.** Decision 4
puts the raw selector into the header in the clear. ADR-0002 decision 4 and
ADR-0003 decision 5 went to some length to keep the raw identifier *out* of the
EDK's key name, deriving a keyed `tenant_ref` instead, on the argument that a
name travels in the clear in every message header. The context travels in
exactly the same header. So in the profile this package expects most hosts to
run, the raw tenant identifier is disclosed by any stolen ciphertext, and the
keyed derivation protects the wrapped-key store's index and the key names, not
the tenant attribution of application rows.

This record chooses that trade deliberately rather than by omission (open
question 1 states the reasoning and the alternative), and it is the single
biggest thing an acceptance reviewer should push back on if they disagree.
Nothing in the threat-model table of ADR-0003 decision 10 changes: the
disclosure is metadata, every "can read" cell is still about plaintext, and a
ciphertext-only attacker still reads nothing. But "ciphertext only reveals
nothing" is not a sentence this package can say any more, and it should stop
saying it.

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
  @tenant_id "tenant_id"
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
  "tenant_id" => "acct_A",   # vault-supplied from :key, decision 4
  "table"     => "customers",
  "column"    => "tax_id",
  "app"       => "my_app"    # static, from configuration
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
  encryption_context: %{"tenant_id" => "acct_B", ...})
#=> {:error, %Encryptor.Error{reason: {:reserved_context_key, "tenant_id"}}}
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
#=> %{"tenant_id" => "acct_A", "table" => "customers",
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
| A3 | Canonical keys include `tenant_id`, `table`, `column` | **Confirmed as vocabulary; denied as to who supplies `tenant_id`** |
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

**A3 - confirmed as vocabulary, denied as to supply.** The three names are
canonical (decision 2) and spelled exactly as assumed. But `tenant_id` is
vault-supplied from the `:key` selector and *refused* from a caller
(decision 4), so the Ecto layer passes the tenant as `key:` rather than as a
context pair. This is a small mechanical change to that record's decision 5
and 5f - the `TenantContext` behaviour, the process scope, `wrap/2`, the
`MissingTenantError`, and the option table are all unaffected; only the shape
of the call in `dump/3` and `load/3` changes. Its decision 5e (`tenant: :none`)
is the one substantive consequence: a global field cannot be a tenant vault
with the pair omitted, because a `:tenant` profile has `tenant_id` in its
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
