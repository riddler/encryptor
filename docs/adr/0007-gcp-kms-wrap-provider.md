# ADR-0007: GCP KMS is a wrap-provider, not a keyring, and it owns the tenant key's whole lifecycle

Status: accepted (2026-09-13)

## Context

ADR-0002 decision 5 sorted every adapter into one of two shapes and then put
GCP KMS in the second one and moved on:

> | GCP KMS, Vault transit | material source | later, on demand |
> (`docs/adr/0002-key-providers.md:221`, read at `c85d400`)

and sketched it in one line in the roadmap section:

> **GCP KMS** - identical to Ecto in shape: a stored wrapped key, decrypted
> by a remote call instead of a local KEK. `encryption_key/2` does network
> I/O and must bound it. Fits.
> (`docs/adr/0002-key-providers.md:550`, read at `c85d400`)

"Later, on demand" has arrived. This record fills that reference in. It does
not overturn the classification: **GCP KMS is a material source, exactly as
ADR-0002 decision 5 said, and this record is that row expanded rather than
that row revised.**

That claim is true of the *shape* and it would be false if left unqualified
of the *contract*, so the qualification is made here rather than discovered
later. Two sentences of ADR-0002 are extended by decision 2 below, and both
are named now:

> `@optional_callbacks init: 1, child_spec: 1`
> (ADR-0002 decision 1's code block, `docs/adr/0002-key-providers.md:96`,
> read at `c85d400`)

> GCP KMS and Vault transit are material sources: they decrypt a stored
> wrapped key and hand back bytes. They are built when someone needs them,
> against the same descriptor, **with no new contract**.
> (`docs/adr/0002-key-providers.md:252-254`, read at `c85d400`, emphasis
> added)

Decision 2 adds one member to that optional-callback list, and "no new
contract" therefore holds for the *resolution* pair - `encryption_key/2` and
`decryption_keys/2` are untouched, and the descriptor really is the same -
but not for *provisioning*, which ADR-0002 had no callback for at all. This
record is an amendment to ADR-0002 decision 1 in that one respect and says
so in those words. Nothing else in ADR-0002 is revised.

**The index row for ADR-0002 was deliberately not edited while this record was
proposed** (it was marked amended at this record's acceptance, 2026-09-13). ADR-0007 was
`proposed`; an amendment does not take effect until the operator accepts it,
and marking an accepted record as amended by an unaccepted one would be this
record flipping a status that is not its to flip. Adding "amended" to
ADR-0002's row in `docs/adr/README.md` belongs with the acceptance of this
record.

What "later, on demand" left undecided turns out to be more than an adapter
sketch, and that is why this needs a record of its own rather than a module
and a test.

**The engine cannot dispatch on a GCP key, and that is the whole design.**
ADR-0002's Context records the engine's closed keyring dispatch, crediting it
to ADR-0001 (`docs/adr/0002-key-providers.md:19-23`, read at `c85d400`):
`Cmm.Default` matches by struct type over `RawAes`, `RawRsa`, `Multi`, and the four AWS KMS
keyrings, and returns `{:error, {:unsupported_keyring_type, module}}` for
anything else. There is no GCP keyring in `aws_encryption_sdk` v1.0.0 and this
package will not add one: the descriptor set is closed at
`%Encryptor.Key.Aes{}` and `%Encryptor.Key.Kms{}`, and the vault-internal
builder declines the second one with a deliberate
`{:no_keyring_mapping, Kms}` (`lib/encryptor/vault/keyring.ex:74`, read at
`c85d400`) rather than an unknown-struct error. So a GCP provider that wanted
to be keyring-backed would have to widen a closed set in this package and add
a keyring to the engine. It does neither. It hands the vault raw AES material
and the vault builds an ordinary `RawAes` keyring, which is the *only* thing
that makes this adapter cost zero engine change.

**The wrapping root moves out of the process and into GCP, and nothing else
moves.** ADR-0003 decision 2 made the tenant key's wrapping "an ordinary
`Encryptor` message produced by a root vault", and listed as its first
consequence that "the root can move to a key manager without a format change".
That sentence anticipated `Encryptor.Provider.Kms` under an AWS root vault. It
holds one step further out too: a GCP `CryptoKey` can be the root, in which
case the stored blob is a GCP KMS ciphertext rather than an engine message,
and *the format that changes is the wrapping's, never the application data's*.
Every ciphertext this vault writes over application data stays an unmodified
AWS ESDK message, readable by the official SDKs, exactly as the package
promises. The GCP dependency is confined to one blob per tenant per version.

**GCP KMS keys cannot be deleted, and that fact reorganizes the ownership
boundary.** A GCP `KeyRing` cannot be deleted at all, and a `CryptoKey` cannot
be deleted either - only its *versions* can be destroyed, with
`DestroyCryptoKeyVersion`, after a scheduled destruction window. An empty,
version-destroyed `CryptoKey` remains as a billable-at-zero, permanently
visible resource. Like decision 10's cost figures this is a premise about a
vendor's current behaviour, to be re-verified against Google's published
limitations when the implementation lands; unlike a price it is a
long-standing, deliberate property of the service rather than a number that
drifts, and every decision below is built so that GCP later permitting a delete
would relax a constraint rather than invalidate one. That is not a footnote;
it decides who creates what. A
resource that cannot be destroyed must not be owned by a tool whose contract
is "I can bring this to the state I describe, including absent". Terraform
destroying a key ring it created leaves the ring behind and the state file
lying about it; the next apply fails on an already-exists it cannot reconcile.
So the ring is provisioned once, out of band, and lives forever - and the
per-tenant keys, which arrive at tenant-creation time and are therefore not
something an infrastructure-as-code plan could enumerate anyway, are created
by this package at mint. The undeletability argument and the
"keys-arrive-with-tenants" argument point at the same split, which is why
decision 3 is confident about it.

**Provisioning has no seam to arrive through, and the one word available is
already taken twice.** `Encryptor.Provider` declares exactly four callbacks
today - `init/1`, `child_spec/1`, `encryption_key/2`, `decryption_keys/2`
(`lib/encryptor/provider.ex:209-232`, read at `c85d400`) - and
`@optional_callbacks init: 1, child_spec: 1` (`:232`). There is no
provisioning callback. Meanwhile `Encryptor.Envelope.provision/3` already
exists, with a default third argument that makes a `provision/2` of its own
(`lib/encryptor/envelope.ex:284-286`, read at `c85d400`). A new provider
callback named `provision` therefore lands one character away from an existing
public function with a different arity split, a different first argument, and
a different job. Decision 2 fixes the callback and decision 2's table fixes
the disambiguation, because a record that introduced this collision silently
would be a record that caused the bug.

**Terminology warning, carried into every decision below.** In this package
"partition" means the cache partition id of ADR-0001 decision 7 - a
fixed-width value hashed from the vault namespace and the encoded selector,
a cache-key input only, explicitly "not key material"
(`docs/adr/0001-vault-layer.md:242-257`). It does not mean a tenant. The
walk that commissioned this record used "partition mint" loosely for what
this package calls **tenant mint**: the moment a tenant's key material is
first created. This record uses `tenant mint` throughout, and readers coming
from the walk's language should map the two. Using "partition" for a tenant
here would have collided with a defined term that is deliberately *not*
secret.

## Decision

**1. `Encryptor.Provider.GcpKms` is a wrap-provider: it wraps and unwraps the
tenant master key through GCP KMS `Encrypt`/`Decrypt` and returns
`%Encryptor.Key.Aes{}`.** It is a material source in ADR-0002 decision 5's
sense and it introduces no descriptor, no keyring, and no engine change.

The tenant master key is what ADR-0003 decision 1 says it is: 32 bytes from
`:crypto.strong_rand_bytes/1`, generated once, never derived, independent per
tenant. The only thing this provider changes is *what wraps it*. Where
ADR-0003 decision 2 wraps it with a root `Encryptor` vault into an engine
message, this provider wraps it with a GCP `CryptoKey` into a GCP KMS
ciphertext.

| | ADR-0003 root-vault envelope | this provider |
|---|---|---|
| what holds the wrapping key | a root `Encryptor` vault | a GCP `CryptoKey` |
| the stored blob | an AWS ESDK message | a GCP KMS ciphertext |
| binding | encryption context, package-owned (ADR-0003 decision 4) | GCP additional authenticated data, same fields (decision 5) |
| unwrap | `Encryptor.Envelope.unwrap/2`, local | `Decrypt`, one network round trip |
| root rotation | `rekey/2` / `rewrap/2` (ADR-0005 P1) | a new `CryptoKeyVersion` plus a re-encrypt pass (decision 7) |
| application ciphertext | unchanged AWS ESDK message | unchanged AWS ESDK message |

The last row is the point. Two hosts running the two shapes write
byte-compatible application data and differ only in one small blob per tenant
per version.

**The GCP key replaces the wrapping subkey and only the wrapping subkey, and
the record would be unimplementable if it did not say so.** ADR-0003 decision
6 expands the host's root material into two labels with different lifetimes:
`"encryptor/v1/root-wrap"`, which is the root vault's material, and
`"encryptor/v1/tenant-ref"`, the reference subkey that ADR-0003 decision 5
derives `tenant_ref` under and from which `name` is built as
`"t/<tenant_ref>/v<n>"`. **This provider replaces the first and not the
second.**

The second one is already where it needs to be. ADR-0004's acceptance
amendment to decision 4 moved it:

> **The reference subkey is tenant-vault configuration**, resolved at start
> like every other key-material input (through `init/1`, never `use`
> options), frozen into the vault's `Config`.
> (`docs/adr/0004-encryption-context.md:248-250`, read at `c85d400`)

So a host running this provider configures `reference_subkey` on the tenant
vault exactly as a host running the store-backed provider does, and the vault
performs the same start-time known-answer check on it, failing with
`{:error, {:invalid_config, :reference_subkey, :known_answer_mismatch}}`
(`docs/adr/0004-encryption-context.md:262`, read at `c85d400`). This provider
neither adds nor relaxes that. It matters here because decision 5's additional
authenticated data and decision 6's `name` and `tenant_ref` fields have no
other source: without the reference subkey there is no `tenant_ref`, and the
record could not be implemented from alone.

That asymmetry is a feature and not an oversight. `tenant_ref` travels in the
clear in every message header (ADR-0003 decision 5), so it must not depend on
a remote service that could be unreachable on the read path; and ADR-0003
decision 6 gave the reference subkey its own lifecycle precisely so that
rotating the wrapping root leaves every stored `tenant_ref` valid. Moving the
wrapping root into GCP is the rotation-shaped change that separation was built
to absorb. So: the wrapping root becomes a GCP `CryptoKey`, the reference
subkey stays local and stays pinned, and every identity column keeps the
meaning ADR-0003 gave it.

**The engine's own GCP keyring is the exit, and it is not this record's
work.** If `aws_encryption_sdk` ever grows a GCP KMS keyring, a *keyring-backed*
GCP provider becomes possible: a descriptor naming the GCP key, dispatched by
the engine, with the data key wrapped by GCP directly and no tenant master key
in the middle. That is a better design on the axis of "how many places
plaintext key material exists" and a worse one on the axis of "how much of the
package's tenancy model survives". It is named here as the exit so that this
record is not mistaken for a claim that the wrap shape is the only shape; it
is upstream work in the engine, out of scope for this package, and nothing
below is built in a way that would have to be torn out if it arrived.

**2. `provision/2` becomes an optional callback on `Encryptor.Provider`, and
the collision with `Encryptor.Envelope.provision/3` is resolved by naming, not
by hope.**

```elixir
@callback provision(state :: state(), selector :: selector()) ::
            {:ok, provisioned()} | {:error, reason()}

@optional_callbacks init: 1, child_spec: 1, provision: 2
```

It is optional for the same reason `init/1` is: most providers have nothing to
provision. `Static` and `Function` do not implement it. A provider that does
not implement it is not broken, it is a provider whose keys arrive some other
way, and a caller that reaches for `provision/2` on such a provider gets an
`{:error, {:not_provisionable, module}}` from the vault-level wrapper rather
than an `UndefinedFunctionError`.

The two seams, side by side, because one of them will otherwise be typed where
the other was meant:

| | `Encryptor.Envelope.provision/3` | `c:Encryptor.Provider.provision/2` |
|---|---|---|
| kind | a public function, exists today | a behaviour callback, new here |
| first argument | `root_vault` (a module) | `state` (what `init/1` froze) |
| second argument | `selector` | `selector` |
| third argument | `opts`, defaulted (`envelope.ex:286`) | none |
| returns | `{:ok, %WrappedKey{}}` | `{:ok, provisioned()}`, decision 6 |
| does | generates 32 bytes and wraps them under a root vault | creates the tenant's GCP `CryptoKey`, then generates and wraps |
| who calls it | the host's onboarding path, directly | the host's onboarding path, through the vault |

This record uses fully-qualified names for both, everywhere, and asks the
implementation to do the same in every moduledoc, spec, and test name.

**A vault-level entry point, not a direct provider call.** Hosts do not hold
the provider state - `init/1` returns it and the vault freezes it for the
vault's life (`lib/encryptor/provider.ex:180-186`, read at `c85d400`). So the
callable surface is `MyApp.TenantVault.provision(selector)`, which resolves the
provider and its frozen state and calls the callback. That is one public
function on the vault that the vault's decision to have a provider already
forces; it is not new surface in the sense ADR-0001 guards, because a host has
no other way to reach a frozen state.

**3. `provision/2` creates the `CryptoKey`; the `KeyRing` and every IAM
binding are provisioned out of band and this package never creates either.**

At tenant mint, `provision/2` issues `CreateCryptoKey` against a `KeyRing`
that already exists, named in `init/1` options, with:

- `purpose: ENCRYPT_DECRYPT`,
- no rotation schedule (decision 7 says why automatic rotation is wrong here),
- protection level and algorithm from `init/1` options, defaulted to
  `SOFTWARE` and the GCP default symmetric algorithm, with `HSM` a
  configuration change and not a code change.

`CreateCryptoKey` is idempotent-adjacent rather than idempotent: a second call
with the same id fails `ALREADY_EXISTS`. Decision 4 makes the id a pure
function of the selector, which turns that failure into a usable signal, and
decision 6 says what the provider does with it.

What it never does:

- **Never `CreateKeyRing`.** A key ring cannot be deleted. A package that
  created one would be permanently enlarging a host's GCP project from inside
  a library call, on a path a host might reach with a typo'd tenant id.
- **Never `SetIamPolicy`, and never any IAM write.** The provider's service
  account needs `cloudkms.cryptoKeyVersions.useToEncrypt` and
  `useToDecrypt` on the ring, plus `cloudkms.cryptoKeys.create` if it mints;
  granting itself those, or anything else, is a privilege-escalation surface
  with no upside. A deployment whose IAM is wrong fails loudly at the first
  call, which is the correct failure.

The ring and the bindings are the operator's Terraform (or console, or
`gcloud`) and they are a one-time, per-environment act. This is the same split
ADR-0003 decision 9 drew for storage - "what this package never sees is the
storage" - applied to infrastructure: the package produces and consumes keys,
it does not own the container they live in.

**A note the runbook must carry: the ring is a destroy-time hazard in
Terraform, not a create-time one.** `google_kms_key_ring` accepts a destroy
and removes only the state entry; the ring survives, and a re-apply hits
`ALREADY_EXISTS` on a resource no `terraform destroy` can clear. The standard
mitigations - `prevent_destroy`, or keeping the ring outside the
application's state entirely - are the operator's choice and belong in the
implementation's guide, not in this record's decisions.

**4. The `CryptoKey` id is an unkeyed, collision-free derivation of the
selector, and never the selector itself.**

ADR-0004 A7 fixed the selector as an opaque `String.t()` supplied by the host
(`docs/adr/0004-encryption-context.md:896`). GCP constrains a `CryptoKey` id
to `[a-zA-Z0-9_-]{1,63}`. Those two facts do not compose: a tenant identifier
that is a UUID happens to fit, one that is an email address or a slug with a
dot does not, and one that is a database integer stringified per ADR-0004 A7
fits but is guessable. And a GCP resource name is visible in IAM policies,
audit logs, Cloud Console, and every error message the client library
produces - which makes putting a raw tenant identifier there a disclosure of
the host's tenant list to everyone with project-level read.

So:

```
crypto_key_id = prefix <> Base.encode32(
  :crypto.hash(:sha256, [vault_namespace, 0, encoded_selector]),
  case: :lower, padding: false
)

where `encoded_selector` is the selector's UTF-8 bytes. ADR-0004 decision 3
narrowed the selector to `String.t()` on a `:tenant` vault, so the encoding is
the identity on every selector this provider can see; it is spelled out anyway,
because the value must be byte-stable for the life of a resource that cannot
be deleted, and "the string" is not a byte specification.
```

- **Full digest, not truncated.** Base32 of 32 bytes is 52 characters; with a
  short prefix it is inside 63. There is no reason to truncate and every
  reason not to: an undeletable resource that collides is unrecoverable.
- **Base32 lower, not Base64.** The GCP id charset excludes `=` and is
  case-sensitive-but-normalizing in tooling; base32 lower-case is entirely
  within `[a-z2-7]` and survives copy-paste, console display, and
  case-folding search.
- **The same pre-image shape as ADR-0001 decision 7's partition id**
  (`hash(namespace, 0, encoded_selector)`), with the same zero separator for
  the same reason: an unseparated concatenation makes two different
  `(namespace, selector)` pairs able to produce one pre-image.
- **Not keyed.** This is deliberately *not* ADR-0003 decision 5's `tenant_ref`,
  which is a keyed derivation under a root subkey. A keyed id would tie the
  GCP resource name to root key material, so a root rotation would rename
  every tenant's key - and GCP keys cannot be renamed, or deleted. The id must
  be stable for the life of the project, so it is derived from values that are
  themselves stable, and its security property is "not reversible to a tenant
  id by an observer who does not already have the tenant list", not
  "unforgeable". A holder of the tenant list can confirm a guess. That is
  acceptable for a resource name and would not be for `tenant_ref`; decision 5
  of ADR-0003 gets to keep its stronger property because it is doing a
  stronger job.

A host that wants a different id policy - one key for all tenants, one key per
region, an externally-assigned id - supplies `key_id_fun` in `init/1`, which
is the same escape hatch `Encryptor.Provider.Function` is, with the same
warning: everything above becomes the host's obligation and nothing enforces
it.

**5. The GCP additional authenticated data carries ADR-0003 decision 4's
context, field for field.**

GCP KMS `Encrypt` takes an `additionalAuthenticatedData` byte string, not a
map. ADR-0003 decision 4's package-owned context is a map. The four fields
are the same ones, unchanged:

```
"encryptor-purpose"        => "tenant-key-wrap"
"encryptor-tenant-ref"     => tenant_ref
"encryptor-key-version"    => Integer.to_string(version)
"encryptor-key-namespace"  => namespace
```

**The encoding is fixed to bytes here, because "canonical" is not a
specification.** Two implementations that both sort and both length-prefix
can still disagree on prefix width, on whether key names are included, and
on how the integer is rendered - and a disagreement is discovered as a
permanent `Decrypt` failure against a key that cannot be deleted. So:

```
aad = for {k, v} <- Enum.sort(context), into: <<>> do
  <<byte_size(k)::unsigned-big-16, k::binary,
    byte_size(v)::unsigned-big-32, v::binary>>
end
```

- Pairs are sorted by key, bytewise ascending, over the UTF-8 key bytes.
- Both the key and the value are included. Including only values would let
  a renamed field go unnoticed.
- Key lengths are 16-bit big-endian, value lengths 32-bit big-endian. The
  widths differ because the keys are a closed, short set and the values are
  host-influenced; both are big-endian because every other length in the
  engine's message format is.
- `version` is rendered by `Integer.to_string/1`, decimal, no padding and no
  sign, which is the same rendering ADR-0003 decision 4 already puts in the
  encryption context - the two must agree, because a host may run both
  shapes.
- No field count is prefixed and none is needed: every field is
  length-delimited, so the concatenation is already unambiguous.

A worked vector, for the implementation to assert against. With
`tenant_ref: "abc"`, `version: 1`, `namespace: "encryptor-tenant"`, the
sorted pairs are `encryptor-key-namespace`, `encryptor-key-version`,
`encryptor-purpose`, `encryptor-tenant-ref`, and the first pair encodes as:

```
0017                                    # 23, the key length
656e63727970746f722d6b65792d6e616d657370616365   # "encryptor-key-namespace"
00000010                                # 16, the value length
656e63727970746f722d74656e616e74        # "encryptor-tenant"
```

The four pairs are 23/16, 21/1, 17/15 and 20/3 key and value bytes, so the
full vector is `4 * 6 + (23+16) + (21+1) + (17+15) + (20+3)` = **140 bytes**.
The implementation pins it as a constant and a change to it is a format
change, not a refactor.

This is not decoration. GCP `Decrypt` fails when the AAD does not match, so
the AAD is what makes a wrapping that has been moved between tenants or
versions in the host's store fail closed instead of silently unwrapping, which
is precisely the property ADR-0003 decision 4 bought with the encryption
context and which would otherwise be lost when the engine message is replaced
by a GCP ciphertext. **The binding is the reason the two shapes are equivalent
in safety and not merely in function.** An implementation that skips it has
built a weaker provider that passes every test that does not test for this.

This encoding is a new serialization and it is decided here, to the byte,
rather than inline, per this repository's rule that cryptographic choices are
ADR choices. Open question 3 records that a second caller should promote it out
of this provider.

**6. The return of `provision/2`, and what it does about a key that is already
there.**

```elixir
@type provisioned :: %{
        tenant_ref: String.t(),
        version: pos_integer(),
        namespace: String.t(),
        name: String.t(),
        bits: 256,
        wrapped: binary(),
        key_id: String.t()
      }
```

**The identity field is `tenant_ref` and never the selector, and that is not
a style choice.** ADR-0004's acceptance amendment to decision 4 is explicit:

> The store-backed provider holds the same subkey and computes references
> from selectors for its row lookups, so the wrapped-key store is keyed by
> reference only and never stores a raw tenant identifier.
> (`docs/adr/0004-encryption-context.md:250-253`, read at `c85d400`)

An earlier draft of this decision returned `selector`, which would have put
the raw tenant identifier into the wrapped-key store and silently reversed
the property ADR-0003 decision 5 and that amendment were both written to
establish. It does not. The selector is a call-time argument; it is used to
derive `tenant_ref` and `key_id` and it is not returned.

It is a map and not `%Encryptor.Envelope.WrappedKey{}` because `WrappedKey`
carries the assumption that `wrapped` is an engine message produced by a
root vault (`lib/encryptor/envelope/wrapped_key.ex:72-83`, read at
`c85d400`). Here `wrapped` is a GCP ciphertext and `key_id` is a field the
envelope has no room for. Reusing the struct would make a store holding both
kinds unable to tell them apart, which is the one thing such a store must be
able to do. The field names are otherwise identical, deliberately, so that a
store can hold one row shape with one extra column.

The plaintext key never appears in the return. That holds the *second*
clause of ADR-0003 decision 3; this decision departs from its first clause -
"the provisioning result is an `%Encryptor.Envelope.WrappedKey{}`" - for the
reasons just given, and that clause stays in force for
`Encryptor.Envelope.provision/3`, which is the function it was written about.

**An existing key is not an error, and provisioning still does not happen on
the read path.** `CreateCryptoKey` returning `ALREADY_EXISTS` means a previous
mint for this selector got as far as creating the key. The provider treats
that as success for the create step and continues to generate and wrap fresh
material - because decision 4 makes the id a pure function of the selector, an
`ALREADY_EXISTS` is always *this* tenant's key and never another's.

**The race this leaves open is the host's, and it is named rather than
left to be found.** Two concurrent `provision/2` calls for one selector both
pass the create step and both mint fresh master-key material at the same
version; whichever row loses the store write leaves anything encrypted under
the winner unreadable. This is the race ADR-0003 decision 8 named in its own
argument ("a race between two requests can mint two keys for one tenant")
and ADR-0003 open question 1 owns. This provider does not make it worse and
does not fix it: single-flight is the host's onboarding transaction or a
unique index on `(tenant_ref, version)` in the store, and an implementation
must say so in the moduledoc rather than implying `provision/2` is safe to
call concurrently. What it
does **not** do is make resolution creative: ADR-0003 decision 8's rule stands
unchanged and is restated here because a provider that can create keys is
exactly where it would erode. `encryption_key/2` and `decryption_keys/2` never
call `provision/2`, never call `CreateCryptoKey`, and answer an unknown
selector with `{:error, {:unknown_key, selector}}` - a term already in the
closed vocabulary (`lib/encryptor/provider.ex:196-201`, read at `c85d400`).

**7. The two version counters are independent, and conflating them is the
failure this decision exists to prevent.**

There are now two things called a version:

| | tenant master key version | GCP `CryptoKeyVersion` |
|---|---|---|
| what it is | ADR-0003's `version`, one per minting of 32 fresh bytes | GCP's version of the wrapping key |
| where it lives | the host's store, and the AAD | GCP |
| rotating it | ADR-0005 R2, level 2: re-encrypt every ciphertext for the tenant | ADR-0005 R1, level 1: re-encrypt one blob per tenant per live version |
| cost | a walk over user tables | a walk over the key store |
| who walks | `encryptor_ecto` / the host | the key store's package |
| destroying it | deletes one wrapping (ADR-0005 P4) | `DestroyCryptoKeyVersion` |

They rotate on their own schedules and neither implies the other. An operator
who reads "rotate the key" and rotates the GCP `CryptoKeyVersion` has done a
level-1 rotation that touches no application data; one who mints a new tenant
master key version has committed to a level-2 re-encrypt. ADR-0005 decision 1
made this same table for this package against `encryptor_ecto`'s vocabulary,
for this same reason; its Context calls such a mismatch "dangerous rather than
cosmetic" (`docs/adr/0005-rotation-and-crypto-shred.md:37-38`, read at
`c85d400`). A third vocabulary has now arrived and gets the same treatment.

**No automatic GCP rotation schedule** (decision 3), because GCP's automatic
rotation moves the primary version and leaves existing ciphertexts decryptable
under their original version, so it silently accumulates live versions that
nobody is tracking, none of which is what ADR-0005's runbook means by a
rotation with a verifiable end. Rotation here is the operator running a
re-encrypt pass, which is ADR-0005 P1 with `Decrypt`-then-`Encrypt` in place
of `rewrap/2`, and which has a defined finish line: every stored blob is
under the new primary version. That is checkable: the `Encrypt` response names
the `CryptoKeyVersion` it used, and `Decrypt` reports `usedPrimary`, so a pass
can verify itself rather than being declared done.

**8. `DestroyCryptoKeyVersion` is ADR-0005's shred, and it closes the gap
ADR-0005 said it could not close.**

ADR-0005 decision 10 declined to ship a shred function on the ground that
"deleting a wrapping is a `DELETE` against the host's store" and this package
does not know what the store's copies are. Its consequences section states the
residual honestly: "a shred is only as good as the copies". Under this
provider, that is no longer the whole story. Destroying every
`CryptoKeyVersion` of a tenant's `CryptoKey` renders every wrapping of that
tenant's master key undecryptable **including every backup copy of the store**,
because the wrapping key is not in the backup. The shred stops depending on
having found every copy.

**What it does not do is make the shred full erasure, and ADR-0005 says so
at acceptance.** Its added-at-acceptance paragraph records that "a shred
destroys plaintext, not attribution": the tenant's permanent pseudonym, the
`tenant_ref`, sits in every message header and every retained backup, the
holder of the reference subkey can resolve it by guess-and-confirm forever,
and "the shred claim must never be stated as full erasure"
(`docs/adr/0005-rotation-and-crypto-shred.md:546-556`, read at `c85d400`).
Destroying the GCP key material does not touch any of that - decision 1
above keeps the reference subkey local and unrotated precisely so that it
does not. P3 step 4's row deletion stays as compliance-mandatory as ADR-0005
made it.

The mapping, against ADR-0005's procedures:

| ADR-0005 | this provider adds | irreversible |
|---|---|---|
| P3 tenant shred, step 2 (delete all wrappings) | `DestroyCryptoKeyVersion` on every version of the tenant's `CryptoKey` | **yes**, after the GCP destruction window elapses |
| P3 step 3 (drain caches) | unchanged; `max_age` still bounds it | n/a |
| P4 retire version *n* (delete one wrapping) | nothing - the tenant's `CryptoKey` is shared across master-key versions | **yes**, the wrapping only |

Two things this does not change. It is still not an `Encryptor.shred/2`:
ADR-0005 decision 10's argument against shipping one survives intact, because
the store delete is still the host's and the destroy is still a GCP API call
the host's runbook makes. And **GCP's scheduled destruction window is a delay,
not a reprieve to design around**: a version is `DESTROY_SCHEDULED` for the
key's configured destroy-scheduled duration (24 hours by default, settable at
key creation) and `RestoreCryptoKeyVersion` works during it. That window is a
safety net for the operator who ran P3
against the wrong tenant - ADR-0005's blast-radius table calls that "the
largest destructive action in the package" - and it is emphatically not a
reason to relax P3's first precondition, which is a recorded human decision.
The runbook says: the window exists, do not rely on it.

**Suspend is a third verb and it is not decided here.** IAM-revoke on the
tenant's `CryptoKey` plus a cache evict makes a tenant's data unreadable
*reversibly*, which is a thing ADR-0005 has no verb for - its vocabulary is
rotate and shred, and "suspend" appears nowhere in this repository. That this
provider makes such a verb cheap is a finding of this record; what the verb is
called, what surface it has, and whether it belongs in this package at all is
the decision of a sibling record - an amendment to ADR-0005 adding the third
verb, filed as `enc-8s9` and proposed in the same campaign as this one - cited
here as proposed at the time (accepted 2026-09-13) and not anticipated further. Nothing in decisions 1 through 8 depends on how it is settled.

**9. The GCP client stack is optional, checked at `init/1`, mirroring the AWS
stack exactly.**

`goth` (for Application Default Credentials and token refresh) and an HTTP
client are `optional: true` in `mix.exs`, beside `argon2_elixir`
(`mix.exs:83-87`, read at `c85d400`), and a host that does not use this
provider carries neither. This is the same obligation ADR-0001 decision 1
assigned and ADR-0002 decision 5 discharged for `Encryptor.Provider.Kms`:

> Its `init/1` checks `Code.ensure_loaded?(...)` and returns
> `{:error, {:missing_optional_dependency, :ex_aws_kms}}` when the host has
> not added the four optional deps [...]. The check is at start, not at first
> use, so a misconfigured deploy fails to boot rather than failing on a
> customer's first write.
> (`docs/adr/0002-key-providers.md:244-250`, read at `c85d400`)

Identical here, with `:goth` as the atom. The reason term is already in the
closed vocabulary (`lib/encryptor/provider.ex:201`, read at `c85d400`), so this
adds no error surface.

**The HTTP client is the host's, named in `init/1`.** `goth` needs one and so
does the KMS REST call, and the package will not pick between `finch`, `req`,
and `hackney` for a host that already runs one. `init/1` takes the module and
validates that it is loaded, on the same at-start principle.

**10. One `CryptoKey` per tenant is the intended shape, and the cost and quota
argument for it is recorded as a premise to re-check, not as a measured fact.**

The walk ruled that key count is effectively unbounded and that per-key-version
cost is noise against the per-tenant cost of a multi-tenant host, so a key per
tenant is right rather than merely tolerable. Recorded as ruled, and flagged:
**current GCP KMS pricing and the current per-project and per-ring resource
limits are not quoted here on purpose and must be re-verified against Google's
published figures when the implementation lands.** A record that quoted a
price would be wrong within a year and would be cited as though it were not.

What is structural rather than priced, and therefore safe to record:

- **Per-version cost is monthly and per *version*, not per key and not per
  tenant-row**, so the bill tracks live key versions, and decision 7's refusal
  of automatic rotation is also the thing that keeps that count equal to the
  tenant count rather than growing on a timer.
- **Operation cost is per `Encrypt`/`Decrypt` call, and the provider makes
  almost none of them.** The materials cache collapses provider round trips to
  one per partition per `max_age` (ADR-0002 decision 2, crediting ADR-0001
  decisions 6 and 7; `docs/adr/0002-key-providers.md:131`, read at `c85d400`), so a tenant with
  continuous traffic costs one `Decrypt` per cache lifetime, not one per
  encrypt. ADR-0002's roadmap line for GCP - "`encryption_key/2` does network
  I/O and must bound it" - is the obligation this satisfies, and the bound is
  the cache plus an explicit request timeout from `init/1`.
- **The alternative shapes are worse where it matters.** One shared key for
  all tenants makes decision 8's shred impossible, because destroying it
  shreds everyone. A key per region or per shard makes it coarse in the same
  way, proportionally. The per-tenant key is what makes the shred a per-tenant
  operation at all, so the cost argument is downstream of a correctness
  argument and would have to lose badly to change the answer.

## Consequences

**A host can run this package against GCP without the engine knowing.** The
adapter is a provider module, an optional dependency pair, and a callback.
No engine change, no descriptor added, no keyring widened, no change to any
application ciphertext. That is the strongest claim this record makes and it
is a direct consequence of decision 1's wrap shape.

**The store now holds two blob kinds and must say which is which.** A
root-vault wrapping is an engine message; a GCP wrapping is a GCP ciphertext
with a `key_id`. Decision 6 keeps them in different types on this side, but
the column they land in is `encryptor_ecto`'s or the host's, and a store that
records only `wrapped` cannot tell a reader which unwrap path to take. That is
a schema question for the downstream package and this record does not answer
it; it does raise it, and an implementation that ignores it will be found by
the first host that migrates from one shape to the other.

**Provisioning becomes a network operation that can half-succeed.**
`CreateCryptoKey` succeeds and then `Encrypt` fails, and a tenant now has a
GCP key and no wrapping. This is survivable by construction - decision 6 makes
a retry find the key and proceed - but it is survivable only because decision
4 made the id deterministic. The dependency between those two decisions is
real and an implementation that "simplifies" the id scheme to a random one
breaks the retry without any test noticing.

**An undeletable resource is created on the host's behalf, by a library
call.** A typo'd tenant identifier that reaches `provision/2` mints a GCP
`CryptoKey` that will exist for the life of the project. Its versions can be
destroyed; it cannot. This is a genuinely new kind of cost the package did not
previously impose - ADR-0003 decision 8's argument against lazy provisioning
("a typo in a tenant identifier silently mints a key") was about a wasted row,
and here it is about a permanent resource. The mitigation is that same
decision: provisioning is explicit, resolution never provisions, and there is
no path from a read to a create.

**The shred gets stronger and the runbook gets longer.** ADR-0005's P3 gains a
step that is more effective than the one it already had and is, unlike it,
genuinely outside the host's control once run. Operators inherit a procedure
whose irreversible step is now irreversible in a second, wider sense, with a
24-hour window that is a safety net and not a plan.

**Two vocabularies of "version" are now live in one system, and this record's
table is the only place they are reconciled.** ADR-0005 decision 1 had to do
this once already for `encryptor_ecto`. The guides and the provider's
moduledoc must carry decision 7's table, not a prose paraphrase of it.

## The contract as typespecs

The additions to `Encryptor.Provider`:

```elixir
@typedoc """
What `c:provision/2` returns: everything a store needs to reconstruct the
descriptor later, and never the plaintext key. Keyed by `tenant_ref`, never by
the raw selector (ADR-0004 decision 4 as amended).
"""
@type provisioned :: %{
        tenant_ref: String.t(),
        version: pos_integer(),
        namespace: String.t(),
        name: String.t(),
        bits: 256,
        wrapped: binary(),
        key_id: String.t()
      }

@doc """
Creates this selector's key material, where the provider is the thing that
can create it. Explicit: never called from `c:encryption_key/2` or
`c:decryption_keys/2` (ADR-0003 decision 8).

Not to be confused with `Encryptor.Envelope.provision/3`, which wraps under
a root vault and takes a vault module as its first argument.
"""
@callback provision(state :: state(), selector :: selector()) ::
            {:ok, provisioned()} | {:error, reason()}

@optional_callbacks init: 1, child_spec: 1, provision: 2
```

The reason vocabulary gains nothing. Every failure below is already a member
(`lib/encryptor/provider.ex:196-201`, read at `c85d400`), except
`{:not_provisionable, module()}`, which the vault wrapper returns for a
provider that does not implement the callback:

| failure | reason |
|---|---|
| `goth` or the HTTP client absent at start | `{:missing_optional_dependency, :goth}` |
| the selector has no key and none is being created | `{:unknown_key, selector}` |
| GCP unreachable, throttled, or IAM-denied | `{:key_unavailable, selector}` |
| GCP returned something that is not a usable key | `{:invalid_key_descriptor, detail}` |
| the provider needs a process and it is not up | `{:provider_not_started, module}` |
| `provision/2` called on a provider without it | `{:not_provisionable, module}` |

`{:key_unavailable, selector}` covering IAM denial alongside a network timeout
is deliberate: they are the same fact to a caller - the key exists and cannot
be had right now - and distinguishing them in the reason would put the shape
of the host's IAM into an error term. The GCP status belongs in telemetry
metadata under ADR-0006 decision 5's `reason_tag` rule and in the log, not in
the closed vocabulary.

The provider's `init/1` options:

```elixir
[
  project: "my-project",             # required
  location: "us-east1",              # required
  key_ring: "encryptor-tenant-keys", # required, exists already (decision 3)
  reference_subkey: <<...>>,         # required: tenant-vault configuration per
                                     # ADR-0004 dec 4 as amended; ADR-0003 dec
                                     # 6's "encryptor/v1/tenant-ref" subkey.
                                     # Local, start-time known-answer checked,
                                     # NOT replaced by GCP (decision 1)
  http_client: MyApp.Finch,          # required, must be loaded at start
  goth: MyApp.Goth,                  # required, the token server's name
  protection_level: :software,       # :software | :hsm, default :software
  key_id_prefix: "t-",               # default "t-"
  key_id_fun: nil,                   # decision 4's escape hatch
  timeout: 5_000                     # per-call, bounds decision 10's I/O
]
```

## Worked example: a multi-tenant host app onboarding and offboarding a tenant

The host runs one vault for application data. Its provider is this one, and
there is no root *vault* at all - the wrapping root is in GCP. The reference
subkey is still local and still configured, per decision 1: it is what makes
`tenant_ref` and `name`, and it is not a wrapping key.

```elixir
defmodule MyApp.TenantVault do
  use Encryptor.Vault, otp_app: :my_app
end

config :my_app, MyApp.TenantVault,
  provider:
    {Encryptor.Provider.GcpKms,
     project: "myapp-prod",
     location: "us-east1",
     key_ring: "encryptor-tenant-keys",
     reference_subkey: {:system, "ENCRYPTOR_REFERENCE_SUBKEY"},
     http_client: MyApp.Finch,
     goth: MyApp.Goth},
  store: MyApp.TenantKeys,
  max_age: :timer.minutes(5)
```

The ring `projects/myapp-prod/locations/us-east1/keyRings/encryptor-tenant-keys`
and the service account's two `useTo*` roles on it were created once, by the
platform team's Terraform, before this config ever ran (decision 3).

**Onboarding.** The host's tenant-creation transaction calls the vault:

```elixir
{:ok, provisioned} = MyApp.TenantVault.provision(tenant.id)
MyApp.TenantKeys.insert!(provisioned)
```

Inside, in order: derive `tenant_ref` from `tenant.id` under the configured
reference subkey (ADR-0003 decision 5) and `name` as `"t/<tenant_ref>/v1"`;
derive the key id as `t-` plus the base32 digest of the namespace and the
encoded selector (decision 4); `CreateCryptoKey` with that id,
`ENCRYPT_DECRYPT`, no rotation schedule (decision 3); 32 bytes from the CSPRNG;
`Encrypt` those bytes under the new key with the four-field AAD (decision 5);
return the map (decision 6) with the plaintext already out of scope. One row in
the host's store - keyed by `tenant_ref`, with `tenant.id` nowhere in it - one
key in GCP, and the plaintext existed inside one function body.

**A write.** `MyApp.TenantVault.encrypt(pii, key: tenant.id)`. The vault asks
`encryption_key/2` for this selector; the provider reads the store's current
row, calls `Decrypt` with the same AAD rebuilt from the row's own
`version`/`namespace`/`tenant_ref`, and returns `%Encryptor.Key.Aes{}`. The
vault builds a `RawAes` keyring from it and the engine writes an ordinary ESDK
message. The next write inside `max_age` makes no GCP call at all (decision
10). Nothing in the host names `AwsEncryptionSdk` and nothing in the host names
GCP.

**A read of something old.** `decryption_keys/2` returns every live version's
descriptor, newest first, one `Decrypt` per version on a cache miss. The
engine's `Multi` walk finds the one whose EDK matches.

**Offboarding.** ADR-0005 P3, quoted in its own numbering, with decision 8's
step added as 2a. P3's preconditions are unchanged and still come first - in
particular the recorded human decision that this tenant's data is to be
destroyed, which this record does not relax (decision 8).

1. Confirm the tenant reference resolves and enumerate the wrappings about to
   be destroyed; record the count and the version numbers in the change
   record. Unchanged.
2. Delete every wrapping for the tenant from the key store. Unchanged, and
   still the host's `DELETE`.
2a. `DestroyCryptoKeyVersion` on every version of `t-<digest>`. **New.** After
   the key's destroy-scheduled window the tenant's data is unreadable from any
   backup of the store, because the key that would unwrap it no longer exists
   anywhere.
3. Drain the caches: wait `max_age` on every vault serving the tenant, or
   restart them. Unchanged.
4. Optionally delete the tenant's ciphertext rows. Unchanged in mechanism, and
   ADR-0005's acceptance addendum makes it compliance-mandatory wherever
   tenant attribution is itself personal data - destroying the GCP key does
   not remove the `tenant_ref` from retained headers (decision 8).

The `CryptoKey` `t-<digest>` remains in the project forever, empty. That is
the cost decision 3 named, paid visibly.

## Open questions

Recorded rather than guessed. Each names who should settle it.

1. **How does a store distinguish the two wrapping shapes?** The consequences
   section raises it; `encryptor_ecto` owns it, because the column, the
   migration, and the row shape are that package's under ADR-0002 decision 5
   and ADR-0003 decision 9. The minimum is probably a discriminator column,
   but "probably" is why this is a question and not a decision, and deciding it
   here would be this package deciding downstream's schema.

2. **Does `provision/2` belong on the provider behaviour or on a separate
   `Encryptor.Provisioner` behaviour?** Decision 2 puts it on the provider,
   optional, which keeps one behaviour and one configured module. A separate
   behaviour would keep `Encryptor.Provider` at four callbacks and would let a
   host configure a provisioner without a provider, which is a thing nobody has
   asked for yet. Revisit if a third provisioning adapter arrives; the
   optional callback is cheap to move and expensive to have split early.

3. **Should the AAD encoding be shared with anything else?** Decision 5
   introduces a canonical serialization of ADR-0003 decision 4's context for
   GCP's byte-string AAD. If a Vault transit provider arrives it will want the
   same thing, and at that point the encoding should move out of this provider
   and be recorded as a package-level format. One caller is not yet a format.

4. **Is `{:key_unavailable, selector}` too coarse for an IAM denial in
   practice?** The typespec section argues it is correct. An operator
   debugging a misconfigured service account at three in the morning may
   disagree, and the honest answer is that nobody has debugged one yet. The
   telemetry metadata is the intended relief valve; if it turns out not to be
   enough, that is evidence for widening the vocabulary, and this package's
   owner decides.

5. **What does a host do about a tenant whose GCP key was destroyed by
   mistake?** Nothing, after the window. This is the same answer ADR-0005's
   blast-radius table gives for P3 step 2 and it is not made better by the
   window existing. Whether the package should refuse to help - no
   `destroy/2` function, by the same argument ADR-0005 decision 10 used
   against `shred/2` - is the neighbourhood of the suspend amendment
   (`enc-8s9`) and is named here so it is not lost.

## Note (2026-09-13): one decision-3 wording, and two cites

Three corrections, none of which changes a decision. Every cite below was
re-read by anchor at enc `ec6a84d`.

### Decision 3's "and algorithm" has no option behind it, and the option block is the contract

Decision 3 says the `CreateCryptoKey` call takes "protection level and
algorithm from `init/1` options, defaulted to `SOFTWARE` and the GCP default
symmetric algorithm, with `HSM` a configuration change and not a code change"
(`:262-264`). The record's own `init/1` option block (`:743-762`) lists
`protection_level:` and no `:algorithm`, and the implementation exposes none:
`Encryptor.Provider.GcpKms` validates `:protection_level` alone
(`lib/encryptor/provider/gcp_kms.ex:540-546`) and the create call sends
`%{"purpose" => "ENCRYPT_DECRYPT", "versionTemplate" => %{"protectionLevel" =>
...}}` with no algorithm field
(`lib/encryptor/provider/gcp_kms/api.ex:51-62`), so GCP applies its default
symmetric algorithm.

**The option block is the contract, and the implementation is right.** Read
decision 3's phrase as "protection level from `init/1` options; the algorithm
is GCP's default symmetric algorithm and is not configurable here". The rest
of the sentence stands unchanged: `HSM` is the configuration change it
describes, and it is reached through `protection_level:`. Only the symmetric
algorithm is affected, and decision 1 already fixes this provider to symmetric
wrap and unwrap, so there is nothing an `:algorithm` option could usefully
select today. Adding one is a decision and therefore an amendment, not this
Note.

### Decision 6's ADR-0003 quote gains the cite its neighbours carry

Decision 6's concurrency paragraph quotes ADR-0003 decision 8 by name - "a
race between two requests can mint two keys for one tenant" (`:481-482`) -
with no `file:line` and no read-at SHA, while every other quote in that cure
carries both. The quote is faithful. It resolves at
`docs/adr/0003-per-tenant-envelope.md:321-322`, read at enc `ec6a84d`; the
sentence it is drawn from is decision 8's, which begins at `:314` of that
file.

### Decision 6's `WrappedKey` cite is re-pointed at the text that states the claim

Decision 6 cites `lib/encryptor/envelope/wrapped_key.ex:72-83` for the claim
that `WrappedKey` "carries the assumption that `wrapped` is an engine message
produced by a root vault" (`:455-458`). Those lines are the `@type t` block
and `@enforce_keys`; they state the shape, not the assumption. The sentence
that states it is in the moduledoc: "`:wrapped` - the wrapping. A complete
`Encryptor` message produced by a root vault (decision 2), so this package
defines no wire format of its own" (`wrapped_key.ex:25-28`, read at enc
`ec6a84d`). Read the cite as `wrapped_key.ex:25-28` for the assumption and
`:72-83` for the struct the assumption is attached to; both ranges still
resolve, and the `c85d400` the decision labels them with was correct for the
struct block when it was written.

Nothing above changes. No decision is amended, no error vocabulary is added or
removed, and this Note carries the record's status rather than one of its own.

## Amendment A (2026-09-13): the operation-cost bullet restated on one provider resolution per call

Status: **proposed** (2026-09-13).

This amendment only adds, and it removes no line. Decisions 1 to 9 above keep
their text and their meaning, and so does decision 10's shape ruling - one
`CryptoKey` per tenant - together with its per-version cost axis. What A1
restates is one bullet inside decision 10, the operation-cost bullet at
`:627-634`, which was argued from a claim another record has now withdrawn.
This amendment's own decision is lettered `A1`, under the house convention this
repo's other records use for lettered amendments; a reference from outside this
section should be spelled "Amendment A's A1".

Every code and document line cited below was read at enc `efd71c5`, the tip of
`origin/main` when this amendment was written.

### Why now

Decision 10's cost bullet "Operation cost is per `Encrypt`/`Decrypt` call, and
the provider makes almost none of them" argues from ADR-0002 decision 2 that
"the materials cache collapses provider round trips to one per partition per
`max_age`", and concludes that "a tenant with continuous traffic costs one
`Decrypt` per cache lifetime, not one per encrypt" (`:627-632`). The worked
example repeats the conclusion: "The next write inside `max_age` makes no GCP
call at all" (`:815-816`).

The premise is gone. ADR-0002's Amendment A, proposed the same day, withdraws
that sentence and rules that the provider is resolved once per call, the
materials cache sitting in front of the CMM rather than in front of the
provider, so a cache hit saves the data-key generation and the keyring's EDK
wrap and never the provider lookup (`docs/adr/0002-key-providers.md`, Amendment
A's A1). ADR-0001's Amendment A had already reached the same fact from the
engine's side and marked this record's bullet as the load-bearing casualty: its
A5 posture table gives `Encryptor.Provider.GcpKms` the row "what it cannot save:
**the GCP `Decrypt` unwrap, paid on every call**" and says in the same cell that
this record's cost argument "rests on the round-trip claim A5 revises, and is
contradicted by this row; it needs the amendment named below"
(`docs/adr/0001-vault-layer.md:836`). This is that amendment. The measurement
behind all three is
`docs/measurements/260912-enc-anz-stated-bounds.md:107-123` - 500 encrypts on
one warm partition, cache on, 500 provider closure calls.

Nothing here disturbs this record's shape decision. A wrap-provider is a
material-source adapter whose resolve path does a network round trip, and that
is exactly why the cost lands where it does.

### A1. Continuous traffic on a GCP-backed vault costs one `Decrypt` per encrypt, not one per cache lifetime

**Read decision 10's operation-cost bullet (`:627-634`) as follows.** Operation
cost is still per
`Encrypt`/`Decrypt` call and still monthly-per-version on the other axis. But
the provider makes one `Decrypt` per vault call that needs a descriptor, not
almost none: a tenant with continuous traffic costs one `Decrypt` per encrypt,
and a read of something old costs one `Decrypt` per live version. The engine's
materials cache does not reduce that count, whatever `max_age` is set to.

**The bullet's obligation is met differently than it claimed.** ADR-0002's
roadmap line for GCP - "`encryption_key/2` does network I/O and must bound it" -
is still the obligation this record satisfies, and the bound is still an
explicit request timeout from `init/1` (`:632-634`). What the bound is not is
the engine's materials cache. The cache bounds how often the engine generates
and wraps a data key; it does not bound how often this provider calls GCP.

**The one thing that could collapse those calls is a cache this provider owns,
and ADR-0002 already says what such a cache must be.** Decision 2's last bullet
there permits a provider cache and constrains it in the same breath: "A
provider that caches anyway must bound it and document the bound"
(`docs/adr/0002-key-providers.md:130-136`). So the shape of an answer exists.
Choosing it does not belong to this amendment; see the open question below.

**Re-anchor the worked example's sentence.** "The next write inside `max_age`
makes no GCP call at all (decision 10)" (`:815-816`) is wrong on the same
premise. Its cross-reference is sound - decision 10 (`:610-641`) is where the
cost argument lives, and this amendment restates that bullet rather than
displacing the decision - so what needs re-anchoring is the claim, not the
citation. Read the sentence as: the next write calls `Decrypt` again, under
the same AAD rebuilt from the same row, and what it saves against a cold
vault is the store read only if the provider itself memoizes the row - which
today it does not. The sentence stays where it is, because an amendment
appends.

**This amendment states the cost rule and counts no call sites.** How many
`Decrypt` calls a given host makes is a property of its traffic and of the
provider's implementation, and belongs to that implementation's tests and to
the host's own measurement, not to this record.

### Open questions this amendment adds

1. **Should `Encryptor.Provider.GcpKms` bound a cache of its own?** This is the
   question A1 raises and does not answer. ADR-0002 decision 2's bullet already
   supplies the constraint any answer must meet - bounded, and documented - and
   ADR-0001's A5 consequence 2 says a material-source adapter that wants its
   round trips collapsed "caches them itself, under ADR-0002's rule"
   (`docs/adr/0001-vault-layer.md:845-851`). What is undecided is everything
   else: whether this provider should have one at all, what it would key on,
   what it would hold and for how long, how it would interact with the shred in
   decision 8 and with the version counters in decision 7, and what it would be
   called. **That is public surface and this amendment does not name an option,
   a default, or a policy for it.** It wants its own walk and its own record.

## Note (2026-09-14): the worked example's "on a cache miss" reads as one `Decrypt` per live version on every such read

Two corrections, neither of which changes a decision. Amendment A above keeps
every word it has and keeps its own status; this Note appends below it and
edits nothing. Every cite below was re-read by anchor at enc `110e266`.
Provenance: campaign RF048, bead `enc-9ro`, which folds in `enc-07g`.

### 1. The worked example's cost sentence still carries the premise Amendment A withdrew

The worked example says "**A read of something old.** `decryption_keys/2`
returns every live version's descriptor, newest first, one `Decrypt` per
version on a cache miss." (anchor "A read of something old", `:819-821`). The
qualifier "on a cache miss" points at a cache in front of the provider.
Amendment A's A1 rules that there is no such cache: "the provider makes one
`Decrypt` per vault call that needs a descriptor, not almost none: a tenant
with continuous traffic costs one `Decrypt` per encrypt, and a read of
something old costs one `Decrypt` per live version. The engine's materials
cache does not reduce that count, whatever `max_age` is set to." (anchor
"### A1. Continuous traffic on a GCP-backed vault costs one `Decrypt` per
encrypt, not one per cache lifetime", `:995-998`).

**Read the worked example's sentence as: `decryption_keys/2` returns every
live version's descriptor, newest first, and costs one `Decrypt` per live
version on every such read.** The qualifier names a cache this record does not
have, and the count it qualifies is the count A1 already states. The sentence
stays where it is, because a Note appends. Nothing else in the worked example
moves, and nothing is amended beyond the decision 10 operation-cost bullet
(`:627-634`, inside decision 10 at `:610-641`) that A1 already restates.

The same phrase appears in this repo's records about a **different** cache -
the engine's own decrypt-side comparison, at
`docs/adr/0004-encryption-context.md:345` and `:395` (read at enc `110e266`).
Neither of those is touched by Amendment A or by this Note.

### 2. Amendment A's "Why now" points at one table row, not one table cell

"Why now" quotes ADR-0001's A5 posture table as giving
`Encryptor.Provider.GcpKms` the row "what it cannot save: **the GCP `Decrypt`
unwrap, paid on every call**" and as saying "in the same cell" that this
record's cost argument "rests on the round-trip claim A5 revises, and is
contradicted by this row" (anchor "in the same cell", `:978`). The two quoted
strings sit in two different cells of one row: the first is the
"What it cannot save" column and the second is the "Recommended posture"
column of the `Encryptor.Provider.GcpKms` row
(`docs/adr/0001-vault-layer.md:836`, its header row at `:831`, read at enc
`110e266`).

**Read "in the same cell" there as "in the same row".** Amendment A's own
wording is left as written - a merged record's body is not rewritten by a Note
- and the claim it makes is unchanged: both strings are ADR-0001's, about this
provider, in one row of the A5 table.

## Note (2026-09-14): "it is still not an `Encryptor.shred/2`" names a function this package has never shipped

One reading, which changes no decision. Decision 8's closing paragraph opens
"Two things this does not change. It is still not an `Encryptor.shred/2`"
(anchor "Two things this does not change", `:562-563`, read at enc
`971f1bf`). The adverb "still" can be read as naming a function that exists
somewhere in this package and is merely not reached on the GCP path.

**Read it as: this package ships no `Encryptor.shred/2`, has never shipped
one, and this record adds none.** ADR-0005 decision 10 is the record that
declines one, and the argument the sentence says survives is that one: the
store delete is the host's, so a function here would imply knowledge of the
store's copies that this package does not have. Whether any `shred/2` exists
is a question for the surface rather than for a record's prose, and the
surface answers it: no such function is defined or generated, which a sweep
of `lib/` confirms at any SHA.

ADR-0005's own three mentions already read that way and are left exactly as
written - "No shred function" (anchor "- No shred function.",
`docs/adr/0005-rotation-and-crypto-shred.md:530-533`), "There is deliberately
no `shred/2`, no `retire/2`, and no `rotate/2`" (`:675-676`), and "Decision
10 declines `shred/2`" (`:989-991`), all read by anchor at enc `971f1bf`.
The "still not an" phrasing is this record's `:562` and nowhere else; a
residue note that also placed it at ADR-0005 `:531` was reading decision
10's hypothetical, which is a different sentence and needs no reading.

Provenance: campaign RF048, bead `enc-4hx`, folding `enc-2gq` (1).

Nothing above changes. No decision is amended, no error vocabulary is added or
removed, and this Note carries the record's status rather than one of its own.
