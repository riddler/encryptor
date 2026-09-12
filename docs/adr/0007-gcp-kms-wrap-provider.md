# ADR-0007: GCP KMS is a wrap-provider, not a keyring, and it owns the tenant key's whole lifecycle

Status: proposed (2026-09-12)

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
that row revised.** Nothing below contradicts ADR-0002; where this record
adds something ADR-0002 left open it says which sentence it is extending.

What "later, on demand" left undecided turns out to be more than an adapter
sketch, and that is why this needs a record of its own rather than a module
and a test.

**The engine cannot dispatch on a GCP key, and that is the whole design.**
ADR-0002 decision 1 records the engine's closed keyring dispatch: `Cmm.Default`
matches by struct type over `RawAes`, `RawRsa`, `Multi`, and the four AWS KMS
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
would relax a constraint rather than invalidate one. That is not a footnote; it decides who creates what. A
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

**4. The `CryptoKey` id is a keyed-free, collision-free derivation of the
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
  :crypto.hash(:sha256, [vault_namespace, 0, selector]),
  case: :lower, padding: false
)
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
map. ADR-0003 decision 4's package-owned context is a map. The provider
serializes the same four fields into a canonical, unambiguous encoding - keys
sorted, each field length-prefixed, no delimiter that a value could contain -
and requires it byte-identically on `Decrypt`:

```
"encryptor-purpose"        => "tenant-key-wrap"
"encryptor-tenant-ref"     => tenant_ref
"encryptor-key-version"    => Integer.to_string(version)
"encryptor-key-namespace"  => namespace
```

This is not decoration. GCP `Decrypt` fails when the AAD does not match, so
the AAD is what makes a wrapping that has been moved between tenants or
versions in the host's store fail closed instead of silently unwrapping, which
is precisely the property ADR-0003 decision 4 bought with the encryption
context and which would otherwise be lost when the engine message is replaced
by a GCP ciphertext. **The binding is the reason the two shapes are equivalent
in safety and not merely in function.** An implementation that skips it has
built a weaker provider that passes every test that does not test for this.

The canonical encoding is a new serialization and it is decided here rather
than inline, per this repository's rule that cryptographic choices are ADR
choices.

**6. The return of `provision/2`, and what it does about a key that is already
there.**

```elixir
@type provisioned :: %{
        selector: selector(),
        version: pos_integer(),
        namespace: String.t(),
        name: String.t(),
        bits: 256,
        wrapped: binary(),
        key_id: String.t()
      }
```

It is a map and not `%Encryptor.Envelope.WrappedKey{}` because `WrappedKey` is
the envelope's struct, enforcing `tenant_ref` and carrying the assumption that
`wrapped` is an engine message (`lib/encryptor/envelope/wrapped_key.ex:72-83`,
read at `c85d400`). Here `wrapped` is a GCP ciphertext and `key_id` is a field
the envelope has no room for. Reusing the struct would make the store unable
to tell the two blob kinds apart, which is the one thing a store holding both
must be able to do. The plaintext key still never appears in the return, which
is ADR-0003 decision 3 held exactly.

**An existing key is not an error, and provisioning still does not happen on
the read path.** `CreateCryptoKey` returning `ALREADY_EXISTS` means a previous
mint for this selector got as far as creating the key. The provider treats
that as success for the create step and continues to generate and wrap fresh
material - because decision 4 makes the id a pure function of the selector, an
`ALREADY_EXISTS` is always *this* tenant's key and never another's. What it
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
for this same reason, and called the mismatch "dangerous rather than
cosmetic". A third vocabulary has now arrived and gets the same treatment.

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
key creation) and `RestoreCryptoKeyVersion` works during it. That window is a safety net for the operator who ran P3
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
a sibling record's decision, cited here as proposed and not anticipated
further. Nothing in decisions 1 through 8 depends on how it is settled.

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
  one per partition per `max_age` (ADR-0002's own observation,
  `docs/adr/0002-key-providers.md:131`, read at `c85d400`), so a tenant with
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
descriptor later, and never the plaintext key.
"""
@type provisioned :: %{
        selector: selector(),
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
there is no root vault at all - the wrapping root is in GCP.

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

Inside, in order: derive `t-` plus the base32 digest of the namespace and
`tenant.id` (decision 4); `CreateCryptoKey` with that id, `ENCRYPT_DECRYPT`,
no rotation schedule (decision 3); 32 bytes from the CSPRNG; `Encrypt` those
bytes under the new key with the four-field AAD (decision 5); return the map
(decision 6) with the plaintext already out of scope. One row in the host's
store, one key in GCP, and the plaintext existed inside one function body.

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

**Offboarding.** ADR-0005 P3, with decision 8's step added:

1. Record the human decision to shred this tenant. Unchanged, and still first.
2. `DELETE` every wrapping row for the tenant. The host's, as ever.
3. `DestroyCryptoKeyVersion` on every version of `t-<digest>`. New. After the
   key's destroy-scheduled window the tenant's data is unreadable from any
   backup of the store, because the key that would unwrap it no longer exists
   anywhere.
4. Drain the caches, or wait `max_age`.

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
   against `shred/2` - is the sibling suspend record's neighbourhood and is
   named here so it is not lost.
