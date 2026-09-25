# ADR-0008: AWS KMS is the keyring-backed row, and the descriptor carries the client

Status: accepted (2026-09-13)

## Context

ADR-0002 decision 5 sorted every adapter into two shapes and gave AWS KMS the
whole of the first one:

> *Keyring-backed adapters* map onto a keyring the engine's dispatch already
> accepts. There are exactly two possible: raw AES material, and AWS KMS.
> (`docs/adr/0002-key-providers.md:205-206`, read at `75807a8`)

and then described the adapter in three sentences:

> `Encryptor.Provider.Kms` is the only adapter that returns
> `%Encryptor.Key.Kms{key_id: String.t(), mrk: boolean()}`, which the vault
> maps to `AwsKms.new/3` or `AwsKmsMrk.new/3` against a client built once in
> `init/1`.
> (`docs/adr/0002-key-providers.md:240-243`, read at `75807a8`)

ADR-0007 filled in the *other* row - the material-source row - for GCP KMS, and
in doing so it established the practice this record follows: a roadmap line is
expanded into a record before its code is written, rather than after. It also
said, in passing, what this record is for:

> **The engine's own GCP keyring is the exit, and it is not this record's
> work.** If `aws_encryption_sdk` ever grows a GCP KMS keyring, a
> *keyring-backed* GCP provider becomes possible: a descriptor naming the GCP
> key, dispatched by the engine [...]
> (`docs/adr/0007-gcp-kms-wrap-provider.md:199-203`, read at `75807a8`)

AWS KMS is that shape today, and it is the only member of it. That makes it
the harder case, because every decision ADR-0002 through ADR-0005 took about
identity, rotation, and the shred was taken against a descriptor whose header
fields this package writes - and a keyring-backed descriptor's header fields
are written by the engine instead.

**This record is ADR-0002 decision 5's keyring-backed row expanded, and in one
respect revised.** The classification stands: AWS KMS is keyring-backed, it
maps to the engine's own AWS KMS keyrings, and no other key manager ever will.
What is revised is that row's *spelling of the descriptor*. Decision 5 is where
the two-field `%Encryptor.Key.Kms{}` is written down -

> `Encryptor.Provider.Kms` is the only adapter that returns
> `%Encryptor.Key.Kms{key_id: String.t(), mrk: boolean()}`
> (`docs/adr/0002-key-providers.md:240-241`, read at `75807a8`)

- because decision 3 deliberately deferred it: its own code block is the
`%Encryptor.Key.Aes{}` struct alone (`:141-147`) and its prose says
"`%Encryptor.Key.Kms{}` is reserved for decision 5's KMS adapter and specified
there" (`:152-153`). So **decision 1 below amends ADR-0002 decision 5, by
addition of a third field to that spelling**, and it is decision 5 rather than
decision 3 that a reader should check. Decision 3's own rule - the set is
closed, package-owned, and a host cannot add a member - is untouched: the set
stays at exactly two members, and only one of them grows a field.

A second amendment, to ADR-0002 decision 4, is named in decision 3 below. Those
two are the whole of what this record changes in an accepted record, and both
are extensions rather than reversals.

**The index row for ADR-0002 was deliberately not edited while this record was
proposed** (it was marked amended at ADR-0007's acceptance, 2026-09-13). ADR-0008 was
`proposed`; an amendment does not take effect until the operator accepts it,
and an unaccepted record flipping an accepted one's status would be this
record flipping a status that is not its to flip. This is ADR-0007's practice
(`docs/adr/0007-gcp-kms-wrap-provider.md:47-52`, read at `75807a8`) and this
record follows it unchanged. Adding "amended" to ADR-0002's row in
`docs/adr/README.md` belongs with the acceptance of this record.

### The four gaps, stated before they are closed

The implementation attempt that produced this record stopped on four of them,
and each is a gap in what ADR-0002 said rather than a contradiction of it.

**1. The client has no channel from `init/1` to the keyring builder.** The
vault-internal builder's whole signature is `(vault, operation, descriptor)`:

> `@spec build(module(), Error.operation(), term()) :: {:ok, t()} | {:error, Error.t()}`
> (`lib/encryptor/vault/keyring.ex:57`, read at `75807a8`)

It sees no `Config` and no provider state. The engine's keyring, meanwhile,
refuses to exist without a client struct:

> `defp validate_client(nil), do: {:error, :client_required}`
> (`aws_encryption_sdk` v1.0.0,
> `lib/aws_encryption_sdk/keyring/aws_kms.ex:226`)

and the descriptor that is supposed to be the wire is closed at two fields:

> `@enforce_keys [:key_id]`
> `defstruct [:key_id, mrk: false]`
> (`lib/encryptor/key/kms.ex:41-42`, read at `75807a8`)

So the client reaches the builder through the descriptor, through a widened
builder signature, or not at all. Decision 1 picks.

**2. `name` is not this package's to write on this path.** ADR-0002 decision 4
makes `name` the version identity and makes it public because it lands in the
message header. On the KMS path the engine writes the header fields itself:

> `@provider_id "aws-kms"`
> (`aws_encryption_sdk` v1.0.0,
> `lib/aws_encryption_sdk/keyring/aws_kms.ex:163`)

> `edk = EncryptedDataKey.new(@provider_id, response.key_id, response.ciphertext)`
> (same file, `:273` and `:297`)

`response.key_id` is the key ARN as KMS returned it. A `%Key.Kms{}` has no
`namespace` and no `name`, and inventing either would put a field in the
descriptor that never reaches a header. Decision 3 says what plays the role
instead.

**3. The shared conformance suite is Aes-shaped, and it is a cross-package
contract rather than a test file.** It ships in `lib/`, and two of its
assertions read `name` off a descriptor:

> `names = Enum.map(descriptors, & &1.name)`
> (`lib/encryptor/provider/conformance.ex:230`, read at `75807a8`)

> `assert %RawAes{} = keyring`
> (`lib/encryptor/provider/conformance.ex:273`, read at `75807a8`)

> `assert Enum.map(children, & &1.key_name) == Enum.map(many, & &1.name)`
> (`lib/encryptor/provider/conformance.ex:278`, read at `75807a8`)

A `%Key.Kms{}` has no `name`, so a keyring-backed provider raises `KeyError`
inside the suite every adapter is held to - including `encryptor_ecto`'s key
store, whose acceptance is a green run of this suite and which has already
landed against its current shape. Decision 5 changes the suite and states the
sequencing.

**4. Nothing describes a `Multi` that mixes the two shapes.** The bead this
record unblocks asks for "multi-keyring overlap wiring ... for raw->KMS
migration", and no record says whether that is allowed, what it means for the
shred, or what stops the two kinds of encrypted data key from being confused
for one another. Decision 6 answers all three.

### A fifth thing, not in the stop report, found while writing this

`%Key.Kms{}`'s `:mrk` field is documented as the thing that "selects between
the single-region and multi-region keyrings"
(`lib/encryptor/key/kms.ex:15-16`, read at `75807a8`). At
`aws_encryption_sdk` v1.0.0 that selection is behaviourally inert:
`AwsKmsMrk.wrap_key/2` and `AwsKmsMrk.unwrap_key/3` both convert to an
`%AwsKms{}` and delegate
(`lib/aws_encryption_sdk/keyring/aws_kms_mrk.ex:200-226`), and `AwsKms`'s own
matching is already MRK-aware:

> `defp match_key_identifier(keyring, provider_info) do`
> `  if KmsKeyArn.mrk_match?(keyring.kms_key_id, provider_info) do`
> (`lib/aws_encryption_sdk/keyring/aws_kms.ex:384-385`)

Decision 8 says what to do about that, because an implementation that assumed
otherwise would write a passing test that proves nothing.

## Decision

**1. `%Encryptor.Key.Kms{}` gains a third field, `:client`, and the descriptor
is the client's only channel to the keyring builder. This amends ADR-0002
decision 5's descriptor spelling (`docs/adr/0002-key-providers.md:240-241`,
read at `75807a8`) by addition, and leaves decision 3's closed-set rule
untouched.**

```elixir
%Encryptor.Key.Kms{
  key_id: String.t(),
  mrk: boolean(),
  client: struct() | nil
}
```

`:client` is the engine's KMS client struct - whatever
`AwsEncryptionSdk.Keyring.KmsClient.ExAws.new/1` or a host's own
implementation of that behaviour returned - built once in the provider's
`init/1` and frozen into provider state for the life of the vault, exactly as
ADR-0002 decision 5 already said it would be. The provider copies the frozen
client onto every descriptor it answers with.

It is **not** added to `@enforce_keys`, and it defaults to `nil`. The struct
is already published at 0.2.0, and enforcing a new key would break a host that
had built one by hand. A `nil` client is caught by the builder with this
package's own reason, not the engine's:

```elixir
def build(vault, operation, %Kms{client: nil}) do
  {:error, invalid(vault, operation, {:missing_client, Kms})}
end
```

which is the same translation the module already performs on every engine
tuple it can anticipate - the reason a caller reads is this package's
vocabulary, never the engine's internals leaking one layer up
(`lib/encryptor/vault/keyring.ex:14-21`, read at `75807a8`).

**`%Kms{}` gets its own `checks/1` clause, because the module's superset rule
is not waived here.** `Encryptor.Vault.Keyring` states that "Our validation is
a superset of the engine's, so the construction below cannot fail on a
descriptor that reached it. If it ever does, the engine's own term arrives as
the detail rather than being swallowed - **that is a defect in this module's
validation**" (`lib/encryptor/vault/keyring.ex:39-44`, read at `75807a8`), and
`checks/1` today matches `%Aes{}` alone (`:148`). A `%Kms{}` path that let
`AwsKms.new/3`'s `:key_id_required`, `:key_id_empty`, `:invalid_key_id_type`
and `:invalid_client_type` reach a caller would therefore be shipping that
defect by design, and would contradict the paragraph above. So the validation
is ours, in the shape the module already uses for every other field:

```elixir
defp checks(%Kms{} = key) do
  with :ok <- validate_header_string(key.key_id, :key_id) do
    validate_client(key.client)
  end
end

defp validate_client(nil), do: {:error, {:invalid_key_field, :client, :missing}}
defp validate_client(%_{}), do: :ok
defp validate_client(_other), do: {:error, {:invalid_key_field, :client, :not_a_struct}}
```

`validate_header_string/2` is reused unchanged (`:158-165`): it already rejects
a non-string, an empty string, and a non-printable one, which is exactly the
engine's three `key_id` failures in this package's vocabulary. The
`{:missing_client, Kms}` clause above stays as the *dedicated* answer for the
commonest misconfiguration - a provider that forgot to copy the frozen client -
because `{:invalid_key_field, :client, :missing}` would not tell a reader that
the provider, rather than the descriptor's author, is at fault. The engine's
own terms therefore reach no caller, and if one ever does, it is the visible
defect `keyring.ex:39-44` says it is.

**Why the descriptor and not a widened builder signature.** The alternative is
to pass the vault's `Config` - which is in scope at every call site
(`lib/encryptor/vault/encrypt.ex:118-121`, `lib/encryptor/vault/decrypt.ex:131`,
`lib/encryptor/vault/rekey.ex:112` and `:118`, all read at `75807a8`) - and
have the builder reach `config.provider_state`. Three things are wrong with
it, in increasing order of seriousness:

- It changes `build/3` and `build_all/3`'s signature, and the conformance
  suite calls both with a bare module (`conformance.ex:179`, `:195`, `:269`,
  read at `75807a8`). Every adapter's test module downstream would move for a
  reason that has nothing to do with that adapter.
- `provider_state` is `term()` and deliberately opaque
  (`lib/encryptor/provider.ex:185`, read at `75807a8`). A vault-internal
  module pattern-matching into it makes every provider's state shape part of
  the vault's contract, which is the opposite of what `init/1` returning an
  opaque term is for.
- It would put the vault, not the provider, in the business of deciding
  *which key* - because reaching into state to find a client is one short step
  from reaching in to find a key id. ADR-0002 decision 3's sentence is
  load-bearing and would have to be rewritten rather than extended: "The
  vault, and only the vault, maps a descriptor to an engine keyring"
  (`docs/adr/0002-key-providers.md:150`, read at `75807a8`) is a claim about
  the *mapping*, and it survives only while the descriptor is a complete
  input to it.

**Why carrying a client on a descriptor is not the widening it looks like.**
The Aes descriptor already carries the single most sensitive value in the
system - `:material`, the raw wrapping key bytes. "The descriptor carries
everything the keyring needs" is the existing rule, and a client struct is
strictly less sensitive than key material. The field is additive, the
descriptor stays a dumb data struct whose validation is the vault's
(`lib/encryptor/key.ex:30-36`, read at `75807a8`), and the closed set stays
closed at two members.

**2. `:client` is redacted from `inspect/2`, for the same reason `:material`
is.**

```elixir
@derive {Inspect, except: [:client]}
```

mirroring `Encryptor.Key.Aes`'s own line (`lib/encryptor/key/aes.ex:80`, read
at `75807a8`). This is not decoration. The engine's shipped client carries a
free-form `config` keyword (`aws_encryption_sdk` v1.0.0,
`lib/aws_encryption_sdk/keyring/kms_client/ex_aws.ex:49-54`), which is where
`ex_aws` conventionally accepts a static access key id and secret. A
descriptor reaches an `Encryptor.Error`'s `:engine` field on some paths and a
host may well log one, so an unredacted client is a credential in a log line.

Two corollaries the implementation must honour and the reviewer must check:

- The `{:missing_client, Kms}` detail names the constraint, never the value,
  which is the rule `lib/encryptor/vault/keyring.ex:29-37` already states for
  every other detail term.
- Nothing key-shaped and nothing credential-shaped enters telemetry metadata.
  ADR-0006's allow-list already says this; `:client` joins the list of things
  it is saying it about. No telemetry module exists in `lib/` at `75807a8`,
  so this is an obligation on whoever ships one, not a change to it.

**3. On the keyring-backed path the key ARN is the version identity, and this
package writes no header field at all.**

ADR-0002 decision 4's three obligations were written for a `name` this package
mints. Each has an exact counterpart here, and the counterpart is the ARN:

- *A name is bound to bytes, forever.* An ARN is bound to a KMS key forever,
  and more strongly: AWS will not reissue it. Where the Aes obligation is a
  discipline a provider must keep, this one is enforced by the service.
- *A name travels in the clear.* So does the ARN - it is the EDK's provider
  info (`aws_kms.ex:273`), inside a header that is authenticated and not
  encrypted. It names an account id and a region. **A host whose tenant
  identifiers are recoverable from its KMS key aliases or key policies has
  published that mapping in every ciphertext**, which is the same warning
  ADR-0002 decision 4 gives about raw tenant identifiers in `name`, applied to
  the field the host actually controls here.
- *Every identity that may still appear in stored ciphertext stays in
  `decryption_keys/2`, newest first.* Unchanged as an obligation, and
  load-bearing for decision 6. **Its second half is amended by scoping, and
  this is the record's second amendment to an accepted record.** ADR-0002
  decision 4's third bullet does not stop at the ordering rule; it continues
  "Dropping a name from that list is what makes the messages written under it
  undecryptable, which is precisely the intended mechanism for crypto-shredding"
  (`docs/adr/0002-key-providers.md:190-197`, read at `75807a8`). That clause is
  true of the material-source shape and **false of the keyring-backed one**,
  for the reason decision 4's table row nine gives: the key material is in KMS
  and not in the dropped entry. So the clause is scoped to `%Key.Aes{}` and
  replaced, on the `%Key.Kms{}` path, by that row. Nothing else in ADR-0002
  decision 4 changes, and the ordering rule holds on both shapes.

What follows for the descriptor: `%Key.Kms{}` gets **no** `namespace` and
**no** `name` field. A field that never reaches a header would be a field two
readers would disagree about, and the one authority on what is in the header
is the engine.

**4. Rotation, the shred, and suspend, per shape. This is the record's
per-variant table and every claim below is scoped to one column.**

| | `%Key.Aes{}` (material source) | `%Key.Kms{}` (keyring-backed) |
|---|---|---|
| version identity | `name`, minted by the provider (ADR-0002 d4) | the KMS key ARN, assigned by AWS |
| header provider id | the descriptor's `namespace` | `"aws-kms"`, written by the engine |
| header provider info | `name` | the key ARN from the `GenerateDataKey` / `Encrypt` response |
| who holds the wrapping key | the host's key store, as a wrapped blob (ADR-0003 d2) | AWS KMS; nothing is stored |
| the data key is generated | by the engine, locally | inside KMS, by `GenerateDataKey` |
| ADR-0003's two-level envelope | yes | **no** - decision 7 |
| rotation (ADR-0005 R2, level 2) | mint a new `name`, prepend its descriptor, re-encrypt | point at a new KMS key, prepend its descriptor, re-encrypt |
| rotation that is invisible here | none | AWS KMS automatic key rotation: new backing material under the *same* ARN. Not R2, not R1, not an operation in this package's vocabulary at all |
| dropping the identity from `decryption_keys/2` | **is** the shred - the material exists nowhere else (ADR-0005 d3) | is **not** the shred - it hides the data from this vault while KMS can still decrypt it |
| the shred (ADR-0005 P3 step 2) | `DELETE` the wrapping from the key store | `ScheduleKeyDeletion` on the tenant's KMS key |
| irreversible | immediately, subject to backups of the store | after the KMS pending-deletion window; `CancelKeyDeletion` works inside it |
| does the shred survive a backup | only if every copy of the store was found (ADR-0005's residual) | yes - the key material was never in the backup |
| suspend (ADR-0005 Amendment A) | the vault-local deny gate, A3's first locus | the vault-local deny gate, **and** an IAM revoke on the key as A3's second locus |

Four things this table is asserting, spelled out because a table is easy to
skim past:

**a. ADR-0005 decision 3 stands verbatim and is not extended.** Its sentence -
"Rotation adds a name and a shred removes one. There is no third mechanism,
and pruning is manual" (`docs/adr/0005-rotation-and-crypto-shred.md:146-147`, read
at `75807a8`) - counts *mechanisms*, where a mechanism is a change to the
membership of what `decryption_keys/2` answers with; that is **ADR-0005's** own
definition, at `docs/adr/0005-rotation-and-crypto-shred.md:150`, read at
`75807a8`. Rotation on the KMS path still adds one member and a
retire still removes one. What changes is not the count but the *consequence*
of a removal, which is row nine of the table, and which is a fact about where
the key material lives rather than a new mechanism.

**b. On the KMS path, the candidate list stops being a shred instrument.**
This is the single most dangerous difference in the table and the reason it
exists. An operator who has internalised "delete the row and it is shredded"
will, on this path, have hidden data that AWS can still decrypt for anyone
with `kms:Decrypt` on the key - including from a backup of the ciphertext.
ADR-0005 P3's step 2 therefore reads differently per shape, and the
implementation's guide must carry this table rather than a paraphrase of it.
This is the same hazard ADR-0007 decision 7 guarded against for two version
counters and is guarded the same way: one table, reproduced, not restated.

**c. The shred gets *stronger* here, in exactly the sense ADR-0007 decision 8
described for GCP.** ADR-0005's honest residual is that "a shred is only as
good as the copies"; destroying the KMS key removes the wrapping key from
every backup at once, because it was never in one. And exactly as ADR-0007
decision 8 says, this does not make the shred full erasure
(`docs/adr/0007-gcp-kms-wrap-provider.md:541-551`, read at `75807a8`): on
this path there is no `tenant_ref` in the header, but the key ARN is in it,
and an ARN that an operator can map back to a tenant is attribution that
survives the shred. P3 step 4's row deletion stays as compliance-mandatory as
ADR-0005 made it.

**d. Suspend needs no new decision, only a second locus.** ADR-0005 Amendment
A decided the verb, its observable, and its surface, and A3 already names two
loci and ships the vault-local one. IAM revoke on a tenant's KMS key is the
second locus on this path, the same finding ADR-0007 recorded for GCP
(`docs/adr/0007-gcp-kms-wrap-provider.md:574-581`, read at `75807a8`) and
declined to build. This record declines it too, identically and for the same
reason: it is an AWS API call in the operator's runbook, and the package's
half is `Encryptor.Vault.suspend/2`, which already exists and needs nothing
from this record.

**5. The conformance suite becomes shape-aware through one private helper, and
the change is additive and behaviour-identical for every Aes-shaped
provider.**

Three assertions move, and nothing else in the suite does:

```elixir
# `assert_distinct_names/1`, replacing `& &1.name` at conformance.ex:230
names = Enum.map(descriptors, &identity/1)
assert names == Enum.uniq(names)

# `assert_candidate_keyring/1`, replacing conformance.ex:273 and :278
case descriptors do
  [one] ->
    assert keyring.__struct__ == expected_keyring(one)

  many ->
    assert %Multi{generator: nil, children: children} = keyring
    assert length(children) == length(many)
    assert Enum.map(children, &keyring_identity/1) == Enum.map(many, &identity/1)
end
```

against three private functions in `Encryptor.Provider.Conformance`:

```elixir
defp identity(%Encryptor.Key.Aes{name: name}), do: name
defp identity(%Encryptor.Key.Kms{key_id: key_id}), do: key_id

defp expected_keyring(%Encryptor.Key.Aes{}), do: AwsEncryptionSdk.Keyring.RawAes
defp expected_keyring(%Encryptor.Key.Kms{mrk: false}), do: AwsEncryptionSdk.Keyring.AwsKms
defp expected_keyring(%Encryptor.Key.Kms{mrk: true}), do: AwsEncryptionSdk.Keyring.AwsKmsMrk

defp keyring_identity(%AwsEncryptionSdk.Keyring.RawAes{key_name: name}), do: name
defp keyring_identity(%AwsEncryptionSdk.Keyring.AwsKms{kms_key_id: id}), do: id
defp keyring_identity(%AwsEncryptionSdk.Keyring.AwsKmsMrk{kms_key_id: id}), do: id
```

**Private, not a new public function, and the exit is named.** The obvious
alternative is `Encryptor.Key.identity/1` as published surface. It is not
taken, because exactly one caller needs it and a published function is a
promise. If a second caller appears - a host writing its own assertions, or a
guide that needs to render a descriptor's identity - promoting these to
`Encryptor.Key.identity/1` is a one-line move and is the named exit. One
caller is not yet an API.

**The name-shaped assertion keeps its name-shaped intent, and four doc sites
move with it.** `assert_distinct_names` is not renamed - renaming a public
assertion function in `lib/` would be a breaking change to the contract
downstream is held to, in service of a word. What changes is prose, at exactly
four places, all of them published description of a cross-package contract and
all of them wrong for a keyring-backed provider if left alone:

| site | what it says today | what it must say |
|---|---|---|
| `conformance.ex:65-67` | "Candidate names are distinct" | distinct *version identities*, per decision 3 |
| `conformance.ex:72-74` | "One element builds a bare `RawAes`" | the keyring its descriptor's shape maps to |
| `conformance.ex:259-262` | `assert_candidate_keyring`'s `@doc`, same claim | the same correction |
| `assert_distinct_names`'s `@doc` | "no two candidates share a name" | "name" means the descriptor's version identity: `name` on the Aes shape, the key ARN on the KMS shape |

All four are line counts read at `75807a8`; an implementation re-locates them
by anchor rather than by number.

**Sequencing, stated because a cross-package contract is being edited.**

- The suite ships in `lib/`, so `encryptor_ecto` sees this change only when it
  bumps its `encryptor` pin. It is not a surprise arriving under a running
  build.
- For any provider whose descriptors are all `%Key.Aes{}` - which is every
  green conformance case that exists today: `Static`, `Function` as every
  known host configures it, and `encryptor_ecto`'s landed key store -
  `identity/1` returns `&1.name`,
  `expected_keyring/1` returns `RawAes`, and `keyring_identity/1` returns
  `key_name`. Two of the three substitutions are then **term-for-term** what
  they are at `75807a8`; the single-candidate one is **outcome-identical**
  rather than term-identical, because it changes form from a struct match
  (`assert %RawAes{} = keyring`) to a struct-module comparison, which alters
  the failure message and nothing else. The change is additive in the strict
  sense: no existing case changes outcome.
- The in-repo proof obligation on `enc-03b` is a green run of the existing
  Aes-shaped conformance cases, unchanged, alongside a new KMS-shaped case -
  the full `mix quality`, not a scoped run.
- The cross-repo obligation is discharged by `encryptor_ecto` re-running its
  own suite at its pin bump, which it does anyway. **No `encryptor_ecto`
  change is expected.** If one turns out to be required, that is a genuine
  cross-package contract change rather than an additive one, and it is
  stop-and-report: the premise of this decision was wrong and the record needs
  amending before the code lands.

**6. The raw-to-KMS migration overlap is an ordinary mixed candidate list. It
needs no new mechanism, the encryption side is never mixed, and the reserved
`aws-kms` prefix is what makes it safe.**

The migration is two independent changes to what one provider answers, which
is ADR-0005 decision 2's window doing exactly what it was built to do:

1. `decryption_keys/2` begins returning both shapes - the new `%Key.Kms{}`
   first, then the live `%Key.Aes{}` versions, newest first as always.
2. `encryption_key/2` flips from the Aes descriptor to the Kms one. New writes
   go through KMS; nothing already written moves.
3. The host re-encrypts at its own pace (ADR-0005 R2, level 2).
4. When the re-encrypt pass is verified, the Aes versions are retired by
   ADR-0005 P4 - and on this side of the migration that retire *is* a shred,
   because the retired shape is the material-source one. Row nine of decision
   4's table applies per entry, not per list.

Three facts make this safe, and all three are properties of code that already
exists rather than things to build:

**The encryption path cannot mix.** `encryption_key/2` returns exactly one
descriptor (`lib/encryptor/provider.ex:249-250`, read at `75807a8`) and the
vault builds one keyring from it (`lib/encryptor/vault/encrypt.ex:121`). There
is no state in which a message is written under both shapes, so there is no
question about which one "wins".

**The engine accepts a mixed `Multi` on both paths.** `Multi`'s internal
dispatch has clauses for `RawAes`, `AwsKms`, `AwsKmsMrk` and their discovery
variants on the wrap side (`aws_encryption_sdk` v1.0.0,
`lib/aws_encryption_sdk/keyring/multi.ex:363-386`), and
`AwsEncryptionSdk.Cmm.Default` has the same set on both
(`lib/aws_encryption_sdk/cmm/default.ex:91-156`). The decrypt-side `Multi` the
vault builds carries `generator: nil`
(`lib/encryptor/vault/keyring.ex:101`, read at `75807a8`), walks its children
in order, and returns the first success - which is the rotation mechanism
already, unchanged.

**The two kinds of encrypted data key cannot be confused for one another, and
the reason is a rule this package already enforces.** A `RawAes` child accepts
an EDK only when the header's provider id equals its own namespace; an
`AwsKms` child accepts one only when the provider id is exactly `"aws-kms"`
(`lib/aws_encryption_sdk/keyring/aws_kms.ex:368-369`). And an Aes descriptor's
namespace can never be `"aws-kms"`, because the vault rejects the prefix
before it builds anything:

> `{:error, :reserved_provider_id} -> {:error, {:reserved_namespace, "aws-kms"}}`
> (`lib/encryptor/vault/keyring.ex:174`, read at `75807a8`)

against the engine's own `String.starts_with?(provider_id, "aws-kms")`
(`lib/aws_encryption_sdk/keyring/behaviour.ex:117`). So the partition between
the two shapes' EDKs is total and is enforced at descriptor validation, one
layer before a keyring exists. ADR-0002 decision 3's reserved-prefix bullet
(`docs/adr/0002-key-providers.md:165`, read at `75807a8`) was written as a
courtesy to the engine; it turns out to be the thing that makes decision 6
sound, and that is worth recording because a future relaxation of it would
break this in a way no test in either package would catch.

**What a mixed list costs.** One wrong-shape child costs a provider-id
comparison, which is cheaper than the wrong-name comparison ADR-0002 decision
4 already calls a performance property. A right-shape KMS child costs a
`Decrypt` round trip per attempt, bounded by the materials cache like every
other resolution cost (ADR-0001 decision 6). Ordering therefore matters more
than it did: **the Kms descriptor goes first while KMS is the write path**, so
the common case is one call and not a walk.

**7. A KMS-backed tenant path does not use ADR-0003's two-level envelope, and
`Encryptor.Provider.Kms` does not implement `provision/2`.**

This is the question the stop report raised as possibly-open. It is decided,
because leaving it open would leave `enc-03b` unable to start.

On this path the tenant's key *is* the KMS key. The engine's keyring calls
`GenerateDataKey` and KMS returns the data key already encrypted
(`aws_encryption_sdk` v1.0.0, `lib/aws_encryption_sdk/keyring/aws_kms.ex:273`).
There is no 32-random-byte tenant master key, no wrapping, no
`%Encryptor.Envelope.WrappedKey{}`, and no key-store row. ADR-0003 decisions 1
through 6 describe the material-source shape and are untouched by this record -
this is **scoping, not amendment**, because ADR-0003 scoped itself. Its own
Context defines the level this record removes:

> **Level 2, the tenant master key.** One key per tenant per version. It
> never encrypts application data either. It is the wrapping key the tenant
> vault's `RawAes` keyring is built from [...]
> (`docs/adr/0003-per-tenant-envelope.md:31-34`, read at `75807a8`)

A vault whose provider is this one builds no `RawAes` keyring for the tenant
at all, so ADR-0003's subject is simply absent on this path rather than
overruled on it.

Five consequences, each of which an implementation would otherwise have to
guess at:

- **`derive/2` is unavailable on this path, and that is already decided and
  already shipped.** `Encryptor.Vault.Derive` refuses any non-`%Aes{}`
  descriptor with `{:invalid_key_descriptor, :not_derivable}`
  (`lib/encryptor/vault/derive.ex:108-118`, read at `75807a8`), on ADR-0003
  Amendment A decision 5's ground that obtaining the material "would mean
  asking a key manager to export a key, which is the property a key manager
  exists to refuse". So a whole public entry point is typed-off on a
  KMS-backed vault, `enc-03b` writes no code for it, and a host that needs
  blind indexes needs the material-source shape. It is listed here because a
  record that specified the encrypt and decrypt paths and said nothing about
  the third one would read as an omission rather than a decision.
- **`Encryptor.Envelope` stays Aes-only.** Its descriptor validation already
  matches `%Aes{}` alone (`lib/encryptor/vault/keyring.ex:140`, read at
  `75807a8`) and `enc-03b` adds no `%Kms{}` clause to it. A `%Key.Kms{}`
  reaching `Encryptor.Envelope` is a defect, not a case.
- **`Encryptor.Provider.Kms` does not implement the optional `provision/2`
  callback.** ADR-0007 decision 2 made it optional and its `provisioned()`
  type is shaped entirely around a wrapped master key -
  `namespace`, `name`, `bits: 256`, `wrapped: binary()`
  (`lib/encryptor/provider.ex:220-228`, read at `75807a8`). None of those
  fields has a value on this path. Widening that type to accommodate a shape
  that has no wrapping would be new surface invented by an implementation, and
  a caller reaching for `provision/2` here correctly gets
  `{:not_provisionable, Encryptor.Provider.Kms}` from
  `Encryptor.Vault.Resolve.provision/3` (`lib/encryptor/vault/resolve.ex:138`,
  read at `75807a8`),
  which is the behaviour that already exists.
- **How a selector maps to a key ARN is host-supplied and out of band.** The
  provider resolves the mapping from what `init/1` was handed - a static map,
  a callback, or a store the host owns - in the manner
  `Encryptor.Provider.Static` and `Encryptor.Provider.Function` already
  establish. Creating the KMS key, its key policy, its alias and its grants is
  the operator's infrastructure, on the same split ADR-0007 decision 3 drew
  for the GCP key ring: the package produces and consumes keys, it does not
  own the container they live in. Whether per-tenant KMS key *minting* ever
  belongs in this package is open question 2.
- **ADR-0004's encryption context becomes the KMS encryption context, and the
  record names the consequence rather than deciding anything new.** The engine
  passes `materials.encryption_context` straight to KMS on `GenerateDataKey`,
  `Encrypt` and `Decrypt` (`aws_encryption_sdk` v1.0.0,
  `lib/aws_encryption_sdk/keyring/aws_kms.ex:262-268`, `:287-293`, `:396-401`).
  Two things follow that do not apply on the material-source path. It **travels
  further in the clear**: a KMS encryption context is recorded unencrypted in
  CloudTrail, so every key ADR-0004's profile composes - `tenant_ref` included -
  is in the host's AWS audit log as well as in the message header, which is the
  same hazard decision 3 names for the ARN and a wider blast radius than
  ADR-0004 was written against. And it must **match byte for byte on
  `Decrypt`**, which ADR-0004's byte-stable composition already guarantees and
  which is therefore a reason not to relax it. No decision is taken here because
  the engine leaves none to take; whether the context profile a host runs is
  *appropriate* to publish into CloudTrail is open question 5.

**8. `:mrk` selects the engine struct and nothing else, and `enc-03b` must not
assert a behavioural difference that v1.0.0 does not have.**

The mapping ADR-0002 decision 5 specified is implemented as written:
`mrk: false` builds `AwsKms.new(key_id, client)`, `mrk: true` builds
`AwsKmsMrk.new(key_id, client)`. The record keeps it because the two are
distinct struct types the engine dispatches on, and an engine version that
gives them different behaviour would then need no change here.

What the record adds is the warning: at `aws_encryption_sdk` v1.0.0 the two
are the same code path, per the Context's cites. The observable `enc-03b` may
assert is therefore **the struct type the builder produces**, and nothing
about decryption reach. A test that round-trips through a mock client and
claims to prove cross-region matching would pass identically with `mrk` set
the other way, which makes it a test that proves nothing and reports success -
the failure mode this package's conformance suite exists to prevent.

Grant tokens are not exposed. `AwsKms.new/3`'s `:grant_tokens` option is a
per-call authorization concern that belongs with the client if it belongs
anywhere, and adding a fourth descriptor field for it on speculation is the
widening decision 1 was careful not to do.

**9. The optional-dependency check runs at `init/1`, as ADR-0002 decision 5
already decided.** Restated only because the implementation needs the module
and the atom, not because anything is being decided:

```elixir
def init(opts) do
  if Code.ensure_loaded?(AwsEncryptionSdk.Keyring.KmsClient.ExAws) do
    {:ok, resolve(opts)}
  else
    {:error, {:missing_optional_dependency, :ex_aws_kms}}
  end
end
```

At start, not at first use, so a misconfigured deploy fails to boot rather
than failing on a customer's first write
(`docs/adr/0002-key-providers.md:244-250`, read at `75807a8`). The reason term
is already in the closed vocabulary (`lib/encryptor/provider.ex:196-201`, read
at `75807a8`), so this adds no error surface. A host supplying its own
`KmsClient` implementation instead of the shipped `ExAws` one passes the client
in `init/1` options and the check is skipped for it - the check is about the
shipped adapter's dependency, not about clients in general.

**The AWS deps are the host's, and `enc-03b` adds none of them to this
package's `mix.exs`.** This is the one thing about decision 9 an implementation
would otherwise get wrong. `mix.exs` at `8f182e3` declares two optional deps,
`argon2_elixir` (`:89`) and `goth` (`:96`), and no AWS client stack; the AWS
deps are optional deps of `aws_encryption_sdk`, and a dependency's optional
deps do not flow into a dependent's build. The shipped client module is itself
compiled only under `if Code.ensure_loaded?(ExAws.KMS)`
(`aws_encryption_sdk` v1.0.0,
`lib/aws_encryption_sdk/keyring/kms_client/ex_aws.ex:1-3`), so the guard above
is false in this package until the *host* adds them - which is exactly what
ADR-0002 decision 5 already says ("when the host has not added the four
optional deps", `:246-248`). Adding them here would make every consumer of
this package carry an AWS HTTP stack it did not ask for.

## Consequences

**The closed descriptor set stays closed, and it is now fully specified.**
Both members are buildable, both map to engine keyrings the dispatch already
accepts, and `{:no_keyring_mapping, Kms}` (`lib/encryptor/vault/keyring.ex:74`,
read at `75807a8`) is deleted along with the two moduledoc passages that
promised it would be: the "The keyring mapping is not here yet" paragraph
(`lib/encryptor/key/kms.ex:18-31`) and the "## The two fields" heading and list
above it (`:12-16`), which becomes three. That deletion is the visible end of ADR-0002 decision 5's
sequencing condition.

**A descriptor can now carry a credential, and two guards are all that stand
between it and a log line.** Decision 2's `@derive` and the detail-term
discipline. Neither is enforced by a type, both are enforced by review, and a
future third field would need the same consideration. This is a real
enlargement of what a descriptor is and the record does not pretend otherwise.

**Two shreds now live in one package, and they are not interchangeable.**
Decision 4's table is the only place they are reconciled, and every guide,
moduledoc and runbook step that mentions the shred must carry the table rather
than a prose paraphrase of it. This is the same obligation ADR-0007 decision 7
imposed for two version counters, and it is imposed here for the same reason:
an operator acting on the wrong row destroys data, or fails to.

**An operator gains a shred that survives backups and loses the one that is
instant.** `ScheduleKeyDeletion` has a mandatory pending window, so a KMS-path
shred is not complete at the moment the runbook step returns. ADR-0005 P3's
verification section - `{:unknown_key, selector}` rather than a decrypt
failure - is about the vault's view and is unaffected; what changes is that
"the data is unrecoverable" becomes true later than "the procedure finished".
The runbook must say so, and must not treat the window as a reprieve to design
around, on ADR-0007 decision 8's argument, which transfers unchanged.

**`encryptor_ecto` is unaffected and must be checked anyway.** Decision 5
argues the suite change is term-for-term identical for Aes-shaped providers in
two of its three substitutions and outcome-identical in the third.
That argument is why no coordination bead exists; the check at the pin bump is
why the argument being wrong is survivable.

**The engine's AWS optional deps become reachable for the first time.** They
have been declared and unexercised. `enc-03b` will exercise them through the
engine's `KmsClient.Mock` (`lib/aws_encryption_sdk/keyring/kms_client/mock.ex`),
and no live AWS call belongs in this repository's gate.

**Nothing about the material-source path changes.** No existing ciphertext
moves, no existing provider changes, no existing test changes outcome, and a
host that never configures this provider carries no new dependency and sees no
new behaviour.

## The contract as typespecs

The descriptor, complete:

```elixir
defmodule Encryptor.Key.Kms do
  @type t :: %__MODULE__{
          key_id: String.t(),
          mrk: boolean(),
          client: struct() | nil
        }

  @derive {Inspect, except: [:client]}
  @enforce_keys [:key_id]
  defstruct [:key_id, :client, mrk: false]
end
```

The builder's three new clauses, in `Encryptor.Vault.Keyring`. **Each one runs
`checks/1` before it constructs**, in the same `with` shape the shipped
`%Aes{}` clause uses (`lib/encryptor/vault/keyring.ex:58-66`, read at
`75807a8`) - that shape is not a style, it is what makes decision 1's
"no engine term reaches a caller" true, and a `case` around
`AwsKms.new/3` alone would hand the engine's own tuples straight to
`invalid/3`:

```elixir
def build(vault, operation, %Kms{client: nil}) do
  {:error, invalid(vault, operation, {:missing_client, Kms})}
end

def build(vault, operation, %Kms{mrk: false} = key) do
  with :ok <- checks(key),
       {:ok, keyring} <- AwsKms.new(key.key_id, key.client) do
    {:ok, keyring}
  else
    {:error, detail} -> {:error, invalid(vault, operation, detail)}
  end
end

def build(vault, operation, %Kms{mrk: true} = key) do
  with :ok <- checks(key),
       {:ok, keyring} <- AwsKmsMrk.new(key.key_id, key.client) do
    {:ok, keyring}
  else
    {:error, detail} -> {:error, invalid(vault, operation, detail)}
  end
end
```

with `@type t :: RawAes.t() | AwsKms.t() | AwsKmsMrk.t() | Multi.t()` replacing
the module's current two-member union at `lib/encryptor/vault/keyring.ex:54`
(read at `75807a8`).

The failure vocabulary gains **four detail terms**, all of them inside the
existing `{:invalid_key_descriptor, detail}` reason and all of them in shapes
the module already emits. No member of `t:Encryptor.Provider.reason/0` and no
member of `t:Encryptor.Error.reason/0` is added, and **no engine term reaches a
caller** - decision 1's `checks/1` clause is what guarantees that, and the
`with :ok <- checks(key)` step above is what makes the guarantee reach the
code:

| failure | what the caller sees | new? |
|---|---|---|
| descriptor built without a client | `{:invalid_key_descriptor, {:missing_client, Kms}}` | new |
| `checks/1` reached with a nil client | `{:invalid_key_descriptor, {:invalid_key_field, :client, :missing}}` | new, and unreachable through `build/3` - the dedicated head clause answers first. It exists so `checks/1` is total on its own, for the next caller that runs the checks without the construction, the way `Encryptor.Envelope` already does for `%Aes{}` (`lib/encryptor/vault/keyring.ex:140`, read at `75807a8`) |
| `client` present but not a struct | `{:invalid_key_descriptor, {:invalid_key_field, :client, :not_a_struct}}` | new detail, existing shape |
| `key_id` not a string, empty, or not printable | `{:invalid_key_descriptor, {:invalid_key_field, :key_id, :not_a_string \| :empty \| :not_printable}}` | new field name, existing shape |
| a descriptor reaches `Encryptor.Derive` | `{:invalid_key_descriptor, :not_derivable}` | pre-existing, already shipped |
| `ex_aws_kms` absent at vault start | `{:missing_optional_dependency, :ex_aws_kms}` | pre-existing |
| the selector has no KMS key | `{:unknown_key, selector}` | pre-existing |
| KMS unreachable, throttled, or IAM-denied | `{:key_unavailable, selector}` | pre-existing |
| `provision/2` called on this provider | `{:not_provisionable, Encryptor.Provider.Kms}` | pre-existing |

The five pre-existing rows are used unchanged. `{:key_unavailable, selector}`
covering IAM denial alongside a network timeout is deliberate and is ADR-0007's
argument verbatim: they are the same fact to a caller, and distinguishing them
in the reason would put the shape of the host's IAM into an error term.

The provider's `init/1` options:

```elixir
[
  client: %AwsEncryptionSdk.Keyring.KmsClient.ExAws{},  # or a host's own
  keys: %{"tenant-a" => "arn:aws:kms:us-east-1:111122223333:key/abcd1234"},
  mrk: false,                                          # default for every key
  region: "us-east-1"                                  # builds the shipped client
]
```

`:keys` is the static-map form, which is `Encryptor.Provider.Static`'s shape
applied to key ids rather than to material. The callback form, matching
`Encryptor.Provider.Function`, is `enc-03b`'s to settle against those two
adapters' existing option grammars; it is an implementation detail because
both shapes already exist in this package and neither is a contract question.

## Worked example: a multi-tenant host app migrating one tenant from raw keys to KMS

The host has been running the Ecto-backed key store: per-tenant AES material,
wrapped into rows, two live versions for a tenant part-way through an ordinary
rotation. It is moving to KMS.

**Before.** `decryption_keys/2` answers two Aes descriptors, newest first:

```elixir
[
  %Encryptor.Key.Aes{namespace: "myapp", name: "t/9f2c/v3", material: <<...>>, bits: 256},
  %Encryptor.Key.Aes{namespace: "myapp", name: "t/9f2c/v2", material: <<...>>, bits: 256}
]
```

and `encryption_key/2` answers the first. The vault builds a `Multi` of two
`RawAes` children on the decrypt path and a bare `RawAes` on the encrypt path.

**Step 1: the KMS key exists, out of band.** The platform team creates
`arn:aws:kms:us-east-1:111122223333:key/abcd1234`, its key policy, and the
application role's `kms:GenerateDataKey` and `kms:Decrypt` grants. The package
creates nothing (decision 7).

**Step 2: the overlap.** The host's provider - a composite of its key store and
this one, or its key store extended - begins answering three descriptors:

```elixir
[
  %Encryptor.Key.Kms{key_id: "arn:aws:kms:us-east-1:111122223333:key/abcd1234", client: client},
  %Encryptor.Key.Aes{namespace: "myapp", name: "t/9f2c/v3", material: <<...>>, bits: 256},
  %Encryptor.Key.Aes{namespace: "myapp", name: "t/9f2c/v2", material: <<...>>, bits: 256}
]
```

and `encryption_key/2` answers the `%Key.Kms{}`. The vault builds
`Multi.new(generator: nil, children: [%AwsKms{}, %RawAes{}, %RawAes{}])` on the
decrypt path. Nothing was migrated; every stored ciphertext still reads. A
message written under `t/9f2c/v3` reaches the `AwsKms` child first, which
declines it on `{:provider_id_mismatch, "myapp"}` without a network call, then
the first `RawAes` child, which decrypts it (decision 6).

**Step 3: writes move.** New messages carry an EDK whose provider id is
`"aws-kms"` and whose provider info is the key ARN. The data key was generated
inside KMS. Nothing in the host's code changed; nothing in the host's store
gained a row.

**Step 4: the re-encrypt pass.** ADR-0005 R2, level 2, at the host's pace,
`rekey/2` per row. Its finish line is checkable: no ciphertext for the tenant
carries an EDK with provider id `"myapp"`.

**Step 5: retire the Aes versions.** ADR-0005 P4 per version: delete the
wrapping, drain the caches, confirm. On this side of the migration the retire
*is* a shred - the material existed only in those rows. The candidate list
becomes one `%Key.Kms{}` and the vault builds a bare `%AwsKms{}` rather than a
`Multi` (decision 5's `expected_keyring/1` is what asserts that in the suite).

**Later: offboarding that tenant.** ADR-0005 P3, with step 2 read from the KMS
column of decision 4's table: `ScheduleKeyDeletion` on
`.../key/abcd1234`, not a `DELETE` - there is no row to delete. After the
pending window the tenant's data is unreadable from every backup of every
store, because the key that would unwrap it is gone from AWS. The key ARN
remains in every retained header, and mapping it back to a tenant remains
possible for whoever holds the host's key-to-tenant mapping, which is why P3
step 4 stays compliance-mandatory.

## Open questions

Recorded rather than guessed. Each names who should settle it.

1. **Does a host want one KMS key per tenant, or one key with per-tenant
   encryption context?** This record is silent, and the silence is deliberate:
   decision 7 puts the selector-to-ARN mapping in the host's hands, so both
   shapes work without a package change. The trade is decision 4's table row
   nine - a shared key makes the KMS-path shred impossible per tenant, exactly
   as ADR-0007 decision 10 argued for GCP - against AWS's per-key quotas and
   per-key monthly cost. **No figures are quoted here on purpose**: a record
   that quoted a price would be wrong within a year and would be cited as
   though it were not. The host decides; the package's guide should carry the
   trade.

2. **Should `Encryptor.Provider.Kms` ever mint keys?** Decision 7 says it does
   not, on the ground that `provisioned()` has no meaning without a wrapping.
   ADR-0007 decision 3 took the opposite route for GCP because tenant keys
   arrive with tenants and no infrastructure-as-code plan can enumerate them,
   and that argument transfers to AWS unchanged - what does not transfer is the
   return type. If a host asks, the answer is probably a `provisioned()` that is
   a tagged union rather than one map, and that is a change to ADR-0007's
   decision 2 rather than to this record. This package's owner decides, and a
   sibling record does it.

3. **Does the key ARN in the header need the same warning `name` got?**
   Decision 3 says it travels in the clear and names the hazard. What it does
   not do is recommend a mitigation, because there is none inside this package:
   the ARN is AWS's, an alias does not appear in the EDK, and the only lever is
   the host's naming discipline for keys and the account structure it puts them
   in. Whether the guide should push harder than "be careful" is the guide
   author's call.

4. **Is `:mrk` worth keeping as a descriptor field at all?** Decision 8 keeps
   it and explains why, but the honest position is that it selects between two
   engine structs that are the same code path today. If `aws_encryption_sdk`
   settles that they will remain identical, the field is a published promise
   with nothing behind it, and removing it would be a breaking change this
   package would rather not have to make later. Re-check at the next engine
   version; this package's owner decides.

5. **Should a KMS-backed vault run a narrower encryption-context profile?**
   Decision 7 records that ADR-0004's composed context reaches CloudTrail
   unencrypted on this path. ADR-0004 fixed the profile against a threat model
   in which the context travels in the message header only, and this record does
   not reopen it, because narrowing the context would change what a message
   binds - an ADR-0004 decision, taken in an ADR-0004 amendment, with the
   `tenant_ref`-in-the-header argument reconsidered as a whole rather than for
   one provider. Named here so the first host to read its own CloudTrail is not
   the first to notice. This package's owner decides.
   *Answered (2026-09-13, proposed): no. ADR-0004 Amendment A ("the composed
   context on a KMS-backed vault") decides that the context profile is
   unchanged on this path and that this package ships no per-provider
   narrowing, because there is one context object on the KMS path - narrowing
   what KMS sees narrows what the message binds, spending ADR-0004 decision 6's
   anti-substitution guarantee to quiet a log the host owns. What the amendment
   adds instead is a disclosure obligation in `Encryptor.Provider.Kms`'s
   generated documentation. Merged at proposed; see
   `docs/adr/0004-encryption-context.md`, section "Amendment A (2026-09-13)".*

6. **What does a mixed candidate list cost when the KMS child is cold and
   wrong?** Decision 6 asserts a provider-id comparison, which is correct for
   the `RawAes`-versus-`aws-kms` direction. The reverse - a stored
   `"aws-kms"` EDK offered to an `AwsKms` child holding a *different* ARN - is
   also local (`match_key_identifier` parses and compares before any call), but
   a host running several KMS keys per tenant would be walking them. Nobody has
   run that shape yet, and the materials cache bounds it either way. Evidence
   from the first host that does is what should settle whether the guide needs
   to say anything.

## Note (2026-09-13): three prose corrections

Three corrections to prose, none of which changes a decision. Cites re-read by
anchor at enc `ec6a84d`.

### The "each one runs `checks/1`" sentence covers the two constructing clauses

"The contract as typespecs" introduces the builder's three new clauses with
"**Each one runs `checks/1` before it constructs**". The block below it shows
three clauses, and the first - `build(vault, operation, %Kms{client: nil})` -
returns `{:error, invalid(vault, operation, {:missing_client, Kms})}`
immediately and constructs nothing, so there is nothing for it to run
`checks/1` before.

Read the sentence as **each clause that constructs a keyring runs `checks/1`
first**, which is the two `%Kms{mrk: false}` and `%Kms{mrk: true}` clauses. The
claim the sentence exists to make is untouched: no engine term reaches a
caller, because every path that calls into `AwsKms.new/3` or `AwsKmsMrk.new/3`
funnels its `{:error, detail}` through `invalid/3`, and the nil-client clause
never reaches the engine at all. Decision 1's own discussion of the dedicated
head clause already says the same thing from the other side - the failure
table's row for "`checks/1` reached with a nil client" calls that term
"unreachable through `build/3` - the dedicated head clause answers first".

### The failure table's `Encryptor.Derive` is `Encryptor.Vault.Derive`

The failure table's last row reads "a descriptor reaches `Encryptor.Derive`"
(`:797`). The module is `Encryptor.Vault.Derive`
(`lib/encryptor/vault/derive.ex:118` raises
`{:invalid_key_descriptor, :not_derivable}` there), and this record names it
correctly elsewhere - decision 4's "`Encryptor.Vault.Derive` refuses any
non-`%Aes{}`" (`:570`). Read the table row as `Encryptor.Vault.Derive`. There
is no `Encryptor.Derive` module in this package.

### Open question 5's closure quotes the ADR-0004 section by a prefix of its heading

The answer line under open question 5 points at
`docs/adr/0004-encryption-context.md`, section "Amendment A (2026-09-13)". The
heading in that file reads "Amendment A (2026-09-13; proposed): the composed
context on a KMS-backed vault", so the quoted title is a prefix rather than the
exact heading. The pointer resolves, and the parenthetical it quotes is the
half that changes when the operator flips that amendment's acceptance.

Read the pointer as naming the section **Amendment A** of
`docs/adr/0004-encryption-context.md`, unadorned. Quoting the status
parenthetical of a proposed amendment inside another record's answer line is
what made this stale-able; the unadorned section name is stable across the
flip.

Nothing above changes. No decision is amended, no error vocabulary is added or
removed, and this Note carries the record's status rather than one of its own.

## Note (2026-09-13): open question 5's status references after the flip, and the failure table's "raises"

Two corrections, neither of which changes a decision. The first is a status
reference that the acceptance flips of 2026-09-13 made stale; the second is a
verb in the Note above that describes the wrong control flow. Cites re-read by
anchor at enc `bdbb63c`.

### ADR-0004 Amendment A is accepted, so "proposed" and "Merged at proposed" are history, not status

Open question 5's answer line opens "*Answered (2026-09-13, proposed)*" and
closes "Merged at proposed; see `docs/adr/0004-encryption-context.md`, section
"Amendment A (2026-09-13)".*" The section above, "Open question 5's closure
quotes the ADR-0004 section by a prefix of its heading", quotes that heading
as "Amendment A (2026-09-13; proposed): the composed context on a KMS-backed
vault".

The operator accepted that amendment on 2026-09-13. Its heading now reads
"Amendment A (2026-09-13; accepted 2026-09-13): the composed context on a
KMS-backed vault" and its own `Status` line reads "**accepted (2026-09-13)**,
by the operator's reading"
(`docs/adr/0004-encryption-context.md`, section "Amendment A", read at enc
`bdbb63c`).

Read both references as naming the section **Amendment A** of
`docs/adr/0004-encryption-context.md`, unadorned - which is exactly what the
section above already prescribes for the pointer, and the reason it gives
applies to the answer line's own parenthetical too. "Merged at proposed"
records how the answer landed on this record, not how the amendment stands
today; it stays true as a record of the landing and should be read as one.

### `Encryptor.Vault.Derive` returns an error tuple; it does not raise

The section above, "The failure table's `Encryptor.Derive` is
`Encryptor.Vault.Derive`", says that module "raises
`{:invalid_key_descriptor, :not_derivable}`". It does not raise. The
catch-all clause returns an error tuple, and `error/2` wraps the reason in an
`%Encryptor.Error{}` carrying `operation: :derive`
(`lib/encryptor/vault/derive.ex:117-118` for the returning clause and
`:124-127` for the wrap, both read at enc `bdbb63c`).

Read "raises" as **refuses with**, which is this record's own phrasing for a
returned refusal and the verb decision 4 already has right:
"`Encryptor.Vault.Derive` refuses any non-`%Aes{}`". The correction that
section exists to make - the module is `Encryptor.Vault.Derive`, and no
`Encryptor.Derive` module exists in this package - is untouched, and so is
decision 4.

Nothing above changes. No decision is amended, no error vocabulary is added or
removed, and this Note carries the record's status rather than one of its own.

## Note (2026-09-13): the `derive/2` bullet names the generated vault's arity

Decision 7's first consequence bullet, "`derive/2` is unavailable on this path",
names the arity a host calls on its own vault module - `MyApp.Vault.derive/2`
(`lib/encryptor/vault.ex:280-283`, read at enc `b359bce`). The package function
it delegates to is one arity wider, `Encryptor.Vault.derive/3`
(`lib/encryptor/vault.ex:473-474`, read at enc `b359bce`), and the refusal
itself is `Encryptor.Vault.Derive`'s catch-all
(`lib/encryptor/vault/derive.ex:117-118`, read at enc `b359bce`). Read the
bullet as naming the entry point a host calls rather than the package function
behind it; both are unavailable on this path, and the bullet's decision is
neither narrowed nor widened by saying which arity it names.

Nothing above changes. No decision is amended, no error vocabulary is added or
removed, and this Note carries the record's status rather than one of its own.

## Note (2026-09-14): decision 7's audit-log enumeration under a signing suite, open question 5's own status parenthetical, and the malformed-`%Kms{}` detail term

Three items, none of which changes a decision. Decisions 1 to 12, the failure
table and the open questions stand as written, no error term is added, and
this Note carries the record's status rather than one of its own. Every cite
was read by anchor at enc `971f1bf`, with `aws_encryption_sdk` at the version
`mix.lock` pins (`1.0.0`, `mix.lock:3`). Provenance: bead
`enc-4hx`, folding `enc-15q`, `enc-83l` (b) and `enc-oxx`.

### 1. Under a signing suite the KMS API also receives the engine's reserved pair

Decision 7's second bullet says a KMS encryption context "is recorded
unencrypted in CloudTrail, so every key ADR-0004's profile composes -
`tenant_ref` included - is in the host's AWS audit log as well as in the
message header" (anchor "It **travels further in the clear**", `:610-615`).
That is true, and as an enumeration of what a reader will find in the audit
log it is short by one engine-owned pair.

**The rule: what the KMS API receives on this path is the composed context
plus, under a signing algorithm suite, the engine's reserved
`aws-crypto-public-key` pair.** This package's default suite is a signing
one, so a vault that says nothing about the suite is a vault whose CloudTrail
carries that pair.

The evidence and the enumeration live in one place rather than two: ADR-0004's
Note of 2026-09-13, "under a signing suite the KMS API receives the composed
context plus the engine's reserved `aws-crypto-public-key` pair"
(`docs/adr/0004-encryption-context.md:1331` to the end of that file, anchor at
the heading, read at enc `971f1bf`), states the rule, names the engine call
sites, and records that the pair carries a signature *verification* key which
the message header already carries in the clear. Decision 7 is neither
narrowed nor widened by this: the hazard it names is the hazard, nothing in
the context is removed, and the profile is unchanged. A reader checking what
reaches CloudTrail on this path reads that Note; a reviewer checking this
bullet against the engine reads it there too.

### 2. Open question 5's own "(2026-09-13, proposed)" parenthetical is this record's status, not ADR-0004's

The Note above, "open question 5's status references after the flip, and the
failure table's "raises"" (anchor at `:1012`), reads the two references that
quote ADR-0004 Amendment A's heading and rules that both name that section
unadorned. Open question 5's answer line opens with a third parenthetical
that quotes nothing of ADR-0004's: "*Answered (2026-09-13, proposed)*"
(`:940`).

**Read it as written: it is the status of this record's answer, on this
record, and no flip of ADR-0004 touches it.** It moves when this record's own
`Status` line moves, which is the operator's reading and never a Note's. That
is exactly the distinction the Note above turns on - a *quoted* status
parenthetical belonging to another record goes stale when that record is
accepted, an *own-status* parenthetical does not - and it is why that Note
left this one alone rather than by oversight. The same reading applies to
every "(date, proposed)" this record writes about itself.

### 3. The malformed `%Kms{}` descriptor gets no new detail term until open question 4 is answered

`Encryptor.Vault.Keyring.build/3`'s catch-all files a *recognised but
malformed* descriptor - a `%Encryptor.Key.Kms{}` whose `:mrk` is neither
`true` nor `false` - as `{:not_a_descriptor, Encryptor.Key.Kms}`, naming the
module it recognised rather than the field that was wrong
(`lib/encryptor/vault/keyring.ex:110-122`, anchor "# A term neither clause
above matched.", read at enc `971f1bf`). The case is unreachable through
`Encryptor.Provider.Kms`, which sets `:mrk` itself, and the module already
carries a comment saying so.

**The ruling: the detail vocabulary gains no term for it here, and the
failure table gains no `:mrk` row** (the table is `:791-801`, anchor
"| failure | what the caller sees | new? |"). `Encryptor.Error`'s reason
set is extended by a record and never by an implementation, and the record
that would extend it is the one whose open question 4 asks whether the field
survives at all: "Is `:mrk` worth keeping as a descriptor field at all?"
(`:923-929`) records that the field selects between two engine structs that
are the same code path today, that keeping it is a published promise with
nothing behind it if the engine settles that way, and that the answer waits
for the next engine version. Naming a field in the error vocabulary is a
second published promise about that field, and this record will not make one
about a field it may remove. **Open question 4 is answered first; only if
`:mrk` stays does a term follow.**

If it stays, the spelling is not left open either - the table fixes it by its
own shape rather than by a later choice. The `:client` and `:key_id` rows
read `{:invalid_key_descriptor, {:invalid_key_field, <field>, <detail>}}`
(`:794` and `:795` for `:client`, `:796` for `:key_id`), so the term is
`{:invalid_key_field, :mrk, :not_a_boolean}`, reusing the detail atom this
package already spells for an option that is not a boolean
(`lib/encryptor/vault/config.ex:649`, anchor `telemetry_tenant_ref`, read at
enc `971f1bf`) rather than coining a second spelling for the same fact.

Until open question 4 is answered, no code changes, no row is added, and no
test asserts a term that does not exist. A reviewer checking this reads
`Encryptor.Error`'s reason set against the table and expects no `:mrk`
anywhere in either.

Nothing above changes. No decision is amended, no error vocabulary is added or
removed, and this Note carries the record's status rather than one of its own.
