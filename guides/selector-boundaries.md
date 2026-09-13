# Selector boundaries

Every vault in this package addresses key material by a **selector**. This
guide is about choosing what a selector *is* in your system, because that
choice is not a naming decision - it fixes the unit you can offboard, and the
unit you can offboard is the unit you can cryptographically erase.

Read the [getting-started guide](getting-started.md) first if you have not
stood a per-tenant vault up yet, and the
[rotation runbook](rotation-runbook.md) for the procedures this guide only
names.

## A word about "partition"

This package already uses "partition" for something else, and the collision is
worth clearing before anything below.

**A partition here is the cache partition id**: a fixed-width value hashed
from the vault namespace and the encoded selector, passed to the engine's
caching materials manager as a cache-key input. ADR-0001 decision 7 defines
it and says what it is not - "a cache-key input only. It is not key material,
it is not secret, and it never reaches the message". `Encryptor.Vault.Partition`
is the only place it is computed.

**The boundary this guide is about is the selector**, and the thing minted at
that boundary is a *tenant master key*. ADR-0007 carries the same warning into
every one of its decisions, and uses "tenant mint" for the moment a boundary's
key material is first created. If you arrived here from a design conversation
that said "partition" for a tenant, that is the word it meant.

## The selector is host-defined

ADR-0004 settles what a selector is. Its review item A7 confirms the
assumption the Ecto layer was built on:

> Tenant key material is addressed by an opaque tenant identifier the host
> already has as a string.

and its first open question says the other half outright:

> Tenant identity itself is the **host's** - the package never mints,
> validates, or interprets a tenant identifier; it requires only that it be a
> non-empty string (decision 3) and treats it as opaque thereafter.

Two halves, and both do work.

**Opaque.** This package never parses a selector, never looks inside it, and
attaches no meaning to its shape. It is hashed into a cache partition id, it
is encoded into the tenant reference, and it comes back verbatim in
`{:unknown_key, selector}` and `{:key_unavailable, selector}`. Nothing else
reads it. Anything you can name with a stable string can be a selector.

**A string.** ADR-0001 originally typed the selector `term()`; ADR-0004
decision 3 narrows it to a non-empty `String.t()` on a `:tenant` vault, and
A7 is where that tightening is recorded against the downstream assumption. An
integer id is stringified by the host at the boundary, once, deliberately - a
silent `to_string/1` inside the package would be a second way for two
boundaries to collide.

So the boundary is yours to draw. The package supplies the consequences of
drawing it, not the drawing.

## Choosing the boundary

The rule is one sentence:

> **A selector is whatever must be able to go away on its own.**

Not whatever your schema happens to have a foreign key for. A tenant is the
common answer because tenants are the common offboarding unit, but it is not
the only one. A data licence that expires, a dataset a customer may withdraw,
a region whose data must be destroyable without touching another region -
each is an offboarding unit, and each is a legitimate selector.

Four questions settle a candidate boundary. A "no" to any of them means the
boundary is drawn in the wrong place.

1. **Can it be destroyed alone?** If destroying this thing's key would make
   some other thing's data unreadable, the boundary is too coarse. Two things
   that must die separately cannot share a selector.
2. **Does it need to be destroyed at all?** If nothing in your compliance or
   contractual story ever terminates this thing, a separate key buys you
   rotation scope and nothing else. That can still be worth it - see below -
   but it is a different argument.
3. **Is its identifier stable?** The selector is hashed into the cache
   partition id and encoded into the tenant reference that goes in every
   message header. An identifier that is reassigned, recycled, or edited by a
   user is not a selector; derive a stable one and keep the mapping.
4. **Is it bounded in number?** Every selector is a key to mint, a wrapping
   row to store, a version lineage to rotate, and a line in a shred runbook.
   A boundary that produces one selector per row is a boundary drawn at the
   wrong level.

Where a system genuinely has two boundaries - a tenant *and*, within it, a
licence that expires early - the answer is two vaults with two namespaces
rather than a composite selector string. A composite gives you one key that
two procedures both want to destroy, which is question 1 failing quietly.

## One boundary, one key

A selector resolves to one live master-key lineage. That is what the boundary
buys, and it is worth being explicit about what follows from it:

- **Erasure is scoped to it.** Destroying the wrappings of one selector
  reaches exactly that selector's plaintext and nothing else's.
- **Rotation is scoped to it.** A level-2 rotation is a re-encrypt pass over
  one boundary's ciphertext, not over the table. A boundary drawn too wide
  makes every rotation a whole-table walk.
- **Derived subkeys ride along.** A purpose-labelled subkey - a blind index,
  a search key - is derived from the master key on demand and never stored,
  so it lives and dies with the boundary without being inventoried
  separately. That is intended, and it means erasure reaches further than a
  list of encrypted columns suggests.
- **Compromise is scoped to it, in one row of the table and not in all of
  them.** ADR-0003 decision 10's attacker table is layered by *what the
  attacker holds*, not by selector: its "wrapped-key store + the root key" row
  reaches every tenant however the boundary is drawn, and a wider boundary does
  not widen it. The row the boundary governs is "ciphertext + one tenant's
  unwrapped master key", which reaches "that tenant, all versions that key
  covers" (`docs/adr/0003-per-tenant-envelope.md:353-360`, read at `6f4b55d`).
  The per-boundary bound is stated as prose beside the table rather than in it -
  "tenant compromise is bounded by version, not by time"
  (`docs/adr/0003-per-tenant-envelope.md:376-379`, read at `6f4b55d`) - and it
  is that sentence, not the table's shape, that a wider boundary makes worse.

## The three verbs

| Verb | What it does | Reversible | What a caller sees | Who performs it | Record | Shipped today |
|---|---|---|---|---|---|---|
| **Rotate** | Mints a new version under the same selector; older versions keep decrypting until their wrappings are deleted | yes, by minting again | nothing - reads and writes continue | `Encryptor.Envelope.provision/3`, then a re-encrypt pass | ADR-0005 P1, P2 | yes |
| **Suspend** | Denies every operation for the selector while leaving its wrappings untouched | **yes**, by `reinstate/2` | `{:key_unavailable, selector}` | `Encryptor.Vault.suspend/2` | ADR-0005 Amendment A | yes |
| **Shred** | Destroys every wrapping of the selector's master key | **no** | `{:unknown_key, selector}` | a `DELETE` against your key store, per runbook P3 | ADR-0005 P3, decisions 9 and 10 | not as a function, by design |

Three things about that table need saying rather than reading between.

**Rotate and shred are the only two mechanisms.** ADR-0005 decision 3 says so
and is unamended: a mechanism is a change to the membership of the set
`decryption_keys/2` answers with, rotation adds a name to it, a shred removes
one, and there is no third. Suspend changes that membership not at all.

**Suspend is shipped.** ADR-0005 Amendment A records it (accepted
2026-09-13), and `Encryptor.Vault.suspend/2` and `Encryptor.Vault.reinstate/2`
exist. The state between "readable" and "destroyed" now has a package-level
answer, which is exactly the gap the amendment was written to close.

**Suspend is deliberately not a shred you can undo.** The deny
gate sits at resolution, ahead of the cache, so a suspension takes effect on
the very next call rather than after `max_age` drains - the opposite of P3
step 3, which must wait for the caches. It is also node-local and volatile by
design: the suspended set lives in an ETS table owned by the vault's
lifecycle process, so a restarted vault serves the selector again and a
four-node host suspends four times. A suspension that must survive a deploy
belongs at the provider instead, where a backing authority can deny durably.

**The Shred row assumes the key material is yours to destroy.** It is, on every
material-source provider - `Static`, `Function`, `GcpKms`, an Ecto-backed
wrapped-key table - where destroying the wrapping destroys the key. It is not on
a keyring-backed one: under `Encryptor.Provider.Kms` the wrapping key lives in
AWS KMS and never in your store, so a `DELETE` hides the selector from this
vault while KMS can still decrypt its data. There the shred is
`ScheduleKeyDeletion` on the tenant's KMS key, and its pending-deletion window
is the interval in which `CancelKeyDeletion` still works rather than a reprieve
to plan around. ADR-0008 decision 4 is where the two shapes are reconciled per
row; the runbook reproduces its table under ["The shred and the rotate, per key
shape"](rotation-runbook.md#the-shred-and-the-rotate-per-key-shape), and
`Encryptor.Provider.Kms`'s moduledoc carries the same reconciliation.

**Shred is not a function here and will not become one.** ADR-0005 decision 10
declines `shred/2`, `retire/2` and `rotate/2` for one reason: deleting a
wrapping is a `DELETE` against a store this package has no access to, and a
function here would imply it knows what that store's copies are. It does not.
The runbook is the surface.

## Cryptographic erasure

Destroying a boundary's key makes its ciphertext unreadable. That is not a
trick particular to this package - it is a recognised sanitization technique,
**Cryptographic Erase**, described in NIST SP 800-88 Rev. 1, *Guidelines for
Media Sanitization*, as a way of reaching the Purge level of sanitization for
media whose data was encrypted before it was stored.

Naming it matters because the guidelines also name its preconditions, and
they are the ones a host has to meet rather than assume:

- **The data must have been encrypted before it was written.** Erasure
  reaches what the key covers and nothing else. A column added later and left
  in plaintext is not erased by anything below.
- **Every copy of the key must be sanitized**, not only the convenient one.
  This is the precondition that does the most work in practice, and the
  runbook's "a shred is only as good as the copies" is the same sentence from
  the operator's side. On a keyring-backed provider it does less work, because
  the wrapping key was never in a copy of your store to begin with: ADR-0008
  decision 4's "does the shred survive a backup" row says the KMS-path shred
  does, where the material-source shred does so "only if every copy of the store
  was found".
- **The encryption has to be strong**, and the key must not be recoverable
  from anything else that survives.
- **The media itself is not sanitized.** The ciphertext is still there. What
  changes is that nobody can read it.

### The honest claim

Say this, and not more:

> Destroying a selector's key material renders that selector's ciphertext
> unreadable wherever the ciphertext exists - including in backups and read
> replicas that no delete has reached - and it does not delete a single row.

Both halves are load-bearing.

**Why it reaches backups.** A backup of your ciphertext without the wrapping
key is inert. That is the whole appeal: erasure does not require you to find
every copy of the *data*, only to destroy the *key*. A host whose deletion
story is row deletion has to chase copies forever; a host whose deletion
story is erasure has to chase one key.

**Why it is not deletion.** Three limits, each with somewhere to read more:

1. **It destroys plaintext, not attribution.** Every message header carries
   the boundary's permanent pseudonym - the `tenant_ref` - and deleting a
   wrapping does not touch it. The holder of the reference subkey can confirm
   a candidate identifier against a header by guess-and-confirm, forever, in
   every retained backup, and the reference subkey is never rotated. Deleting
   the rows is therefore compliance-mandatory wherever attribution is itself
   personal data, not hygiene. ADR-0005 says so at acceptance, and the
   runbook's [what a shred does not
   destroy](rotation-runbook.md#what-a-shred-does-not-destroy) works the
   consequence through.
2. **It is only as good as the copy of the key you missed.** A wrapping in a
   pre-shred database backup, on an unreached replica, in a logical dump or
   in a disaster-recovery vault is a live key. This package cannot see any of
   them. A KMS-backed wrap provider changes this materially - if the wrapping
   key lives in the KMS and its versions are destroyed, the wrappings in
   every backup become undecryptable because the wrapping key was never in
   the backup. ADR-0007 decision 8 records that for GCP KMS
   (`DestroyCryptoKeyVersion`); it is a runbook API call rather than
   anything this package exposes.
3. **It is the termination mechanism, not the deletion story.** Erasure is
   what makes offboarding instantaneous and complete-enough to commit to. It
   does not replace row deletion, retention policy, or a backup expiry
   schedule; it makes the window between "offboarded" and "backups aged out"
   survivable.

### Before you promise it to anyone

Erasure is a claim made to auditors, customers and regulators, so the
runbook's preconditions for P3 are not ceremony:

- The decision to destroy is **recorded and human**. It is never automated
  and never a cascade from a `DELETE` on a tenants table.
- Partial destruction is the worst state in the system - some rows readable,
  some permanently not, indistinguishable to the application. If the deletion
  pass fails partway, complete it rather than reverting it.
- After the wrappings are gone, a running node still decrypts from cached
  materials until the caches drain. The shred is not observable until then;
  suspend is.

## Which verb

| You need | Verb |
|---|---|
| To limit how much data one key version covers | Rotate |
| To respond to a suspected key compromise | Rotate, then shred the old versions' wrappings once the re-encrypt pass is verified |
| To make a boundary's data unreadable while a dispute, hold or unpaid invoice is resolved | Suspend |
| To offboard a boundary permanently | Shred, and delete its rows |
| To stop a boundary's data being readable on one node, right now, before you have decided | Nothing in this package yet - stop the vault |

The trap the amendment was written to catch: **an operator who needs a pause
and is offered only a shred will eventually take the shred.** If your
offboarding flow has a "provisional" state, do not implement it with P3.

## Records

- **ADR-0001** decision 7 - the cache partition id, and why it is not key
  material (accepted).
- **ADR-0004** decision 3 and review item A7 - the selector is an opaque,
  non-empty host-supplied string (accepted, with amendments).
- **ADR-0005** - rotation and crypto-shred: the two mechanisms, the four
  procedures, the blast-radius tables (accepted). **Amendment A** - suspend
  as the third verb (accepted 2026-09-13).
- **ADR-0007** decision 8 - KMS-backed destruction as ADR-0005's shred, and
  what it still does not erase (accepted 2026-09-13).
- **ADR-0008** decision 4 - rotation, the shred and suspend per key shape; the
  table the runbook reproduces, and the reason the Shred row above is not one
  sentence for every provider.

Where this guide and a record disagree, the record wins and the disagreement
is a bug in this guide.
