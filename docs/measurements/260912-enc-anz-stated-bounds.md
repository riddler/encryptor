# Measuring the stated-but-unmeasured bounds

Bead: `enc-anz`. Date: 2026-09-12. Harness: [`bench/bounds.exs`](../../bench/bounds.exs),
run as `mix run bench/bounds.exs`.

Four accepted records state numbers and say plainly that they are chosen
rather than derived. This is the single measurement pass all four asked for.

**This note measures. It does not retune.** No default changed in this bead,
and no record was edited. Where a number contradicts a record, it is written
up below as a finding for the operator, because a cryptographic parameter is
an ADR decision here and an implementation bead does not amend an accepted
record.

## What was measured, and the verdict

| Stated bound | Record | Verdict |
|---|---|---|
| `max_messages: 100`, `max_bytes: 1 GiB` | ADR-0001 OQ2 | **contradicted in intent** - see finding 1 |
| `recycle_after: 20 * max_age` under per-column partitioning | ADR-0004 OQ6 | **recontextualized** - the worry is real in shape, modest in size |
| the 32-pair and 4 KiB context bounds | ADR-0004 OQ4 | **confirmed** - both live, neither redundant |
| the 32-byte tenant master key and `0x0478` | ADR-0003 OQ7 | **confirmed** for the suite; **not measurable** for the key size |
| Argon2id 64 MiB / 3 iterations (addendum) | ADR-0003 amendment B, B4 (*proposed*) | **confirmed** as memory-dominated |

## The machine, and what the numbers are not

| | |
|---|---|
| Elixir / OTP | 1.18.3 / 27 |
| schedulers online | 15 |
| `encryptor` | 0.2.0, at `75807a8` |
| `aws_encryption_sdk` | 1.0.0 |

Every timing is a median of five batches on one machine, single-process, after
a warmup of the same shape. They are ratios worth trusting and absolutes worth
re-measuring elsewhere.

**The honest limit on all of it: every provider here is in memory.** A cache
miss in this harness pays the engine's data-key generation and EDK wrap and a
closure call, and nothing else. A store-backed or KMS-backed provider adds its
own round trip on top of every number in section 1, and that round trip is the
case ADR-0002 decision 2's sentence was written about. Section 1's conclusion
is therefore scoped to raw-AES keyrings and says so.

---

## 1. `max_messages: 100` and `max_bytes: 1 GiB` (ADR-0001 OQ2)

ADR-0001 decision 6 sets both "to be obviously below the engine's ceilings and
plausibly above a single request", and OQ2 asks for a benchmark. Here it is.

### The bounds against each other

| | |
|---|---|
| warm encrypts/sec, one process | 85,837 |
| `max_messages: 100` is reached after | **1.17 ms** |
| `max_age: 60` would be reached after | 5,150,215 messages |
| ratio of the two lifetimes | **~51,500 : 1** |
| payload at which `max_bytes` binds before `max_messages` | **10.7 MB** (`1 GiB / 100`) |

At a 64-byte column payload, `max_bytes: 1 GiB` is reached after 195 seconds
of continuous single-process encryption - and it never gets there, because
`max_messages` has recycled the entry 167,000 times first. For every payload
below 10.7 MB, `max_bytes` is unreachable and `max_messages` is the only bound
that fires.

The consequence worth stating plainly: **`max_age` is the one bound the
package refuses to default, on the grounds that it is the host's threat-model
call - and on a busy vault it is the bound that never fires.** A data key's
real lifetime is 100 messages, which at any meaningful request rate is
milliseconds. The operator is forced to think hard about a number that, for
their hot partitions, does nothing.

That is not an argument that `max_age` should go away. It still governs idle
partitions, and it is still what bounds how long a shred takes to bite. It is
an argument that decision 6 describes the bounds as though `max_age` were the
binding one, and it is not.

### What the cache costs, and what it saves

| | µs/encrypt |
|---|---|
| `cache: false` | 8.93 |
| cache on, `max_messages: 100` (the default) | 11.65 |
| cache on, `max_messages: 1_000_000` | 11.40 |
| cache on, `max_messages: 1` (every call a miss) | 13.42 |

| | µs/decrypt |
|---|---|
| `cache: false` | 8.25 |
| cache on | 9.87 |

Read those two tables together:

- **Cache hits are real.** Forcing every call to miss costs 2.02 µs more than
  the loose-bound vault. The harness runs this as an explicit discriminator,
  because without it the rest of this section would be measuring nothing.
- **And the cache is still a net loss.** Turning it on costs **+2.72 µs on
  encrypt** (about 30% of an uncached encrypt) and **+1.61 µs on decrypt**.
  The caching CMM's bookkeeping - two `GenServer.call`s into `LocalCache` plus
  a SHA-384 over the cache-id pre-image - is more expensive than generating
  and wrapping a fresh data key against a raw-AES keyring.
- **Relaxing `max_messages` a thousandfold buys 0.25 µs.** The bound is not
  what is costing anything. The cache is.

### Why: the provider is consulted on every call

`lib/encryptor/vault/encrypt.ex` flags a tension between ADR-0001 decision 2
("build the engine's keyring, CMM, and `Client` structs per call") and
ADR-0002 decision 2 (the cache "collapses provider round trips to one per
partition per `max_age`"), and takes the first reading. This pass puts a
number on it:

| | |
|---|---|
| encrypts on one warm partition | 500 |
| provider closure calls observed | **500** |

One provider call per encrypt, warm partition, cache on. The implementation
follows ADR-0001 decision 2, exactly as `encrypt.ex` says it does. What a warm
cache saves is the data-key generation and the EDK wrap - and on a raw-AES
keyring, that is cheaper than asking the cache.

### Finding 1 (for the operator)

Three claims in the accepted records are contradicted by measurement, and all
three are amendments to make or decline, not edits this bead may write:

1. **ADR-0001 decision 6's bounds are effectively `max_messages` alone.**
   `max_bytes: 1 GiB` is unreachable for any payload under 10.7 MB, and
   `max_age` is out-lived 51,500:1 by `max_messages: 100` on a hot partition.
2. **On a raw-AES keyring the materials cache is a pessimization**, costing
   ~30% on encrypt and ~20% on decrypt. ADR-0001 decision 6 presents the cache
   as an optimization that needs bounding; for the `Static` and
   in-memory-`Function` provider cases it is a cost that needs justifying.
   Nothing here measures the KMS case, where the EDK wrap is a network call
   and the conclusion should invert.
3. **ADR-0002 decision 2's "collapses provider round trips to one per
   partition per `max_age`" is not what the code does** - it is one per call.
   `encrypt.ex` already records the tension in a comment; no record carries
   the measurement.

A reasonable shape for the amendment, offered and not adopted: say that the
cache is for expensive keyrings, recommend `cache: false` as the default
posture for raw-AES providers, and either raise `max_messages` to something
that lets `max_age` mean what decision 6 says it means, or state that
`max_messages` is the binding bound and `max_age` the backstop.

---

## 2. `recycle_after: 20 * max_age` under per-column partitioning (ADR-0004 OQ6)

OQ6 asks whether `max_messages: 100` and `recycle_after: 20 * max_age` are
still sensible "when the entry count is tenants times columns". First, what
the entry count actually is.

### The partition is not what multiplies

| source | inputs |
|---|---|
| partition id (`lib/encryptor/vault/partition.ex:74-78`, read at `75807a8`) | vault module, selector |
| engine cache id (`deps/aws_encryption_sdk/.../cmm/caching.ex:201-219`, `aws_encryption_sdk` 1.0.0) | partition id, suite, **serialized encryption context** |

Measured over 8 tenants and 25 distinct `{table, column}` contexts:

| | |
|---|---|
| distinct partition ids | 8 |
| distinct cache ids | **200** |

So the entry count is tenants times distinct contexts, and the partition id
contributes **separation, not cardinality** - it is what keeps one tenant's
data key out of another's lookup, and the context is what multiplies. OQ6's
framing is correct; the mechanism is the engine's cache id, not the package's
partition.

### What an entry costs

| | |
|---|---|
| ETS bytes per live cache entry | **1,237** |

| tenants | columns | entries | ETS |
|---|---|---|---|
| 100 | 10 | 1,000 | 1.2 MiB |
| 1,000 | 10 | 10,000 | 11.8 MiB |
| 1,000 | 25 | 25,000 | 29.5 MiB |
| 10,000 | 10 | 100,000 | 118.0 MiB |
| 10,000 | 25 | 250,000 | 294.9 MiB |

(`:erlang.memory(:ets)` delta over 500 entries. `:erlang.memory(:total)` over
the same window is dominated by process heaps and GC timing - it came back
*negative* on a run where ETS grew cleanly - so it is not reported.)

### What `recycle_after` actually bounds

`recycle_after` drops the whole table on an interval; at `max_age: 60` that
interval is 1,200 seconds. The peak it bounds is therefore the number of
**distinct** `(tenant, context)` pairs *touched* in the window - not a rate. A
busy vault re-touches the same entries and does not grow.

| active tenants in 1,200 s | columns | peak entries | peak ETS |
|---|---|---|---|
| 50 | 10 | 500 | 0.6 MiB |
| 500 | 10 | 5,000 | 5.9 MiB |
| 5,000 | 10 | 50,000 | 59.0 MiB |
| 50,000 | 10 | 500,000 | 589.8 MiB |

**Verdict: the OQ6 worry is real in shape and modest in size.** At any tenant
count a single BEAM node plausibly serves, the unbounded cache costs tens of
megabytes, and `recycle_after: 20 * max_age` is a sufficient ceiling. It
becomes a genuine memory problem somewhere past ~10,000 tenants active within
one recycle window, and a host at that scale should shorten `recycle_after`
rather than have the number revisited in the record.

No amendment proposed. The default survives measurement.

---

## 3. The 32-pair and 4 KiB context bounds (ADR-0004 OQ4)

Decision 9's bounds are "chosen to be obviously above a canonical context and
obviously below a per-row storage problem". Both halves check out.

### How far above a real context

| context | pairs | of 32 | bytes | of 4096 |
|---|---|---|---|---|
| single: `table`, `column` | 2 | 6.3% | 42 | 1.0% |
| single: + `app` | 3 | 9.4% | 62 | 1.5% |
| tenant: + `tenant_ref` | 4 | 12.5% | 98 | 2.4% |
| tenant: + `purpose` | 5 | 15.6% | 112 | 2.7% |
| blob-shaped | 4 | 12.5% | 103 | 2.5% |

The richest realistic context uses **16% of the pair bound and 2.7% of the
byte bound**. "Obviously above a canonical context" is measured and true, with
roughly 6x headroom on pairs and 37x on bytes.

### Both bounds are live

`serialized_size/1` is `2 + Σ(4 + |k| + |v|)` (`lib/encryptor/context.ex:252-261`, read at `75807a8`),
so the two bounds cross at a per-pair width of **123 bytes**:

- below 123 bytes of key-plus-value per pair, **`max_pairs` binds first**
- above it, **`max_bytes` binds first**

Confirmed at the edges: 32 pairs at realistic widths is 1,264 bytes (pair
bound binds); 32 pairs at 64-byte keys and 61-byte values is 4,130 bytes
(byte bound binds); 2 pairs at ~2 KiB each is 4,021 bytes (byte bound
binds at two pairs).

Neither bound is redundant, which is the thing a measurement pass could have
found wrong and did not.

### What a wide context costs

| pairs | context bytes | ciphertext bytes | µs/encrypt |
|---|---|---|---|
| 1 | 40 | 323 | 11.72 |
| 2 | 78 | 361 | 12.01 |
| 4 | 154 | 437 | 13.73 |
| 8 | 306 | 589 | 15.91 |
| 16 | 624 | 907 | 23.13 |
| 32 | 1,264 | 1,547 | 33.60 |

A context at the pair bound costs 2.9x the encrypt time of a one-pair context
and adds 1,224 bytes to every row. The context rides in the clear in every
message, so that is per-row storage, permanently. The bound is doing real work
at the top end.

**Verdict: confirmed.** No amendment proposed.

---

## 4. The 32-byte tenant master key and the `0x0478` default (ADR-0003 OQ7)

OQ7 says both "are conservative and consistent with the sibling records, and
neither is derived from a benchmark". The two halves come out differently.

### The suite: measured, and the recommendation holds

| suite | payload | ciphertext | overhead | µs/encrypt | µs/decrypt |
|---|---|---|---|---|---|
| `0x0478` commit, no signature | 64 B | 325 B | 261 B | 16.20 | 13.33 |
| `0x0578` commit + ECDSA P-384 | 64 B | 588 B | 524 B | 377.21 | 310.74 |

The signature costs **23x on encrypt, 23x on decrypt, and 263 extra bytes in
every row**. Overhead is flat in payload size for both suites (261 B and
~523 B at 16 B, 64 B and 4 KiB alike), so at column sizes the signature more
than doubles the stored bytes.

Read the µs columns here against each other, not against section 1. The
`0x0478` row and section 1's `max_messages: 100` row are the same vault on the
same 64-byte column payload, and they read 16.20 µs and 11.65 µs: the suite
table times 500 iterations late in the run (`bench/bounds.exs`, the section-4
suite loop, read at `ec6a84d`) where section 1 times 2,000 earlier (same file,
the `warm_us`/`loose_us`/`tight_us` batches, same SHA), and batch size and run
order move the absolute by that much on this machine. Every conclusion in this
document is a ratio inside one table, for that reason.

`0x0578` is the engine's default and the package's default, and ADR-0001
decision 9 makes `0x0478` the configured choice when writer and reader share a
trust domain. That recommendation was made on a qualitative argument -
"the signature costs an ECDSA P-384 sign on every write, a verify on every
read, and its bytes in every row, in exchange for nothing". It is now
quantified, and it is a much stronger argument than it looked: for encrypted
columns, keeping the signature is a 23x latency tax and a 2x storage tax for a
property the deployment cannot use.

### The key size: not a measurable question

| | |
|---|---|
| declared bits | 256 |
| wrapped blob | 407 bytes |
| `tenant_ref` | 22 characters |
| `provision/3` | 10.60 µs |
| `unwrap/2` | 9.84 µs |

Provisioning and unwrapping a tenant master key are both ~10 µs and the stored
blob is 407 bytes. Those costs are dominated by the root vault's envelope
round trip, not by the 32 bytes inside it: a 16-byte or 64-byte master key
would move none of these numbers meaningfully, because the key is wrapped
inside a full ESDK message either way.

**This is an honest negative result.** OQ7 asked for the key size to be
"re-examined once there is a real workload". There is no workload-driven
answer: 32 bytes has no measurable cost, so the choice is a pure security
parameter and the record should settle it on security grounds or close the
question as not-a-performance-decision. Only the suite half of OQ7 was ever
measurable, and it is now measured.

---

## 5. Addendum: Argon2id at 64 MiB / 3 iterations

**Outside this bead's four bullets.** Measured on the dispatch brief's
direction because it is the same kind of evidence, and recorded separately
because ADR-0003 **amendment B was proposed when this was measured and was
accepted on 2026-09-13**. Its B4 table sets
`memory_kib: 65_536`, `iterations: 3`, `parallelism: 1`
(`lib/encryptor/vault/config.ex:191-194`, read at `75807a8`) and argues they are "deliberately
memory-heavy rather than iteration-heavy".

| parameters | ms/hash | hashes/sec, one core |
|---|---|---|
| 32 MiB, 2 iterations (the bound's floor) | 19.00 | 52.6 |
| 32 MiB, 3 iterations | 30.71 | 32.6 |
| **64 MiB, 3 iterations (B4 default)** | **64.24** | **15.6** |
| 64 MiB, 1 iteration | 20.00 | 50.0 |
| 128 MiB, 3 iterations | 135.15 | 7.4 |

The memory-heavy framing is confirmed: doubling memory at fixed iterations
costs 2.1x (30.7 → 64.2 ms), and tripling iterations at fixed memory costs
3.2x (20.0 → 64.2 ms), so the two knobs are roughly linear and the defaults
sit where B4 says they do relative to the published floor.

The operational number B4 does not state: **15.6 hashes per second per core.**
A blind index built at these parameters costs about 64 ms of CPU per value. A
one-million-row backfill is ~18 core-hours, and a write path that indexes two
columns spends ~128 ms of CPU per row. That is a real capacity planning input
for whichever record fixes the blind index, and it belongs in that record
rather than this note.

---

## Reproducing

```
mix run bench/bounds.exs
```

The harness is `bench/bounds.exs`. It is outside `elixirc_paths` and outside
the gate's `build_paths`, so it is not compiled by `mix quality`; it is kept
formatted by an entry added to `.formatter.exs` for this bead. Re-run it on
any machine before citing an absolute number from this note.
