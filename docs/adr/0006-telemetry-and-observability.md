# ADR-0006: Telemetry is a closed event set whose metadata is an allow-list, and nothing key-shaped is ever in it

Status: proposed (2026-08-27)

## Context

ADR-0002 open question 3 declined to decide this and said why: "Nothing here
emits telemetry, and `{:key_unavailable, _}` is exactly the event an operator
wants a metric on. Telemetry is not this record's subject and belongs in a
record of its own covering the whole package." This is that record.

The package emits nothing today. There is no `:telemetry` call in `lib/`, no
`Logger` call in `lib/`, no `:telemetry` entry in `mix.lock`, and no
`{:telemetry, _}` in `mix.exs` - the only runtime dependency is
`aws_encryption_sdk`. So this record is not documenting an existing surface;
it is fixing one before any of it is written, which is what the repository's
own rule requires ("Until an ADR is accepted, its contract is open: do not
encode a guess about it in code").

What exists on `main` matters more than usual here, because half of what an
observability record would naturally want to instrument has not been built.
Taken from the code rather than from the plan:

**The vault's supervision tree is complete, and it is where the only running
code lives.** `Encryptor.Vault.Supervisor.start_link/2` resolves configuration
*before* the supervisor process exists, then starts a `:one_for_one` tree of
`Encryptor.Vault.Lifecycle` (always), the engine's
`AwsEncryptionSdk.Cache.LocalCache` and `Encryptor.Vault.CacheRecycler` (when
`cache` is a map), and the provider module (when it exports `child_spec/1`).
`Lifecycle` does exactly two things at start - `Process.flag(:trap_exit,
true)` and `Config.freeze/1` into `:persistent_term` - and one at stop,
`Config.erase/1`. Those are the two lifecycle boundaries in the package.

**The recycler is the only recurring runtime event, and its failure is
currently silent.** `CacheRecycler.handle_info(:recycle, state)` calls
`Supervisor.terminate_child(supervisor, :cache)` followed by
`restart_child/2`, on a `:recycle_after` interval defaulting to
`20 * max_age`. A `{:error, reason}` from the terminate is returned and
dropped: not logged, not raised, not counted. ADR-0001 decision 6 called the
recycler "a crude mechanism" and documented it as one; nothing anywhere tells
an operator whether it ran.

**The cache cannot be measured from here, and that is a property of the
engine, not an oversight.** `LocalCache.init/1` creates its ETS table as
`:ets.new(:cache, [:set, :private])` and the hit-or-miss decision is made
inside `LocalCache.handle_call({:get, cache_id}, ...)` - `:ets.lookup` empty,
or found-but-`CacheEntry.expired?/1`, both returning `{:error, :cache_miss}` -
called from `Cmm.Caching.get_encryption_materials/2` and
`get_decryption_materials/2`. Every one of those frames is in the dependency.
ADR-0001 decision 6 already said the cache "cannot be swept, measured, or
substituted", and gave that as the reason the recycler exists at all. It is
also the reason this record cannot promise a hit rate.

**The entry points that an observability record would most want to wrap do not
exist.** `encrypt/2`, `decrypt/2` and `rekey/2` are not defined on a generated
vault; `use Encryptor.Vault` defines `__vault__/1`, `child_spec/1`,
`start_link/1`, `stop/0`, `config/0` and `started?/0`, and both moduledocs say
the rest is later beads' work. Nothing in `lib/` calls `encryption_key/2` or
`decryption_keys/2` outside the adapters and the conformance suite;
`Encryptor.Context.compose/3` has no caller in `lib/` at all. `ready/2` is the
declared funnel every future entry point runs through, and it is written.

Two more facts shape the decisions, and both are about disclosure rather than
about mechanism.

**Redaction is already the house style, in code, in four places.**
`Encryptor.Key.Aes` carries `@derive {Inspect, except: [:material]}`;
`Encryptor.Vault.Config` has a hand-written `Inspect` implementation replacing
`:reference_subkey` and the provider's options with `"[redacted]"`;
`Encryptor.Context`'s private `render/1` renders a context **key** and never a
value, with the comment "A value never does: it can be anything the caller
passed"; and `Encryptor.Error`'s private `describe/1` drops the detail from both
`{:invalid_config, key, _detail}` and `{:invalid_key_descriptor, _detail}`.
Telemetry is a fifth place, and it is the one where getting it wrong is
loudest, because a handler is arbitrary host code that routinely forwards
metadata verbatim to a third-party APM with a retention policy nobody here
chose.

**The partition id is safe where it is used and unsafe in a metric.**
`Encryptor.Vault.Partition.id/2` is
`:crypto.hash(:sha256, [Atom.to_string(vault), 0, encoded(selector)])`
truncated to 16 bytes, and ADR-0001 decision 7 is right that it "is not key
material, it is not secret, and it never reaches the message". But it is
**unkeyed**, and
ADR-0004 open question 1 already made the argument against an unkeyed
reference in a different context: "an unkeyed hash of a short tenant slug is
confirmable by anyone who can guess the slug". A cache-key input that never
leaves the VM and a metric dimension retained for thirteen months in a vendor
are not the same disclosure, even though the bytes are.

The family has a telemetry practice this record inherits rather than invents.
statifier-ex's st-ADR-0040 fixes an event contract as a public commitment,
takes `{:telemetry, "~> 1.3"}` as a hard runtime dependency, emits with plain
`:telemetry.execute/3`, splits measurements (numbers) from metadata
(identity), and exposes an `events/0` that is the single definition site for
the vocabulary. `opentelemetry_statifier`'s ADR-0003 attaches one handler id
per event name because `attach_many/4`'s detach is total. This record follows
all of that, and inverts exactly one thing: st-ADR-0040 lets the raw effect
struct and datamodel values ride in metadata for in-VM consumers, and draws
the redaction line at the *bridge*. That is correct there, where the worst
case is a verbose span. It is not available here, where the worst case is a
data key in a log line.

This record owns the event names, their measurements and metadata, the
disclosure rules, and the cardinality rules. It does not own the encrypt path
(ADR-0001 decision 4 and its implementation beads), the error vocabulary
(ADR-0001 decision 10 as extended by ADR-0002 decision 6 and ADR-0004
decision 8), or anything about a bridge to OpenTelemetry, which is a package
someone else may write against these events.

## Decision

**1. `:telemetry` is a hard runtime dependency and emission is
unconditional.** `{:telemetry, "~> 1.3"}` joins `aws_encryption_sdk` in the
main deps list. No `optional: true`, no `Code.ensure_loaded?/1` guard, no
configuration key that turns emission off, and no compile-time flag.

The package's dependency promise is that "raw-keyring usage pulls no AWS,
HTTP, or XML libraries", and `:telemetry` is none of those - it is a
zero-dependency Erlang library that every host running Ecto, Phoenix, Oban or
Finch already has in the tree. Against that, an optional dependency buys two
builds with different observability, and the un-observed one is the build in
production at three in the morning. `:telemetry.execute/3` with no attached
handlers is a `persistent_term` read and a walk over an empty list; a
configuration flag to avoid that cost is a flag whose only real effect is
that someone eventually ships with it set.

statifier-ex takes the same dependency on the same terms, which is not by
itself an argument, but it does mean a host embedding both packages gains no
new transitive dependency from this decision.

**2. The vault never calls `:telemetry.span/3`.** It emits start and stop
halves by hand. Two independent reasons, and either would be sufficient.
`:telemetry.span/3` wraps the work in a `rescue` and emits a matching
`:exception` event, and ADR-0001 decision 10 says this package does not rescue
exceptions - "The vault does not rescue exceptions into `{:error, _}`" - so
using the helper would install exactly the rescue that record refused, in
order to emit an event. And st-ADR-0040's reason applies unchanged: there is
no `:exception` half to offer, so the helper would invent a failure mode the
package does not have.

The consequence is stated rather than hidden: an entry point that raises
leaves an unmatched start, and a consumer pairing on `span_ref` must not
assume every start arrives again as a stop.

**3. The event vocabulary is closed, defined once in `Encryptor.Telemetry`,
and `:start`/`:stop` name a span pair and nothing else.** Every other event is
a point event and is named in the past tense, so that a reader of an attach
list can tell a pair from a point without reading this record.

| Event | Kind | Fires |
|---|---|---|
| `[:encryptor, :vault, :started]` | point | a vault's supervisor came up with its configuration frozen |
| `[:encryptor, :vault, :stopped]` | point | `Lifecycle.terminate/2` erased the frozen configuration |
| `[:encryptor, :vault, :start_refused]` | point | `Config.resolve/4` refused, before any process existed |
| `[:encryptor, :cache, :recycled]` | point | the recycler dropped and restarted the cache child |
| `[:encryptor, :encrypt, :start]` / `[..., :stop]` | span | `encrypt/2` |
| `[:encryptor, :decrypt, :start]` / `[..., :stop]` | span | `decrypt/2` |
| `[:encryptor, :rekey, :start]` / `[..., :stop]` | span | `rekey/2` |
| `[:encryptor, :provider, :start]` / `[..., :stop]` | span | one `encryption_key/2` or `decryption_keys/2` round trip |

Ten names, four of which are span halves' partners. `Encryptor.Telemetry` is
the only module in `lib/` that calls `:telemetry.execute/3`, and
`Encryptor.Telemetry.events/0` returns the list, built from the module's own
attributes, so a host writes `:telemetry.attach_many(id,
Encryptor.Telemetry.events(), &handler/4, cfg)` without hand-copying names
that this record may later extend.

Adding a name, a measurement, or a metadata key is additive. Removing or
renaming one, after this record is accepted and the events ship, is a breaking
change to a consumer's `case` and to their dashboards, and takes an amendment
here - the same commitment st-ADR-0040 made, for the same reason.

**4. Measurements are numbers. Metadata is an allow-list, and the list is in
this record.** The first half is st-ADR-0040's rule, inherited verbatim:
`:telemetry_metrics` aggregates measurements, so a value that has no numeric
meaning does not belong there. The second half is this record's, and it is the
inversion.

**No struct rides verbatim in metadata. No term reaches metadata that is not
named in the table below.** Not `%Encryptor.Vault.Config{}` (it holds the
reference subkey), not an `%Encryptor.Key.Aes{}` or any other descriptor (it
holds material), not a keyring, not a CMM, not a client, not a context map,
not a ciphertext, not a plaintext, not an `%Encryptor.Error{}`, and not the
error's `:engine` term. A handler that wants more than the table offers is
asking for a field this record has to add, deliberately, one at a time.

| Key | Type | On | Meaning |
|---|---|---|---|
| `vault` | `module()` | every event | the vault module, which is half of the configuration key |
| `operation` | `:encrypt \| :decrypt \| :rekey \| :start` | spans, `:start_refused` | `Encryptor.Error.operation/0`, unchanged |
| `span_ref` | `reference()` | span halves | `make_ref/0`; the only correct way to pair a stop with its start |
| `outcome` | `:ok \| :error` | span stops, `:recycled` | |
| `reason_tag` | `Encryptor.Telemetry.reason_tag/0` | when `outcome` is `:error` | decision 5 |
| `provider` | `module()` | provider spans | the adapter module, not its state and not its options |
| `callback` | `:encryption_key \| :decryption_keys` | provider spans | which half of the behaviour was called |
| `cache` | `boolean()` | `:vault, :started` | whether this vault runs a cache child at all |
| `profile` | `:single \| :tenant` | `:vault, :started` | ADR-0004 decision 3's context profile |
| `reference_check` | `:verified \| :unpinned` | `:vault, :started` | whether decision 4's known-answer check had a pinned value to check against |

| Measurement | Unit | On |
|---|---|---|
| `duration` | `:native` | every span stop, and `:recycled` |
| `system_time` | `:native` | every span start and every point event |
| `size` | bytes | `[:encryptor, :encrypt, :start]` and `[:encryptor, :decrypt, :stop]` |
| `candidates` | count | `[:encryptor, :provider, :stop]` on a successful `decryption_keys/2` |

`size` is the one measurement that needs a justification rather than a
definition, and it is ADR-0004 decision 12's argument reused: the plaintext's
length is already recoverable from the ciphertext the host stores, so
measuring it discloses nothing the row did not. Its *contents* are decision 6.
`candidates` is the length of `decryption_keys/2`'s list, which ADR-0002's
consequence "Long-lived tenants accumulate candidates" says grows without
bound; this is the measurement that would tell an operator it had.

**5. `reason_tag` is the head of the reason term, never the term.** The error
vocabulary is fourteen members and all but one are tagged tuples whose second
element is caller data - a selector, a context key, a config path, a module.
Telemetry carries the tag alone:

```
:decrypt_failed | :vault_not_started | :missing_config | :invalid_config |
:unknown_key | :encryption_context_conflict | :reserved_context_key |
:key_unavailable | :invalid_key_descriptor | :provider_not_started |
:missing_optional_dependency | :missing_required_context_keys |
:invalid_context_value | :invalid_selector
```

Fourteen atoms, closed, extended only when the reason vocabulary is - which is
already an ADR-gated act under ADR-0001 decision 10. That closure is what makes
it safe as a metric dimension: a backend keying on `reason_tag` has a bounded
label set no matter what a caller passes, and the one thing an operator most
wants a counter on, `:key_unavailable`, is a tag rather than a payload.

The tag is *not* a narrowing of the error a caller receives. A call site still
gets `{:error, %Encryptor.Error{reason: {:key_unavailable, "acct_9f21"},
engine: ...}}` with everything in it. The tag is what leaves the process.

**6. What is never emitted, and why each one.** This is the load-bearing half
of the record. None of the following reaches a measurement, a metadata value,
or an event name, under any configuration, in any build:

- **Plaintext, in whole or in part**, including a prefix, a hash of it, or a
  length-plus-first-byte. `size` is the only thing said about a plaintext.
- **A data key, a wrapping key, a root key, a tenant master key, the reference
  subkey, or any value derived from any of them.** This is the repository's
  standing rule - "Never log, inspect, or put in an exception message:
  plaintext, a data key, or wrapping key material. A test fixture key is still
  key-shaped" - and telemetry is a place it had not yet been said out loud.
  The mechanical form of the rule is that no key descriptor and no `Config`
  ever appears as a metadata value, so there is no field for material to ride
  in.
- **An encryption context value.** A context key name may appear inside a
  reason a caller already holds; a value never leaves the process.
  `Encryptor.Context`'s `render/1` already draws exactly this line and gives
  exactly this reason, and telemetry inherits it rather than restating it
  differently.
- **The raw `:key` selector.** ADR-0004's acceptance amendment 1 exists
  because publishing the raw tenant identifier beside its derived reference
  voided ADR-0003 decision 5's keying for every tenant that had ever written a
  row. A metrics backend is a second copy of that header problem with worse
  retention, no authentication, and a vendor boundary. If the selector must
  not be in a message it must not be in a metric.
- **The partition id.** Two independent reasons, and this is the one a
  well-meaning implementation is most likely to get wrong, because ADR-0001
  decision 7 truthfully says the partition id is not secret. It is not
  *secret*, and it is also an unkeyed SHA-256 of the selector, so it is
  confirmable by guess-and-confirm by anyone who can guess a tenant identifier
  - ADR-0004 open question 1's own argument, applied to the other unkeyed
  derivation in the package. It is additionally unbounded cardinality. **No
  event carries a per-tenant dimension of any kind**, keyed or unkeyed, which
  is the shortest correct statement of this rule and the one to put in the
  moduledoc.
- **`Encryptor.Error`'s `:engine` field.** ADR-0001 decision 10 keeps the
  engine's raw term for an operator reading a log line at their own call site.
  A telemetry handler is not that: it is host code the vault hands data to
  without knowing where it goes. And on the decrypt path the engine term is
  precisely the distinction that record collapsed to avoid a decryption
  oracle.

**7. The oracle rule holds in telemetry, and holds harder.**
`[:encryptor, :decrypt, :stop]` on a failure carries `outcome: :error,
reason_tag: :decrypt_failed` and nothing finer, because ADR-0001 decision 10
collapses a wrong key, a failed authentication tag, a context mismatch and a
commitment-policy rejection into one reason, and ADR-0004 decision 8 kept that
for context mismatches specifically.

An event that distinguished them would rebuild the oracle sideways, and would
be a *worse* oracle than an error return, because an error return goes to the
caller who made the call while an event goes to every attached handler whether
or not anyone asked. The two failures ADR-0002 decision 6 deliberately carved
out of the collapse - `:unknown_key` and `:key_unavailable` - stay distinct
here too, on the same grounds: they are decided before any ciphertext is
examined, from the caller's own selector. That carve-out is the entire reason
this record has anything useful to say to an operator.

**8. Provider resolution is a span of its own, nested inside the operation
span.** It is the record's answer to ADR-0002 open question 3 as asked. The
stop half carries `outcome`, `reason_tag` and `candidates`, so one
`Telemetry.Metrics` definition gives an operator a `key_unavailable` rate, an
`unknown_key` rate, and the latency distribution of whatever store the host's
provider talks to - which is the thing that actually pages someone.

What the provider span counts is not settled, and this record does not settle
it: see open question 1. It counts round trips either way, and whether the
number of round trips equals the number of calls or the number of cold cache
misses is a property of where the encrypt path puts resolution relative to the
materials cache, which is the encrypt path's decision and not this one's.

**9. Events are emitted synchronously, on the caller's process, before the
entry point returns.** This is `:telemetry`'s model and there is no useful
alternative, but it has a consequence worth writing down in the record rather
than leaving for someone to discover: a slow handler is a slow encrypt, on a
path ADR-0001 decision 5 spent real design effort making allocation-free
because it is "the path of every encrypted column read". The generated
documentation says so at the attach point. This package does not wrap handlers
in a task, a queue, or a timeout, for the same reason ADR-0002 decision 2
gives for not wrapping provider callbacks: the process hop costs more than the
problem.

**10. Two events ship now; the rest ship with the paths they instrument.**
Stated as sequencing rather than left implicit, because the code that six of
these ten events describe does not exist.

| Event | When it can be written |
|---|---|
| `[:encryptor, :vault, :started \| :stopped \| :start_refused]` | now - `Supervisor.start_link/2` and `Lifecycle` are written |
| `[:encryptor, :cache, :recycled]` | now - `CacheRecycler.recycle/1` is written, and today its failure branch is silent |
| the three operation spans | with `encrypt/2`, `decrypt/2`, `rekey/2` |
| the provider span | with the first `lib/` caller of `encryption_key/2` |

The four that can be written now are worth writing now, and the recycler one
most of all: it is the only recurring runtime event in the package, ADR-0001
documented the mechanism as crude, and there is currently no way for an
operator to know it ran, let alone that its `terminate_child/2` returned an
error and was dropped.

The six that cannot are specified here anyway, and deliberately. This
repository's rule is that an implementation bead may not encode a guess about
an undecided contract; without this record, the encrypt-path bead either emits
nothing or invents a vocabulary. Specifying ahead is the cheaper of those.

## Consequences

**A raising handler is detached by `:telemetry` and nobody is told.** This is
the library's documented behaviour and it is the right one, but it means the
`key_unavailable` counter this record exists to provide can stop working
permanently and silently, at the first malformed handler, for the VM's
lifetime. `opentelemetry_statifier`'s ADR-0003 decision 2 met the same hazard
from the consumer side and bounded it by attaching one handler id per event
name rather than one `attach_many/4` whose detach is total. This package
cannot enforce that on a host, so it does the two things it can: the generated
documentation says it, and `events/0` exists so that a host attaching
per-event ids has the list to iterate.

**The cache gets a recycle count and no hit rate, and this record will not
pretend otherwise.** `LocalCache`'s table is `:private` and its hit-or-miss
decision is three frames deep in the dependency. A hit rate would take either
a fork of the engine, or a wrapper CMM interposed between `Cmm.Caching` and
the vault whose only job is to count - which would be this package
re-implementing a cache lookup in order to observe one. The honest surface is
smaller than an operator wants, and the derived proxy (open question 1)
depends on a question this record does not own. It is filed upstream instead,
alongside the two asks already open there.

**Adding `:telemetry` doubles this package's runtime dependency count.** From
one to two. That is a real change to a package whose pitch includes its
dependency footprint, and the mitigation is only that the second one is
`:telemetry`, which has no dependencies of its own and is already resident in
essentially every host that would run this package. A host with genuinely one
dependency and no telemetry consumer pays a `persistent_term` read per event.

**Six of ten events are a contract against unwritten code, so this record will
be tested by the encrypt path rather than by review.** The measurements and
metadata for the operation spans are chosen from the ADRs' description of
those paths, not from reading them. If the encrypt path arrives and a field is
wrong - `size` unavailable at start rather than at stop, `provider` not in
hand where the span opens - the amendment is here and it is small. What the
record buys in the meantime is that the path does not get to invent a
vocabulary while nobody is looking.

**An operator cannot answer "which tenant is failing?" from telemetry, by
design.** Decision 6 refuses every per-tenant dimension, so a
`key_unavailable` spike is visible as a rate and not attributable to a
customer without correlating it against something else the host already has -
its own request logs, its own tenant scope, the `%Encryptor.Error{}` its own
call site received, which carries the selector in full. That is a genuine
ergonomic cost paid for a disclosure property, it will be felt during an
incident, and the alternative shape (an opt-in keyed dimension) is recorded as
open question 4 rather than being taken quietly now.

**The `:engine` term stays out of telemetry, so the two observability surfaces
disagree on purpose.** An operator reading an exception message sees the
engine's own term; the same failure in a metric is `:decrypt_failed`. Anyone
building a dashboard and a log search side by side will notice, and the reason
is ADR-0001 decision 10's, not this record's: `:engine` is for the process that
made the call, and telemetry leaves that process.

## The contract as typespecs

```elixir
defmodule Encryptor.Telemetry do
  @moduledoc """
  The package's `:telemetry` events.

  No event carries a plaintext, a key of any kind, an encryption context
  value, a `:key` selector, a partition id, or an `Encryptor.Error`'s
  `:engine` term. No event carries a per-tenant dimension, keyed or unkeyed.
  Handlers run on the calling process, so a slow handler is a slow encrypt.
  """

  @type span_name :: :encrypt | :decrypt | :rekey | :provider

  @type reason_tag ::
          :decrypt_failed
          | :vault_not_started
          | :missing_config
          | :invalid_config
          | :unknown_key
          | :encryption_context_conflict
          | :reserved_context_key
          | :key_unavailable
          | :invalid_key_descriptor
          | :provider_not_started
          | :missing_optional_dependency
          | :missing_required_context_keys
          | :invalid_context_value
          | :invalid_selector

  @type metadata :: %{
          optional(:vault) => module(),
          optional(:operation) => Encryptor.Error.operation(),
          optional(:span_ref) => reference(),
          optional(:outcome) => :ok | :error,
          optional(:reason_tag) => reason_tag(),
          optional(:provider) => module(),
          optional(:callback) => :encryption_key | :decryption_keys,
          optional(:cache) => boolean(),
          optional(:profile) => Encryptor.Vault.Config.profile(),
          optional(:reference_check) => :verified | :unpinned
        }

  @doc "Every event name this package emits. The single definition site."
  @spec events() :: [[atom(), ...], ...]

  @doc "The metadata tag for a reason term. Never the term itself."
  @spec reason_tag(Encryptor.Error.reason()) :: reason_tag()
end
```

The mapping from a reason to its tag is one function with fourteen clauses,
and it is deliberately not `elem(reason, 0)`: a `:decrypt_failed` is a bare
atom, and a fallthrough that reached `elem/2` on a term this record did not
anticipate would either raise inside an emit or leak whatever the term was.

## Worked example: a card-processing vault losing its key store

The motivating case, end to end. A payments host runs a `:tenant` vault per
merchant, with a store-backed provider reading wrapped keys out of its own
database.

```elixir
config :my_app, MyApp.CardVault,
  algorithm_suite_id: 0x0478,
  context_profile: :tenant,
  required_context: ["table", "column"],
  static_encryption_context: %{"app" => "my_app", "purpose" => "pan"},
  cache: [max_age: 300]
```

Four `Telemetry.Metrics` definitions is the whole integration:

```elixir
[
  counter("encryptor.provider.stop.duration",
    tags: [:vault, :callback, :outcome, :reason_tag]),
  distribution("encryptor.provider.stop.duration",
    unit: {:native, :millisecond}, tags: [:vault, :callback]),
  counter("encryptor.decrypt.stop.duration", tags: [:vault, :outcome]),
  counter("encryptor.cache.recycled.duration", tags: [:vault, :outcome])
]
```

The store goes away. What arrives, per failing call:

```elixir
{[:encryptor, :provider, :start],
 %{system_time: 1_756_312_800_000_000_000},
 %{vault: MyApp.CardVault, provider: MyApp.KeyStoreProvider,
   callback: :decryption_keys, operation: :decrypt, span_ref: #Reference<...>}}

{[:encryptor, :provider, :stop],
 %{duration: 2_014_233_000},
 %{vault: MyApp.CardVault, provider: MyApp.KeyStoreProvider,
   callback: :decryption_keys, operation: :decrypt, span_ref: #Reference<...>,
   outcome: :error, reason_tag: :key_unavailable}}

{[:encryptor, :decrypt, :stop],
 %{duration: 2_014_901_000, size: 0},
 %{vault: MyApp.CardVault, operation: :decrypt, span_ref: #Reference<...>,
   outcome: :error, reason_tag: :key_unavailable}}
```

The `key_unavailable` counter climbs, the provider latency distribution shows
a two-second tail, and the operator knows the key store is down rather than
that the data is corrupt - which is the distinction ADR-0002 decision 6 built
the error vocabulary around and which nothing until now surfaced as a metric.

Note what is not there. No selector, so the operator cannot see which merchant
- they correlate with their own request logs, where the merchant id already
is. No partition id. No context. No `:engine` term, so the store's own
`Postgrex.Error` is not forwarded to the APM by a package the host did not ask
to do that.

Contrast the same three events when the row is genuinely unreadable - a
retired key version, ADR-0005 decision 9's P4 case:

```elixir
{[:encryptor, :provider, :stop], %{duration: 412_000, candidates: 3},
 %{..., outcome: :ok}}

{[:encryptor, :decrypt, :stop], %{duration: 903_000, size: 0},
 %{..., outcome: :error, reason_tag: :decrypt_failed}}
```

The provider answered fine and the decrypt failed, which is the whole content
of the signal. `:decrypt_failed` does not say whether the key was retired, the
context disagreed, the tag failed, or the bytes were corrupt - decision 7 -
and the operator's next step is ADR-0005's fence, not a finer metric.

## Worked example: a signup-wizard vault starting and recycling

The events that can be written against the code on `main` today. A host
encrypting A/B assignment payloads for a signup wizard, one key, no tenancy:

```elixir
config :my_app, MyApp.SignupVault,
  context_profile: :single,
  required_context: ["table", "column"],
  cache: [max_age: 60, recycle_after: 1_200]
```

At boot:

```elixir
{[:encryptor, :vault, :started],
 %{system_time: 1_756_312_800_000_000_000},
 %{vault: MyApp.SignupVault, cache: true, profile: :single,
   reference_check: :unpinned}}
```

`reference_check: :unpinned` is accurate and worth having: a `:single` vault
has no reference subkey to check, and `Config`'s `reference_check/4` runs only
on a `:tenant` vault with a pinned value. A `:tenant` vault reporting
`:unpinned` in production is a real finding, and this is the only place it is
visible.

Every twenty minutes, the recycler:

```elixir
{[:encryptor, :cache, :recycled], %{duration: 1_180_000},
 %{vault: MyApp.SignupVault, outcome: :ok}}
```

and, on the branch that today returns an error and drops it:

```elixir
{[:encryptor, :cache, :recycled], %{duration: 240_000},
 %{vault: MyApp.SignupVault, outcome: :error, reason_tag: :vault_not_started}}
```

A misconfigured vault, refused before its supervisor exists:

```elixir
{[:encryptor, :vault, :start_refused],
 %{system_time: 1_756_312_800_000_000_000},
 %{vault: MyApp.SignupVault, operation: :start,
   reason_tag: :missing_config}}
```

Which key was missing is in the `{:error, %Encryptor.Error{reason:
{:missing_config, [:cache, :max_age]}}}` that `start_link/1` returned to the
supervisor that called it. The event says a vault refused to start; the return
value says why. Open question 6 is honest about how much use the event is at
that point in a boot.

## Open questions

Recorded rather than guessed. Each names who should settle it.

1. **Does the provider span count calls or cold cache misses?** ADR-0002
   decision 2 says "the engine's materials cache already collapses provider
   round trips to one per partition per `max_age`", which would make
   `[:encryptor, :provider, :stop]` a cold-miss counter and make
   `provider.stop / encrypt.stop` the cache miss rate this record otherwise
   cannot offer. ADR-0001 decision 2 says "Encrypt and decrypt build the
   engine's keyring, CMM, and `Client` structs per call", and building a
   keyring needs descriptors, which needs the provider - which would make it a
   per-call counter and the ratio always one. The two records are not
   obviously compatible and the seam is the encrypt path's, not this
   record's. Whoever writes `encrypt/2` settles it,
   and this record's decision 8 is deliberately neutral so that either answer
   leaves it correct. If the answer is the first, the derived miss rate should
   be documented at the metric.

2. **The cache's hit rate has no seam, and it should be filed upstream.**
   `LocalCache`'s table is `:private` and the decision is made in
   `handle_call({:get, _}, ...)` below `Cmm.Caching`. The engine emitting its
   own `:telemetry` event on hit and miss, or exposing a stats call, would
   give every wrapper the number for free. This is a third upstream ask
   alongside the two already tracked (`aws-encryption-sdk-elixir` #95 and
   #96), and it is an ergonomic gap rather than a defect, so it queues behind
   them.

3. **Whether `:telemetry` should have been optional after all.** Decision 1
   says no, and the reasoning is about which build ends up in production
   rather than about bytes. What would reopen it is a host that genuinely
   cannot take the dependency - an embedded or vendored target - reporting it.
   The remedy if that happens is `Code.ensure_loaded?/1` at the emit site,
   which is cheap to add and impossible to remove once consumers have
   attached, so the door is closed in the direction that keeps it openable.

4. **Whether a host should be able to opt in to a per-tenant dimension.**
   Decision 6 refuses every one, and the consequence section says what that
   costs during an incident. The shape that would be arguable is an opt-in at
   attach time carrying the *keyed* `tenant_ref` rather than the unkeyed
   partition id - statifier's `record_datamodel_values: true` is the family's
   precedent for exactly this kind of default-off extra detail. It is not taken
   now for two reasons: the reference is a permanent pseudonym the subkey
   holder can re-identify (ADR-0004's consequence), so an opt-in is a
   disclosure decision rather than a verbosity decision; and computing it
   costs an HMAC per event on a path the same record was careful about. Worth
   revisiting after a real incident says how badly it was wanted.

5. **Whether `size` should exist at all.** The argument for it is ADR-0004
   decision 12's - the ciphertext already discloses the length to anyone
   holding the row. The argument against is that a metric is held by people
   who do not hold the row, and a length distribution over a column of short
   encrypted values is not nothing: it distinguishes a stored card number from
   a stored note. This is a disclosure judgement rather than a mechanism
   question, and it is the operator's.

6. **Whether `[:encryptor, :vault, :start_refused]` is reachable in the case
   it is for.** Configuration is resolved inside `Supervisor.start_link/2`,
   before any process exists, and a vault is typically started from the host's
   application supervisor - so the most likely refusal happens before the
   host's own telemetry handlers are attached, and the event goes nowhere. It
   still fires usefully for a vault started later, or in a host that attaches
   handlers first. Whether that is worth an event, or whether the refused
   return value is the whole of the surface, is worth a second look when the
   event is written.

7. **Nothing here says anything about an OpenTelemetry bridge, and that is a
   different package's question.** st-ADR-0062 decided the family's bridge is
   its own package consuming public telemetry contracts only, and these events
   are built to be bridgeable - span pairs on `span_ref`, bounded cardinality,
   no unbounded metadata. Whether anyone writes
   `opentelemetry_encryptor`, and whether it belongs beside the statifier
   bridge or on its own, is not this record's and not this repository's.
