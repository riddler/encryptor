# ADR-0006: Telemetry is a closed event set whose metadata is an allow-list, and nothing key-shaped is ever in it

Status: accepted (2026-09-13)

**Amendment A (2026-09-13) is accepted (2026-09-13).** It is appended at the
end of this record, it is additive, and it changes none of decisions 1 to 10
below; the three sentences it narrows are quoted with their amended wording in
its A6.

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

   *Resolved at Amendment A's acceptance (2026-09-13): yes - opt-in and
   keyed. The vault option `:telemetry_tenant_ref` is off by default, refused
   on a `:single` vault, and carries ADR-0003 decision 5's `tenant_ref` in full
   and never the partition id. Amendment A below is this record's answer to
   this question.*

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

## Amendment A (2026-09-13; accepted 2026-09-13): the opt-in keyed tenant dimension

Status: **accepted (2026-09-13)**, by the operator's reading. This amendment
answers open question 4. It only adds: decisions 1 to 10 stand as written, and the three sentences it
narrows are quoted with their amended wording in A6 rather than edited where
they sit.

### Why now

Open question 4 asked "whether a host should be able to opt in to a per-tenant
dimension", described the only arguable shape - "an opt-in at attach time
carrying the *keyed* `tenant_ref` rather than the unkeyed partition id" - and
declined it for two stated reasons: the reference is a permanent pseudonym the
subkey holder can re-identify, so an opt-in is a disclosure decision rather
than a verbosity decision, and computing it "costs an HMAC per event on a path
the same record was careful about"
(`docs/adr/0006-telemetry-and-observability.md:623-633`, read at `40957e6`).

The answer is **yes, opt-in and keyed**, and both of the reasons for declining
survive intact rather than being overruled:

- The disclosure reason is answered by making the opt-in *explicit, off by
  default, and documented as a disclosure choice*, not by denying that it is
  one. A1 and A5 are that answer.
- The cost reason is answered by the code rather than by accepting the cost.
  On a `:tenant` vault the reference is **already derived once per operation**,
  for ADR-0004 decision 4's context pair:
  `Encryptor.Vault.Resolve.vault_supplied/2` computes
  `%{Context.tenant_ref_key() => Reference.derive(config.reference_subkey,
  selector)}` (`lib/encryptor/vault/resolve.ex:213-216`, read at `40957e6`),
  from the reference subkey that ADR-0004 decision 4 froze onto the
  configuration (`lib/encryptor/vault/config.ex:252` and `:677-687`, read at
  `40957e6`). A3 therefore fixes the emit contract as *one derivation per
  operation, threaded*, never one per event. The residual cost of the option
  is a map write per event, not an HMAC per event.

The ergonomic cost the record accepted is also unchanged for everyone who
leaves the option off. The consequence section's sentence - "An operator
cannot answer 'which tenant is failing?' from telemetry, by design"
(`:382-390`, read at `40957e6`) - remains the default posture of this package.
What this amendment removes is the need for a host that *has* made the
disclosure decision to fork the record to act on it.

### Decision

**A1. The dimension is one vault option, `:telemetry_tenant_ref`, a boolean,
default `false`, refused on a `:single` vault.** It joins
`Encryptor.Vault.Config.defaults/0` beside `cache: false`
(`lib/encryptor/vault/config.ex:274-283`, read at `40957e6`) and is frozen
onto the configuration struct like every other option. A `:single` vault that
declares it is refused at `Config.resolve/4` with
`{:invalid_config, :telemetry_tenant_ref, :vault_is_single_profile}`, for
`Encryptor.Envelope.tenant_ref/2`'s own reason: "a `:single` vault has no
tenant to name" (`lib/encryptor/envelope.ex:441`, read at `40957e6`). The
refusal is a start-time error and not a silent no-op, because a host that
asked for the dimension and quietly did not get it would build a dashboard on
a key that is never there. A non-boolean value is refused the same way, with
`{:invalid_config, :telemetry_tenant_ref, :not_a_boolean}`, following the
detail atom every other option already carries - `:cache`'s is
`{:invalid_config, :cache, :not_false_or_keyword_list}`
(`lib/encryptor/vault/config.ex:552`, read at `40957e6`).

It is **vault configuration and not attach-time configuration**, which is the
one particular where this amendment departs from open question 4's own
sketch, and it departs deliberately. `:telemetry.execute/3` does not tell the
emitting process who is attached or with what config, so an attach-time flag
could only be honoured by computing the dimension unconditionally and letting
handlers discard it - which pays the cost the open question refused, and puts
the pseudonym into every handler's metadata including the ones that did not
opt in. The option has to be visible where the event is built, and that is the
frozen `Config`.

Decision 1 is not disturbed. It refuses "a configuration key that turns
emission off", and this is not one: with the option on or off, every event of
decision 3 fires, with the same name and the same measurements. The option
adds one metadata key. Decision 3's rule that "adding a name, a measurement,
or a metadata key is additive" is exactly the rule this amendment is using,
and decision 3's requirement that such an addition "takes an amendment here"
is why this is a record and not a bead.

**A2. What it carries is `tenant_ref` in full - 16 bytes of HMAC tag, encoded
to 22 characters - and
this amendment fixes that length by reusing ADR-0003 decision 5's rather than
choosing a second one.** The value is exactly
`Base.url_encode64(binary_part(HMAC-SHA256(ref_key, tenant_id), 0, 16),
padding: false)` (`docs/adr/0003-per-tenant-envelope.md:228-246`, read at
`40957e6`), where `ref_key` is the reference subkey
`HKDF-Expand(root_key, info: "encryptor/v1/tenant-ref", 32)` of that same
decision; in code it is `Encryptor.Envelope.tenant_ref/2`, whose own doctest
asserts `byte_size(ref) == 22` (`lib/encryptor/envelope.ex:435-450`, read at
`40957e6`). It is the same string, byte for byte, that ADR-0004 decision 4
puts in the encryption context (`docs/adr/0004-encryption-context.md:227-234`,
read at `40957e6`), and the same string ADR-0003 decision 5 puts in the key
name as `"t/<tenant_ref>/v<n>"`.

**The truncation is the one ADR-0003 decision 5 already performed, and there
is no second truncation.** The obvious alternative - emitting a shorter prefix
to make a metric dimension "less identifying" - is refused for three reasons,
and the first is the decisive one:

- It buys no disclosure property. Re-identification of this value is by the
  reference subkey (which recomputes it from a candidate tenant id) or by
  guess-and-confirm against a guessable tenant space. Both work on an 8- or
  12-character prefix exactly as well as on the whole 22, because both go
  forward from the identifier rather than backwards from the string. A prefix
  is shorter, not more private.
- It silently corrupts the metric it exists to serve. Two tenants sharing a
  prefix become one dimension value, and the failure mode is an operator
  attributing one tenant's `key_unavailable` spike to another during the
  incident this option exists for.
- It does not bound cardinality, which is the only honest reason to truncate a
  metric dimension. Cardinality here is the host's tenant count under either
  width; a prefix short enough to bound it would collide constantly. A3's
  scope, not the string's width, is what bounds this dimension.

What it is **never**, under this option or any other: the partition id, and
the raw `:key` selector. Decision 6's two bullets on those stand unamended and
unqualified. The partition id is refused because it is unkeyed and
guess-confirmable (decision 6 and ADR-0004 open question 1's argument,
`:239-273` and `docs/adr/0004-encryption-context.md:908-939`, read at
`40957e6`); the selector is refused because ADR-0004's acceptance amendment 1
exists precisely to keep it out of anything that leaves the process. This
amendment widens neither.

Decision 6's *second* bullet is a third matter, and A6 handles it: it refuses
"the reference subkey, or any value derived from any of them", and
`tenant_ref` is derived from the reference subkey. A6 states the amended
reading rather than leaving a reader to infer it.

**A3. It rides on the four span names, on both halves, and on nothing else;
and it is derived once per operation, never once per event.** When the option
is on, a `:tenant` vault's events carry `tenant_ref` as follows:

| Event | Carries `tenant_ref` when the option is on | Why |
|---|---|---|
| `[:encryptor, :encrypt, :start]` / `[..., :stop]` | yes | the selector is the call's own argument |
| `[:encryptor, :decrypt, :start]` / `[..., :stop]` | yes | as above |
| `[:encryptor, :rekey, :start]` / `[..., :stop]` | yes | as above |
| `[:encryptor, :provider, :start]` / `[..., :stop]` | yes | decision 8 nests it inside an operation span, so the value is already in hand and this is the span an operator actually pages on |
| `[:encryptor, :vault, :started]` | no | a vault start has no tenant in scope; the vault is the whole of its identity |
| `[:encryptor, :vault, :stopped]` | no | as above |
| `[:encryptor, :vault, :start_refused]` | no | decision 3 fires it when "`Config.resolve/4` refused, before any process existed" - there is no frozen configuration to read the option from, let alone a selector |
| `[:encryptor, :cache, :recycled]` | no | the recycler drops and restarts the cache child for every partition at once; there is no single tenant it is about |

The derivation rule is part of this decision. The emitting code derives the
reference **once per `encrypt/2`, `decrypt/2` or `rekey/2` call** and threads
the same string through both halves of the operation span and through the
nested provider span's halves. Where the implementation can reuse the value
`Resolve.vault_supplied/2` already computed for the context
(`lib/encryptor/vault/resolve.ex:213-216`, read at `40957e6`), it reuses it
and derives nothing. A per-event derivation is a defect against this
amendment, not a slow implementation of it.

One path has the option on and no reference to emit, and it gets a rule here
rather than an implementer's guess. `Encryptor.Vault.Resolve.selector/3`
refuses a non-binary or empty `:key` on a `:tenant` vault with
`{:invalid_selector, other}` before any reference is derived
(`lib/encryptor/vault/resolve.ex:60-65`, read at `40957e6`). On that refusal
the span halves still fire exactly as decision 3 and decision 9 say, and they
**omit** `tenant_ref`; `reason_tag: :invalid_selector` on the stop half is the
disambiguator a handler uses, so an absent key is never ambiguous in practice.
It follows, and this decision states it rather than implying it, that the
`:start` half is emitted **after** selector resolution: a start event that
fired first could not carry the key the option promises, and decision 3's
span pairing gives no other place to put it.

On a `:single` vault the key is absent from every event, because A1 refuses
the option there. When the option is off - the default - the key is **absent**
from the metadata map, not present as `nil`: a handler distinguishes "this
host did not opt in" from any value by `Map.has_key?/2`, and a `nil` in a
`:telemetry_metrics` tag is a dimension value.

**A4. The metadata allow-list gains exactly one key, conditionally.** Decision
4's rule - "No term reaches metadata that is not named in the table below"
(`:180-186`, read at `40957e6`) - stands; this amendment names the term. The
row to read alongside decision 4's table (`:188-199`, read at `40957e6`) is:

| Key | Type | On | Meaning |
|---|---|---|---|
| `tenant_ref` | `String.t()` | the four span names' halves, **only when `:telemetry_tenant_ref` is on** | ADR-0003 decision 5's keyed reference, in full; A2 |

and the corresponding line in the `metadata` typespec of "The contract as
typespecs" (`:430-441`, read at `40957e6`) is
`optional(:tenant_ref) => String.t()`. The key is spelled `tenant_ref` and not
`tenant` or `tenant_id`, deliberately: it is the same name ADR-0004 gives the
same string in the context, and a handler author who sees `tenant_id` would
reasonably believe it was one.

No measurement is added. No event name is added. Nothing else in decision 4's
two tables changes.

**A5. The option's generated documentation says who can re-identify, in those
words.** An opt-in is a disclosure decision, so the disclosure travels with
the option rather than with this record. `:telemetry_tenant_ref`'s
documentation on `Encryptor.Vault` and in `Encryptor.Telemetry`'s moduledoc
states, at minimum:

> With `telemetry_tenant_ref: true`, every encrypt, decrypt, rekey and
> provider event carries `tenant_ref` - ADR-0003 decision 5's keyed reference
> for the tenant the call routed to. It is a pseudonym and not an identifier:
> it does not contain the tenant identifier and cannot be reversed into it.
> Anyone holding the vault's reference subkey can re-identify it, by deriving
> the reference for a candidate tenant and comparing, and so can anyone who
> can enumerate or guess your tenant identifiers. Telemetry metadata is
> forwarded verbatim by handlers you did not write to vendors whose retention
> you did not choose. Turning this on is a decision about that, and it is off
> by default.

The second and third sentences are the load-bearing ones and neither may be
dropped as boilerplate: the first half is why this is safe enough to offer at
all, and the second half is why it is not on by default.

**A6. What this amendment narrows, quoted.** Two sentences in the accepted
record say "no per-tenant dimension" without qualification. They are correct
for the default build and wrong as absolutes once this option exists, so this
amendment records their amended wording here, and the implementation writes
the amended wording:

- Decision 6, fifth bullet, last sentence: "**No event carries a per-tenant
  dimension of any kind**, keyed or unkeyed, which is the shortest correct
  statement of this rule and the one to put in the moduledoc" (`:270-273`,
  read at `40957e6`). Amended to: **no event carries the partition id or the
  raw selector, under any configuration; no event carries a per-tenant
  dimension of any kind unless the vault set `telemetry_tenant_ref: true`, and
  the only dimension that option adds is ADR-0003 decision 5's keyed
  reference.** The rest of that bullet - the whole argument against the
  partition id - is untouched and remains the reason the option carries the
  keyed reference instead.
- The `Encryptor.Telemetry` moduledoc in "The contract as typespecs": "No
  event carries a per-tenant dimension, keyed or unkeyed" (`:408`, read at
  `40957e6`). Amended to: **no event carries a per-tenant dimension unless the
  vault opted in with `telemetry_tenant_ref: true`, and then it is the keyed
  `tenant_ref` and never the partition id.** The preceding sentence of that
  moduledoc, which refuses plaintexts, keys, context values, selectors,
  partition ids and `:engine` terms, is unchanged.
- Decision 6, **second** bullet, under that decision's preamble "None of the
  following reaches a measurement, a metadata value, or an event name, under
  any configuration, in any build": "**A data key, a wrapping key, a root key,
  a tenant master key, the reference subkey, or any value derived from any of
  them.**" (`:239-241` and `:245-246`, read at `40957e6`). Read literally that
  reaches `tenant_ref`, which is `HMAC-SHA256(reference_subkey, selector)`
  truncated and encoded (`lib/encryptor/vault/reference.ex:47-54`, read at
  `40957e6`), and this amendment will not rely on a reader inferring an
  exception. Amended to: **the bullet refuses key material and anything from
  which key material can be recovered; it does not reach ADR-0003 decision 5's
  keyed reference, which is a one-way 128-bit tag that recovers neither the
  subkey nor the selector, and which that decision already publishes in every
  message header and ADR-0004 decision 4 already publishes in every
  application-data encryption context.** The bullet's own mechanical form -
  "no key descriptor and no `Config` ever appears as a metadata value, so
  there is no field for material to ride in" - is unchanged and is untouched
  by this option, which adds a `String.t()` and no struct.

Decision 10's sequencing (`:321-341`, read at `40957e6`) puts the four span
names in the "ships with the path it instruments" half, so this option ships
with them and not before: there is no event for it to ride on until
`encrypt/2` is written. A vault that declares the option before then is still
refused-or-accepted per A1, and simply has nothing to add the key to.

**Accepting this amendment flips four sites**, and they are listed here so
the flip is mechanical: the pointer under the record's own `Status` line, this
amendment's heading, its `Status` line, and the answer line under open
question 4 - which says "proposed" today and becomes this record's resolution
of that question on acceptance, in the form ADR-0004 uses for the same job
(`docs/adr/0004-encryption-context.md:939`, read at `40957e6`). Until then the
question is answered by a proposed amendment and the line says so, because a
proposed record may not record itself as resolved.

### Consequences

**The disclosure posture of the package is unchanged for a host that does
nothing.** Default off, refused on `:single`, absent key rather than `nil`.
The only way to get a pseudonym into a metrics vendor from this package is to
write one option and mean it.

**A host that opts in gets exactly the incident capability decision 6's
consequence said it was giving up**, and no more: a `key_unavailable` rate
broken down by an opaque, stable, per-tenant value that correlates against the
host's own store - which is where the mapping from reference to tenant already
lives, because ADR-0003 decision 5 made the key store keyed by reference.

**The cost is a map write, not an HMAC.** A3's threading rule is what makes
that true, and it is the reason this amendment could answer open question 4
without reopening decision 9's synchronous-emission argument. An
implementation that derives per event has both regressed the hot path and
broken this amendment.

**`tenant_ref` in telemetry is now a third publication site for the same
string**, after the message header (ADR-0003 decision 5) and the encryption
context (ADR-0004 decision 4). That is deliberate and is the reason the value
is the keyed one: all three sites publish the same pseudonym, so a compromise
of one discloses nothing the other two did not, and the reference subkey
remains the single thing that re-identifies any of them. It also means the
reference subkey's "effective unrotatability", which ADR-0003 decision 6
isolated onto the cheap half of the root, now has one more consumer to
consider if it is ever revisited.

**A `:telemetry_metrics` user gains a genuinely unbounded tag.** Cardinality
is the host's tenant count, which is exactly what the host asked for, and it
is the host's vendor bill. The option's documentation is where that belongs;
this record does not cap it, because a cap would either drop tenants silently
or collide them, which is A2's argument a second time.

### Open questions

A-1. **Whether the dimension should also be available per attach rather than
per vault.** A1 refuses attach-time for a mechanical reason, not a
philosophical one: the emitter cannot see handler config. A host with two
handlers - an in-VM aggregator that wants the dimension and a vendor exporter
that must not have it - is not served by a per-vault switch, and the honest
answer today is that such a host filters in its own handler before forwarding.
If that turns out to be common, the shape to look at is a second option that
names which events carry it, not a second mechanism. Settle with the first
host that reports the split.

A-2. **Whether `[:encryptor, :cache, :recycled]` should carry a count of
partitions dropped.** A3 refuses the tenant dimension there because a recycle
is about all of them at once, which immediately raises the question of whether
"how many" is a measurement worth having - it is a number, so decision 4's
first half permits it. It is out of this amendment's scope because it is not a
tenant dimension and does not need the option. Whoever writes the recycler's
events should decide it.

## Note (2026-09-13): the enumerations are snapshots, the rules are the contract; open question 6 answered

Five corrections to the accepted decisions and three to Amendment A, none of
which changes a decision. Every code cite below was re-read by anchor at enc
`ec6a84d` unless it says otherwise.

### 1. Decision 5's "fourteen members" is a snapshot; the rule is the contract

Decision 5 says "the error vocabulary is fourteen members" and enumerates
fourteen. `t:Encryptor.Error.reason/0` has **fifteen** today
(`lib/encryptor/error.ex:89-104`): `{:not_provisionable, module()}` was added
by ADR-0007 decision 2 after this enumeration was written, and
`Encryptor.Telemetry.reason_tag/1` ships fifteen clauses to match
(`lib/encryptor/telemetry.ex:201-215`, on this branch).

**Decision 5's rule is what binds, and it held.** The rule is that
`reason_tag` is the head of the reason term and that the tag set "extends only
when the error vocabulary does, which is itself an ADR-gated act". ADR-0007
was that act, the vocabulary extended, and the tag set extended with it. Read
the count and the code block as a snapshot of the vocabulary on the day the
decision was written, not as a bound on it. The same reading applies to the
"one function with fourteen clauses" sentence in "The contract as typespecs".

### 2. Decision 3's "Ten names" is likewise a snapshot, and its own table says twelve

Decision 3's table lists four point events and four span **pairs**. Four
points plus eight halves is twelve names, and `Encryptor.Telemetry.events/0`
returns twelve, pinned by a doctest
(`lib/encryptor/telemetry.ex:111-124` for the attributes,
`:181-182` for the pin; both on this branch). The sentence "Ten names, four
of which are span halves' partners" undercounts:
`t:Encryptor.Telemetry.span_name/0` has four members, so there are four
partners, but eight halves.

The rule decision 3 states is unaffected: the vocabulary is closed, defined
once in `Encryptor.Telemetry`, `events/0` is the single definition site a host
attaches against, and adding a name takes an amendment. Read "Ten names" as a
count taken before the span pairs were fully enumerated in the same table.

### 3. `[:encryptor, :cache, :recycled]` carries `duration` alone, as the worked example shows

Decision 4's measurement table says `system_time` is on "every span start and
every point event", and decision 3 classes `:recycled` as a point event. Read
together those two say `:recycled` carries `system_time`. This record's own
worked example shows it with `duration` and nothing else, and
`Encryptor.Telemetry.cache_recycled/3` emits `%{duration: duration}`
(`lib/encryptor/telemetry.ex:274-282`, on this branch).

**The worked example is right and the code follows it.** `:recycled` is the
one point event that measures an elapsed interval - the recycler times its own
terminate-and-restart - so `duration` is the measurement it has to report, and
a wall-clock reading adds nothing a handler cannot get from its own receipt
time. Read the `system_time` row as "every span start, and every point event
that has no duration of its own". Adding `system_time` to `:recycled` later
would be additive and harmless, but it would be an amendment, not a defect
fix, because this Note settles the reading the other way.

### 4. The `:recycled` error branch has two sub-cases, and the closed tag set covers one

The worked example tags the error branch `reason_tag: :vault_not_started`, and
`cache_recycled/3` hard-codes that tag on every `{:error, _}`. But
`Encryptor.Vault.CacheRecycler.recycle/2` reaches the error branch two ways
(`lib/encryptor/vault/cache_recycler.ex:144-156`): `terminate_child/2`
returning `{:error, :not_found}`, which genuinely is a cache child that was
not there to drop; and `terminate_child/2` succeeding and `restart_child/2`
then returning `{:error, :running | :restarting | term}`, which is not a
not-started vault at all.

This Note **records the gap and does not close it.** A second tag is a new
member of a closed vocabulary, and decision 5 makes that an ADR-gated act: if
one is wanted, it is an Amendment to this record and to
`t:Encryptor.Error.reason/0`, not a Note. Until then, read
`reason_tag: :vault_not_started` on `:recycled` as "the recycle did not
complete", with the sub-case in the supervisor's own return to the caller,
which `recycle/2` passes through unchanged.

### 5. Open question 6 is answered: `:start_refused` is reachable in the case it is for

Open question 6 asks whether `[:encryptor, :vault, :start_refused]` is
reachable "in the case it is for", given that configuration resolves inside
`Supervisor.start_link/2` before any process exists
(`lib/encryptor/vault/supervisor.ex:34-42`) and a vault is typically started
from the host's application supervisor, before the host's handlers attach.

**It is reachable, and the case it is for is a vault started after the host's
handlers are attached.** That is not a corner: a host that starts a tenant
vault on demand, restarts one after a configuration change, or starts one from
a test setup is in it, and those are exactly the starts whose refusals an
operator has no other signal for. The open question's own second half - "It
still fires usefully for a vault started later, or in a host that attaches
handlers first" - is the answer; what it lacked was a decision that this is
enough to keep the event. It is. The event stays, and hosts that want to catch
boot-time refusals attach before their vault's supervisor starts.

### 6. Amendment A's A1 refuses `true`, not the option

A1 says "A `:single` vault that declares it is refused at `Config.resolve/4`".
The implementation refuses only `telemetry_tenant_ref: true` on a `:single`
vault; `telemetry_tenant_ref: false` declared explicitly on a `:single` vault
is accepted, and so it should be - it asks for the default
(`lib/encryptor/vault/config.ex:646-657`, on this branch). Read A1's sentence
as **a `:single` vault that sets the option to `true` is refused**. A
non-boolean is refused on either profile, which A1 already says separately
and which the same clause implements.

### 7. Amendment A's A3 ordering rule is conditional on a resolution that succeeded

A3 states that the `:start` half "is emitted **after** selector resolution".
It does not say whether a *refused* resolution counts, and as written the
ordering rule reads unconditionally. The paragraph above it already settles
the substance - on an `{:invalid_selector, other}` refusal "the span halves
still fire exactly as decision 3 and decision 9 say, and they **omit**
`tenant_ref`" - so the two are only in tension about wording.

Read A3's ordering rule as: **the `:start` half is emitted after selector
resolution has been attempted, and carries `tenant_ref` only when that
resolution succeeded.** Both halves fire either way; a refusal produces a span
pair with no `tenant_ref` and `reason_tag: :invalid_selector` on the stop half,
which is what A3's own disambiguator sentence assumes.

### 8. The acceptance flip's fourth site takes composed prose, not a substitution

A6 lists four sites the operator's acceptance flip touches: the pointer under
this record's `Status` line, Amendment A's heading, its `Status` line, and the
answer line under open question 4. The first three are word substitutions. The
fourth is not: that line reads "*Answered by Amendment A (2026-09-13;
proposed): yes - opt-in and keyed. ...*", and the parenthetical is load-bearing
prose rather than a status token - the sentence exists to say the question is
answered *by a proposed amendment*, which is the thing that stops being true
at the flip.

At the flip, that line is **composed**, not substituted. The shape ADR-0004
uses for the same job is the model: the answer line drops the proposed-ness
and states the resolution as the record's own, dated to the acceptance. A
find-and-replace of "proposed" with "accepted" would leave a sentence whose
grammar still hedges.

Nothing above changes. No decision is amended, no error vocabulary is added or
removed, no event name is added or removed, and this Note carries the record's
status rather than one of its own.

## Note (2026-09-13): Amendment A accepted; the flip's four sites, and where its cites resolve today

The operator accepted Amendment A on 2026-09-13, in the same reading that
accepted this record itself. This Note records that acceptance, meets the
sentences in Amendment A's body that named its own proposed status, and
re-locates the amendment's cites against `main` at `6acefff`. It changes no
decision: decisions 1 to 10 and A1 to A6 stand exactly as written, and it
carries the record's status rather than one of its own.

### 1. The four sites A6 named are flipped

A6 says the flip touches "the pointer under the record's own `Status` line,
this amendment's heading, its `Status` line, and the answer line under open
question 4". All four are flipped in this commit, and nothing else in the
record's words changed. The fourth is composed rather than substituted,
because the Note above (item 8) settled that it takes composed prose and
named ADR-0004's `*Resolved at acceptance (...)*` form as the model.

### 2. The sentences that named the proposed status are met, not reworded

Two sentences speak of Amendment A as proposed. They are left exactly as they
stand, and this Note is where they are answered.

- A6's closing paragraph: "Until then the question is answered by a proposed
  amendment and the line says so, because a proposed record may not record
  itself as resolved." **Met.** The "until then" ended on 2026-09-13, and open
  question 4's answer line now records the resolution as this record's own.
- The Note above, item 8: "At the flip, that line is **composed**, not
  substituted." **Met**, in the form that item prescribed.

### 3. Where Amendment A's cites resolve at `6acefff`

Amendment A labels its cites `read at 40957e6`. Its own implementation - the
four spans and the opt-in dimension - and the prose corrections that landed
with the Note above have moved several of them since. Every cite below was
re-read by anchor at `6acefff`. **Every claim holds**; what follows is
re-location, not correction.

| Cited in Amendment A | Resolves at `6acefff` |
|---|---|
| `lib/encryptor/vault/resolve.ex:213-216`, `Resolve.vault_supplied/2` deriving the reference | `Encryptor.Vault.Resolve.reference/2` (`lib/encryptor/vault/resolve.ex:206-209`) derives it once per `open/3`, and `vault_supplied/1` (`:263-267`) receives the derived string. The arity changed because A3's derive-once threading is what this code now implements |
| `lib/encryptor/vault/config.ex:252` and `:677-687`, the reference subkey frozen onto the configuration | the typespec at `lib/encryptor/vault/config.ex:246`, the struct field at `:266`, the resolve at `:432` and `:451`, the `:tenant` clause of `reference_subkey/3` at `:721-732`, with the `:single` clause beside it at `:734-743` |
| `lib/encryptor/vault/config.ex:274-283`, `defaults/0` beside `cache: false` | `lib/encryptor/vault/config.ex:288-297`, where `telemetry_tenant_ref: false` now sits at `:296` as A1 decided |
| `lib/encryptor/vault/config.ex:552`, `{:invalid_config, :cache, :not_false_or_keyword_list}` | `lib/encryptor/vault/config.ex:569` and `:572` |
| `lib/encryptor/envelope.ex:435-450` and `:441`; `lib/encryptor/vault/reference.ex:47-54`; `lib/encryptor/vault/resolve.ex:60-65` | unchanged, at those anchors |
| `docs/adr/0003-per-tenant-envelope.md:228-246`; `docs/adr/0004-encryption-context.md:227-234`, `:908-939` and `:939` | unchanged, at those anchors |
| this record's own `:180-186`, `:188-199`, `:239-241`, `:245-246`, `:270-273`, `:321-341`, `:382-390`, `:408`, `:430-441`, `:623-633` | each five lines later **in this record as it now stands**: read them as `:185-191`, `:193-204`, `:244-246`, `:250-251`, `:275-278`, `:326-346`, `:387-395`, `:413`, `:435-446`, `:628-638`. Four of those five lines are the Amendment A pointer paragraph that landed under the record's `Status` line with the amendment itself; the fifth is this flip re-wrapping that paragraph. Nothing in decision 4's tables moved relative to its own neighbours. Against `6acefff`, before this flip, the same anchors read one line lower |

### 4. A1 to A6 are implemented, and the implementation matches

A1's option is in `defaults/0` and its two refusals are at
`lib/encryptor/vault/config.ex:646-657`. A3's derive-once rule is the
`reference/2` and `telemetry_reference/1` pair at
`lib/encryptor/vault/resolve.ex:202-225`. A6's amended moduledoc wording is
written at `lib/encryptor/telemetry.ex:7`. The three sentences A6 quotes are
still unamended where they sit in this record, which is what A6 said it would
do: record their amended wording rather than edit them in place.

### 6. What the pass-1 direction review corrected in this Note

The cold direction review of this flip found section 3's table wrong in two
ways, and it is corrected above rather than left for a reader to trip over.
`:180-186` and `:188-199` were listed as unchanged; they moved with every
other self-cite. And the stated cause - four rows added to decision 4's
metadata table - was false: those four rows already existed when Amendment A
was written, and the whole shift is the amendment's own pointer paragraph
under the record's `Status` line. The re-located values are also now given
as they read in this record after the flip, rather than one line lower.

## Note (2026-09-13): the acceptance Note's self-cite table is one row short, and its sections skip 5

Two corrections to the Note above, "Amendment A accepted; the flip's four
sites, and where its cites resolve today". Both are about that Note rather
than about Amendment A or any decision, and neither changes anything. Cites
re-read by anchor at enc `bdbb63c`.

### Amendment A carries eleven self-cites; section 3's table re-locates ten

Section 3, "Where Amendment A's cites resolve at `6acefff`", ends with a row
listing this record's own self-cites as `:180-186`, `:188-199`, `:239-241`,
`:245-246`, `:270-273`, `:321-341`, `:382-390`, `:408`, `:430-441` and
`:623-633` - ten anchors - and re-locates each of them five lines later.
Amendment A carries an eleventh. Under "What it is **never**, under this
option or any other", the refusal of the partition id cites decision 6 and
ADR-0004 open question 1's argument together as "`:239-273` and
`docs/adr/0004-encryption-context.md:908-939`, read at `40957e6`".

That cite takes the same shift as its neighbours and reads as **`:244-278`**
in this record as it now stands: `:244` opens decision 6, "What is never
emitted, and why each one", and `:278` closes its partition-id bullet. Read
section 3's table as carrying that eleventh row, `:239-273` re-located to
`:244-278`. Nothing in section 3's conclusion changes: every Amendment A
self-cite moved by the same five lines, for the same reason, and each still
resolves.

### The Note's sections are numbered 1, 2, 3, 4, 6

The Note above heads its sections "1. The four sites A6 named are flipped",
"2. The sentences that named the proposed status are met, not reworded",
"3. Where Amendment A's cites resolve at `6acefff`", "4. A1 to A6 are
implemented, and the implementation matches", and "6. What the pass-1
direction review corrected in this Note". There is no section 5.

Nothing is missing between 4 and 6: the numbering skipped a value. Read the
last section as **section 5**, and read the Note as five sections rather than
six.

Nothing above changes. No decision is amended, no error vocabulary is added or
removed, and this Note carries the record's status rather than one of its own.
