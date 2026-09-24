# ADR-0010: A suspension is read from a store behaviour, the per-node ETS set is its default, and a shared store is the host's

Status: accepted (2026-09-24)

## Context

ADR-0005 Amendment A gave this package its third verb: `Encryptor.Vault.suspend/2`
makes a scope unreadable and leaves its wrappings intact, and
`Encryptor.Vault.reinstate/2` lifts it. Its decision A8 fixed where the
suspended set lives, and fixed it on purpose to the smallest thing that
delivers the verb: an ETS table owned by the vault's `Lifecycle` child. All
cites in this record were read at `79bdced` unless another SHA is given.

The table is created by `Encryptor.Vault.Suspension.create/1`, which
`Encryptor.Vault.Lifecycle.init/1` calls beside the configuration freeze.
`Encryptor.Vault.Suspension.suspend/2` inserts the selector and then recycles
the cache; `reinstate/2` deletes it. The gate is
`Encryptor.Vault.Suspension.suspended?/2`, called from the private `allowed/3`
in `Encryptor.Vault.Resolve`, ahead of both provider callbacks and therefore
ahead of the materials cache (Amendment A decision A5). It answers `false`
when the table does not exist, because a vault between a crash and its
restart has no table and A8 makes the set die with the process.

Two properties follow, and A8 records them as decisions rather than defects.
The set is **per node**: a suspension set on one node is not seen by another.
It is **volatile**: a restarted vault serves the scope again. The comment
block at the head of `lib/encryptor/vault/suspension.ex` says what a host
does about that today:

> A host that needs either uses the provider locus of A3 instead - an IAM
> binding revoked on the key material itself - and this package ships no
> distribution and no persistence for it.

and `Encryptor.Vault.suspend/2`'s own doc says "a host running four nodes
suspends on each".

That is a hard operational contract. ADR-0005's P5 makes step 1 "on every
node", and its failure section admits the result of missing one: "some nodes
denying and some serving, which is visible as an intermittent
`{:key_unavailable, _}`". A deploy undoes every suspension on every node it
restarts. The provider locus is durable, but it exists only for a provider
whose key material sits behind an authority that can revoke access to it
(the KMS-backed providers of ADR-0007 and ADR-0008); a host on the `Static`
or `Function` provider has no second locus to fall back on.

Amendment A left the door open in its own words. Its open question A-1 asks
whether a suspension should be durable "in this package rather than only at
the provider", names the evidence that would settle it - two hosts writing
the same re-suspend-on-boot glue - and says "the shape it would take is a
provider callback rather than a store this package owns".

This record answers A-1. The shape is not a provider callback, and it is not
a store this package owns: it is a behaviour this package defines, whose
default is exactly A8's table and whose shared implementation is the host's.

## Decision

**1. The suspended set is read through a behaviour,
`Encryptor.Vault.Suspension.Store`.** A store holds one vault's suspended
set. It has four callbacks and nothing else:

| Callback | Returns | Meaning |
|---|---|---|
| `init(vault, opts)` | `{:ok, state} \| {:error, term}` | validates the store's options for one vault and builds its state; performs no I/O |
| `suspend(state, selector)` | `:ok \| {:error, term}` | adds the selector to this vault's set; idempotent |
| `reinstate(state, selector)` | `:ok \| {:error, term}` | removes the selector from this vault's set; idempotent, and `:ok` for a selector that was never in it |
| `list(state)` | `{:ok, [selector]} \| {:error, term}` | the whole of this vault's set; order is meaningless and duplicates collapse |

`selector` is `Encryptor.Error.selector()`, unchanged. A store keys its set by
the vault it was initialised for: two vaults never share a set, which is the
property `Encryptor.Vault.Suspension.table/1` gives today by naming the table
after the vault. An `{:error, term}` from any callback is the store's own
term; the vault carries it in `Encryptor.Error`'s `:engine` field and never
inspects it (decision 7).

There is deliberately no `suspended?(state, selector)` callback. The gate
never asks the store (decision 3).

It is a behaviour of its own rather than the provider callback A-1 sketched,
for two reasons. Where a host keeps its shared state is independent of where
its key material comes from: a host on the `Static` provider needs a
cluster-wide suspension as much as one on KMS, and a provider callback would
make every provider re-implement the same store. And A5 puts the deny ahead
of the provider on purpose; a deny read through the provider would sit behind
the component whose own failures it has to stay independent of.

**2. The vault takes the store as one option, `:suspension_store`, a
`{module, opts}` pair.** It defaults to
`{Encryptor.Vault.Suspension.Store.Ets, []}`. The store's `init/2` runs once,
during configuration resolution, and its state is frozen with the rest of
`%Encryptor.Vault.Config{}`. An `init/2` that returns `{:error, term}`
refuses the vault's start as `{:invalid_config, :suspension_store, :init}`
with the term in `:engine`, and emits `[:encryptor, :vault, :start_refused]`,
the path `Config.resolve/4` already takes for a provider whose `init/1`
refuses. A value that is not a `{module, keyword}` pair is refused as
`{:invalid_config, :suspension_store, :shape}`. A store's state holds no key
material; the configuration's inspect redacts it as it redacts the
provider's.

A second option, `:suspension_poll_interval`, is a positive integer of
milliseconds and defaults to `5_000`. Any other value is refused as
`{:invalid_config, :suspension_poll_interval, value}`. It is accepted and has
no effect under the default store (decision 4).

**3. The gate reads a per-node view, never the store.** Every vault keeps its
suspended set as the ETS table A8 fixes, owned by `Lifecycle` as today, and
`Resolve`'s gate reads that table and nothing else. This is A5 and A8
unchanged: the read on every encrypt and decrypt stays one concurrent ETS
lookup, with no network round trip, no serialization point, and no
dependency of the hot path on the store's availability. The store is where
the set is *agreed*; the table is where it is *read*.

**4. The default store is A8's table, and changes nothing.**
`Encryptor.Vault.Suspension.Store.Ets` is the store whose set *is* the view:
its `suspend/2` and `reinstate/2` write the table decision 3 reads, and its
`list/1` reads it back. Under it every property A8 decides holds as today,
and the docs say so wherever the default is described:

- a suspension is **per node**: a suspension set on one node is not seen by
  another;
- it is **volatile**: it is lost when the vault's `Lifecycle` restarts,
  including at every deploy;
- a vault whose table is absent, between a crash and its restart, serves
  every scope (`suspended?/2` answers `false`, as today).

No refresher process runs under the default store, because a refresh would
read back the table it would write.

**5. Under any other store, a refresher keeps the view in step with the
store, once per poll interval.** The vault starts one refresher per vault, a
child of the vault's supervisor started after `Lifecycle`, and not inside
`Lifecycle`: a refresher that crashes must not take the view table with it.
The refresher:

- calls `list/1` once at start, then again `suspension_poll_interval`
  milliseconds after each call returns (a fixed delay, not a fixed rate, so a
  slow store is never asked twice at once);
- on `{:ok, selectors}`, makes the view equal to that set, **adding the new
  members before removing the departed ones**, so a scope present both
  before and after is never momentarily absent from the view;
- on `{:error, term}`, an exit, or a raise from the callback, leaves the
  view exactly as it was (decision 7).

`suspend/2` and `reinstate/2` under such a store are calls into the
refresher, so a write and a refresh on one node never interleave: a refresh
that listed the store before a local write landed can never remove what that
write just added. They are operator verbs invoked from a console or a release
task, so serializing them costs nothing on the call path A8 protects. The
call waits the `GenServer` default of five seconds; a call that exits,
because it timed out or because the refresher is restarting, is reported as
decision 7's failed write.

**6. What a suspended scope answers, and where.** The answer is Amendment A's
and is unchanged: `encrypt/2`, `decrypt/2`, `rekey/2` and `derive/2` fail
with `{:key_unavailable, selector}`, and `provision/2` is not gated (A1's
list). What this record adds is *when* each node answers it:

| Store | Node that ran `suspend/2` | Every other node serving the vault |
|---|---|---|
| default (`Store.Ets`) | immediately | never, unless `suspend/2` is run there too |
| shared | immediately, once the store write returned `:ok` | within one poll interval of that write, and across every restart after it |

`reinstate/2` is the same table read in the other direction: immediate on the
node that ran it, within one poll interval everywhere else. A1's observable
("on every vault that serves it") is therefore reached by one call on one node
under a shared store, bounded by the poll interval, and P5's "on every node"
remains true only of the default.

**7. The failure mode when the store is unreachable: fail closed while the
node knows nothing, serve the last known set once it knows something.** This
is a security decision and it is made in three parts.

*A write that fails changes nothing.* `suspend/2` or `reinstate/2` whose store
callback returns `{:error, term}`, exits or raises returns
`{:error, %Encryptor.Error{reason: {:suspension_store_unavailable, store}}}`,
where `store` is the store module, the store's term is in `:engine`, and the
view is left as it was. The vault does not apply a suspension locally that
the store did not accept: the next successful refresh would take it out of
the view again, and a suspension that lifts itself a few seconds after
succeeding locally is worse than a loud refusal the operator can retry. Both
writes are idempotent, so a retry after a timeout, whose write may or may not
have landed, is always safe.

*Before the first successful `list/1`, the view denies every scope.* A vault
under a shared store that has not yet read its set does not know which scopes
are suspended, and the one answer that cannot serve a suspended scope is to
serve none: every gated call answers `{:key_unavailable, selector}`, which ADR-0002
decision 6 defines as "the provider could not answer" and ADR-0003 restates
as the term "for a store that could not answer". This covers a
cold start with the store down, a `Lifecycle` restart that recreated the
table empty, and the moment between a `Lifecycle` crash and its restart when
there is no table at all (where the default store answers `false`, decision
4). It is what makes a shared store durable across restarts in fact
and not only in storage: without it, a restarted node would serve every
suspended scope until its first refresh, which is exactly A8's volatility put
back in through the side door.

*After the first successful `list/1`, a failed refresh keeps the last known
set, for as long as the store stays unreachable.* The choice against failing
closed here is deliberate, and the reason is what each answer costs:

- Failing closed would turn any outage of the host's shared store into an
  outage of every scope on every node, for a mechanism whose job is to deny
  a few. The store will usually be the host's own database; a host whose
  database blips would lose all encryption and decryption, not just the
  suspended scopes.
- Serving the last known set never *lifts* a suspension the node has seen.
  The only thing a failed refresh can do is delay news: a suspension written
  elsewhere during the outage is not enforced on this node until the store
  answers again, and a reinstatement is not honoured until then either (the
  second fails closed on its own).
- The delayed suspension is the residual risk, and it is bounded by what the
  operator can see: the refresher reports every failed refresh and the
  recovery after it (decision 8), and the verification step of P5 runs
  against the nodes that matter. A scope that must be denied regardless of
  any store is a scope for the provider locus (decision 9), which does not
  depend on this store at all.

No staleness cutoff is decided; open question 1 carries it.

**8. `[:encryptor, :suspension, :changed]` is the one new telemetry event.**
It is a point event, emitted synchronously on the process that performed the
action, when the vault's suspension state changes:

- after every `suspend/2` or `reinstate/2` the vault performed, successful or
  not;
- after a refresh that changed the view's membership;
- after a refresh that failed, which changes the view from current to last
  known, and after the first refresh that succeeds following one or more
  failures, which changes it back.

A successful refresh that changed nothing emits nothing, so a healthy vault
is silent between operator actions.

| Metadata key | Type | Meaning |
|---|---|---|
| `vault` | `module()` | as on every event (ADR-0006 decision 4) |
| `action` | `:suspend \| :reinstate \| :refresh` | what the vault did |
| `store` | `module()` | the store module, never its state or options |
| `outcome` | `:ok \| :error` | as ADR-0006 decision 4 defines it |
| `reason_tag` | `:suspension_store_unavailable` | present only when `outcome` is `:error` |

| Measurement | Unit | On |
|---|---|---|
| `system_time` | `:native` | every emission, as on every point event |
| `count` | count | `outcome: :ok` only: the number of scopes in the view after the action |

**The selector is never in it**, by ADR-0006 decision 6: "No event carries a
per-tenant dimension of any kind", and a suspension event is the event a
well-meaning implementation would most want to label with its scope. The
opt-in reference dimension of ADR-0006 Amendment A does not extend to it. An
operator who needs to know *which* scope was suspended reads the store,
which is the host's and already records it. `count` is bounded by the number
of suspended scopes and is not a per-scope dimension.

These are additions to ADR-0006 decision 3's event table, decision 4's
allow-list and decision 5's tag set, recorded here as that record's decision 3
permits ("Adding a name, a measurement, or a metadata key is additive").

**9. The provider locus stays, and the two loci now split on who is denied
rather than on durability.** Amendment A's A3 tabled two loci and told them
apart by durability and scope. A shared store gives the vault-local locus both
of the properties A3 credited only to the provider: it survives restarts and
it covers every node. What still separates them is *who* the deny binds:

| Locus | Denies | Survives restart | Covers |
|---|---|---|---|
| Vault-local, default store | calls through this vault on this node | no | one node |
| Vault-local, shared store | calls through this vault on every node that shares the store | yes | every node configured with that store |
| Provider-level (for example an IAM binding revoked on a KMS key) | every holder of credentials to the key material, this package or not | yes | everything that can reach the key |

A suspension through the store is an application-level deny: code that
reaches the key material without this vault, a second client, or a node
configured with a different store, is not denied by it. IAM revocation is a
key-level deny and binds all of those. They compose as A3 says - both surface
`{:key_unavailable, selector}`, and a host may hold either or both - and the
sentence at the head of `suspension.ex` that sends a host to the provider
locus for durability and cluster reach becomes, once this record is
implemented, the sentence that sends it there for a deny that binds more than
this vault.

**10. The store is the host's, and so is its schema.** This package ships the
behaviour and the default store, and no shared store: it has no database,
no network client and no cluster membership of its own, for the reason A8
gives about a scheduler - the host's existing mechanism for "every node sees
this" is better than a second one invented here. A Repo-backed store is
planned for `encryptor_ecto`, as a later piece of work in that repository;
it is not landed, and this record does not decide its schema.

**11. What this record amends.** ADR-0005 Amendment A is accepted, and this
record changes none of its text. If this record is accepted, A8's last
paragraphs read with one qualification - "This package ships no
distribution, no persistence, and no gossip for it" is true of the default
store and of the package, and a host that configures a shared store has
distribution and persistence of its own making - and open question A-1 is
answered as decisions 1 and 10 give. A1 to A7, the P5 procedure under the
default store, and the blast-radius rows are unchanged.

## Consequences

- **The error vocabulary gains one term**, `{:suspension_store_unavailable,
  module()}`, reached only from `suspend/2` and `reinstate/2` and only under a
  store that can fail. ADR-0001 decision 10 closes the vocabulary to
  extension by a record, and this is that record. `Encryptor.Telemetry.reason_tag/1`
  gains its tag. Its `:operation` is `:start`, which is what every error
  `suspend/2` and `reinstate/2` return today carries (the private `live/1` in
  `Encryptor.Vault.Suspension`, and `Encryptor.Vault.suspend/2`'s
  `ensure_started/2` call); open question 3 asks whether that should change.
- **The gate's answer now depends on one more thing than the selector**:
  whether a shared store has ever been read. Two calls a second apart could
  already differ under Amendment A; now a vault that just started can refuse
  every scope until its first refresh. The implementation's tests have to
  pin both halves of decision 7: the deny-all before the first `list/1`, and
  the last known set after a failed one.
- **A host that changes nothing observes nothing.** The default store is the
  table that exists today, the refresher does not run, and no new event fires
  except `[:encryptor, :suspension, :changed]` on the operator's own
  `suspend/2` and `reinstate/2` calls.
- **`guides/rotation-runbook.md` changes with the implementation.** Its P5
  section describes the set as node-local and volatile, which stays true of
  the default and becomes false under a shared store; the guide says which
  holds for which store, and P5's "on every node" becomes "on every node,
  unless the vault's store is shared".
- **A shared store is one more thing that can make a scope unreadable.** A
  misconfigured shared store that never answers leaves its vault denying
  every scope. That is decision 7's first-load rule doing what it is for, and
  `[:encryptor, :suspension, :changed]` with `action: :refresh` and
  `outcome: :error` is how the host finds out.

## The contract as typespecs

A proposal, not landed code.

```elixir
defmodule Encryptor.Vault.Suspension.Store do
  @moduledoc "Where a vault's suspended set is agreed. See ADR-0010."

  @type state :: term()
  @type selector :: Encryptor.Error.selector()

  @callback init(vault :: module(), opts :: keyword()) ::
              {:ok, state()} | {:error, term()}

  @callback suspend(state(), selector()) :: :ok | {:error, term()}

  @callback reinstate(state(), selector()) :: :ok | {:error, term()}

  @callback list(state()) :: {:ok, [selector()]} | {:error, term()}
end

# Encryptor.Vault.Config, the two options
suspension_store: {module(), keyword()}     # default {Encryptor.Vault.Suspension.Store.Ets, []}
suspension_poll_interval: pos_integer()     # milliseconds, default 5_000

# Encryptor.Error, the one added reason
| {:suspension_store_unavailable, module()}

# Encryptor.Vault, unchanged signatures
@spec suspend(module(), Encryptor.Error.selector()) :: :ok | {:error, Encryptor.Error.t()}
@spec reinstate(module(), Encryptor.Error.selector()) :: :ok | {:error, Encryptor.Error.t()}
```

## Worked example: a shared store across three nodes

A host runs three nodes, each starting `MyApp.ScopedVault` with a store its
own application provides:

```elixir
config :my_app, MyApp.ScopedVault,
  suspension_store: {MyApp.SuspensionStore, repo: MyApp.Repo},
  suspension_poll_interval: 5_000
```

An operator on node 1 suspends one scope:

```elixir
:ok = Encryptor.Vault.suspend(MyApp.ScopedVault, "workspace-7")
# node 1: the store row is written, then the view; the next call is refused
{:error, %Encryptor.Error{reason: {:key_unavailable, "workspace-7"}}} =
  MyApp.ScopedVault.decrypt(ciphertext, key: "workspace-7")
```

Within five seconds nodes 2 and 3 refresh, find `"workspace-7"` in `list/1`,
add it to their views, and each emits `[:encryptor, :suspension, :changed]`
with `action: :refresh, outcome: :ok, count: 1`. From then on every node
refuses the scope.

Node 3 is redeployed. Its new `Lifecycle` creates an empty view, and until
its refresher's first `list/1` returns, node 3 refuses every scope, not only
`"workspace-7"`. The first `list/1` returns `["workspace-7"]`; node 3 serves
every other scope again and still refuses the suspended one. Under the
default store, the same redeploy would have served `"workspace-7"` the moment
node 3 came up.

The database becomes unreachable from node 2 for a minute. Node 2's refresh
fails; it emits `action: :refresh, outcome: :error, reason_tag:
:suspension_store_unavailable` and keeps refusing `"workspace-7"`. An
operator who suspends a second scope on node 1 during that minute is enforced
on nodes 1 and 3 at once and on node 2 at the first refresh after the
database answers again, which emits `action: :refresh, outcome: :ok,
count: 2`.

## Open questions

1. **Whether a shared store should fail closed after a staleness bound.**
   Decision 7 serves the last known set for as long as the store is
   unreachable. A `suspension_max_stale` option, after which the vault denies
   every scope as it does before its first read, would bound how long a new
   suspension can go unenforced on a partitioned node, at the price of the
   total outage decision 7 declines. Worth deciding with a host's measured
   store availability, not in advance. Owner: this repository.
2. **Whether the poll should give way to a push.** A store that can notify
   (a database's `LISTEN`, a cluster's process groups) could shorten the
   window to near zero. The behaviour above has no callback for it, and one
   can be added as an optional callback without changing the four. Owner:
   this repository, when a host asks for a window shorter than a poll.
3. **Whether `suspend/2` and `reinstate/2` earn `:operation` values of their
   own.** Their errors say `:start` today, which predates this record and
   reads oddly beside a store failure. Changing it is an addition to
   `Encryptor.Error.operation/0`, which ADR-0006 also uses as a metadata
   type. Owner: this repository.
4. **Amendment A's A-4 is untouched.** Whether `suspend/2` refuses a selector
   of the wrong shape, or one the provider does not know, is as open as it
   was; a shared store makes a mistyped suspension reach every node, which is
   one more reason to decide the shape check first.

## Note (2026-09-24): accepted; what was verified, decision 10's superseded sentence, and the first load's event

This record is accepted on 2026-09-24. Its code shipped in encryptor 0.5.0,
published on Hex from the `v0.5.0` tag at `9ad74e2`. Every claim below was
re-read by anchor at `e84b648`, the tip of `main` when this Note was written;
`lib/` is byte-identical between the two, and the only files that differ are
`mix.exs` and `mix.lock`. This Note changes no decision, and it carries the
record's status rather than one of its own.

### 1. Decisions 1 to 9 are implemented as written

- Decision 1: `Encryptor.Vault.Suspension.Store` declares `init/2`,
  `suspend/2`, `reinstate/2` and `list/1` and no other callback, with
  `selector` typed as `Encryptor.Error.selector()`.
- Decision 2: `Encryptor.Vault.Config`'s defaults name
  `{Encryptor.Vault.Suspension.Store.Ets, []}` and `5_000`. The private
  `suspension_store/2` refuses a value that is not a `{module, keyword}`
  pair as `{:invalid_config, :suspension_store, :shape}`, and refuses a
  module that does not export the four callbacks the same way. The private
  `suspension_store_state/2` runs `init/2` during `resolve/4` and refuses an
  error as `{:invalid_config, :suspension_store, :init}` with the term in
  `:engine`; `Encryptor.Vault.Supervisor` emits
  `[:encryptor, :vault, :start_refused]` for it as for every configuration
  refusal. The private `suspension_poll_interval/2` refuses anything but a
  positive integer as `{:invalid_config, :suspension_poll_interval, value}`.
  The configuration's inspect redacts `:suspension_store_state`.
- Decision 3: the gate is `Encryptor.Vault.Suspension.suspended?/2`, one
  `:ets.member/2` on the table `table/1` names, called from the private
  `allowed/3` in `Encryptor.Vault.Resolve` ahead of both provider callbacks.
- Decision 4: `Encryptor.Vault.Suspension.Store.Ets` writes and lists the
  table the gate reads, `suspended?/2` answers `false` for an absent table
  under it, and `Encryptor.Vault.Supervisor`'s private `refresher_child/1`
  starts no refresher under it.
- Decision 5: `Encryptor.Vault.Suspension.Refresher` is a child of the vault's
  supervisor listed after `Encryptor.Vault.Lifecycle`. It lists the store in
  `handle_continue/2` at start and schedules the next list
  `suspension_poll_interval` milliseconds after each one returns. The private
  `apply_view/2` in `Encryptor.Vault.Suspension` inserts the added members
  before deleting the departed ones. `suspend/2` and `reinstate/2` under a
  shared store are `GenServer.call`s into the refresher at the default
  timeout, and an exit is reported through `failed/3` as a failed write.
- Decision 6: the gate still covers `encrypt/2`, `decrypt/2`, `rekey/2` and
  `derive/2` through `Resolve.encryption_key/3` and
  `Resolve.decryption_keys/3`. Under a shared store, `perform/3` updates the
  local view only after the store's write returned `:ok`.
- Decision 7: `perform/3` changes nothing locally when the store refuses, and
  `failed/3` returns `{:suspension_store_unavailable, store}` with the
  store's term in `:engine` and `:operation` `:start`. The private
  `call_store/3` turns an error, an exit and a raise into that one outcome.
  Before the first successful `list/1`, a shared store's view lives under
  `unloaded_table/1`, which the gate never reads, and `suspended?/2` answers
  `true` for an absent table under any store but the default: a cold start,
  a view recreated by a `Lifecycle` restart, and the moment with no table all
  deny every scope. After it, `refresh/2` leaves the view alone on a failed
  list.
- Decision 8: `Encryptor.Telemetry.suspension_changed/4` emits the event with
  `vault`, `action`, `store` and `outcome`, adds `reason_tag`
  `:suspension_store_unavailable` on an error, and measures `system_time`
  always and `count` only on `:ok`. No call passes it the selector.
- Decision 9: the comment at the head of `lib/encryptor/vault/suspension.ex`
  now sends a host to the provider locus for "a deny that must bind more than
  this vault", which is the sentence decision 9 said it would become.

### 2. Decision 8's enumeration and the first successful load

Decision 8 says the event fires "when the vault's suspension state changes"
and lists three occasions. The code emits on one more, and it is the kind of
change the record's own third bullet counts: the first successful `list/1`
under a shared store takes the view out of decision 7's deny-all state, so it
emits `action: :refresh, outcome: :ok` even when the store's set is empty and
no membership changed. `refresh/2` emits whenever the private `apply_view/2`
answers `true`, and `apply_view/2` answers `true` for a view it has just
renamed into place. `test/encryptor/vault/suspension_store_test.exs` relies
on it in `await_first_refresh/0`, whose comment says "The first successful
list/1 is a change even when the set is empty". Read the list as including
that occasion. The sentence "A successful refresh that changed nothing emits
nothing" still holds: the first load changes what the node answers.

### 3. Decision 10's "it is not landed" is superseded by a later record

Decision 10 says "A Repo-backed store is planned for `encryptor_ecto`, as a
later piece of work in that repository; it is not landed, and this record
does not decide its schema." That work has since landed there:
`Encryptor.Ecto.SuspensionStore`, released in encryptor_ecto 0.6.0 and
recorded by ece-ADR-0007 (2026-09-24), "A Repo-backed suspension store, and
a shred on the key store that returns what it destroyed". The sentence is
left as it stands; read "it is not landed" as true on the day it was written.
The rest of decision 10 holds: this package still ships no shared store, no
database, no network client and no cluster membership, and the schema is
ece-ADR-0007's, not this record's.

### 4. The Consequences hold

- `Encryptor.Error`'s reason type and its description carry
  `{:suspension_store_unavailable, module()}`, and
  `Encryptor.Telemetry.reason_tag/1` maps it to its tag.
- The deny-all before the first `list/1` and the kept set after a failed one
  are pinned in `test/encryptor/vault/suspension_store_test.exs`, including
  "before the first successful list, every scope is denied" and "after it,
  a failed refresh keeps the last known set".
- `guides/rotation-runbook.md` says which property holds for which store,
  and its P5 steps say "on every node" under the default store and "once, on
  any node" under a shared store.

### 5. The sentences that named the record as unimplemented are met, not reworded

The typespec section's "A proposal, not landed code", decision 9's "once
this record is implemented", and decision 11's "If this record is accepted"
were conditional when written. They are left as they stand. The typespecs
match `Encryptor.Vault.Suspension.Store`, the two options in
`Encryptor.Vault.Config`'s `@type t`, and `Encryptor.Error`'s added reason;
decision 9's sentence is met as section 1 says; and decision 11's
qualification of ADR-0005 Amendment A's A8 and its answer to open question
A-1 now stand. ADR-0005's text is unchanged, as decision 11 said it would be.
Open questions 1 to 4 stay open.
