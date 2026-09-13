# Secrets at start

Every vault in this package gets its key material from exactly one place: the
return of your vault's own `init/1`. The [getting-started
guide](getting-started.md) shows the shape in passing. This guide is the
pattern in full - how to read a secret out of the environment or a secrets
manager at boot, what happens when it is not there, and why sourcing is the
vault's job rather than the provider's.

Everything below is about one moment: the vault starting. Configuration is
resolved once, frozen, and never read again (ADR-0001 decision 5), so the
start is the only place a mistake about a secret can be caught, and it is the
only place this guide is about.

## Layer 5 is the only layer that runs your code

The precedence chain has five layers, lowest to highest:

1. the package defaults,
2. options passed to `use Encryptor.Vault`,
3. `Application.get_env(otp_app, vault)` - your `config/*.exs`,
4. options passed to `start_link/1`,
5. the return of your vault's optional `init/1` callback.

Layers 1 to 4 are *data*: a literal in a `.beam` file, a literal in a config
file, a literal at a call site. Layer 5 is the only one that is *code*, and
that is the whole reason it exists. A secret has to be fetched from somewhere
at the moment the system starts, and fetching is something only code can do.

So the rule is not a style preference:

> **Key material belongs in layer 5, because layer 5 is the only layer that
> can go and get it.**

The package enforces the negative half mechanically at layer 2. A `use`
option named `:key`, `:keys`, `:root_key`, `:private_key`, `:passphrase` or
`:reference_subkey` - or a `:provider` option nesting one of those - fails
compilation, from `Encryptor.Vault.Config.validate_use_opts!/2`, while the
macro expands. The list is closed and is extended by a record, not by a call
site.

Layer 3 is not enforced, because the package cannot tell a key from any other
binary in your application environment. That half is discipline: structure in
config, secret in `init/1`.

## Reading the environment at boot

```elixir
defmodule MyApp.LedgerVault do
  use Encryptor.Vault, otp_app: :my_app

  @impl true
  def init(config) do
    key = Base.decode64!(System.fetch_env!("MY_APP_LEDGER_KEY"))

    {:ok,
     Keyword.put(
       config,
       :provider,
       {Encryptor.Provider.Static, key: key, namespace: "acme_payments", name: "ledger/v1"}
     )}
  end
end
```

```elixir
# config/config.exs - structure only, never key material
config :my_app, MyApp.LedgerVault,
  context_profile: :single,
  algorithm_suite_id: 0x0478,
  required_context: ["table", "column"],
  static_encryption_context: %{"app" => "acme_payments"},
  cache: [max_age: 60]
```

Five things in eight lines, and each one is a decision rather than a habit.

**`System.fetch_env!/1`, never `System.get_env/1`.** This is the single most
consequential character in the example. `fetch_env!/1` raises when the
variable is absent, in `init/1`, during the vault's start - so a deployment
that forgot to set it never comes up. `get_env/1` returns `nil`, and `nil` is
a value: it travels down into the provider options and becomes a *different*
failure, further from the mistake. See [what each mistake looks
like](#what-each-mistake-looks-like) below for both.

**Base64, decoded here.** A key is bytes, and an environment variable is a
string. Encoding it means the value that passes through your deployment
tooling, your process table and whatever wrote it there is at least not
directly a key. `decode64!/1` raises on a malformed value, which is the
behaviour you want at start.

**`Keyword.put/3` on the list you were handed.** `init/1` receives the merge
of layers 1 to 4 and its return **replaces** that merge rather than being
merged over it. The package defaults are re-applied underneath, so a callback
that builds a fresh list does not silently drop the commitment-policy floor -
but everything *you* configured in layers 2 to 4 would be gone. Add to the
list you were given.

**`:namespace` and `:name` are chosen, not defaulted.** They default to
`"encryptor"` and `"v1"`, and a name is bound to its bytes forever. Name the
key for what it protects and version it, on day one, while it is still free.

**`init/1` runs once.** It runs inside the starting process, before the
vault's children are up, from `Encryptor.Vault.Config.resolve/4`. It is not
on the encrypt path, so it may do real work; see [sourcing from a secrets
manager](#sourcing-from-a-secrets-manager).

## Refusing to boot without the key

A vault that cannot be configured correctly does not start. That is a
package-wide rule - none of the start-time checks is deferred to the first
encrypt - and it is the behaviour the pattern above is built to get.

Put the vault in your supervision tree **above** anything that serves
traffic:

```elixir
children = [
  MyApp.Repo,
  MyApp.LedgerVault,
  MyAppWeb.Endpoint
]
```

A missing secret then stops the boot before the endpoint accepts a request.
The alternative - a node that comes up, serves, and fails every encrypt - is
the failure mode this ordering exists to prevent.

### What each mistake looks like

| The mistake | What you get, and when |
|---|---|
| `fetch_env!/1` and the variable is unset | a `System.EnvError` from `init/1`; the vault's supervisor never starts |
| the variable holds something that is not base64 | an `ArgumentError` from `Base.decode64!/1`; same, at start |
| `get_env/1` and the variable is unset | the vault starts resolving a `nil` key, and the provider refuses it: `{:invalid_config, :provider, :key_size}` at start |
| the key is the wrong length | the same `{:invalid_config, :provider, :key_size}` - 16, 24 and 32 bytes are the accepted sizes |
| no `:provider` in what `init/1` returned | `{:missing_config, [:provider]}` at start |
| `init/1` returns something other than `{:ok, keyword}` | `{:invalid_config, :init, :bad_return}` at start |

The first two rows are exceptions and the rest are
`{:error, %Encryptor.Error{operation: :start}}`, and the difference is not
arbitrary. The exceptions are raised by *your* callback, out of the standard
library, and the package deliberately does not rescue them into its own error
vocabulary - it never rescues an exception into an `{:error, _}` (ADR-0001
decision 10). What the package refuses, it refuses in its own closed
vocabulary.

The `get_env/1` row is the one worth sitting with. Nothing about that failure
names the environment variable, because by the time it happens nobody
remembers there was one: a `nil` was put into the provider's options and the
provider reported the only thing it can see, which is that `nil` is not a key
of an acceptable size. The refusal is correct and the diagnosis is now yours
to do. `fetch_env!/1` costs one character and reports the actual mistake.

A vault that failed to start is not a landmine, either. Call sites get
`{:error, %Encryptor.Error{reason: {:vault_not_started, MyApp.LedgerVault}}}`
rather than an exit from inside a library - but they get it on every call,
which is why you want the boot to have stopped instead.

## Sourcing from a secrets manager

The environment is the common case, not the required one. `init/1` is an
ordinary function call, so anything you can do in a function you can do here:

```elixir
defmodule MyApp.LedgerVault do
  use Encryptor.Vault, otp_app: :my_app

  @impl true
  def init(config) do
    # Your own client, and it raises or returns a bad value on failure.
    key = MyApp.Secrets.fetch!("ledger/master-key", timeout: :timer.seconds(5))

    {:ok,
     Keyword.put(
       config,
       :provider,
       {Encryptor.Provider.Static, key: key, namespace: "acme_payments", name: "ledger/v1"}
     )}
  end
end
```

Four constraints come with doing I/O at start, and all four are about the
fact that this code runs during boot:

- **Bound the call.** `init/1` runs inside the starting process, so a fetch
  with no timeout is a boot that hangs rather than a boot that fails. A
  hanging boot is worse than a failing one: it has no error to read.
- **Fetch once.** The resolved configuration is frozen into
  `:persistent_term`, and per-call reads never touch this code again. Do not
  build a provider that calls your secrets manager per encrypt - that is a
  network round trip on the path of every encrypted column read.
- **Fail loudly.** A client that returns `{:error, _}` or `nil` on an
  unreachable manager turns a secrets outage into the `get_env/1` row of the
  table above. Let it raise.
- **Mind the restart loop.** A vault that raises at start is a supervisor
  child that fails, and your application's restart intensity decides whether
  that becomes a crash loop or a stopped node. Either is a visible outage,
  which is the point; decide which one you want rather than discovering it.

## Two `init/1`s, and only one of them sources anything

There are two `init/1` callbacks in this package, they run within a few
microseconds of each other at the same start, and confusing them is the
easiest mistake in this whole area.

| | `c:Encryptor.Vault.init/1` | `c:Encryptor.Provider.init/1` |
|---|---|---|
| Whose module | yours, the host's vault | the provider adapter's |
| Argument | the merged configuration (layers 1 to 4) | the provider's own options, as layer 5 handed them over |
| Returns | `{:ok, keyword}` - the configuration to start with | `{:ok, state}` or `{:error, reason}` - frozen as `:provider_state` |
| Optional | yes | yes - a provider exporting none keeps its option list as its state |
| Job | decide **where the secret comes from** and go get it | validate and shape **what it was handed** |

The provider's `init/1` also runs once, at start, and what it returns is the
state every later resolution callback is handed (ADR-0002 decision 1). That
is what makes resolution a lock-free read on the hot path, and what makes a
provider that cannot configure itself a vault that does not start.

Note the one-way flow: the vault's callback produces the provider's options,
never the reverse. Sourcing happens strictly above the provider boundary.

## Why sourcing is not a provider feature

`Encryptor.Provider.Static` holds its keys in configuration and resolves
nothing from a store. It would be a small change to have it read
`MY_APP_LEDGER_KEY` itself and save its users four lines. That change is
declined, and the reasons compound:

1. **A variable name would become package API.** Whatever string the provider
   read would be a name this package owns, in your deployment, forever. There
   is no version of that which is not worse than you naming it yourself.
2. **Every provider would need it, and they would drift.** `Static`,
   `Function`, a KMS-backed provider, and whatever provider you write for
   your own key table are four adapters behind one behaviour. Sourcing in one
   of them is a feature the other three lack; sourcing in all four is the same
   code written four times, with four option names and four precedence
   orders.
3. **It would not compose.** A host that moves from an environment variable
   to a secrets manager would need a *second* option on the provider, and then
   a rule for what happens when both are set. In `init/1` it is a different
   line of your own code.
4. **The secret's origin would leave your codebase.** Today, where your key
   material comes from is visible in your own vault module, in a review, in a
   diff. A provider that sources it moves that fact into a dependency's
   configuration, where nobody looks.

The contract this protects is one sentence: **the provider holds what it was
handed.** `Static` does not know whether its key came from an environment
variable, a secrets manager, a hardware token or a test fixture, and that is
exactly why the same provider serves all four. ADR-0002 decision 5 says the
same thing from the provider's side: `Static` resolves its key in its own
`init/1` "from what the host's `init/1` handed it", the secret "having come
from the host vault's own `init/1` and therefore from the environment, never
from config or from `use` options".

### "So is an environment variable"

ADR-0002 decision 5 does list an environment variable among the *shapes* a
key provider can have - alongside a database of wrapped keys and every
external key manager other than AWS KMS - and that is a taxonomy of where
bytes can come from, not a roadmap row. The roadmap ships no such adapter,
and the same decision says why it does not need one: the environment is
already reachable, through the vault's `init/1`, without a provider knowing
it exists. A shape that is reachable for free is not an adapter.

### The apparent exception

A KMS-backed provider does take something credential-shaped.
`Encryptor.Provider.GcpKms` requires `:goth` - a running token server's name,
or a `{module, name}` pair for anything exporting `fetch/1` with Goth's return
shape.

That is not a counter-example, and the shape of the option is the tell: the
provider takes **the name of a process the host already runs**, not a secret.
The credential addresses the provider's own backing authority rather than
being the key material, the host still owns the process that holds it, and
the key material itself never enters or leaves as a configuration value at
all. The rule holds: nothing sources key material below the vault.

## Rotating the variable

Changing a secret in the environment does not reach a running vault. The
configuration is resolved once and frozen, so a new value takes effect at the
next vault start and not before - which for a deployed node means a restart.

That is not a limitation to work around; it is the shape of the procedure.
Rotating the value in `MY_APP_LEDGER_KEY` is a **root rotation**, and a root
rotation has an order of operations, an overlap window in which both the
outgoing and the incoming secret must resolve, and a verification step. The
[rotation runbook](rotation-runbook.md)'s P1 is that procedure; `Static`'s
candidate-list option (`:keys`, newest first) is what makes the overlap
window possible. Do not swap the variable and restart.

## Two things not to do

**Do not log the resolved configuration.** Never log, inspect, or put in an
exception message any plaintext, data key, or wrapping key material. The
package holds itself to this: a provider's own failure term is carried in the
error's `:engine` field and never rendered, precisely because a provider's
failure term can hold key material. A `Logger.debug(inspect(config))` in your
`init/1` undoes that in one line.

**Do not put the secret in `runtime.exs` instead.** It is tempting: it runs
at boot, it can read the environment, and it feels like the same thing. It is
not. A value placed there lands in application environment - layer 3 - which
is a global namespace every dependency in the VM can read by name, and which
turns up in a `:observer` pane and in `Application.get_all_env/1`. Reading
it in `init/1` keeps it in one vault's frozen configuration instead. Use
`runtime.exs` for the per-deployment structure around the vault, which is
exactly what it is for.

## Records

- **ADR-0001** decision 5 - the five-layer chain, the compile-time refusal of
  key material, and `init/1` as the runtime escape hatch for the environment
  or a secrets manager (accepted). Decision 10 - the package never rescues an
  exception into an `{:error, _}`.
- **ADR-0002** decision 1 - the provider behaviour, and its `init/1` running
  once at start into the frozen `:provider_state` (accepted). Decision 5 -
  the adapter roadmap: `Static` and `Function` ship day one, `Static`
  resolves from what the host's `init/1` handed it, and an environment
  variable is a material-source *shape* rather than an adapter.
- **ADR-0003** amendment A decision 3 - `:derivation_salt` is refused at
  layer 2 as well, for a different reason: not secret, but per deployment.
  The amendment is **proposed**, not accepted (the record says so at its
  head); the refusal itself is landed, in `Encryptor.Vault.Config`'s
  deployment-option list.
- **ADR-0004** decision 4 - the reference subkey is key material and is
  refused at layer 2 with the rest (accepted, with amendments).

Where this guide and a record disagree, the record wins and the disagreement
is a bug in this guide.
