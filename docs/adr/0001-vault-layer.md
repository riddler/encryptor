# ADR-0001: A vault is a supervised, host-owned module that wraps the engine completely

Status: proposed (2026-08-26)

## Context

This package exists to give an Elixir application one obvious way to encrypt
application data at rest, on top of an AWS Encryption SDK implementation
rather than a hand-rolled AES call. The engine is `aws_encryption_sdk`
v1.0.0. This record fixes the layer that sits between a host application and
that engine: what a consumer writes, what runs in the supervision tree, how
it is configured, and what it can be handed back when something goes wrong.

Four forces bind the shape of that layer.

**The engine is data, not a service.** Reading v1.0.0 rather than assuming:
`AwsEncryptionSdk.Client` is a plain struct built by `Client.new/2`, holding
a CMM, a commitment policy, and an EDK limit. Keyrings are structs. CMMs are
structs. Encrypt and decrypt are pure functions over those structs plus a
binary. Exactly one component in the whole library is a process:
`AwsEncryptionSdk.Cache.LocalCache`, a `GenServer` owning a `:private` ETS
table. So a wrapper has almost nothing to supervise, and the temptation to
put a `GenServer` in front of encryption for its own sake would only add a
serialization point to a CPU-bound pure function. Whatever supervision this
layer has must be justified by state that actually exists.

**The engine's extension points are closed in v1.0.0.** Three findings from
the source, each load-bearing:

- `Client.encrypt/3` dispatches to the CMM by struct type, over a closed set
  of `Cmm.Default`, `Cmm.RequiredEncryptionContext`, and `Cmm.Caching`;
  anything else returns `{:error, {:unsupported_cmm_type, module}}`. A
  host-defined CMM is not usable.
- `Cmm.Default` dispatches to the keyring the same way, over a closed set of
  `RawAes`, `RawRsa`, `Multi`, and the four AWS KMS keyrings, returning
  `{:error, {:unsupported_keyring_type, module}}` otherwise. A host-defined
  keyring is not usable either.
- `Cmm.Caching` calls `LocalCache` by name, not through the
  `Cache.CryptographicMaterialsCache` behaviour it nominally targets, so the
  behaviour is not a substitution seam. The cache is `LocalCache` or nothing.

Everything this package builds has to compose the engine's built-in pieces.
It cannot extend the engine from outside. That constraint is inherited by
the key-provider record (enc-6i0) and the envelope record (enc-2u6), which
must not assume a custom keyring or a custom CMM is available.

**The cache is the only stateful thing, and it is unbounded.** `LocalCache`
stores entries keyed by a 48-byte cache id and deletes an entry only when a
read finds it expired, or when someone calls `delete_cache_entry/2` with an
id they already know. There is no capacity limit, no sweeper, no size query,
and the ETS table is `:private` to the `GenServer`, so no outside code can
enumerate or measure it. Meanwhile `Cmm.Caching`'s defaults are the
specification's ceilings, not recommendations: `max_bytes` defaults to
2^63-1 and `max_messages` to 2^32. A wrapper that inherits those defaults
has, in practice, no data key rotation at all. Bounding the cache is
therefore this layer's job and not an optional refinement.

**A multi-tenant host app is the demanding consumer.** The shape that has to
work is one application process encrypting data for many tenants, where a
tenant's data must be cryptographically separable from every other tenant's,
and where key material for a tenant is resolved at request time rather than
read from a config file at boot. That rules out a design where the vault is
a single global keyring, and it makes the cache partitioning question a
correctness question rather than a performance one: two tenants sharing a
cache entry would mean two tenants sharing a data key.

This record fixes the vault surface, its supervision, its configuration, its
cache bounds, and its error vocabulary. It deliberately stops where the key
provider's contract begins. What a provider is, how a selector resolves to
key material, and which adapters ship are enc-6i0. The wrapping structure of
tenant keys is enc-2u6. The encryption context vocabulary is enc-cvw. The
rotation and crypto-shred procedures are enc-53a. This ADR only guarantees
that the vault can host all four.

## Decision

**1. `use Encryptor.Vault, otp_app: :my_app` defines a vault module, and
that module is the entire public surface.** A host writes:

```elixir
defmodule MyApp.Vault do
  use Encryptor.Vault, otp_app: :my_app
end
```

and from then on calls `MyApp.Vault.encrypt/2` and friends. No host code
names `AwsEncryptionSdk` or any module under it, no vault function accepts
an engine struct, and no vault function returns one. `aws_encryption_sdk` is
an ordinary required dependency of this package, not an optional one and not
something the host adds. The one documented exception is the AWS KMS
keyrings: the engine makes `ex_aws`, `ex_aws_kms`, `hackney`, and
`sweet_xml` optional, so a host that configures a KMS-backed provider adds
those four to its own `deps`. That is a documented host obligation, not a
leak of the engine's API, and enc-6i0 owns how it is surfaced.

The reason for total wrapping is not aesthetics. It is that every decision
in the four downstream records (which suite, which commitment policy, which
context keys are required, how a tenant maps to a partition) is enforceable
only if there is exactly one door. A host that can construct its own
`Client` can bypass all of them.

**2. The vault supervises the materials cache, and nothing else.** `use`
generates `child_spec/1` and `start_link/1`. Starting a vault starts a
`Supervisor` whose children are the vault's `LocalCache` (registered under a
name derived from the vault module) and any stateful key providers the
provider record introduces. Encrypt and decrypt build the engine's keyring,
CMM, and `Client` structs per call from resolved configuration; they are
cheap struct constructions over already-resolved material, and making them
per-call is what keeps a per-tenant keyring possible at all.

Two consequences are deliberate. A vault configured with caching disabled
still starts, because providers may need supervision even when the cache
does not exist. And a vault that is not running is a typed error, not a
crash: every entry point checks that the vault's registered name is alive
and returns `{:error, %Encryptor.Error{reason: {:vault_not_started, MyApp.Vault}}}`
rather than letting a `GenServer.call` to an unregistered name raise an
exit from inside a library.

**3. Many vaults per application; one vault per key domain.** The pair
`{otp_app, vault_module}` is the configuration key
(`config :my_app, MyApp.Vault, ...`), so nothing is global and two vaults
never collide. A host is expected to run more than one: a single-key vault
for application-level secrets and a per-tenant vault for tenant data is the
common shape, and the two want different providers, different bounds, and
different blast radii.

Vaults do not share a cache process. Sharing one would mean one vault's
`max_age` and usage limits applying to another vault's materials, since
those bounds live on the `Cmm.Caching` struct while eviction lives in the
cache; the combination is only coherent when a cache serves one bound set.
The cost is one extra process per vault, which is not a cost.

**4. The entry points are `encrypt/2`, `decrypt/2`, `rekey/2`, and their
bang variants.**

`encrypt(plaintext, opts)` returns `{:ok, ciphertext}` where `ciphertext` is
the complete self-describing engine message, and nothing else. The engine's
`encrypt_result` is a map carrying the ciphertext plus the header, the
context, and the suite; the vault returns only the binary, because the
binary is the only thing a caller stores, and returning derived metadata
invites callers to persist a second copy of facts the message already
carries authenticated.

`decrypt(ciphertext, opts)` returns `{:ok, plaintext}`.

`rekey(ciphertext, opts)` returns `{:ok, new_ciphertext}`. Its semantics are
fixed here even though the procedures around it are enc-53a: rekey decrypts
with whatever materials the message's own encrypted data keys resolve to,
then re-encrypts under the vault's currently resolved materials, preserving
the message's encryption context byte for byte. A rekey never changes the
context. Changing the context changes what the ciphertext is bound to, which
is an encrypt of new data, not a rotation of old data, and conflating the
two is how a rotation job silently unbinds a million rows. `rekey/2` touches
no storage; it is a pure binary-to-binary function, and the batch job that
walks rows lives in `encryptor_ecto`.

Recognized options:

- `:key` - the selector handed to the key provider (a tenant identifier, or
  the atom `:default` for a single-key vault). Its type is opaque to the
  vault and belongs to enc-6i0; the vault requires only that it be a term it
  can hash into a partition id (decision 7).
- `:encryption_context` - a map of `String.t()` to `String.t()`, merged over
  the vault's configured static context. A key present in both with
  different values is `{:error, {:encryption_context_conflict, key}}`, not a
  silent override. Keys prefixed `aws-crypto-` are reserved by the engine
  and are refused by the vault before the call rather than after. The
  vocabulary of which keys are expected is enc-cvw.
- `:context` on `decrypt/2` and `rekey/2` is the same option name,
  `:encryption_context`, carrying the reproduced context the engine
  validates against the message.

Deliberately not options: `:algorithm_suite`, `:commitment_policy`,
`:frame_length`, and `:max_encrypted_data_keys`. All four are configuration,
never per-call. A per-call suite is precisely the shape of an algorithm
downgrade, and a per-call commitment policy is the shape of an attacker
choosing to be trusted. Making them configuration means one place to review.

**5. Configuration resolves at start, in a fixed precedence, and key
material may never be compile-time.** The `use` macro captures `:otp_app`
and the module name and nothing else. Everything else is read when the vault
starts. Precedence, lowest to highest:

1. defaults declared by this package,
2. options passed to `use`,
3. `Application.get_env(otp_app, vault_module)`,
4. options passed to `start_link/1`,
5. the return of the vault's optional `init/1` callback.

`init/1` receives the merged keyword list and returns `{:ok, config}`. It is
the runtime escape hatch and the intended place to read a secret out of the
environment or a secrets manager, following the same pattern hosts already
know from `Ecto.Repo.init/2`.

The resolved configuration is frozen at start into an `Encryptor.Vault.Config`
struct published in `:persistent_term` under `{Encryptor.Vault, vault_module}`.
Per-call reads are then lock-free and allocate nothing, which matters because
this is on the path of every encrypted column read. Writes happen once per
vault start, which is exactly the access pattern `:persistent_term` is for.
Changing configuration under a running vault therefore requires restarting the
vault, and that is the intended behaviour: configuration that changes key
selection silently underneath in-flight operations is worse than an explicit
restart.

Any option in the key-material set - raw key bytes, a root key, a private
key, a passphrase - passed to `use` is a compile-time error, not a warning.
A secret in `use` options is a secret compiled into a `.beam` file and
committed to the host's build artifacts. The vault refuses to be the reason
that happens.

**6. A cache is opt-in, and when it is on it is bounded far below the
engine's ceilings.** Configuration is `cache: false` (the vault runs a
`Cmm.Default` and starts no cache process) or a keyword list:

- `:max_age` in seconds is **required**. There is no default, and omitting
  it is `{:error, {:missing_config, [:cache, :max_age]}}` at start. It is
  the only bound with no defensible default, because the acceptable window
  for reusing a data key is a property of the host's threat model.
- `:max_messages` defaults to `100`.
- `:max_bytes` defaults to `1_073_741_824` (1 GiB).

The engine's own defaults for the latter two, 2^32 and 2^63-1, are the
specification's maxima. Inheriting a ceiling as a default is how a wrapper
ends up with an unbounded data key, so the vault substitutes conservative
values and makes them explicit in the generated documentation. The numbers
are a starting point pending measurement, not a derived optimum, and they
are recorded as an open question rather than dressed up as one.

Because `LocalCache` cannot be swept, measured, or substituted (see
Context), the vault bounds the cache's total size the only way the engine
permits: by recycling the process. The vault's supervisor runs an
`Encryptor.Vault.CacheRecycler` that stops the cache child on a configured
`:recycle_after` interval, defaulting to `20 * max_age`, letting the
supervisor restart it with a fresh empty table. Dropping the entire table is
always safe - every entry is derived material that can be re-fetched, and
the worst outcome is a cold miss - and it is the only available answer to a
per-tenant partitioning scheme that would otherwise accumulate one entry per
tenant per context forever, including for tenants that were offboarded. This
is a crude mechanism and it is documented as one; the durable fix is
upstream and is recorded as an open question.

**7. A tenant partitions the cache through a fixed-width derived partition
id.** The vault computes, per call, from the `:key` selector:

```
partition_id = binary_part(:crypto.hash(:sha256, [vault_namespace, 0, encoded_selector]), 0, 16)
```

and passes it as `:partition_id` to `Cmm.Caching.new/3`. Two properties
matter and both come from reading `Cmm.Caching.compute_encryption_cache_id/3`:

- The engine concatenates `partition_id` into the cache id pre-image with no
  length prefix. A variable-width partition id therefore makes the pre-image
  ambiguous, and two different partitions could in principle produce one
  cache id. Sixteen bytes, the width of the UUID the engine generates when
  no partition id is given, removes the ambiguity by construction.
- The partition id is a cache-key input only. It is not key material, it is
  not secret, and it never reaches the message. Deriving it by hash rather
  than using the raw tenant identifier keeps tenant identifiers out of a
  structure the vault does not control the lifetime of, and gives a uniform
  width for free.

One cache process serves every partition within a vault. Partitioning is by
id, as the engine designed it, not by process, so the number of processes
does not grow with the number of tenants.

**8. Commitment policy is pinned; the legacy policy is refused.** The
vault's default is the engine's strictest, `:require_encrypt_require_decrypt`.
Configuration may relax it to `:require_encrypt_allow_decrypt` for a host
migrating in messages written elsewhere. `:forbid_encrypt_allow_decrypt` is
refused outright with `{:error, {:invalid_config, :commitment_policy, :forbidden}}`.
That policy exists to write non-committed messages, this package has never
written one, and a configuration key that can turn key commitment off is a
configuration key that will eventually be turned off by someone who does not
know what it does.

Relatedly, `:max_encrypted_data_keys` defaults to `10` and may never be
`nil`. The engine's default of `nil` means unlimited, and an unlimited EDK
count on the decrypt path is a work-amplification lever handed to whoever
supplies the ciphertext.

**9. The algorithm suite is configuration with an explicit default and a
documented reason to change it.** The vault defaults to the engine's default
suite, `0x0578` (AES-256-GCM, HKDF-SHA512, key commitment, ECDSA P-384
signing), because a wrapper should not silently weaken what the engine
chose. Hosts encrypting many small values where the writer and the reader
are the same trust domain - the encrypted-column case `encryptor_ecto`
serves - should configure `0x0478`, which keeps commitment and drops the
signature. Signing exists so a reader can verify a writer it does not trust;
paying an ECDSA P-384 sign per column write and a verify per read, plus the
signature's bytes per row, buys nothing when there is one trust domain. The
vault states this in its generated documentation and makes the host choose
rather than choosing quietly for them.

**10. One error struct, a fixed reason vocabulary, and no rescue-to-default,
ever.** Every non-bang entry point returns `{:ok, binary}` or
`{:error, %Encryptor.Error{}}`. Every bang variant raises that same struct.
The struct carries `:reason` (the vault's own stable, matchable term),
`:vault`, `:operation`, and `:engine` (the engine's raw error term, or
`nil`).

The split between `:reason` and `:engine` is what makes decision 1
survivable. Consumers match on `:reason`, which this package owns and
versions. Operators read `:engine` in a log line when they need to know
which keyring rejected what. The engine's terms are carried, never
translated away and never promoted into the contract.

The rules around it:

- The vault has no `:default` option, no `decrypt/3` with a fallback value,
  and no configuration that turns a decrypt failure into a success. A caller
  who wants a fallback writes the `case` themselves, where a reviewer can
  see it. A library that can be configured to hand back a plausible-looking
  value when authentication fails is a library that will do so in
  production.
- The vault does not rescue exceptions into `{:error, _}`. Engine failures
  already arrive as error tuples and are wrapped. The single exception is
  the not-started check in decision 2, which is a check rather than a
  rescue.
- **Every decrypt-side failure collapses to one reason, `:decrypt_failed`.**
  A wrong key, a failed authentication tag, a context mismatch, and a
  commitment policy rejection are indistinguishable in `:reason`; the detail
  lives in `:engine` for logs only. Distinguishable decrypt failures are a
  decryption oracle, and the caller cannot act differently on the
  distinctions anyway.
- Failures that depend only on caller-supplied arguments, not on ciphertext,
  stay distinct, because they are not an oracle and the caller needs them:
  `{:vault_not_started, module}`, `{:missing_config, path}`,
  `{:invalid_config, key, detail}`, `{:unknown_key, selector}`,
  `{:encryption_context_conflict, key}`, `{:reserved_context_key, key}`.

The vocabulary above is the complete set this record fixes. It is extended
only by a subsequent ADR, so that a consumer's `case` over reasons has a
stable enumeration to match.

## Consequences

**The engine can be replaced or forked without a consumer-visible change.**
Since no host names an engine module and no vault function passes one, the
dependency is genuinely internal. Given that the engine's extension points
are closed (Context), this matters more than it usually would: the realistic
path to a host-defined keyring runs through changing the engine, and that
change must not become a change to this package's API.

**The closed dispatch is now a constraint on two downstream records.**
enc-2u6's sketch of "one custom keyring resolving by tenant id" is not
available in engine v1.0.0. Per-tenant separation has to be built from a
per-tenant `RawAes` keyring plus the per-tenant partition id of decision 7.
That is a workable design and arguably a better one, since the keyring stays
a value the vault constructs per call. But it has to be stated, and enc-6i0
inherits it.

**Cache recycling is visible in latency percentiles.** A recycle empties
every partition at once, so the request that follows a recycle pays a
provider round trip. For a static or environment-backed provider this is
unmeasurable. For a KMS-backed provider it is a real p99 spike on a
predictable interval. The mitigation is a longer `:recycle_after`, which
trades memory for latency, and the tradeoff is the host's to make.

**Configuration changes need a vault restart.** Frozen-at-start resolution
in `:persistent_term` buys a lock-free hot path and costs live
reconfiguration. Rotating a root key therefore means restarting the vault,
which enc-53a's runbook has to account for. Restarting a vault is cheap - it
drops a cache and re-resolves config - but it is not nothing, and it is not
hot-swappable.

**A host can still do something unsafe, in exactly one place.** Nothing
stops a host from adding `aws_encryption_sdk` to its own deps and calling
the engine directly. The vault makes the safe path the easy one; it is not a
sandbox, and this record does not pretend otherwise.

**Two vaults cost two processes and two caches.** A host running a
single-key vault and a per-tenant vault holds two `LocalCache` tables with
independent bounds. That is the intent, and the memory is bounded by
decision 6's recycling in both.

## The contract as typespecs

```elixir
defmodule Encryptor.Vault do
  @type selector :: term()
  @type context :: %{optional(String.t()) => String.t()}
  @type ciphertext :: binary()
  @type plaintext :: binary()

  @type opts :: [
          key: selector(),
          encryption_context: context()
        ]

  @callback encrypt(plaintext(), opts()) :: {:ok, ciphertext()} | {:error, Encryptor.Error.t()}
  @callback decrypt(ciphertext(), opts()) :: {:ok, plaintext()} | {:error, Encryptor.Error.t()}
  @callback rekey(ciphertext(), opts()) :: {:ok, ciphertext()} | {:error, Encryptor.Error.t()}

  @callback encrypt!(plaintext(), opts()) :: ciphertext()
  @callback decrypt!(ciphertext(), opts()) :: plaintext()
  @callback rekey!(ciphertext(), opts()) :: ciphertext()

  @callback child_spec(keyword()) :: Supervisor.child_spec()
  @callback start_link(keyword()) :: Supervisor.on_start()

  @callback init(keyword()) :: {:ok, keyword()}
  @optional_callbacks init: 1
end
```

```elixir
defmodule Encryptor.Error do
  @type reason ::
          :decrypt_failed
          | {:vault_not_started, module()}
          | {:missing_config, [atom()]}
          | {:invalid_config, atom(), term()}
          | {:unknown_key, Encryptor.Vault.selector()}
          | {:encryption_context_conflict, String.t()}
          | {:reserved_context_key, String.t()}

  @type t :: %__MODULE__{
          reason: reason(),
          vault: module(),
          operation: :encrypt | :decrypt | :rekey | :start,
          engine: term() | nil
        }

  defexception [:reason, :vault, :operation, :engine]
end
```

```elixir
defmodule Encryptor.Vault.Config do
  @type cache ::
          false
          | %{
              max_age: pos_integer(),
              max_messages: pos_integer(),
              max_bytes: pos_integer(),
              recycle_after: pos_integer()
            }

  @type t :: %__MODULE__{
          vault: module(),
          otp_app: atom(),
          provider: {module(), term()},
          cache: cache(),
          commitment_policy: :require_encrypt_require_decrypt | :require_encrypt_allow_decrypt,
          algorithm_suite_id: 0x0578 | 0x0478,
          max_encrypted_data_keys: pos_integer(),
          static_encryption_context: Encryptor.Vault.context()
        }
end
```

The `:provider` pair is a forward reference: its shape is fixed by enc-6i0,
and this record commits only to the fact that a vault holds exactly one and
resolves selectors through it.

## Worked example: a single-key application

An application encrypting its own secrets with one key, no tenants.

```elixir
# lib/my_app/vault.ex
defmodule MyApp.Vault do
  use Encryptor.Vault, otp_app: :my_app

  @impl true
  def init(config) do
    {:ok, Keyword.put(config, :provider, {Encryptor.Provider.Static,
      key: Base.decode64!(System.fetch_env!("MY_APP_VAULT_KEY"))})}
  end
end
```

```elixir
# config/config.exs - structure only, never key material
config :my_app, MyApp.Vault,
  algorithm_suite_id: 0x0478,
  static_encryption_context: %{"app" => "my_app"},
  cache: [max_age: 60]
```

```elixir
# lib/my_app/application.ex
children = [
  MyApp.Repo,
  MyApp.Vault,
  MyAppWeb.Endpoint
]
```

```elixir
{:ok, ct} = MyApp.Vault.encrypt(token, encryption_context: %{"purpose" => "oauth_token"})
{:ok, ^token} = MyApp.Vault.decrypt(ct, encryption_context: %{"purpose" => "oauth_token"})
```

What this example is chosen to demonstrate:

- **`:key` is absent.** A single-key vault resolves the `:default` selector,
  so the common case carries no per-call ceremony.
- **Key material arrives through `init/1`, not config.** The config file
  holds structure. The same file committed to a repository holds no secret,
  and decision 5's compile-time refusal makes the mistake impossible rather
  than discouraged.
- **`0x0478` is chosen explicitly.** One trust domain, so the ECDSA
  signature is dropped, and the choice is visible in review rather than
  buried in a default.
- **`max_age: 60` is the only required cache key.** The other two bounds
  take the vault's conservative defaults, not the engine's ceilings.

## Worked example: a multi-tenant host app

A SaaS application storing data for many tenants, each with its own key,
resolved at request time.

```elixir
defmodule MyApp.TenantVault do
  use Encryptor.Vault, otp_app: :my_app

  @impl true
  def init(config) do
    {:ok, Keyword.put(config, :provider, {MyApp.TenantKeyProvider,
      root_key: Base.decode64!(System.fetch_env!("MY_APP_ROOT_KEY"))})}
  end
end
```

```elixir
config :my_app, MyApp.TenantVault,
  algorithm_suite_id: 0x0478,
  commitment_policy: :require_encrypt_require_decrypt,
  max_encrypted_data_keys: 2,
  cache: [
    max_age: 300,
    max_messages: 100,
    max_bytes: 1_073_741_824,
    recycle_after: 6_000
  ]
```

```elixir
{:ok, ct} =
  MyApp.TenantVault.encrypt(record.notes,
    key: tenant.id,
    encryption_context: %{"tenant_id" => tenant.id, "table" => "records", "column" => "notes"}
  )

# The same ciphertext under a different tenant's key fails, and says only this:
MyApp.TenantVault.decrypt(ct, key: other_tenant.id, encryption_context: %{...})
#=> {:error, %Encryptor.Error{reason: :decrypt_failed, operation: :decrypt, vault: MyApp.TenantVault}}

# An unrecognized tenant fails differently, because that is not an oracle:
MyApp.TenantVault.encrypt(data, key: "no-such-tenant")
#=> {:error, %Encryptor.Error{reason: {:unknown_key, "no-such-tenant"}, operation: :encrypt}}

# Rotation is a pure function on the ciphertext; the context is preserved.
{:ok, rotated} = MyApp.TenantVault.rekey(ct, key: tenant.id)
```

What this example is chosen to demonstrate:

- **`:key` is the whole of per-tenant routing.** One option selects the key
  material and, through decision 7, the cache partition. There is no second
  place to get tenancy wrong.
- **The two failure modes are shaped differently on purpose.** Wrong key on
  a ciphertext is `:decrypt_failed` with no detail. Unknown selector on the
  way in is specific, because it depends on the caller's argument and not on
  the message.
- **`recycle_after: 6_000` is `20 * max_age`.** Written out so the
  relationship is visible; omitting it produces the same value.
- **`max_encrypted_data_keys: 2`** is tightened below the vault's default of
  10, because a per-tenant envelope produces a known small number of EDKs
  and anything larger arriving on the decrypt path is not this host's
  message.
- **The context keys shown are illustrative.** Whether `tenant_id`, `table`,
  and `column` are the canonical vocabulary, and which of them are
  *required* rather than advisory, is enc-cvw's decision, not this one.

## Open questions

Recorded rather than guessed. Each names who should settle it.

1. **Should `decrypt/2` return the verified encryption context?** Decision 4
   returns plaintext only. Tooling that inspects stored ciphertexts wants
   the context, and the engine's `decrypt_result` already carries it. A
   separate read-only `inspect/1` may be the right answer instead of
   widening `decrypt/2`. Settle in enc-cvw, which owns what the context
   means.

2. **The `max_messages` and `max_bytes` defaults are unmeasured.** 100 and
   1 GiB are chosen to be obviously below the engine's ceilings and
   plausibly above a single request. They want a benchmark against a real
   provider before they are treated as recommendations.

3. **`recycle_after` is a workaround for a missing upstream seam.** The
   durable fixes are upstream in the engine: either a bounded-capacity
   `LocalCache`, or making `Cmm.Caching` dispatch through the
   `Cache.CryptographicMaterialsCache` behaviour it already declares so a
   bounded cache can be substituted. Both are engine changes; neither is
   this package's to decide. This package should file them upstream and, if
   they land, retire decision 6's recycler.

4. **Whether the engine should open its keyring and CMM dispatch.** The
   closed dispatch is what forces per-tenant separation into RawAes plus
   partition ids. That may well be the better design anyway, but the
   constraint should be a choice rather than an accident. An engine-side
   record, not this one.

5. **Whether `rekey/2` belongs on the vault at all.** It may be that the
   only real caller is `encryptor_ecto`'s re-wrap task, in which case the
   vault surface is smaller without it. Settle in enc-53a, which owns
   rotation.

6. **The streaming surface is undecided.** The engine offers
   `encrypt_stream/3` and `decrypt_stream/3`, with the documented caveat
   that a stream without an explicit `:plaintext_length` bypasses the cache
   entirely. This record makes no decision about exposing streaming, because
   the bead did not assign one and the file-sized use case has not been
   established.

7. **Whether multiple vaults may ever share one cache process.** Decision 3
   says no. If a host runs many vaults with identical bounds, the answer may
   want revisiting, but only with a rule that makes the shared bounds
   explicit.
