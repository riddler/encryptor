# ADR-0001: A vault is a supervised, host-owned module that wraps the engine completely

Status: accepted (2026-08-27, amended)

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

   *Resolved at Amendment A's acceptance (2026-09-13): the benchmark ran, as
   `enc-anz` and `docs/measurements/260912-enc-anz-stated-bounds.md`, and
   Amendment A's A1 to A3 answer this question. `max_messages` is the bound
   that fires on an active partition and its default is `10_000`; `max_age`
   is the backstop and stays required with no default; `max_bytes` stays
   `1_073_741_824`, with its crossover at about 107 KB recorded rather than
   left to be discovered. The question is answered here rather than struck,
   so the amendment that answers it still has something to point at.*

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

## Amendment A (2026-09-13; accepted 2026-09-13): the measured cache bounds, and the posture per provider shape

Status: **accepted (2026-09-13)**, by the operator's reading. This amendment
only adds. Decisions 1 to 10 above are unchanged, and nothing below reverses, narrows, or re-words any of them. Its
decisions are lettered `A1` to `A5`, under the house convention this repo's
other records use for lettered amendments; a reference from outside this
section should be spelled "Amendment A's A2".

Every code and document line cited below was read at `6f4b55d`, the tip of
`origin/main` when this amendment was last re-anchored.

### Why now

Open question 2 (`:589-592`) says the `max_messages` and `max_bytes` defaults
"want a benchmark against a real provider before they are treated as
recommendations". `enc-anz` ran it. The results are
`docs/measurements/260912-enc-anz-stated-bounds.md` section 1 (`:47-151`), and
its Finding 1 puts two claims against this decision:

> 1. **ADR-0001 decision 6's bounds are effectively `max_messages` alone.**
>    `max_bytes: 1 GiB` is unreachable for any payload under 10.7 MB, and
>    `max_age` is out-lived 51,500:1 by `max_messages: 100` on a hot partition.
> 2. **On a raw-AES keyring the materials cache is a pessimization**, costing
>    ~30% on encrypt and ~20% on decrypt. ADR-0001 decision 6 presents the cache
>    as an optimization that needs bounding; for the `Static` and
>    in-memory-`Function` provider cases it is a cost that needs justifying.
>    Nothing here measures the KMS case, where the EDK wrap is a network call
>    and the conclusion should invert.
>
> (`docs/measurements/260912-enc-anz-stated-bounds.md:130-138`)

Finding 1's third claim is against ADR-0002 decision 2, not this record, and
this amendment does not answer it. It returns below under "What this leaves
open", because A5 depends on the same fact.

Scope, from the ruling that scheduled this record (ruled by the operator,
2026-09-13): **this amendment revises the shipped bound defaults
and records a recommended posture; it does not flip the `cache:` default,
which is already `false`.** `Encryptor.Vault.Config.defaults/0` returns
`cache: false` (`lib/encryptor/vault/config.ex:281-291`, the entry at `:283`),
exactly as decision 6's first sentence says. The opt-in stands. What was wrong
was the description of the bounds, and the silence about when the cache is
worth opting into at all.

### The numbers this record is now answerable to

One process, warm partition, a `Static` provider on a raw-AES keyring, on the
machine section "The machine, and what the numbers are not" describes
(`:25-43`). Every timing there is a median of five batches, a ratio worth
trusting and an absolute worth re-measuring elsewhere.

| | |
|---|---|
| warm encrypts/sec | 85,837 |
| `max_messages: 100` reached after | 1.17 ms |
| `max_age: 60` reached after | 5,150,215 messages |
| ratio of the two lifetimes | ~51,500 : 1 |
| payload at which `max_bytes` binds first | 10.7 MB (`1 GiB / 100`) |

(`:52-60`.)

| | µs/encrypt |
|---|---|
| `cache: false` | 8.93 |
| cache on, `max_messages: 100` (the shipped default) | 11.65 |
| cache on, `max_messages: 1_000_000` | 11.40 |
| cache on, `max_messages: 1` (every call a miss) | 13.42 |

| | µs/decrypt |
|---|---|
| `cache: false` | 8.25 |
| cache on | 9.87 |

(`:82-92`. The `max_messages: 1` row is the discriminator: forcing every call
to miss costs 2.02 µs more than the loose-bound vault, which is what proves
the hits are real and the rest of the section is measuring something,
`:96-98`.)

### A1. `max_messages` is the binding bound; `max_age` is the backstop

Decision 6 presents three bounds as though they cooperate. They do not. At any
rate a busy vault actually runs, `max_messages` fires first, every time, and
the other two never fire at all. A data key's real lifetime under the shipped
defaults is 100 messages - 1.17 ms at the measured rate - not the `max_age`
seconds the host was asked to reason about.

This record therefore states the roles plainly:

- **`max_messages` bounds a data key's lifetime on an active partition.** It
  is the bound that fires.
- **`max_age` bounds a data key's lifetime on an idle or slow partition, and
  bounds how long a crypto-shred takes to bite in the cache.** It is a
  backstop, and it remains **required, with no default**, for exactly the
  reason decision 6 gives: the acceptable reuse window is the host's
  threat-model call. What changes is the claim that it is the bound doing the
  work on a hot partition.
- **`max_bytes` bounds a data key's lifetime for large payloads only.** See
  A3.

No sentence here relaxes a bound. A1 is a re-description, and on its own it
changes no shipped number.

### A2. The default `max_messages` rises from `100` to `10_000`

`@default_max_messages 100` (`lib/encryptor/vault/config.ex:173`, applied at
`:572`) becomes `10_000`. This is a **breaking change to a shipped default**,
and the code half ships it as one.

The argument is A5's, run backwards. The materials cache is worth turning on
only where a cache miss costs a network round trip *inside the CMM* - which,
per A5, is the AWS KMS keyring-backed row and nothing else. On that row
`max_messages` is not a performance knob over a local wrap; it is the
**amortization factor for a KMS call**. At `100`, a partition running at the
measured rate asks KMS for fresh material roughly 858 times a second. At
`10_000` it asks 8.6 times a second, inside the same security envelope.

That envelope is why a hundredfold raise is still conservative:

- The engine's own default and the specification's maximum are both 2^32
  (`docs/adr/0001-vault-layer.md:222-223`). `10_000` is still roughly five
  orders of magnitude below the
  ceiling decision 6 refused to inherit, so the principle it was protecting -
  do not inherit a ceiling as a default - is untouched.
- Relaxing the bound is measurably not a performance lever on the cheap path:
  the measurement's ten-thousandfold raise, `max_messages: 100` against
  `1_000_000`, buys 0.25 µs of 11.65
  (`docs/measurements/260912-enc-anz-stated-bounds.md:104-105`, which words it
  as a thousandfold). Nobody should read
  A2 as a speed change on a raw-AES vault. On that vault, A5 says turn the
  cache off entirely.
- It does not lengthen a crypto-shred or a suspend, because neither is bounded
  by a message count. A suspension is immediate because the deny runs ahead of
  the cache: `lib/encryptor/vault/resolve.ex:100-102` records that "every path
  resolves before it builds a caching CMM, so the deny is ahead of the
  materials cache and the very next call fails, warm cache or cold". The shred
  is the opposite case, and the same comment says so - its P3 must drain the
  caches before a running node stops serving a tenant. `max_age`, the drain,
  and `recycle_after` are the shred-latency bounds, and A2 moves none of them.

A host that wants the old behaviour writes `max_messages: 100` explicitly. The
option is unchanged, the validation is unchanged, and the error vocabulary is
unchanged.

### A3. `max_bytes` stays `1_073_741_824`, and its crossover is documented

`@default_max_bytes` (`lib/encryptor/vault/config.ex:174`, applied at `:573`)
is unchanged. Lowering it would invent a second binding bound the measurement
did not ask for, and raising it would remove the only protection a
large-payload host has.

What changes is that the record now says when it binds. `max_bytes` fires
before `max_messages` at a payload of `max_bytes / max_messages`. Under the
old pair that crossover was 10.7 MB, and the bound was inert for every
workload this package was written for. Under A2's pair it is **107,374 bytes,
about 107 KB** - above a column value, below a document, which is where a
wrapper for application data at rest wants it. A2 makes `max_bytes` a live
bound again rather than decoration.

### A4. `recycle_after: 20 * max_age` stands

`@recycle_after_multiplier 20` (`lib/encryptor/vault/config.ex:175`, applied
at `:574`) is unchanged, and this amendment records why rather than leaving it
an implication of silence. Section 2 measured a live cache entry at 1,237 ETS
bytes and found that what `recycle_after` bounds is the number of *distinct*
`(tenant, context)` pairs touched in one window, not a rate: 500 tenants
across 10 columns peak at 5.9 MiB, 5,000 tenants at 59.0 MiB. Its verdict:
"the OQ6 worry is real in shape and modest in size [...] No amendment
proposed. The default survives measurement"
(`docs/measurements/260912-enc-anz-stated-bounds.md:196-217`). A host past
roughly 10,000 tenants active within one window shortens `recycle_after`; the
default does not move.

### A5. The recommended posture, per provider shape

The fact that decides every row: **the materials cache sits in front of the
CMM, not in front of the provider.** Decision 2 above has encrypt and decrypt
"build the engine's keyring, CMM, and `Client` structs per call" (`:106-109`),
so the provider is asked for a descriptor before there is a CMM to consult,
and `Encryptor.Vault.Encrypt` then wraps the `Default` CMM in `Cmm.Caching` -
outside the keyring, inside the required-context CMM - in a pipeline that runs
once the descriptor is already in hand
(`lib/encryptor/vault/encrypt.ex:162-164`, with `maybe_caching/3` itself at
`:184-194`). The measurement
confirms it empirically: 500 encrypts on one warm partition, cache on,
produced 500 provider closure calls (`:107-123`).

So a cache hit saves exactly two things - the data-key generation and the
keyring's EDK wrap. It saves nothing a provider does.

ADR-0002 decision 5 (`docs/adr/0002-key-providers.md:203-255`) already sorts
every adapter into the two shapes that decide the answer: *keyring-backed*
adapters, which map onto a keyring the engine dispatches to, and
*material-source* adapters, which produce the bytes of an
`%Encryptor.Key.Aes{}` by some other means. The expensive work of a
keyring-backed adapter is inside the CMM, behind the cache. The expensive work
of a material-source adapter is on the resolve path, in front of it.

| Provider | Shape (ADR-0002 d5) | What a cache hit saves | What it cannot save | Recommended posture |
|---|---|---|---|---|
| `Encryptor.Provider.Static` | material-source, key in frozen state | a local AES-KW wrap | nothing left to save; resolve is a lookup | **`cache: false`** - measured net cost: +2.72 µs/encrypt (~30%), +1.62 µs/decrypt (~20%) |
| `Encryptor.Provider.Function`, resolving in memory | material-source | a local AES-KW wrap | nothing left to save | **`cache: false`** - the same measurement; this closure is what section 1 ran |
| `Encryptor.Provider.Function`, resolving over I/O | material-source | a local AES-KW wrap | **the host's round trip, paid on every call** | **`cache: false`**; see the note below on where that round trip is amortized |
| `Encryptor.Provider.GcpKms` (ADR-0007, a wrap-provider) | material-source | a local AES-KW wrap | **the GCP `Decrypt` unwrap, paid on every call** | **`cache: false`**, for the same reason. Note that ADR-0007's operation-cost argument (`docs/adr/0007-gcp-kms-wrap-provider.md:627-632`, repeated at `:815-816`) rests on the round-trip claim A5 revises, and is contradicted by this row; it needs the amendment named below. |
| `Encryptor.Provider.Kms` (ADR-0008) | keyring-backed | **the KMS `GenerateDataKey` / `Decrypt` network call**, because the wrap happens inside the keyring the CMM calls (`lib/encryptor/vault/keyring.ex:85-109`) | - | **`cache: [max_age: <threat model>, ...]`** - the case the materials cache exists for |

Three consequences, because they are what a reader will otherwise get wrong:

1. **"Expensive provider" is not the test. "Expensive keyring" is.** A
   material-source adapter that talks to a network is exactly as un-helped by
   the materials cache as one that reads a map, because its cost is on the
   resolve path and the resolve path runs first.
2. **A material-source adapter that wants its round trips collapsed caches
   them itself, under ADR-0002's rule, not this one.** Decision 2's last
   bullet there already permits it and already constrains it: "A provider that
   caches anyway must bound it and document the bound"
   (`docs/adr/0002-key-providers.md:130-136`). A5 does not loosen that; it
   removes the reason a provider author might have believed the vault's cache
   had already done the job.
3. **The KMS row is reasoned, not measured.** Section 1 scopes itself to
   raw-AES keyrings and says the conclusion "should invert" for KMS without
   measuring it (`:38-43`, `:137-138`). The row rests on where the wrap
   happens in the call graph, and it is recorded as an open question below
   rather than dressed up as a result.

A5 records ADR-0001's side of the tension `lib/encryptor/vault/encrypt.ex:59-84`
names and declines to resolve. ADR-0002's sentence is still unamended; see
below.

### What the code half changes

`enc-d3u`, and nothing else this amendment implies:

1. `@default_max_messages`, `100` -> `10_000`
   (`lib/encryptor/vault/config.ex:173`), carrying a breaking changelog entry.
2. The `:cache` paragraph of `Encryptor.Vault.Config`'s moduledoc (`:90-92`),
   restated for A1 to A3: the new default, `max_messages` as the binding
   bound, `max_age` as the required backstop, the ~107 KB crossover.
3. `guides/getting-started.md`'s cache section (`:160-186`, including the
   stated defaults at `:170-171`), restated for A5, so the guide recommends
   `cache: false` outside the keyring-backed row instead of presenting the
   cache as a default good.
4. `@default_max_bytes` (`config.ex:174`) and `@recycle_after_multiplier`
   (`config.ex:175`) are **not** touched, and neither is `defaults/0`'s
   `cache: false` (`config.ex:283`).

### What this leaves open

1. **Open question 2 above (`:589-592`) is answered** by A1 to A3. It is left
   standing rather than rewritten, because an amendment appends; striking it
   belongs to the acceptance flip, which is the operator's.
2. **ADR-0002 decision 2's round-trip sentence is wrong in two records and two
   documents, and this amendment fixes none of them.**
   `docs/adr/0002-key-providers.md:130-132`,
   `docs/adr/0007-gcp-kms-wrap-provider.md:627-632` and `:815-816`,
   `lib/encryptor/provider/gcp_kms.ex:293-295`, and
   `guides/getting-started.md:351-353` each say the materials cache collapses
   provider resolutions, which A5 shows it cannot. ADR-0007's is the
   load-bearing one: its per-operation GCP cost is argued from that claim, so
   the ADR-0002 amendment has to carry an ADR-0007 amendment with it.
   `lib/encryptor/vault/encrypt.ex:59-84` already records the tension and
   correctly refuses to resolve it from code. That is an ADR-0002 amendment
   plus the doc edits that follow it, and it is out of this record's scope.
3. **The KMS row is unmeasured.** A benchmark against a real KMS keyring - the
   thing section 1 declined to run - would settle whether `10_000` is the
   right amortization factor or whether the honest answer is larger still.
4. **`max_messages` is one global default across both shapes.** If the
   keyring-backed row wants a different number from a material-source vault
   that opted in anyway, the fix is a per-shape default rather than one
   compromise, and that is a new decision rather than a tuning change.

## Note (2026-09-13): Amendment A accepted; open question 2 answered in place, and where its cites resolve today

The operator accepted Amendment A on 2026-09-13. This Note records that
acceptance, says what the flip did with the amendment's own instruction about
open question 2, records which of the amendment's obligations its code half
has since discharged, and re-locates every cite against `main` at `6acefff`.
It changes no decision: decisions 1 to 10 and A1 to A5 stand exactly as
written, and it carries the record's status rather than one of its own.

### 1. Open question 2 is answered in place, not struck

Amendment A's "What this leaves open" item 1 says open question 2 "is left
standing rather than rewritten, because an amendment appends; striking it
belongs to the acceptance flip, which is the operator's." The flip **answers
it in place rather than striking it**, and says so here rather than leaving
the difference unexplained. Two reasons. A record is amended by addition, so
removing a question a merged amendment cites by anchor (`:589-592`) would
break that cite and delete the thing A1 to A3 are an answer to. And this
repository already has a house form for exactly this: an answer line in
italics under the question, which is what ADR-0004 uses at `:939` and what
ADR-0006's acceptance flip used for its own open question 4. Open question 2
now carries that line, and the question text above it is untouched.

One half of that precedent needs stating precisely. ADR-0004's answer line at
`:939` is an acceptance-time line and is the model. ADR-0006's answer line
under its open question 4 was written by its amendment rather than by an
acceptance flip, and ADR-0006's own A6 records that flipping it is still owed
to the operator's acceptance; it is being flipped in the same sitting as this
one, not before it. The form is ADR-0004's.

### 2. The top `Status` line now reads amended

`Status: accepted (2026-08-27)` becomes `accepted (2026-08-27, amended)`.
This record carries no per-amendment pointer paragraph of the kind ADR-0003
and ADR-0005 have, so the top line is the only place a reader learns the
record has an amendment at all. It follows the precedent of the 2026-09-13
acceptance commit `fbbd36b`, which made the same edit to ADR-0005's top line
when it accepted that record's Amendment A.

### 3. What the code half has already discharged

A2 and the "What the code half changes" list are written in the future tense,
against the tree at `6f4b55d`. `enc-d3u` has since shipped them, so read those
sentences as the state at `6f4b55d` and the obligations as met:

- `@default_max_messages` is `10_000` at `lib/encryptor/vault/config.ex:180`,
  applied at `:579`. A2's "`@default_max_messages 100` ... becomes `10_000`"
  is done.
- `@default_max_bytes` (`:181`, applied at `:580`) and
  `@recycle_after_multiplier` (`:182`, applied at `:581`) are untouched, as A3
  and A4 required, and `defaults/0` still carries `cache: false`
  (`:288-297`, the entry at `:290`).
- The `:cache` paragraph of `Encryptor.Vault.Config`'s moduledoc is restated
  for A1 to A3 at `lib/encryptor/vault/config.ex:90-97`, including the ~107 KB
  crossover.
- `guides/getting-started.md`'s cache section is restated for A5 as "The
  materials cache, and when to turn it on" (`:159-177`), with the per-shape
  posture table at `:171-177`. The stated defaults left that section for
  "`max_age` is required, and has no default": `10_000`, 1 GiB and
  `20 * max_age` at `:190-192`, and the ~107 KB crossover at `:194-197`.

### 4. What A5 says is still wrong is still wrong

"What this leaves open" item 2 names four sites that say the materials cache
collapses provider resolutions, and says this amendment fixes none of them.
All four still say it at `6acefff`, so the ADR-0002 amendment that item calls
for is still owed: `docs/adr/0002-key-providers.md:130-132`,
`docs/adr/0007-gcp-kms-wrap-provider.md:627-632` and `:815-816`,
`lib/encryptor/provider/gcp_kms.ex:293-295`, and the root-vault bullet in
`guides/getting-started.md`, which has moved from `:351-353` to `:395-397`.

### 5. Where Amendment A's cites resolve at `6acefff`

Amendment A says every line it cites was read at `6f4b55d`. Every cite was
re-read by anchor at `6acefff`. **Every claim holds**; what follows is
re-location, not correction.

| Cited in Amendment A | Resolves at `6acefff` |
|---|---|
| `lib/encryptor/vault/config.ex:173`, `:174`, `:175` (the three constants), applied at `:572`, `:573`, `:574` | `:180`, `:181`, `:182`, applied at `:579`, `:580`, `:581` |
| `lib/encryptor/vault/config.ex:281-291`, the `cache: false` entry at `:283` | `:288-297`, the entry at `:290` |
| `lib/encryptor/vault/config.ex:90-92`, the `:cache` moduledoc paragraph | `:90-97`, restated for A1 to A3 |
| `guides/getting-started.md:160-186`, the cache section | `:159-177`, "The materials cache, and when to turn it on", restated for A5, with the per-shape posture table at `:171-177` |
| `guides/getting-started.md:170-171`, the stated defaults | MOVED OUT of the cache section into "`max_age` is required, and has no default": the defaults are at `:190-192` and the ~107 KB crossover at `:194-197` |
| `guides/getting-started.md:351-353` | `:395-397`, unchanged in wording |
| `lib/encryptor/vault/resolve.ex:100-102`; `lib/encryptor/vault/encrypt.ex:162-164`, `:184-194`, `:59-84`; `lib/encryptor/vault/keyring.ex:85-109`; `lib/encryptor/provider/gcp_kms.ex:293-295` | unchanged, at those anchors |
| `docs/adr/0002-key-providers.md:130-136`, `:130-132`, `:203-255`; `docs/adr/0007-gcp-kms-wrap-provider.md:627-632`, `:815-816` | unchanged, at those anchors |
| `docs/measurements/260912-enc-anz-stated-bounds.md:25-43`, `:38-43`, `:47-151`, `:52-60`, `:82-92`, `:96-98`, `:104-105`, `:107-123`, `:130-138`, `:137-138`, `:196-217` | unchanged, at those anchors |
| this record's own `:106-109`, `:222-223`, `:589-592` | unchanged, at those anchors |

### 6. What the acceptance does not settle

Items 2, 3 and 4 of "What this leaves open" stay open: the ADR-0002
round-trip amendment and the ADR-0007 amendment it has to carry, the
unmeasured KMS row, and whether `max_messages` should have a per-shape default
rather than one global compromise.

### 7. What the pass-1 direction review corrected in this Note

Three things, all in this Note rather than in the record:

1. Section 5's table gave one destination for two different cites, and it was
   wrong for the second. `guides/getting-started.md`'s stated defaults did not
   stay in the cache section; they moved into the `max_age` subsection. The
   table and section 3's fourth bullet now say where each lands.
2. Section 1 credited ADR-0006's acceptance flip with a precedent it does not
   yet set. The paragraph added there says so.
3. `docs/adr/0005-rotation-and-crypto-shred.md:901` still sends a reader to
   "ADR-0001 open question 2's unmeasured cache bounds". Those bounds are
   measured now and the question is answered, so that pointer is stale. It
   states nothing about this record's amendment status, so it is not a flip
   site; it is an edit ADR-0005 owes, recorded here so it is not lost. ADR-0003
   already cured its parallel reference in its own Note.
