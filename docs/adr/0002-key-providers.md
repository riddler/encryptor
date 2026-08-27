# ADR-0002: A key provider resolves a selector to key descriptors, and the vault alone builds keyrings

Status: accepted (2026-08-27)

## Context

ADR-0001 fixed the vault: one host-owned module, one door, one provider per
vault, a `:key` selector on every call, and a `Config` struct carrying
`provider: {module(), term()}` as an explicit forward reference to this
record. This record fills that reference in. It fixes what a provider is,
what it returns, when it is called, what it may keep, how it fails, and which
adapters ship in which order.

**The bead's framing does not survive contact with the engine, and this is
the load-bearing finding.** enc-6i0 was written as "how a provider turns
configuration + a key selector into an engine keyring". A provider cannot
return an engine keyring, for two independent reasons.

The first is the closed dispatch ADR-0001 recorded: `Cmm.Default` matches the
keyring by struct type over `RawAes`, `RawRsa`, `Multi`, and the four AWS KMS
keyrings, and returns `{:error, {:unsupported_keyring_type, module}}` for
anything else (`lib/aws_encryption_sdk/cmm/default.ex`). So the set of
keyrings a provider could return is closed anyway.

The second is ADR-0001 decision 1: no host code names `AwsEncryptionSdk` or
any module under it. A provider is frequently host-written - ADR-0001's own
multi-tenant example writes `MyApp.TenantKeyProvider` - so a provider that
returned `%AwsEncryptionSdk.Keyring.RawAes{}` would make every serious host
an engine consumer and would let a provider quietly choose its own wrapping
algorithm, namespace, and suite behind the vault's back. The one door would
have a second door behind it.

Therefore: **a provider returns a key descriptor, and the vault turns the
descriptor into a keyring.** The provider decides *which key*; the vault
decides *what a key is in engine terms*. That is a delta from the bead text
and it is flagged here for acceptance review rather than buried.

Four further findings from the v1.0.0 source shape the rest.

**The encrypted data key names the key that must decrypt it.**
`RawAes.unwrap_key/3` accepts an EDK only if `edk.key_provider_id ==
keyring.key_namespace` and the deserialized provider info's `key_name ==
keyring.key_name`; otherwise `:provider_id_mismatch` or `:key_name_mismatch`
(`lib/aws_encryption_sdk/keyring/raw_aes.ex`). So the namespace and the name
are not decoration. They are the message's own record of which key material
is required, they are written into the message header in the clear, and a
decrypt years later must be able to reconstruct exactly the keyring that
wrote the EDK. Key identity is thus part of the on-disk format, and a
provider that reuses one name for two different byte strings has produced
ciphertext nobody can decrypt.

**Encrypt wants one key; decrypt wants a candidate set.** `Multi.unwrap_key/3`
walks the generator and every child in order and returns the first success
(`attempt_decryption/4`), and `Multi.new/1` permits `generator: nil` when
there is at least one child (`validate_generator_can_encrypt(nil) :: :ok`).
A decrypt-side Multi of every live version of a tenant's key is therefore
exactly the mechanism rotation needs, and it costs nothing on encrypt because
encrypt uses a different keyring. On encrypt, a Multi with children would
wrap the data key once per child and emit one EDK per child, which is a
larger message for no benefit. The two operations want different keyrings
built from the same resolution, so the provider contract has two callbacks,
not one.

**Every non-AWS key manager is a material source, not a keyring.** The
roadmap in the bead names GCP KMS and Vault transit. Neither can ever be a
keyring in engine v1.0.0, and no amount of adapter work changes that, because
the dispatch is closed. What they can be is the thing that decrypts a stored
wrapped key into the bytes a `RawAes` keyring is built from. This splits the
adapter roadmap in two along a line that is a property of the engine rather
than of this package, and decision 5 makes the split explicit.

**The AWS KMS client is compiled conditionally.**
`lib/aws_encryption_sdk/keyring/kms_client/ex_aws.ex` opens with
`if Code.ensure_loaded?(ExAws.KMS) do`, and the engine's `mix.exs` marks
`ex_aws`, `ex_aws_kms`, `hackney`, and `sweet_xml` `optional: true`. A host
that has not added those four to its own `deps` does not merely fail at
runtime; the module does not exist. A KMS-backed provider must detect that at
vault start and say so plainly, because the failure otherwise surfaces as an
`UndefinedFunctionError` from inside a library on the first encrypt.

This record owns the provider contract and the adapter roadmap. It does not
own how a per-tenant key is wrapped or stored (enc-2u6), what the encryption
context says about it (enc-cvw), or the rotation and shredding procedures
that drive it (enc-53a). It gives all three a contract to attach to.

## Decision

**1. `Encryptor.Provider` is a behaviour with one required resolution pair
and two optional lifecycle callbacks.**

```elixir
@callback init(opts :: keyword()) :: {:ok, state :: term()} | {:error, term()}
@callback child_spec(opts :: keyword()) :: Supervisor.child_spec()
@callback encryption_key(state :: term(), selector) :: {:ok, descriptor} | {:error, reason}
@callback decryption_keys(state :: term(), selector) :: {:ok, [descriptor]} | {:error, reason}
@optional_callbacks init: 1, child_spec: 1
```

`init/1` runs once, during vault start, inside the vault's configuration
resolution. Its return is the provider state, frozen into the
`Encryptor.Vault.Config` struct that ADR-0001 decision 5 publishes in
`:persistent_term`. State is therefore whatever a provider needs that is
constant for the life of the vault: a root key, a namespace, an ETS table
name, a KMS client struct. It is read lock-free on every call and it is not
mutable. A provider with no configuration may omit `init/1`, in which case
its state is the option list as given.

`child_spec/1`, when exported, is added to the vault's supervisor beside the
cache, which is the slot ADR-0001 decision 2 reserved. This is the only way a
provider gets a process, and a provider that has one still resolves through
the same two pure-looking callbacks; the process is an implementation detail
of the callback, never something the vault or the host talks to directly.

**2. Both resolution callbacks run on the caller's process, synchronously,
and must be bounded.** There is no provider task pool and no vault-side
timeout wrapper. A provider that performs I/O owns its own timeout, and a
provider that would block indefinitely is a provider that hangs the caller's
request. The rule is stated rather than enforced, because enforcing it would
mean a process hop on the hot path of every encrypted column read, and
ADR-0001 decision 5 spent real design effort making that path allocation-free.

Two rules make the boundedness affordable in practice:

- **Resolution is stable.** For a given state and selector, `encryption_key/2`
  must return the same descriptor until something outside the vault changes -
  a rotation, an offboarding. It is a lookup, not a decision, and in
  particular it never generates fresh key material as a side effect of being
  asked. Key creation is a rotation procedure (enc-53a), reached deliberately,
  not a lazy side effect of the first encrypt after a deploy.
- **A provider may not add a second unbounded cache.** The engine's materials
  cache already collapses provider round trips to one per partition per
  `max_age` (ADR-0001 decisions 6 and 7), so a provider-level cache is
  a second copy of the same idea with none of ADR-0001's bounds on it. A
  provider that caches anyway must bound it and document the bound; an
  unbounded provider cache re-creates exactly the growth that ADR-0001's
  recycler exists to contain, and does so where the vault cannot see it.

**3. A descriptor is a struct from a closed, package-owned set. Day one, the
set has one member.**

```elixir
%Encryptor.Key.Aes{
  namespace: String.t(),
  name: String.t(),
  material: binary(),
  bits: 128 | 192 | 256
}
```

The vault, and only the vault, maps a descriptor to an engine keyring: an
`%Encryptor.Key.Aes{}` becomes `RawAes.new(namespace, name, material,
:aes_256_gcm | :aes_192_gcm | :aes_128_gcm)`. `%Encryptor.Key.Kms{}` is
reserved for decision 5's KMS adapter and specified there. Nothing else
exists, and a host cannot add a member.

That the descriptor set is closed is not an accident of design taste; it is
the engine's closed dispatch reappearing one layer up, and pretending
otherwise by publishing an open behaviour that will reject most
implementations would be worse than saying so. A descriptor the vault does
not recognize is `{:error, {:invalid_key_descriptor, detail}}` at resolution
time.

The vault validates before constructing:

- `namespace` must not begin with `aws-kms`; the engine reserves that prefix
  (`Keyring.Behaviour.validate_provider_id/1`) and rejecting it here gives a
  reason a caller can read instead of a bare engine tuple.
- `byte_size(material) * 8` must equal `bits`, which is the check
  `RawAes.new/4` performs and which is worth failing on with our own reason.
- `namespace` and `name` must be non-empty printable strings, because they
  are written into the message header.

**4. `name` is the key's version identity, it is public, and it is
append-only.** The vault treats `name` as opaque and the provider owns its
grammar, subject to three obligations that follow from the source finding
above:

- **A name is bound to bytes, forever.** Reusing a name for different
  material makes previously written messages undecryptable, silently, at some
  later date. A provider that rotates a tenant's key mints a new name. The
  recommended grammar is therefore an opaque tenant reference plus a
  monotonic version, `"t/<derived>/v<n>"`, and the vault documents that
  recommendation without enforcing it.
- **A name travels in the clear.** It lands in the EDK's provider info, in
  the message header, which is authenticated but not encrypted. Anyone
  holding a ciphertext can read it. A provider that puts a raw tenant
  identifier there has published that identifier in every row. The vault
  recommends a derived reference for the same reason ADR-0001 decision 7
  derives the cache partition id rather than using the selector directly.
- **`decryption_keys/2` returns every name that may still appear in stored
  ciphertext, newest first.** The vault builds
  `Multi.new(generator: nil, children: [...])` from the list, and the engine
  tries them in order. Dropping a name from that list is what makes the
  messages written under it undecryptable, which is precisely the intended
  mechanism for crypto-shredding, and is enc-53a's to schedule. Ordering is
  a performance property, not a correctness one: a wrong-name keyring fails
  a cheap comparison, not a decryption.

For a single-key vault `decryption_keys/2` returns a one-element list and the
vault builds a plain `RawAes` rather than a `Multi`, since a Multi of one is
an extra struct and an extra error-wrapping layer for nothing.

**5. The adapter roadmap has two rows, because the engine has two shapes.**

*Keyring-backed adapters* map onto a keyring the engine's dispatch already
accepts. There are exactly two possible: raw AES material, and AWS KMS.

*Material-source adapters* produce the bytes of an `%Encryptor.Key.Aes{}` by
some other means, and the engine never learns where they came from. Every
external key manager other than AWS KMS is necessarily this shape. So is a
database of wrapped keys, and so is an environment variable.

The order, and what ships when:

| Adapter | Shape | Ships |
|---|---|---|
| `Encryptor.Provider.Static` | material source | day one, this package |
| `Encryptor.Provider.Function` | material source | day one, this package |
| Ecto-backed wrapped per-tenant keys | material source | `encryptor_ecto` |
| `Encryptor.Provider.Kms` | keyring-backed | after enc-2u6, this package |
| GCP KMS, Vault transit | material source | later, on demand |

`Static` holds one key, or a small map of selector to key, resolved in
`init/1` from what the host's `init/1` handed it. It is the single-key vault
and the test double, and it is deliberately not a tenancy solution.

`Function` wraps a host-supplied `(selector -> descriptor)` pair of closures.
It exists so that the per-tenant case is reachable on day one without waiting
for the storage adapter, and so that a host with an existing key store can
use this package without writing a behaviour implementation. It is the
escape hatch, and like all escape hatches it inherits every obligation in
decisions 2 and 4 with nothing enforcing them.

The Ecto-backed provider lives in `encryptor_ecto`, not here, because it owns
a schema, a migration, and a repo, and because ADR-0001's boundary puts
storage on that side. This package owns only the behaviour it implements.
That the wrapped-key table's shape is enc-2u6's decision is why the adapter
follows it rather than leading.

`Encryptor.Provider.Kms` is the only adapter that returns
`%Encryptor.Key.Kms{key_id: String.t(), mrk: boolean()}`, which the vault
maps to `AwsKms.new/3` or `AwsKmsMrk.new/3` against a client built once in
`init/1`. It ships after enc-2u6 because a per-tenant KMS key per tenant is
a cost and quota decision the envelope record has to make first. Its `init/1`
checks `Code.ensure_loaded?(AwsEncryptionSdk.Keyring.KmsClient.ExAws)` and
returns `{:error, {:missing_optional_dependency, :ex_aws_kms}}` when the
host has not added the four optional deps, which is the surfacing obligation
ADR-0001 decision 1 assigned to this record. The check is at start, not at
first use, so a misconfigured deploy fails to boot rather than failing on a
customer's first write.

GCP KMS and Vault transit are material sources: they decrypt a stored wrapped
key and hand back bytes. They are built when someone needs them, against the
same descriptor, with no new contract.

**6. Provider failures stay distinguishable, including on the decrypt path.**
ADR-0001 decision 10 collapses every decrypt-side failure to
`:decrypt_failed` to avoid a decryption oracle. Provider resolution is
carved out of that rule, in both directions, because resolution happens
before any ciphertext is examined and depends only on the selector the caller
supplied. Collapsing an unreachable key store into `:decrypt_failed` would
report an outage as data corruption, and an operator would go looking for the
wrong thing at three in the morning.

This record extends ADR-0001's reason vocabulary by exactly four terms, which
is the extension mechanism that record specified:

- `{:unknown_key, selector}` - already in ADR-0001; this record fixes its
  meaning as "the provider resolved and the selector is not one it serves",
  a settled negative answer.
- `{:key_unavailable, selector}` - the provider could not answer. A network
  failure, a timeout, a `LOCK` contention, a KMS throttle. Distinct from
  `:unknown_key` because a caller retries this one and only this one.
- `{:invalid_key_descriptor, detail}` - the provider answered with something
  the vault cannot build a keyring from. A bug in the provider, not in the
  caller.
- `{:provider_not_started, module}` - a provider with a `child_spec/1` whose
  process is not alive. The sibling of ADR-0001's `{:vault_not_started, _}`,
  and a check rather than a rescue, for the same reason.
- `{:missing_optional_dependency, dep}` - returned at start, only by
  adapters that need the host's optional deps.

The engine's own error term is carried in the `Encryptor.Error` struct's
`:engine` field unchanged, per ADR-0001 decision 10. A provider's underlying
error - an `Ecto` changeset, an `ExAws` tuple - is carried there too rather
than being translated into the reason vocabulary, which is what keeps that
vocabulary a closed enumeration a `case` can be written against.

**7. A provider never sees plaintext, ciphertext, or the encryption
context.** It sees a selector and its own state, and it returns descriptors.
It is not consulted about the algorithm suite, the commitment policy, the
context, or the cache, all of which ADR-0001 made configuration. The
narrowness is the point: a provider is the one component a host is most
likely to write itself, so it is the component that must not be able to
weaken anything.

## Consequences

**Key material sits in the BEAM for every adapter except the KMS one.** A
material-source provider, by definition, produces wrapping key bytes into
process memory. AWS KMS as a keyring is the only shape where unwrapping
happens inside the key manager and the wrapping key never leaves it. This is
worth stating plainly because a reader who sees "Vault transit adapter" on
the roadmap may reasonably assume the security properties of Vault transit,
and what they actually get is Vault transit protecting a key at rest that is
then held in memory to do the wrapping. That is a real and common design, but
it is not the same design, and the engine's closed dispatch is what forecloses
the alternative.

**Rotation is a list-membership property, and so is shredding.** Because
`decryption_keys/2` returns candidates and the engine tries them in order, a
key is retired by adding a new name, and messages become permanently
unreadable by removing an old one. That gives enc-53a a mechanism with no new
machinery, and it gives it a sharp edge: a provider bug that returns a short
list is indistinguishable, from the caller's side, from data that was
deliberately shredded. Both look like `:decrypt_failed`.

**Long-lived tenants accumulate candidates.** A tenant rotated monthly for
five years has sixty names, and every decrypt of an old message walks the
list until it matches. The cost is a struct comparison per miss, so it is
small, but it is not zero and it grows without bound unless something prunes
it. Whether pruning is age-based, count-based, or manual is enc-53a's.

**A host-written provider is unreviewed code on the key path.**
`Encryptor.Provider.Function` in particular takes two closures and trusts
them. Decisions 2 and 4 are obligations expressed in documentation, not in
types: nothing stops a closure from blocking for thirty seconds, reusing a
name, or caching unboundedly. The alternative - refusing a function-shaped
provider - would push hosts into forking the package, which is worse.

**The descriptor set being closed means adding a key shape is a release of
this package.** A host that needs, say, an HSM-backed RSA wrapping key cannot
add it without a change here. Given that the engine's keyring set is closed
too, the number of genuinely new shapes is small and bounded, and each one
deserves the review a release forces.

**`encryptor_ecto` now has a contract to build against, and a dependency
order.** Its provider implements this behaviour, but the shape of the row it
reads is enc-2u6's, so the useful order is enc-2u6 first. That ordering is
recorded here rather than discovered later.

## The contract as typespecs

```elixir
defmodule Encryptor.Provider do
  @type selector :: Encryptor.Vault.selector()
  @type state :: term()
  @type descriptor :: Encryptor.Key.Aes.t() | Encryptor.Key.Kms.t()

  @type reason ::
          {:unknown_key, selector()}
          | {:key_unavailable, selector()}
          | {:provider_not_started, module()}
          | {:missing_optional_dependency, atom()}

  @callback init(keyword()) :: {:ok, state()} | {:error, term()}
  @callback child_spec(keyword()) :: Supervisor.child_spec()

  @callback encryption_key(state(), selector()) :: {:ok, descriptor()} | {:error, reason()}
  @callback decryption_keys(state(), selector()) :: {:ok, [descriptor(), ...]} | {:error, reason()}

  @optional_callbacks init: 1, child_spec: 1
end
```

```elixir
defmodule Encryptor.Key.Aes do
  @type t :: %__MODULE__{
          namespace: String.t(),
          name: String.t(),
          material: binary(),
          bits: 128 | 192 | 256
        }

  @enforce_keys [:namespace, :name, :material, :bits]
  defstruct @enforce_keys
end

defmodule Encryptor.Key.Kms do
  @type t :: %__MODULE__{
          key_id: String.t(),
          mrk: boolean()
        }

  @enforce_keys [:key_id]
  defstruct [:key_id, mrk: false]
end
```

The additions to `Encryptor.Error.reason/0` from ADR-0001 decision 10:

```elixir
  @type reason ::
          # ... every term from ADR-0001 ...
          | {:key_unavailable, Encryptor.Vault.selector()}
          | {:invalid_key_descriptor, term()}
          | {:provider_not_started, module()}
          | {:missing_optional_dependency, atom()}
```

## Worked example: the static provider behind a single-key vault

This is ADR-0001's first worked example, seen from the provider side.

```elixir
defmodule Encryptor.Provider.Static do
  @behaviour Encryptor.Provider

  @impl true
  def init(opts) do
    with {:ok, material} <- Keyword.fetch(opts, :key) do
      {:ok,
       %{
         namespace: Keyword.get(opts, :namespace, "encryptor"),
         name: Keyword.get(opts, :name, "v1"),
         material: material
       }}
    else
      :error -> {:error, {:missing_config, [:provider, :key]}}
    end
  end

  @impl true
  def encryption_key(state, _selector), do: {:ok, descriptor(state)}

  @impl true
  def decryption_keys(state, _selector), do: {:ok, [descriptor(state)]}

  defp descriptor(state) do
    %Encryptor.Key.Aes{
      namespace: state.namespace,
      name: state.name,
      material: state.material,
      bits: byte_size(state.material) * 8
    }
  end
end
```

What this is chosen to demonstrate:

- **The selector is ignored, not rejected.** A single-key vault resolves
  `:default` and anything else identically, which is what makes ADR-0001's
  "`:key` is absent" ergonomics work without a special case in the vault.
- **`init/1` is where the secret lands**, having come from the host vault's
  own `init/1` and therefore from the environment, never from config or from
  `use` options.
- **No `child_spec/1`.** A pure provider adds no process, and the vault's
  supervisor holds only the cache.
- **`name: "v1"` is a default that a host will regret if it rotates**, which
  is why decision 4's grammar recommendation exists and why rotation for this
  provider means a config change plus a vault restart.

## Worked example: per-tenant keys with two live versions

A multi-tenant host app, on day one, before the storage adapter exists.

```elixir
defmodule MyApp.TenantKeyProvider do
  @behaviour Encryptor.Provider

  @impl true
  def init(opts) do
    {:ok, %{root_key: Keyword.fetch!(opts, :root_key), versions: MyApp.KeyVersions}}
  end

  @impl true
  def encryption_key(state, tenant_id) do
    case state.versions.current(tenant_id) do
      {:ok, version} -> {:ok, derive(state, tenant_id, version)}
      :not_found -> {:error, {:unknown_key, tenant_id}}
      {:error, :timeout} -> {:error, {:key_unavailable, tenant_id}}
    end
  end

  @impl true
  def decryption_keys(state, tenant_id) do
    case state.versions.live(tenant_id) do
      {:ok, [_ | _] = versions} ->
        {:ok, Enum.map(versions, &derive(state, tenant_id, &1))}

      {:ok, []} ->
        {:error, {:unknown_key, tenant_id}}

      {:error, :timeout} ->
        {:error, {:key_unavailable, tenant_id}}
    end
  end

  # Illustrative only: the real wrapping structure is enc-2u6's decision.
  defp derive(state, tenant_id, version) do
    reference = Base.url_encode64(:crypto.hash(:sha256, tenant_id), padding: false)

    %Encryptor.Key.Aes{
      namespace: "myapp-tenant",
      name: "t/#{binary_part(reference, 0, 16)}/v#{version}",
      material: :crypto.mac(:hmac, :sha256, state.root_key, "#{tenant_id}/#{version}"),
      bits: 256
    }
  end
end
```

```elixir
{:ok, ct} = MyApp.TenantVault.encrypt(record.notes, key: tenant.id, encryption_context: %{...})
{:ok, notes} = MyApp.TenantVault.decrypt(ct, key: tenant.id, encryption_context: %{...})

MyApp.TenantVault.encrypt(data, key: "no-such-tenant")
#=> {:error, %Encryptor.Error{reason: {:unknown_key, "no-such-tenant"}, operation: :encrypt}}

# The key store is down. This is not a decrypt failure and does not pretend to be.
MyApp.TenantVault.decrypt(ct, key: tenant.id)
#=> {:error, %Encryptor.Error{reason: {:key_unavailable, "tenant-42"}, operation: :decrypt}}
```

What this is chosen to demonstrate:

- **Encrypt takes the current version; decrypt takes all live versions.** The
  vault builds a `RawAes` from the first and a `Multi` from the second, and
  a message written under `v2` still decrypts after `v3` exists with no
  caller-visible change.
- **`name` carries a derived reference, not the tenant id**, because the name
  is published in every message header.
- **Three failure arms, three different reasons.** Unknown tenant, unreachable
  store, and wrong ciphertext are distinct in exactly the places where the
  distinction is not an oracle.
- **`derive/3` is a placeholder with a pointer.** HKDF from a root key is one
  possible envelope; enc-2u6 decides the real one. The provider contract does
  not depend on which.

## Roadmap sketch: every planned adapter against the contract

The bead's acceptance criterion is that each roadmap adapter is sketched
against the behaviour to prove it fits. In one line each:

- **Static** - `init/1` holds the key; both callbacks ignore the selector.
  No process. Fits.
- **Function** - `init/1` holds two closures; both callbacks call theirs and
  validate the returned struct. No process. Fits.
- **Ecto wrapped keys** (`encryptor_ecto`) - `init/1` holds the repo, the
  table module, and the KEK; `encryption_key/2` reads the tenant's current
  row and unwraps it, `decryption_keys/2` reads all non-shredded rows.
  A process only if it caches, and then a bounded one. Fits, and needs
  enc-2u6's row shape first.
- **AWS KMS** - `init/1` builds the client struct and checks the optional
  deps; `encryption_key/2` returns `%Encryptor.Key.Kms{}` for the tenant's
  key id; `decryption_keys/2` returns the same id plus any predecessors. No
  process; `ex_aws` owns the HTTP pool. Fits, and is the only keyring-backed
  member.
- **GCP KMS** - identical to Ecto in shape: a stored wrapped key, decrypted
  by a remote call instead of a local KEK. `encryption_key/2` does network
  I/O and must bound it. Fits.
- **Vault transit** - as GCP KMS. The `vaultx` Transit module is the prior
  art for the client half; the provider half is this contract unchanged.
  Fits.

Six adapters, two shapes, one behaviour, no keyring escapes into a host.

## Open questions

Recorded rather than guessed. Each names who should settle it.

1. **Should `decryption_keys/2` receive a hint from the message?** The vault
   holds the ciphertext, so it could parse the header's provider info and ask
   the provider for one name rather than for all live names. That turns a
   sixty-candidate walk into a single lookup and would matter for a
   long-lived tenant. It also means the vault parses the message format
   itself, which is a new dependency on the engine's header layout, and it
   lets a ciphertext steer a provider lookup. Worth deciding when the
   candidate lists are long enough to measure; not now.

2. **Whether `Encryptor.Provider.Function` should ship at all.** It is the
   fastest path to a per-tenant vault and the easiest way for a host to
   violate decisions 2 and 4 without noticing. The alternative is to ship
   only `Static` and make every host write a behaviour implementation. An
   operator call, and a reasonable one to defer to first-user feedback.

   *Resolved at acceptance (2026-08-27): `Provider.Function` ships in the
   day-one set as written. A behaviour implementation is no better enforced
   than a closure pair, and `Function` is the only day-one per-tenant path
   before the storage adapter exists.*

3. **Where a provider's failures should be observed.** Nothing here emits
   telemetry, and `{:key_unavailable, _}` is exactly the event an operator
   wants a metric on. Telemetry is not this record's subject and belongs in
   a record of its own covering the whole package.

4. **Whether the vault should verify descriptor stability in test builds.**
   A `Mix.env() == :test` mode that memoizes name-to-material and screams on
   a mismatch would catch decision 4's worst failure mode at development
   time, when it is free, rather than in production years later. It is a
   testing affordance rather than a contract, so it is noted, not decided.

5. **Whether the `:default` selector should be a distinguished type.** It is
   currently just an atom a `Static` provider ignores, which means a
   per-tenant provider handed `:default` by mistake resolves a tenant named
   `:default` or returns `{:unknown_key, :default}` depending on how it was
   written. A distinguished type would catch the confusion in the vault.
   Settle with enc-cvw, which is deciding what identifies a tenant anyway.

6. **How a provider's key material is zeroed, if at all.** Consequence one
   observes that every material-source adapter holds wrapping key bytes in
   BEAM memory. The BEAM offers no reliable erasure for binaries, and a
   `:persistent_term`-held root key is copied nowhere but is also collected
   on no schedule. Whether this package should say anything beyond
   documenting the fact is a security-review question, not a design one.
