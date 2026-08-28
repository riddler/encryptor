# Getting started

This guide stands up two vaults from nothing: a **single-key vault**, which is
what a host wants when one application encrypts its own columns, and a
**per-tenant vault**, which is what it wants when each tenant's data must be
cryptographically separable from every other tenant's.

The worked domain is card processing. A payments application stores card
data for its own use (single key), and later serves many merchants, each of
whom must be separable and shreddable (per tenant).

Everything below is code that runs against the package as it exists on `main`.
Where a statement is a decision rather than a mechanism, the record that fixes
it is cited, because a cryptographic claim you cannot trace to a record is a
claim nobody can review.

## Installing

The package is **not published to Hex yet**. The reserved `encryptor 0.1.0` on
Hex is a name reservation and holds no implementation; depending on it gets you
an empty package. Until the first real release, consume this package as a git
dependency, pinned to a commit:

```elixir
def deps do
  [
    {:encryptor, github: "riddler/encryptor", ref: "<full 40-character sha>"}
  ]
end
```

Pin a full SHA rather than a branch. A moving `branch:` dependency on a package
that decides ciphertext layout is a package that can change what your stored
rows mean between two `mix deps.get` runs.

`encryptor` pulls in `aws_encryption_sdk` and nothing else at runtime.
Raw-keyring usage brings in no AWS, HTTP, or XML libraries.

## Part 1: a single-key vault

### The vault module

A vault is a module in your application. It is the only thing your call sites
ever name:

```elixir
defmodule MyApp.Vault do
  use Encryptor.Vault, otp_app: :my_app

  @impl true
  def init(config) do
    key = Base.decode64!(System.fetch_env!("MY_APP_CARD_KEY"))

    {:ok,
     Keyword.put(config, :provider,
       {Encryptor.Provider.Static,
        key: key, namespace: "acme_payments", name: "card/v1"})}
  end
end
```

`use Encryptor.Vault` takes `:otp_app` and the module name and nothing else of
substance. It generates `encrypt/2`, `decrypt/2`, `rekey/2`, their bang
variants, `start_link/1`, `child_spec/1`, `stop/0`, `config/0` and `started?/0`
on your module (ADR-0001 decision 1).

Add it to your supervision tree:

```elixir
children = [
  MyApp.Repo,
  MyApp.Vault,
  MyAppWeb.Endpoint
]
```

### Key material arrives through `init/1`, and only through `init/1`

This is the rule the package enforces most aggressively, so it is worth
stating before anything else.

Configuration is resolved once, when the vault starts, through five layers in
this order (ADR-0001 decision 5):

1. the package defaults,
2. options passed to `use Encryptor.Vault`,
3. `Application.get_env(otp_app, vault)` - your `config/*.exs`,
4. options passed to `start_link/1`,
5. the return of your vault's optional `init/1` callback.

**Layer 5 is where key material belongs, and layers 2 and 3 are where it must
never be.**

Layer 2 is refused mechanically. A `use` option named `:key`, `:keys`,
`:root_key`, `:private_key`, `:passphrase` or `:reference_subkey` - or a
`:provider` option nesting one of those - **fails compilation**, not start:

```elixir
defmodule MyApp.BadVault do
  # ** (ArgumentError) MyApp.BadVault: option :key is key material and may not
  # be passed to `use Encryptor.Vault`.
  use Encryptor.Vault, otp_app: :my_app, key: "hunter2"
end
```

The refusal is a compile error because by the time the vault starts, the secret
is already baked into a `.beam` file and committed to your build artifacts.
`Encryptor.Vault.Config.validate_use_opts!/2` runs while the macro expands.

Layer 3 is not refused mechanically - the package cannot tell a key from any
other binary in your application environment - so it is a discipline: put
everything that is not secret in config, and read the secret in `init/1` from
the environment or your secrets manager. `init/1` is the same pattern
`Ecto.Repo.init/2` uses, and it exists here for the same reason.

### The rest of the configuration

Everything that is not key material goes in application config:

```elixir
# config/config.exs
config :my_app, MyApp.Vault,
  context_profile: :single,
  algorithm_suite_id: 0x0478,
  required_context: ["table", "column"],
  static_encryption_context: %{"app" => "acme_payments"},
  cache: [max_age: 60]
```

`:context_profile` and `:provider` are the two settings with no default.
There is no defensible default for where key material comes from, or for
whether a vault is per-tenant, and a wrong guess at either changes what goes
into a message.

### Why `0x0478`

The default is `0x0578`: AES-256-GCM, HKDF-SHA512, key commitment, **and**
ECDSA P-384 signing. That is the engine's own default, and a wrapper should
not silently weaken what the engine chose - so it is what you get by saying
nothing.

Configure `0x0478` - key commitment kept, the signature dropped - when **the
writer and the reader are the same trust domain** (ADR-0001 decision 9).

Signing exists so a reader can verify a writer it does not trust. When one
application both writes and reads its own encrypted columns, there is no
untrusted writer, and the signature costs an ECDSA P-384 sign on every write,
a verify on every read, and its bytes in every row, in exchange for nothing.
The encrypted-column case is exactly that shape, which is why this guide's
vaults use `0x0478`.

Keep `0x0578` when a ciphertext crosses a trust boundary: written by one
service and read by another that should not be able to forge it, or handed to
a third party.

Two suites are accepted and nothing else is. `:commitment_policy` may be
relaxed from `:require_encrypt_require_decrypt` to
`:require_encrypt_allow_decrypt` when you have older non-committed messages to
read; `:forbid_encrypt_allow_decrypt` is refused outright at start, because a
setting that turns key commitment off will eventually be turned off by someone
who does not know what it does (ADR-0001 decision 8).

### `max_age` is required, and has no default

`:cache` is `false` or a keyword list. When it is a list, **`:max_age` is
required and the package supplies no default** (ADR-0001 decision 6):

```elixir
# This vault does not start:
cache: [max_messages: 500]
#=> {:error, %Encryptor.Error{reason: {:missing_config, [:cache, :max_age]}}}
```

`:max_age` is in **seconds**. So is `:recycle_after`. (`:max_messages`
defaults to 100, `:max_bytes` to 1 GiB, `:recycle_after` to `20 * max_age`.)

There is no default because `max_age` is the answer to a question this package
cannot answer for you: **how long a data key may stay in this node's memory,
and therefore how long a crypto-shred takes to actually take effect.** Deleting
a tenant's wrapping does not stop a running node from decrypting that tenant's
data for up to `max_age` afterwards - which is why cache drainage is an
explicit step in every destructive procedure in the
[rotation runbook](rotation-runbook.md).

Naming a number forces you to have decided. A shorter `max_age` means more
provider round trips and a faster shred; a longer one means fewer round trips
and a longer tail on every deletion.

`cache: false` is a legitimate answer, and it is what a root vault uses.

### Encrypting and decrypting

```elixir
{:ok, ciphertext} =
  MyApp.Vault.encrypt(card_number,
    encryption_context: %{"table" => "payment_methods", "column" => "number"}
  )

{:ok, ^card_number} =
  MyApp.Vault.decrypt(ciphertext,
    encryption_context: %{"table" => "payment_methods", "column" => "number"}
  )
```

The return is the complete self-describing AWS Encryption SDK message and
nothing else (ADR-0001 decision 4). You store that one binary. It carries its
own encryption context, its own suite, and the name of the key that wrote it,
so there is no second column to keep in step with it.

The encryption context rides **in the clear** and is covered by the header
authentication tag. Two things follow, and both matter:

- every pair is public to anyone holding the ciphertext, so putting a value in
  the context is a disclosure decision, and
- no pair can be edited without breaking the tag, which is what binds a message
  to the row and column it was written for.

Because `required_context: ["table", "column"]` is configured above, a call
that omits either is refused rather than silently written unbound:

```elixir
MyApp.Vault.encrypt(card_number, encryption_context: %{"table" => "payment_methods"})
#=> {:error, %Encryptor.Error{reason: {:missing_required_context_keys, ["column"]}}}
```

The canonical context keys are `tenant_ref`, `table`, `column`, `blob`,
`purpose` and `app` (ADR-0004 decision 2). `table` and `column` are yours;
`purpose` and `app` are typically vault configuration; `blob` is the name for a
payload with no table. A signup flow storing a wizard payload, on a vault whose
`:required_context` does not name `table` and `column`, might use:

```elixir
MyApp.PayloadVault.encrypt(wizard_payload,
  encryption_context: %{"blob" => "signup_wizard_variant_b", "purpose" => "pii"}
)
```

You may add your own keys freely. You may not redefine one of the six, and you
may not write under `aws-crypto-` (the engine's) or `encryptor-` (this
package's).

**Nothing that varies per row may go in the context.** Not a primary key, not a
row id, not a timestamp, not a request id. The serialized context is hashed
into the materials cache id, so each distinct context is its own cache entry
and its own cold-cache provider round trip - a key-store read and a root-vault
decrypt, per row, forever. `table` and `column` are bounded by your schema;
a row id is not. The vault cannot tell the difference and will not stop you.

## Part 2: a per-tenant vault

Now the same application serves merchants, and each merchant's data must be
separable: rotatable on its own schedule, and destroyable without touching
anyone else's rows.

The design is a three-level hierarchy (ADR-0003):

| Level | What | Where it lives |
|---|---|---|
| 1, root key | one per deployment | your secrets manager, never encrypts application data |
| 2, tenant master key | one per tenant per version | 32 random bytes, wrapped by level 1, stored in your key store |
| 3, data key | one per message | generated by the engine, wrapped by level 2, discarded |

A tenant master key is **32 random bytes, generated once and never derived**.
That is what makes a crypto-shred honest: destroying every copy of the wrapping
destroys the key. A key derived from the tenant id could be recomputed forever
by anyone holding the root, and deleting its row would delete a memo rather
than a secret.

### Provision two root secrets at install, holding the same bytes

**Do this before you write a single tenant key.** It is the single most
important step in this guide, and the reason for it is that skipping it leaves
a deployment one copy-paste away from an unrecoverable mistake later.

A deployment holds **two** root secrets:

| Secret | Expands the label | Lifecycle |
|---|---|---|
| the **reference root** | `"encryptor/v1/tenant-ref"` | pinned at generation 1, **never rotated** |
| the **wrapping root** | `"encryptor/v1/root-wrap"` | rotated by procedure P1 |

At install, generate one 32-byte value and write it into **both** secrets:

```bash
# Once, at install. The SAME bytes into both.
ROOT=$(openssl rand -base64 32)
export MY_APP_WRAPPING_ROOT_KEY="$ROOT"
export MY_APP_REFERENCE_ROOT_KEY="$ROOT"
```

The two hold identical bytes until the first root rotation, at which point the
wrapping root changes and the reference root does not.

The reason to create both on day one, equal, is that the alternative is worse.
If a deployment ships with one root secret, then the first root rotation has to
begin by copying the current root into a newly created reference-root secret
(procedure P1, step 0). That step looks like a no-op and is not: generating a
fresh value there instead of copying **changes every tenant reference in the
deployment**, orphaning every stored key name and every message header already
written, for every tenant, with no way back except restoring the original root
material. ADR-0005 calls it "the most destructive-looking no-op in the record".

A deployment that provisions both secrets at install, equal, never performs
step 0 and cannot get it wrong. That is ADR-0005 open question 5's answer, and
this guide is where it is enforced.

Two further rules follow:

- **Never rotate the reference root.** Every stored key name and every written
  message header carries a reference derived from it. It is effectively
  permanent from the first message onward.
- **Store them as two separate secrets from the start**, with two names, even
  while they hold the same value. A single secret read twice is a single secret
  that will be rotated once.

### The root vault

The root vault's only job is to wrap and unwrap tenant keys. It is an ordinary
`Encryptor.Vault`, configured `:single`, `cache: false`, and holding **the
wrapping subkey** rather than the root itself:

```elixir
defmodule MyApp.RootVault do
  use Encryptor.Vault, otp_app: :my_app

  @impl true
  def init(config) do
    wrapping_root = Base.decode64!(System.fetch_env!("MY_APP_WRAPPING_ROOT_KEY"))

    {:ok,
     Keyword.put(config, :provider,
       {Encryptor.Provider.Static,
        key: Encryptor.Envelope.root_subkey(wrapping_root, "root-wrap"),
        namespace: "encryptor-root",
        name: "r/v1"})}
  end
end
```

```elixir
# config/config.exs
config :my_app, MyApp.RootVault,
  context_profile: :single,
  algorithm_suite_id: 0x0478,
  cache: false
```

`Encryptor.Envelope.root_subkey/2` is an HKDF expansion under
`"encryptor/v1/<purpose>"`. Passing the root material through it - rather than
using the root directly - is what lets the wrapping subkey rotate later while
every stored tenant reference stays valid (ADR-0003 decision 6).

Two constraints on a root vault, and both are load-bearing:

- **`cache: false`.** Provisioning is rare, and unwraps are already collapsed
  by the tenant vault's own materials cache. A second cache here would hold the
  root's data keys in memory for no measurable benefit.
- **A `Static` provider, never a store-backed one.** A root vault whose
  provider reads from the store it is used to unwrap would be a genuine cycle,
  and it would recurse or deadlock rather than fail cleanly.

### Onboarding a merchant

```elixir
reference_root = Base.decode64!(System.fetch_env!("MY_APP_REFERENCE_ROOT_KEY"))
reference_subkey = Encryptor.Envelope.root_subkey(reference_root, "tenant-ref")

{:ok, wrapped} =
  Encryptor.Envelope.provision(MyApp.RootVault, merchant.id,
    reference_subkey: reference_subkey,
    namespace: "acme-merchant"
  )

{:ok, _row} = MyApp.MerchantKeys.insert(wrapped)
```

`provision/3` mints 32 bytes from the CSPRNG, wraps them into an ordinary
`Encryptor` message under the root vault, and returns an
`Encryptor.Envelope.WrappedKey` with six fields: `tenant_ref`, `version`,
`namespace`, `name`, `bits` and `wrapped`.

**The plaintext key never leaves that function.** There is no function in this
package that returns a bare tenant master key as a binary.

`MyApp.MerchantKeys` is yours. **This package defines no storage** - no table,
no migration, no repo, no transaction - and no function here takes one. The
Ecto schema, its migration, and a store-backed provider are
[`encryptor_ecto`](https://github.com/riddler/encryptor_ecto)'s.

The wrapping carries a package-owned encryption context binding it to one
purpose, one tenant reference, one version and one namespace. A wrapping copied
into another merchant's row does not unwrap; nor does one copied between
versions. You cannot set that context and you cannot suppress it: passing
`:encryption_context` to `provision/3` is `{:reserved_context_key, key}`.

### Resolving a merchant's key

Your provider unwraps a stored row into a descriptor. `unwrap/2` returns an
`%Encryptor.Key.Aes{}`, never a binary:

```elixir
{:ok, %Encryptor.Key.Aes{} = descriptor} =
  Encryptor.Envelope.unwrap(MyApp.RootVault, row)
```

Resolution **never provisions**. A selector with no live key is
`{:unknown_key, selector}`, full stop. A provider that lazily minted a key on
first use would mean a typo in a merchant id silently creates a key, that two
concurrent requests can mint two keys for one merchant, and that the first
encrypt after a deploy performs a write on the read path.

### The tenant vault

```elixir
defmodule MyApp.MerchantVault do
  use Encryptor.Vault, otp_app: :my_app

  @impl true
  def init(config) do
    reference_root = Base.decode64!(System.fetch_env!("MY_APP_REFERENCE_ROOT_KEY"))

    {:ok,
     config
     |> Keyword.put(:reference_subkey,
       Encryptor.Envelope.root_subkey(reference_root, "tenant-ref"))
     |> Keyword.put(:provider, {MyApp.MerchantKeyProvider, root_vault: MyApp.RootVault})}
  end
end
```

```elixir
# config/config.exs
config :my_app, MyApp.MerchantVault,
  context_profile: :tenant,
  algorithm_suite_id: 0x0478,
  required_context: ["table", "column"],
  cache: [max_age: 60]
```

`:reference_subkey` is key material, so it comes through `init/1` like every
other secret - and it is on the list `use` refuses at compile time.

A `:tenant` vault takes the tenant as `key:` on every call, and derives the
`tenant_ref` context pair itself:

```elixir
{:ok, ciphertext} =
  MyApp.MerchantVault.encrypt(card_number,
    key: merchant.id,
    encryption_context: %{"table" => "payment_methods", "column" => "number"}
  )
```

You never pass `tenant_ref` yourself. `tenant_ref` and `tenant_id` are both
refused from a caller on a tenant vault: `key:` is the whole of per-tenant
routing, and a tenant named twice is a tenant that can disagree with itself.

The reference is a **keyed** derivation, not a hash:

```
tenant_ref =
  Base.url_encode64(
    binary_part(HMAC-SHA256(reference_subkey, selector), 0, 16),
    padding: false
  )
```

It is stable, so the same merchant always resolves to the same reference. It is
unguessable without the subkey, so a header discloses that two ciphertexts
belong to the same merchant without disclosing which merchant. An unkeyed hash
of a short id or a small integer would not - the identifier space is guessable
by anyone who thinks to try it.

The output is public and travels in the clear. The **input** is secret and
never reaches a message, a log line, or a failure report.

### Pinning the reference subkey with a known-answer check

Optional, and worth doing on any fleet with more than one node.

A node deployed with the wrong reference subkey does not fail loudly. It writes
messages no correct reader can open, and fails every correct message as
`:decrypt_failed` - which looks exactly like corruption, and is discovered at
decrypt time, when the reference subkey is already effectively permanent.

Compute the value once, from the reference subkey the deployment was
provisioned with:

```elixir
Encryptor.Vault.Config.known_answer(reference_subkey)
#=> "2Kk...", 22 characters
```

Then pin it:

```elixir
config :my_app, MyApp.MerchantVault,
  context_profile: :tenant,
  reference_check: "2Kk..."
```

Every node now refuses to start unless its subkey reproduces that value. The
value is not secret - it is the same shape as a `tenant_ref`, which travels in
the clear in every header - so it belongs in config rather than in a secret.

## What the vault refuses, and why

A quick index of the failures you are most likely to meet first. Every one is
an `{:error, %Encryptor.Error{reason: ...}}` from a closed vocabulary; the
package never rescues an exception into an error tuple.

| You did | You get |
|---|---|
| put key material in `use` options | `ArgumentError` **at compile time** |
| start a vault with no `:provider` or no `:context_profile` | `{:missing_config, [:provider]}` |
| configure `cache:` without `:max_age` | `{:missing_config, [:cache, :max_age]}` |
| set `commitment_policy: :forbid_encrypt_allow_decrypt` | `{:invalid_config, :commitment_policy, :forbidden}` |
| set `max_encrypted_data_keys: nil` | `{:invalid_config, :max_encrypted_data_keys, :unlimited}` |
| call a `:tenant` vault without `key:` | `{:invalid_selector, :default}` |
| pass `key:` to a `:single` vault | `{:invalid_selector, "..."}` |
| pass `tenant_ref` in `:encryption_context` | `{:reserved_context_key, "tenant_ref"}` |
| omit a key named in `:required_context` | `{:missing_required_context_keys, [...]}` |
| call a vault that is not running | `{:vault_not_started, MyApp.Vault}` |
| anything at all on the decrypt side that depends on the message | `:decrypt_failed` |

That last row is deliberate and it is not laziness. A wrong key, a corrupted
message, a context mismatch and a truncated blob all collapse to one reason,
because a decrypt path that distinguishes them is a decryption oracle. The
engine's own term is carried in the error's `:engine` field for an operator to
read; it is never matched on.

## Reading a stored message

`Encryptor.Message.describe/1` parses a message header with no key and no
vault:

```elixir
{:ok, info} = Encryptor.Message.describe(ciphertext)
info.encryption_context     #=> %{"table" => "payment_methods", ...}
info.algorithm_suite_id     #=> 1144
info.committed?             #=> true
info.encrypted_data_keys    #=> [%{provider_id: "acme-merchant", key_name: "t/<ref>/v1"}]
```

**The return is an unverified claim.** The header authentication tag is not
checked - checking it needs the data key - so every field is what whoever wrote
the bytes says. Use it for support tooling and for a migration that needs to
know which key version wrote a row. Never make an authorization or routing
decision on it: a host that reads `tenant_ref` out of a header and shows the
row to that tenant has built an access check out of an attacker-editable field.

## Where to go next

- **[The rotation runbook](rotation-runbook.md)** - the four operator
  procedures, what each one destroys, and the one step that cannot be undone.
  Read it before you need it; two of the four procedures are irreversible.
- **The decision records** in `docs/adr/` - ADR-0001 (the vault layer),
  ADR-0002 (key providers), ADR-0003 (the per-tenant envelope), ADR-0004 (the
  encryption context), ADR-0005 (rotation and crypto-shred).
- **[`encryptor_ecto`](https://github.com/riddler/encryptor_ecto)** - the Ecto
  types, the wrapped-key schema and its migration, and the re-encryption
  migrator. It supplies `table` and `column` from its declared values and
  enforces nothing; enforcement is your vault's `required_context`, because two
  schemas sharing a vault must not be able to disagree about how strictly their
  rows are bound.
