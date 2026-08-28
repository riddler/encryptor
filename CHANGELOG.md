# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Entries for unreleased work are not written here directly. Each issue drops a
fragment in [`changelog.d/`](changelog.d/README.md); the fragments are assembled
into a version section at release. See that README for the format and for when a
change warrants an entry at all.

## [0.2.0] - 2026-08-28

### Added

- `use Encryptor.Vault, otp_app: :my_app` defines a vault: a supervised module
  that is the host's entire surface. It captures the `:otp_app` and the module
  name and nothing else, and generates `child_spec/1`, `start_link/1`,
  `stop/0`, `config/0` and `started?/0`.
- Starting a vault starts a supervisor whose children are the process that
  owns the frozen configuration, the materials cache when caching is
  configured on, and the key provider when its module exports `child_spec/1`.
  A vault configured with `cache: false` still starts, because a provider may
  need supervision even when the cache does not exist.
- Two vaults never share a cache process. The pair `{otp_app, vault_module}`
  is the whole configuration key, so one vault's bounds never apply to
  another vault's materials.
- Stopping a vault erases its frozen configuration, so a later call answers
  `{:vault_not_started, vault}` rather than reading the configuration of a
  vault that is gone.
- A vault that is not running is a typed error, never an exit raised from
  inside a library: `Encryptor.Vault.ready/2` checks the vault and its
  provider before any operation and returns `{:vault_not_started, vault}` or
  `{:provider_not_started, module}`. Both are checks, not rescues.
- A configuration the vault refuses is an `{:error, %Encryptor.Error{}}` from
  `start_link/1`, resolved before the supervisor process exists, rather than
  a started vault that fails at its first encrypt.
- `Encryptor.Vault.Config` resolves a vault's configuration once, at start,
  through the five-layer precedence chain - package defaults, `use` options,
  application environment, `start_link/1` options, the optional `init/1`
  callback - and freezes it in `:persistent_term`, so per-call reads are
  lock-free.
- Key material passed to `use Encryptor.Vault` is a compile-time error rather
  than a warning, including a secret nested in a `:provider` option: a secret
  in `use` options is a secret compiled into a `.beam` file.
- Configuration that would weaken the vault is refused at start, not at the
  first encrypt: the legacy commitment policy, a `nil` encrypted-data-key
  limit, an unsupported algorithm suite, a cache with no `max_age`, a
  misspelled cache bound, and a static encryption context that is unbounded
  or uses a reserved key.
- A tenant vault requires its reference subkey and, once a deployment has
  pinned a known-answer value, refuses to start unless the subkey reproduces
  it - the misconfiguration that would otherwise be discovered as fleet-wide,
  corruption-shaped decrypt failures.
- A vault's context profile (`:single` or `:tenant`) is readable at runtime
  through `Encryptor.Vault.Config.fetch/1`. It is start-time state, not
  compile-time: `encryptor_ecto` reads it from the running vault.
- `Encryptor.Provider` is the key-provider behaviour: `encryption_key/2` and
  `decryption_keys/2` required, `init/1` and `child_spec/1` optional. A
  provider answers which key, and the vault alone turns the answer into an
  engine keyring. `Encryptor.Provider.init/2` runs a provider's `init/1`, or
  takes the option list as state for a provider that omits it.
- `Encryptor.Provider.Static` holds one key, or a candidate list of them
  newest first, in configuration. With `keys:`, `encryption_key/2` answers the
  head and `decryption_keys/2` answers the whole list, which is what makes a
  staged root rotation readable mid-pass. Passing both `key:` and `keys:` is
  `{:invalid_config, :provider, :key_and_keys}` at start, and so are two
  entries sharing a name and material that is not 16, 24, or 32 bytes.
- `Encryptor.Provider.Function` wraps a host-supplied pair of closures, so a
  per-tenant vault is reachable without writing a behaviour implementation. It
  validates the answer on the way back: a non-descriptor, an empty candidate
  list, or a refusal outside the closed reason vocabulary becomes
  `{:invalid_key_descriptor, detail}` naming the constraint rather than the
  value.
- `Encryptor.Provider.Conformance` is the shared test suite every adapter is
  held to, in `lib/` so adapters in other packages can run it. It checks that
  the encryption key is the head of the candidate list, that candidate names
  are distinct, that resolution is stable, and that one candidate builds a
  bare `RawAes` while more build a `Multi` with no generator.
- `Encryptor.Key.Aes` and `Encryptor.Key.Kms` are the key descriptors a
  provider returns: the closed, package-owned set that says which key, rather
  than an engine keyring. A host cannot add a member; adding one is a release
  of this package.
- `Encryptor.Key.Aes` redacts `:material` from `inspect/2`, so a wrapping key
  cannot reach a log line, a crash report, or a rendered error through the
  descriptor that carries it.
- A descriptor the vault cannot build a keyring from fails as
  `{:invalid_key_descriptor, detail}`, where the detail names the constraint
  that was violated - a reserved namespace, an unusable namespace or name, an
  unsupported key size, a material length that does not match the declared
  size - and never the value that violated it.
- `Encryptor.Error` is the single error struct every entry point returns and
  every bang variant raises, carrying a stable `:reason` you can match on
  alongside the underlying `:engine` term for logs.
- The reason vocabulary is one closed enumeration, so a `case` over failures
  has a fixed set to match and is extended only by a new decision record.
- Decrypt-side failures that depend on the message all collapse to
  `:decrypt_failed`, so no caller can use the error as a decryption oracle.
- `Encryptor.Context` owns the encryption-context vocabulary: the six canonical
  host-facing keys and the two reserved prefixes are readable through
  `canonical_keys/0` and `reserved_prefixes/0`, rather than repeated as string
  literals across packages.
- `Encryptor.Context.compose/3` merges the four context layers - static
  configuration, the caller's per-call map, the vault's own derived keys, and
  the package-reserved pairs - and refuses rather than silently overriding: a
  caller key that disagrees with configuration is a conflict, a caller key that
  names a reserved prefix or a tenant is refused, and a non-string, empty, or
  non-UTF-8 key or value is refused before the engine is called.
- A composed context is bounded per call at 32 pairs and 4 KiB serialized, the
  bound the engine performs no check of at all.
- `encrypt/2` and `encrypt!/2` on every vault module. A call resolves its
  selector through the provider, maps the descriptor to a keyring, composes
  the encryption context, derives the cache partition id, builds the CMM
  stack and the client, and returns `{:ok, ciphertext}` - the complete
  self-describing engine message and nothing else. The engine also reports
  the header, the context and the suite; the vault does not, because the
  message already carries them authenticated and a second stored copy can
  disagree with it.
- The CMM stack order is fixed and not configurable, because it is a security
  property rather than a style choice: `Default` innermost, the caching CMM in
  the middle when caching is configured, and `RequiredEncryptionContext`
  outermost. Required on the outside runs the presence check before the cache
  is consulted; caching on the outside would skip it for exactly the messages
  that are read often. When the required set is empty the outer wrap is
  skipped.
- Selector typing is enforced before the provider is consulted: a `:tenant`
  vault refuses `:default` and a `:single` vault refuses a string, both as
  `{:invalid_selector, selector}`. An absent `:key` means `:default`, so a
  single-key vault carries no per-call ceremony and a tenant vault refuses a
  call that names no tenant.
- On a `:tenant` vault the encryption context's `tenant_ref` is derived by the
  vault from the `:key` selector, under the configured reference subkey. A
  caller supplying `tenant_ref` or `tenant_id` is refused, so the routing
  argument and the context pair are incapable of disagreeing.
- The cache partition id is derived from the same selector that chose the key,
  so one merchant's data key cannot be served from another merchant's cache
  lookup.
- A provider's `init/1` now runs once, at vault start, and what it returns is
  frozen as the configuration's `:provider_state` - the state every later
  resolution callback is handed. A provider that cannot configure itself is a
  vault that does not start, rather than a vault that fails at its first
  encrypt.
- `decrypt/2` and `decrypt!/2` on every vault module. A call resolves its
  selector through the provider's `decryption_keys/2` callback, builds one
  keyring from the whole candidate list - a plain raw-AES keyring for a single
  candidate, a multi-keyring walked in order for more, which is what lets a
  message written before a rotation still open - composes the reproduced
  encryption context, and returns `{:ok, plaintext}` and nothing else. The
  engine also reports the header, the verified context and the suite; a caller
  that wants the context reads `Encryptor.Message.describe/1`, which is honest
  about being an unverified claim.
- The vault compares the reproduced encryption context against the message's
  own **itself**, above the engine, before any decryption is attempted. For
  every key present in both, the values must agree; a disagreement is
  `:decrypt_failed` and the engine is never called. This is not a duplicate of
  the engine's check. The engine's lives below its materials cache, and the
  decryption cache id is derived from the message's stored context rather than
  the reader's claim, so a warm cache serves a legitimate first read's
  materials to a reader claiming a different tenant, table or column. Comparing
  above the cache is what makes anti-substitution a property of this package
  rather than one inherited from the engine: it holds on the first read of a
  row and on the thousandth alike, with caching on or off.
- The reader's cryptographic materials manager stack is the writer's, built by
  the same code. The engine mixes the required subset of the context into the
  header's additional authenticated data, so a reader that does not know which
  keys the writer required fails header authentication rather than a context
  comparison.
- `rekey/2` and `rekey!/2` on a generated vault, and `Encryptor.Vault.rekey/3`
  behind them: one message, decrypted with whatever its own encrypted data keys
  resolve to and re-encrypted under the vault's currently resolved materials,
  with its encryption context preserved byte for byte. This is the last entry
  point of the vault surface, and it completes it.
- The encryption context a rekey writes comes from the message's own header,
  not from the caller, because a rekey caller holds a ciphertext and not a row.
  `:encryption_context` is therefore not an option: passing one is
  `{:reserved_context_key, key}`, since the only correct value is the one
  already in the message and accepting a second copy is how a rotation job
  rewrites what a million rows are bound to while believing it is rotating
  keys.
- A rekey is refused when the message's stored context disagrees with the one
  the vault composes from the call's own arguments, through the same comparison
  a read goes through. On a per-tenant vault that is what stops a rekey moving
  a message between tenants.
- A rekey touches no storage and is a pure binary-to-binary function. Its
  canonical caller in this family is the envelope's rewrap; it is available to
  a host that stores ciphertext outside Ecto and wants a key rotation rewritten
  without a migrator, and it is deliberately **not** the downstream migrator's
  tool, which has to stay uniform across a rotation and a change of format,
  algorithm or context.
- Every failure of a rekey is stamped `operation: :rekey`, on both halves: what
  failed is the operation the caller asked for, not the half of it the failure
  landed in. Message-dependent failures collapse to `:decrypt_failed` exactly
  as a read's do.
- `Encryptor.Kdf` derives labelled subkeys with HKDF-SHA256, using `:crypto`
  and nothing else. `derive_subkey/3` is the labelled derivation the key
  hierarchy is built from; `expand/3` is RFC 5869 HKDF-Expand underneath it,
  checked against the RFC's three SHA-256 test vectors.
- `Encryptor.Kdf.label/1` is the one place the `"encryptor/v1/"` label prefix
  is written, so a purpose cannot be spelled into an existing label by hand.
  The label space is reserved: a new purpose always takes a new label and
  never reuses one.
- `expand/3` takes its `info` string verbatim, so a consumer that owns a
  purpose-separated key tree can derive within the label it was given.
- `Encryptor.Vault.derive/3`, and a generated `derive/2` on every vault
  module: a consumer names a scope and receives derived key bytes, without the
  key material they were derived from ever being exported to it.
  `encryptor_ecto`'s blind index is the first caller. The scope is
  `{ikm_selector, salt, info, length}`: a label purpose plus the vault's own
  selector, the vault's per-deployment salt, and the caller's own info string
  and output length.
- `Encryptor.Kdf.extract/2`, HKDF-Extract with SHA-256 per RFC 5869
  section 2.2, and `Encryptor.Kdf.salted_subkey/5`, the salted construction
  the new vault surface derives through. Both are covered by the RFC's own
  appendix A vectors.
- `:derivation_salt`, a per-deployment vault configuration value of at least
  32 bytes. It is optional at start and required at derivation, so an existing
  vault starts unchanged and only `derive/3` refuses. Like key material it may
  not be passed to `use Encryptor.Vault` - not because it is secret, but
  because a per-deployment value compiled into a `.beam` is shared by every
  deployment built from that artifact.
- `:derive` joins the `Encryptor.Error` operation vocabulary.
- A vault with caching on now supervises `Encryptor.Vault.CacheRecycler`
  beside its cache. The engine's local cache has no capacity limit, no
  sweeper, and no way for outside code to measure it, so the recycler bounds
  it the only way available: it stops the cache child on the configured
  `:recycle_after` interval and starts it again with a fresh empty table.
  Dropping the whole table is always safe - every entry is derived material
  that can be re-fetched, and the worst outcome is a cold miss.
- `:recycle_after` is in seconds and defaults to `20 * max_age`. A vault
  configured with `cache: false` runs no recycler.
- `Encryptor.Vault.Partition.id/2` derives the fixed-width cache partition id
  a tenant's materials are cached under: 16 bytes of
  `sha256(vault, 0, encoded_selector)`. The width is fixed because the engine
  concatenates the partition id into its cache-id pre-image with no length
  prefix, so a variable width would let two partitions collide on one cache
  id. The id is a cache-key input only: it is never key material and it never
  reaches a message.
- `Encryptor.Vault.recycler_name/1` gives a vault's recycler its registered
  name, derived from the vault module like the cache and supervisor names.
- `Encryptor.Message.describe/1` reads what a message says about itself - the
  stored encryption context, the algorithm suite id, whether the suite commits,
  and the `{provider_id, key_name}` pair of each encrypted data key - with no
  key material, no vault, and no provider.
- `Encryptor.Message.Info` is the struct it returns. Every field is read
  without verifying the header authentication tag, so the value is an
  unverified claim: it is for support tooling and migrations, and never an
  authorization input.
- `Encryptor.Message` is the single place this package reads the engine's
  message layout, so the decrypt-path context check, `rekey/2`, and a rotation
  census all share one parse.
- `Encryptor.Envelope`, the level 1 to level 2 relationship: how a tenant
  master key comes into existence, what protects it at rest, and how it gets
  back into memory. It sits above the vault rather than beside it, because a
  wrapped tenant key is an ordinary `Encryptor` message.
- `Encryptor.Envelope.provision/3` mints a tenant master key: 32 bytes from
  the CSPRNG, generated once and never derived, wrapped under a root vault and
  returned as an `Encryptor.Envelope.WrappedKey`. Storing an independently
  random key rather than deriving one is what makes crypto-shredding honest -
  destroying the wrapping destroys the key, even for the holder of the root.
- The plaintext key exists inside one function body and never appears in a
  return value, a log line, or a struct. There is no function in this package
  that returns a bare tenant master key as a binary; `unwrap/2` hands back an
  `%Encryptor.Key.Aes{}` descriptor, whose material is redacted from
  `inspect/2`.
- `Encryptor.Envelope.WrappedKey`: the six fields a store has to give back -
  the wrapping, the tenant reference, the version, the namespace, the derived
  name, and the key size. This package defines no table, migration, repo, or
  transaction, and no function here takes one.
- The wrapping carries a package-owned encryption context binding it to one
  purpose, one tenant, one version and one namespace. `provision/3` sets it and
  `unwrap/2` requires it, so a wrapping copied between tenants, copied between
  versions, or taken from elsewhere in the application does not unwrap. It is
  not a host option: passing `:encryption_context` to `provision/3` is
  `{:reserved_context_key, key}`.
- `Encryptor.Envelope.unwrap/2` returns the descriptor a key provider returns,
  rebuilt from the row and validated the way the vault validates one, so a row
  whose columns cannot form a descriptor is refused at resolution rather than
  as an encrypted-data-key mismatch on a later read.
- `Encryptor.Envelope.rewrap/2` is root rotation: one wrapping re-encrypted
  under the root vault's current materials, built on `Encryptor.Vault.rekey/2`,
  with every identity column and the whole binding carried across unchanged. It
  is idempotent in effect and never in bytes, so a partial pass is safe to
  resume.
- `Encryptor.Envelope.tenant_ref/2` derives the keyed, stable, public reference
  for a tenant identifier from the reference subkey. It is keyed rather than a
  plain hash because an unkeyed hash of a low-entropy identifier is reversible
  by anyone who can guess the identifier space, and the reference travels in
  the clear in every message header.
- `Encryptor.Envelope.root_subkey/2` and `Encryptor.Envelope.subkey/2` are the
  two labelled derivations, one line each onto `Encryptor.Kdf`. The root's two
  purposes have deliberately different lifetimes, so a routine root rotation
  replaces the wrapping subkey while every stored tenant reference stays valid.
  The label namespace is reserved beyond them: `subkey/2` refuses the root's
  purposes outright, so a tenant-side key can never be derived under a label
  that already means something else.
- A getting-started guide (`guides/getting-started.md`): a single-key vault and
  a per-tenant vault, stood up from nothing. It states where key material is
  allowed to come from (the `init/1` callback, never `use` options and never a
  config file), when to configure the unsigned `0x0478` suite and when to keep
  the signing default, and why `:max_age` is required with no default - it is
  the answer to how long a crypto-shred takes to take effect on a running node.
- The guide requires **two root secrets from day one, holding the same bytes**:
  a pinned reference root that is never rotated, and a wrapping root that
  procedure P1 rotates. A deployment that provisions both at install never has
  to perform P1's copy-the-reference-root step, which is the most
  destructive-looking no-op in the design - generating a fresh value there
  instead of copying changes every tenant reference in the deployment.
- A rotation runbook (`guides/rotation-runbook.md`): the four operator
  procedures - root rotation, tenant key rotation, tenant shred, version retire
  - each with its preconditions, steps, independent verification and rollback,
  plus both blast radius tables. Every step is labelled with whether it is a
  function this package ships or an action on a store it does not own, and
  cache drainage is a step inside each destructive procedure rather than a
  follow-up.
- The runbook carries the two-vocabulary mapping table across `encryptor` and
  `encryptor_ecto`, because the two packages name the three key levels
  differently and an operator reading one runbook against the other's names can
  run a level 2 rotation believing it is a level 1 rotation.
- The runbook states plainly what a crypto-shred does not destroy: **a shred
  destroys plaintext, not attribution**. The tenant pseudonym in every message
  header is permanent, and the holder of the reference subkey can re-identify
  it by guess-and-confirm forever, in every retained backup. Deleting the
  tenant's ciphertext rows is compliance-mandatory wherever tenant attribution
  is itself personal data, and the shred claim must never be stated as full
  erasure.
- Both guides are ExDoc extras, and every code block in them is executed by
  `Encryptor.GuidesTest` against modules transcribed from the printed text.

### Changed

- The selector profile check, the provider call and its failure vocabulary,
  and the four-layer context composition are now shared between the encrypt
  and decrypt paths rather than spelled once per path. A `:tenant` vault that
  refused `:default` on the way in and accepted it on the way out would accept
  a read no write could have produced, and a caller-supplied tenant pair
  refused at encrypt and honoured at decrypt would reopen the second place to
  claim a tenant that routing through `:key` exists to close.
- `Encryptor.Kdf` is no longer expand-only. `"encryptor/v1/root-wrap"` and
  `"encryptor/v1/tenant-ref"` keep the expand-only construction and the RFC
  5869 section 3.3 argument for it; only the new exported tree is salted.
  Nothing derived through the two unsalted trees changes. Records: ADR-0003
  amendment A, proposed 2026-08-28 and not yet accepted.
- `README.md` reports the package as built rather than as a scaffold, links
  both guides, and gives the installation form as a SHA-pinned git dependency.
  The reserved `encryptor 0.1.0` on Hex is a name reservation holding no
  implementation and must not be depended on.
- `README.md` carries a pre-1.0 stability notice at the top: public APIs,
  storage formats, and derivation constants may change between releases
  without a deprecation cycle until 1.0.0, so pin an exact version and read the
  changelog before upgrading.
- `README.md` describes the landed surface - the vault entry points including
  `derive/2`, the provider behaviour and its conformance suite, the envelope,
  `Encryptor.Kdf`, the error vocabulary and the cache recycler - with a
  quickstart that runs, and states plainly what does not exist yet: no
  Argon2id surface, and telemetry proposed but not emitted.
- The installation section names the first real release as `0.2.0`, so a
  reader knows what to move to when the SHA-pinned git dependency is no longer
  needed. The reserved `encryptor 0.1.0` on Hex still holds no implementation.

### Notes

- `:algorithm_suite`, `:commitment_policy`, `:frame_length` and
  `:max_encrypted_data_keys` are deliberately not per-call options. All four
  are configuration, and one place to review them is the point.
- This behaviour depends on the engine storing the full encryption context in
  the message header, which is a deviation from the AWS Encryption SDK
  specification. If the engine is ever corrected to strip required keys from
  the header, `rekey/2` will need the context as an argument, supplied by
  whatever owns the row. `Encryptor.Vault.Rekey` is the one place that
  assumption is made.
- `provision/3` takes a required `:reference_subkey` option. The reference
  derives from the pinned reference root, which a root vault does not hold
  once the two roots have diverged, so the value has to arrive the same way
  `tenant_ref/2` takes it. This is an extension of the originally recorded
  options list, forced by the same amendment that changed `tenant_ref/2`'s
  signature.
- A root vault must be configured with a static, self-contained key provider.
  One configured with a store-backed provider would be a genuine cycle - a
  vault whose provider resolves keys that the vault itself has to unwrap - and
  it would recurse rather than fail cleanly.
- Requiring the binding is the envelope's own check, above the engine and above
  the vault. The vault-side comparison compares only keys present in both the
  stored and the reproduced context, which is right for a host's advisory
  context and wrong for a binding whose absence is the failure.
