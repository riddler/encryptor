### Added

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

### Notes

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
