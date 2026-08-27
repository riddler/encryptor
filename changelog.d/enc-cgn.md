### Added

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
