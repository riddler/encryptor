### Changed

- A root vault's `decrypt/2` and `rekey/2` no longer open a scope-key wrapping: a host that read key material out of a wrapping through `decrypt/2` reads the key descriptor from `Encryptor.Envelope.unwrap/2` instead, and a wrapping is moved onto a new root with `Encryptor.Envelope.rewrap/2`.

### Fixed

- `Encryptor.Vault.decrypt/3` and `Encryptor.Vault.rekey/3`, and a vault's generated `decrypt/2` and `rekey/2`, now return `{:error, %Encryptor.Error{reason: :decrypt_failed}}` (the bang forms raise it) for a message whose stored encryption context carries a key under the package's `encryptor-` prefix, which every scope-key wrapping `Encryptor.Envelope.provision/3` writes does; before, a root vault's own `decrypt/2` opened a wrapping and returned the bare scope master key, which the package documents that no function returns.
