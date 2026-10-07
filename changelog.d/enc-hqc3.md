### Changed

- `Encryptor.Vault.provision/2` on `Encryptor.Provider.GcpKms` now refuses a scope its store already holds a row for with the new reason `{:key_name_in_use, selector}` (telemetry tag `:key_name_in_use`), before any GCP call, instead of minting new bytes under the version-1 name the stored row carries. A name whose rows a shred deleted is not visible to it, and `Encryptor.Envelope.provision/3` sees no store at all: refusing a version a store has already used stays the store's.
- Every cache partition id for an AES key changes once, on both the encryption and the decryption side, so a node's warm materials cache is cold after it first runs this version. A single retired version now stops decrypting at once on a warm cache, instead of serving from the cache until it is drained.

### Fixed

- After a scope is shredded and provisioned again under the same key name, a message written under the shredded bytes no longer decrypts again from a warm cache entry, and the next write no longer reuses a cached data key wrapped under the shredded bytes, which left that message unreadable once the cache was dropped. Both cache partitions now carry a fingerprint of the key material.
