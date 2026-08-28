### Changed

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
