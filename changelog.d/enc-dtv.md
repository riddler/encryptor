### Added

- `Encryptor.Kdf.slow_hash/3` hashes a value with Argon2id and returns 32 raw
  bytes, so a downstream blind index over low-entropy plaintext can be
  pre-hashed before it is keyed.
- Vaults take an optional `:slow_hash` parameter set - `:memory_kib`,
  `:iterations`, `:parallelism`, defaulting to 64 MiB, 3 and 1 - readable
  through `config/0`, so the cost is one operator decision rather than one per
  call site.
- `:argon2_elixir` is an optional dependency: a host whose vaults declare no
  `:slow_hash` carries no NIF, and one that declares it without the dependency
  refuses to start with `{:missing_optional_dependency, :argon2_elixir}`.
