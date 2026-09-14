### Fixed

- `Encryptor.Kdf.slow_hash/3` names the offending key when a complete
  parameter set carries a zero or negative `:memory_kib`, `:iterations` or
  `:parallelism`, instead of reporting the completeness constraint the set
  already satisfies.
