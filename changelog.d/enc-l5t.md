### Changed

- A vault's `:slow_hash` parameters are declared as a keyword list only: the
  map shape, which no record names, is now refused at start with
  `{:invalid_config, :slow_hash, :shape}`.
- `Encryptor.Kdf.slow_hash/3` documents that the 32_768 KiB memory floor and
  the positive iteration and lane counts are start-time bounds on a declared
  set, which the primitive does not re-check.
