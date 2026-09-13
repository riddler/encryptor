### Changed

- A vault's `:slow_hash` parameters are declared as a keyword list only: the
  map shape, which no record names, is now refused at start with
  `{:invalid_config, :slow_hash, :shape}`, so a host handing a frozen set from
  one vault to another passes it through `Map.to_list/1`.
- `Encryptor.Kdf.slow_hash/3` documents that the 32_768 KiB memory floor is a
  start-time bound on a declared set which the primitive does not re-check,
  and lists what it does check.
