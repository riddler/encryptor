### Added

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
