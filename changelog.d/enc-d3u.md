### Changed

- **Breaking:** a cache's `:max_messages` now defaults to `10_000` rather than
  `100`. A vault that configures `:cache` without naming `:max_messages` keeps
  a data key for a hundred times as many messages as before; to keep the old
  bound, set `cache: [max_age: ..., max_messages: 100]` explicitly. Nothing
  else moves: `:max_bytes` is still 1 GiB, `:recycle_after` is still
  `20 * max_age`, `:max_age` is still required with no default, and `:cache`
  still defaults to `false`, so a vault that has not opted into the cache is
  unaffected. `:max_messages` is the bound that fires on an active partition,
  and at `100` it asked the provider's keyring for fresh material roughly 858
  times a second on the measured machine; `10_000` amortizes that where a
  cache miss is a network call, and stays five orders of magnitude below the
  engine's own 2^32 ceiling (ADR-0001 amendment A, A1 to A4).
