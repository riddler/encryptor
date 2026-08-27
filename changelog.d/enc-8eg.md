### Added

- `Encryptor.Context` owns the encryption-context vocabulary: the six canonical
  host-facing keys and the two reserved prefixes are readable through
  `canonical_keys/0` and `reserved_prefixes/0`, rather than repeated as string
  literals across packages.
- `Encryptor.Context.compose/3` merges the four context layers - static
  configuration, the caller's per-call map, the vault's own derived keys, and
  the package-reserved pairs - and refuses rather than silently overriding: a
  caller key that disagrees with configuration is a conflict, a caller key that
  names a reserved prefix or a tenant is refused, and a non-string, empty, or
  non-UTF-8 key or value is refused before the engine is called.
- A composed context is bounded per call at 32 pairs and 4 KiB serialized, the
  bound the engine performs no check of at all.
