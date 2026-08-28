### Added

- `encrypt/2` and `encrypt!/2` on every vault module. A call resolves its
  selector through the provider, maps the descriptor to a keyring, composes
  the encryption context, derives the cache partition id, builds the CMM
  stack and the client, and returns `{:ok, ciphertext}` - the complete
  self-describing engine message and nothing else. The engine also reports
  the header, the context and the suite; the vault does not, because the
  message already carries them authenticated and a second stored copy can
  disagree with it.
- The CMM stack order is fixed and not configurable, because it is a security
  property rather than a style choice: `Default` innermost, the caching CMM in
  the middle when caching is configured, and `RequiredEncryptionContext`
  outermost. Required on the outside runs the presence check before the cache
  is consulted; caching on the outside would skip it for exactly the messages
  that are read often. When the required set is empty the outer wrap is
  skipped.
- Selector typing is enforced before the provider is consulted: a `:tenant`
  vault refuses `:default` and a `:single` vault refuses a string, both as
  `{:invalid_selector, selector}`. An absent `:key` means `:default`, so a
  single-key vault carries no per-call ceremony and a tenant vault refuses a
  call that names no tenant.
- On a `:tenant` vault the encryption context's `tenant_ref` is derived by the
  vault from the `:key` selector, under the configured reference subkey. A
  caller supplying `tenant_ref` or `tenant_id` is refused, so the routing
  argument and the context pair are incapable of disagreeing.
- The cache partition id is derived from the same selector that chose the key,
  so one merchant's data key cannot be served from another merchant's cache
  lookup.
- A provider's `init/1` now runs once, at vault start, and what it returns is
  frozen as the configuration's `:provider_state` - the state every later
  resolution callback is handed. A provider that cannot configure itself is a
  vault that does not start, rather than a vault that fails at its first
  encrypt.

### Notes

- `:algorithm_suite`, `:commitment_policy`, `:frame_length` and
  `:max_encrypted_data_keys` are deliberately not per-call options. All four
  are configuration, and one place to review them is the point.
