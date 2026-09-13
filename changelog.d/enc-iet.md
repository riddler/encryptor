### Added

- Telemetry: `encrypt/2`, `decrypt/2` and `rekey/2` each emit a
  `[:encryptor, <operation>, :start | :stop]` span pair, with a nested
  `[:encryptor, :provider, :start | :stop]` span around key resolution
  carrying the provider module, the callback, the outcome, the failure's
  `reason_tag` and the candidate count. A failure's stop half carries the
  tag alone, never the reason term and never the engine's.
- Vaults take `telemetry_tenant_ref: true` (default `false`, refused on a
  `:single` vault) to add `tenant_ref` - the keyed 22-character reference,
  never the partition id - to those span halves. It is a disclosure
  decision: anyone holding the vault's reference subkey can re-identify it.
  See `Encryptor.Telemetry`.
