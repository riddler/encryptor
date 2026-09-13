### Added

- Telemetry: the vault emits `[:encryptor, :vault, :started | :stopped |
  :start_refused]` and `[:encryptor, :cache, :recycled]`, and
  `Encryptor.Telemetry.events/0` is the attach list. Metadata is an
  allow-list - no plaintext, key, context value, selector or partition id
  reaches a handler.
