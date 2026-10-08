### Changed

- `rekey/2` takes, as `:encryption_context`, the vault's required pairs that the message's header does not store and the vault does not compose itself; any other key is still `{:reserved_context_key, key}`. A message written with required context on `aws_encryption_sdk` 1.1 rekeys only with those pairs from whatever owns the row (without them, `{:missing_required_context_keys, keys}`); a message written earlier rekeys with no option, as before.
- `decrypt/2` hands the engine only the pairs the message's header stores or the vault requires, so a key a reader passes that the message never carried is still ignored on the new engine.
- `Encryptor.Envelope.unwrap/2` and `rewrap/2` work through a root vault that requires the envelope's binding keys on the new engine, which no longer stores them: the binding is checked against the engine's unwrap instead of the header.
