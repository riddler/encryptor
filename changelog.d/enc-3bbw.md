### Changed

- `rekey/2` takes, as `:encryption_context`, the vault's required pairs that the message's header does not store and the vault does not compose itself; any other key is still `{:reserved_context_key, key}`. A message written with required context on `aws_encryption_sdk` 1.1 rekeys only with those pairs from whatever owns the row (without them, `{:missing_required_context_keys, keys}`); a message written earlier rekeys with no option, as before.
- `decrypt/2` hands the engine only the pairs the message's header stores or the vault requires, so a key a reader passes that the message never carried is still ignored on the new engine.
- `Encryptor.Envelope.unwrap/2` and `rewrap/2` work through a root vault that requires the envelope's binding keys on the new engine, which no longer stores them: the binding is checked against the engine's unwrap instead of the header.
- `rekey/2` with a non-empty `:encryption_context` on a ciphertext whose header cannot be parsed now answers `:decrypt_failed`, where it answered `{:reserved_context_key, key}`: the header is parsed to check the option.
- `rekey/2` composes the vault's context before it consults the provider, so a context the vault cannot compose is reported ahead of a provider failure.
- `Encryptor.Envelope.unwrap/2` and `rewrap/2` answer `{:vault_not_started, vault}` for a root vault that is not running before they read the wrapping's header, so a malformed or foreign wrapping under a stopped root vault reports the stopped vault rather than `:decrypt_failed`.
