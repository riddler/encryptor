### Fixed

- `Encryptor.Vault.decrypt/3` and `Encryptor.Vault.rekey/3` (and a vault's generated `decrypt/2` and `rekey/2`) now return `{:error, %Encryptor.Error{reason: :decrypt_failed}}` for a message followed by trailing bytes, or any other engine answer outside `{:ok, _}` and `{:error, _}`, instead of raising a `CaseClauseError` whose text rendered the parsed message; the error carries `:unexpected_engine_result` in `:engine` rather than the engine's term.
