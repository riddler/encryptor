### Fixed

- `inspect/2` of an `Encryptor.Error` no longer renders the `:engine` term or the detail of `{:invalid_config, key, detail}` and `{:invalid_key_descriptor, detail}`, so a log line, a crash report or a supervisor's report of a vault that failed to start can no longer carry a provider's own failure term, which may hold key material. The error renders as `#Encryptor.Error<...>` with those values shown as `"[redacted]"`; the struct's fields and `Exception.message/1` are unchanged, and code that needs the term still reads `error.engine`.
