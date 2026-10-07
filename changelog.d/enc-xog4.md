### Fixed

- `rekey/2` and `Encryptor.Envelope.rewrap/2` now work on the default signing suite `0x0578`: the re-encrypt leaves out the engine's own verification-key pair, which the engine refused from a caller, and the engine writes a fresh one.
