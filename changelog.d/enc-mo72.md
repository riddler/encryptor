### Fixed

- The Cloud KMS provider now refuses a key-store row naming another scope: on `encryption_key` and `decryption_keys`, a row whose `scope_ref` is not the one derived from the selector is answered `{:invalid_key_descriptor, :invalid_row}` before any `Decrypt`, where it used to unwrap under its own binding and hand back the other scope's key.
