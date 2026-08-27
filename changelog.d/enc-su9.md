### Added

- `Encryptor.Error` is the single error struct every entry point returns and
  every bang variant raises, carrying a stable `:reason` you can match on
  alongside the underlying `:engine` term for logs.
- The reason vocabulary is one closed enumeration, so a `case` over failures
  has a fixed set to match and is extended only by a new decision record.
- Decrypt-side failures that depend on the message all collapse to
  `:decrypt_failed`, so no caller can use the error as a decryption oracle.
