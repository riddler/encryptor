### Added

- `Encryptor.Message.describe/1` reads what a message says about itself - the
  stored encryption context, the algorithm suite id, whether the suite commits,
  and the `{provider_id, key_name}` pair of each encrypted data key - with no
  key material, no vault, and no provider.
- `Encryptor.Message.Info` is the struct it returns. Every field is read
  without verifying the header authentication tag, so the value is an
  unverified claim: it is for support tooling and migrations, and never an
  authorization input.
- `Encryptor.Message` is the single place this package reads the engine's
  message layout, so the decrypt-path context check, `rekey/2`, and a rotation
  census all share one parse.
