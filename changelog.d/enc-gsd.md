### Added

- `rekey/2` and `rekey!/2` on a generated vault, and `Encryptor.Vault.rekey/3`
  behind them: one message, decrypted with whatever its own encrypted data keys
  resolve to and re-encrypted under the vault's currently resolved materials,
  with its encryption context preserved byte for byte. This is the last entry
  point of the vault surface, and it completes it.
- The encryption context a rekey writes comes from the message's own header,
  not from the caller, because a rekey caller holds a ciphertext and not a row.
  `:encryption_context` is therefore not an option: passing one is
  `{:reserved_context_key, key}`, since the only correct value is the one
  already in the message and accepting a second copy is how a rotation job
  rewrites what a million rows are bound to while believing it is rotating
  keys.
- A rekey is refused when the message's stored context disagrees with the one
  the vault composes from the call's own arguments, through the same comparison
  a read goes through. On a per-tenant vault that is what stops a rekey moving
  a message between tenants.
- A rekey touches no storage and is a pure binary-to-binary function. Its
  canonical caller in this family is the envelope's rewrap; it is available to
  a host that stores ciphertext outside Ecto and wants a key rotation rewritten
  without a migrator, and it is deliberately **not** the downstream migrator's
  tool, which has to stay uniform across a rotation and a change of format,
  algorithm or context.
- Every failure of a rekey is stamped `operation: :rekey`, on both halves: what
  failed is the operation the caller asked for, not the half of it the failure
  landed in. Message-dependent failures collapse to `:decrypt_failed` exactly
  as a read's do.

### Notes

- This behaviour depends on the engine storing the full encryption context in
  the message header, which is a deviation from the AWS Encryption SDK
  specification. If the engine is ever corrected to strip required keys from
  the header, `rekey/2` will need the context as an argument, supplied by
  whatever owns the row. `Encryptor.Vault.Rekey` is the one place that
  assumption is made.
