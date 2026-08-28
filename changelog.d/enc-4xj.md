### Added

- `decrypt/2` and `decrypt!/2` on every vault module. A call resolves its
  selector through the provider's `decryption_keys/2` callback, builds one
  keyring from the whole candidate list - a plain raw-AES keyring for a single
  candidate, a multi-keyring walked in order for more, which is what lets a
  message written before a rotation still open - composes the reproduced
  encryption context, and returns `{:ok, plaintext}` and nothing else. The
  engine also reports the header, the verified context and the suite; a caller
  that wants the context reads `Encryptor.Message.describe/1`, which is honest
  about being an unverified claim.
- The vault compares the reproduced encryption context against the message's
  own **itself**, above the engine, before any decryption is attempted. For
  every key present in both, the values must agree; a disagreement is
  `:decrypt_failed` and the engine is never called. This is not a duplicate of
  the engine's check. The engine's lives below its materials cache, and the
  decryption cache id is derived from the message's stored context rather than
  the reader's claim, so a warm cache serves a legitimate first read's
  materials to a reader claiming a different tenant, table or column. Comparing
  above the cache is what makes anti-substitution a property of this package
  rather than one inherited from the engine: it holds on the first read of a
  row and on the thousandth alike, with caching on or off.
- The reader's cryptographic materials manager stack is the writer's, built by
  the same code. The engine mixes the required subset of the context into the
  header's additional authenticated data, so a reader that does not know which
  keys the writer required fails header authentication rather than a context
  comparison.

### Changed

- The selector profile check, the provider call and its failure vocabulary,
  and the four-layer context composition are now shared between the encrypt
  and decrypt paths rather than spelled once per path. A `:tenant` vault that
  refused `:default` on the way in and accepted it on the way out would accept
  a read no write could have produced, and a caller-supplied tenant pair
  refused at encrypt and honoured at decrypt would reopen the second place to
  claim a tenant that routing through `:key` exists to close.
