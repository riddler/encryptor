### Added

- `Encryptor.Vault.derive/3`, and a generated `derive/2` on every vault
  module: a consumer names a scope and receives derived key bytes, without the
  key material they were derived from ever being exported to it.
  `encryptor_ecto`'s blind index is the first caller. The scope is
  `{ikm_selector, salt, info, length}`: a label purpose plus the vault's own
  selector, the vault's per-deployment salt, and the caller's own info string
  and output length.
- `Encryptor.Kdf.extract/2`, HKDF-Extract with SHA-256 per RFC 5869
  section 2.2, and `Encryptor.Kdf.salted_subkey/5`, the salted construction
  the new vault surface derives through. Both are covered by the RFC's own
  appendix A vectors.
- `:derivation_salt`, a per-deployment vault configuration value of at least
  32 bytes. It is optional at start and required at derivation, so an existing
  vault starts unchanged and only `derive/3` refuses. Like key material it may
  not be passed to `use Encryptor.Vault` - not because it is secret, but
  because a per-deployment value compiled into a `.beam` is shared by every
  deployment built from that artifact.
- `:derive` joins the `Encryptor.Error` operation vocabulary.

### Changed

- `Encryptor.Kdf` is no longer expand-only. `"encryptor/v1/root-wrap"` and
  `"encryptor/v1/tenant-ref"` keep the expand-only construction and the RFC
  5869 section 3.3 argument for it; only the new exported tree is salted.
  Nothing derived through the two unsalted trees changes.

Records: ADR-0003 amendment A, proposed 2026-08-28 and not yet accepted.
