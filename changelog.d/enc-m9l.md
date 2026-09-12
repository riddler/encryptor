### Added

- `Encryptor.Provider.GcpKms` wraps a tenant's master key through GCP Cloud
  KMS, so a host can run per-tenant keys against GCP with no engine change and
  byte-compatible application ciphertext.
- `c:Encryptor.Provider.provision/2`, an optional callback, and
  `MyApp.Vault.provision/1`, which creates a selector's key material through
  the vault's provider and returns the row a store needs.
