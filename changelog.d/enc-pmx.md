### Added

- `Encryptor.Vault.suspend/2` and `Encryptor.Vault.reinstate/2` make a
  selector's data unreadable and intact - every entry point answers
  `{:key_unavailable, selector}` while the key store keeps its rows - so
  offboarding a tenant provisionally no longer means running the irreversible
  crypto-shred. The refusal is immediate on a warm cache, node-local, and
  lost when the vault restarts.
