### Added

- `Encryptor.Provider` is the key-provider behaviour: `encryption_key/2` and
  `decryption_keys/2` required, `init/1` and `child_spec/1` optional. A
  provider answers which key, and the vault alone turns the answer into an
  engine keyring. `Encryptor.Provider.init/2` runs a provider's `init/1`, or
  takes the option list as state for a provider that omits it.
- `Encryptor.Provider.Static` holds one key, or a candidate list of them
  newest first, in configuration. With `keys:`, `encryption_key/2` answers the
  head and `decryption_keys/2` answers the whole list, which is what makes a
  staged root rotation readable mid-pass. Passing both `key:` and `keys:` is
  `{:invalid_config, :provider, :key_and_keys}` at start, and so are two
  entries sharing a name and material that is not 16, 24, or 32 bytes.
- `Encryptor.Provider.Function` wraps a host-supplied pair of closures, so a
  per-tenant vault is reachable without writing a behaviour implementation. It
  validates the answer on the way back: a non-descriptor, an empty candidate
  list, or a refusal outside the closed reason vocabulary becomes
  `{:invalid_key_descriptor, detail}` naming the constraint rather than the
  value.
- `Encryptor.Provider.Conformance` is the shared test suite every adapter is
  held to, in `lib/` so adapters in other packages can run it. It checks that
  the encryption key is the head of the candidate list, that candidate names
  are distinct, that resolution is stable, and that one candidate builds a
  bare `RawAes` while more build a `Multi` with no generator.
