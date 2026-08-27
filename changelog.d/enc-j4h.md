### Added

- `Encryptor.Kdf` derives labelled subkeys with HKDF-SHA256, using `:crypto`
  and nothing else. `derive_subkey/3` is the labelled derivation the key
  hierarchy is built from; `expand/3` is RFC 5869 HKDF-Expand underneath it,
  checked against the RFC's three SHA-256 test vectors.
- `Encryptor.Kdf.label/1` is the one place the `"encryptor/v1/"` label prefix
  is written, so a purpose cannot be spelled into an existing label by hand.
  The label space is reserved: a new purpose always takes a new label and
  never reuses one.
- `expand/3` takes its `info` string verbatim, so a consumer that owns a
  purpose-separated key tree can derive within the label it was given.
