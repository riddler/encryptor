### Added

- `Encryptor.Provider.Kms` answers a selector with an AWS KMS key, so a vault
  can encrypt under keys AWS holds and never exports: the data key is
  generated inside KMS, nothing is stored, and no call site changes.
- `Encryptor.Key.Kms` descriptors build the engine's `AwsKms` and `AwsKmsMrk`
  keyrings, which is the mapping that was reserved when the descriptor set was
  closed; a candidate list may hold both descriptor shapes at once, so a
  tenant moves from raw keys to KMS as an ordinary rotation window.
- `Encryptor.Key.Kms` carries the KMS client its keyring is built from, on a
  new `:client` field that defaults to `nil` and is redacted from `inspect/2`.
  A descriptor that reaches the vault without one is
  `{:invalid_key_descriptor, {:missing_client, Encryptor.Key.Kms}}`.

### Changed

- Dropping a key from what a provider answers is a crypto-shred only on the
  raw-material path. On the KMS path the key material is in AWS, so the shred
  is `ScheduleKeyDeletion` on the key and is not complete until the pending
  window elapses; `Encryptor.Provider.Kms` carries the per-shape table.
- The shared conformance suite reads a candidate's version identity per shape
  - the name on a raw-AES descriptor, the key ARN on a KMS one - and expects
  the keyring that shape maps to. Every raw-AES provider passes it unchanged;
  `assert_distinct_names/1` keeps its name.
- A KMS-backed vault has no two-level envelope, so `derive/3` refuses its
  descriptors with `{:invalid_key_descriptor, :not_derivable}` and
  `provision/2` answers `{:not_provisionable, Encryptor.Provider.Kms}`.
- The AWS client stack stays the host's: `Encryptor.Provider.Kms` declares no
  AWS dependency, and a vault configured with `:region` but without
  `:ex_aws_kms` refuses to start with
  `{:missing_optional_dependency, :ex_aws_kms}`.
