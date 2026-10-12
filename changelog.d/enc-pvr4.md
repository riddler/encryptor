### Fixed

- A provider's re-mint refusal, `{:key_name_in_use, selector}`, now answers `{:invalid_key_descriptor, :provider_off_contract}` when it comes from `encryption_key/2` or `decryption_keys/2`, where it used to reach the caller as `{:key_name_in_use, selector}`; the term stays in contract from `provision/2` only.
