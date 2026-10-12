### Fixed

- The Cloud KMS provider's `provision` now answers a store's invalid key descriptor as the read path does, passing the store's own refusal through instead of `{:key_unavailable, selector}`.
