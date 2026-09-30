### Fixed

- A write after a new key version is minted wraps its data key under that
  version at once, even when the vault's materials cache is warm. The write
  side's cache partition id now carries the resolved key as well as the
  vault and the selector, so the entry from before the mint is no longer
  found; `rekey/2`'s write half gets the same fix. Upgrading changes every
  write-side partition id once: the first write per context after the deploy
  is a cache miss (on the KMS path, one KMS call). Messages, stored rows and
  the read side are unchanged.
