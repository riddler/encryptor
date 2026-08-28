### Added

- A getting-started guide (`guides/getting-started.md`): a single-key vault and
  a per-tenant vault, stood up from nothing. It states where key material is
  allowed to come from (the `init/1` callback, never `use` options and never a
  config file), when to configure the unsigned `0x0478` suite and when to keep
  the signing default, and why `:max_age` is required with no default - it is
  the answer to how long a crypto-shred takes to take effect on a running node.
- The guide requires **two root secrets from day one, holding the same bytes**:
  a pinned reference root that is never rotated, and a wrapping root that
  procedure P1 rotates. A deployment that provisions both at install never has
  to perform P1's copy-the-reference-root step, which is the most
  destructive-looking no-op in the design - generating a fresh value there
  instead of copying changes every tenant reference in the deployment.
- A rotation runbook (`guides/rotation-runbook.md`): the four operator
  procedures - root rotation, tenant key rotation, tenant shred, version retire
  - each with its preconditions, steps, independent verification and rollback,
  plus both blast radius tables. Every step is labelled with whether it is a
  function this package ships or an action on a store it does not own, and
  cache drainage is a step inside each destructive procedure rather than a
  follow-up.
- The runbook carries the two-vocabulary mapping table across `encryptor` and
  `encryptor_ecto`, because the two packages name the three key levels
  differently and an operator reading one runbook against the other's names can
  run a level 2 rotation believing it is a level 1 rotation.
- The runbook states plainly what a crypto-shred does not destroy: **a shred
  destroys plaintext, not attribution**. The tenant pseudonym in every message
  header is permanent, and the holder of the reference subkey can re-identify
  it by guess-and-confirm forever, in every retained backup. Deleting the
  tenant's ciphertext rows is compliance-mandatory wherever tenant attribution
  is itself personal data, and the shred claim must never be stated as full
  erasure.
- Both guides are ExDoc extras, and every code block in them is executed by
  `Encryptor.GuidesTest` against modules transcribed from the printed text.

### Changed

- `README.md` reports the package as built rather than as a scaffold, links
  both guides, and gives the installation form as a SHA-pinned git dependency.
  The reserved `encryptor 0.1.0` on Hex is a name reservation holding no
  implementation and must not be depended on.
