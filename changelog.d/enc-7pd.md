### Added

- `Encryptor.Vault.Config` resolves a vault's configuration once, at start,
  through the five-layer precedence chain - package defaults, `use` options,
  application environment, `start_link/1` options, the optional `init/1`
  callback - and freezes it in `:persistent_term`, so per-call reads are
  lock-free.
- Key material passed to `use Encryptor.Vault` is a compile-time error rather
  than a warning, including a secret nested in a `:provider` option: a secret
  in `use` options is a secret compiled into a `.beam` file.
- Configuration that would weaken the vault is refused at start, not at the
  first encrypt: the legacy commitment policy, a `nil` encrypted-data-key
  limit, an unsupported algorithm suite, a cache with no `max_age`, a
  misspelled cache bound, and a static encryption context that is unbounded
  or uses a reserved key.
- A tenant vault requires its reference subkey and, once a deployment has
  pinned a known-answer value, refuses to start unless the subkey reproduces
  it - the misconfiguration that would otherwise be discovered as fleet-wide,
  corruption-shaped decrypt failures.
- A vault's context profile (`:single` or `:tenant`) is readable at runtime
  through `Encryptor.Vault.Config.fetch/1`. It is start-time state, not
  compile-time: `encryptor_ecto` reads it from the running vault.
