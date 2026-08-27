### Added

- `use Encryptor.Vault, otp_app: :my_app` defines a vault: a supervised module
  that is the host's entire surface. It captures the `:otp_app` and the module
  name and nothing else, and generates `child_spec/1`, `start_link/1`,
  `stop/0`, `config/0` and `started?/0`.
- Starting a vault starts a supervisor whose children are the process that
  owns the frozen configuration, the materials cache when caching is
  configured on, and the key provider when its module exports `child_spec/1`.
  A vault configured with `cache: false` still starts, because a provider may
  need supervision even when the cache does not exist.
- Two vaults never share a cache process. The pair `{otp_app, vault_module}`
  is the whole configuration key, so one vault's bounds never apply to
  another vault's materials.
- Stopping a vault erases its frozen configuration, so a later call answers
  `{:vault_not_started, vault}` rather than reading the configuration of a
  vault that is gone.
- A vault that is not running is a typed error, never an exit raised from
  inside a library: `Encryptor.Vault.ready/2` checks the vault and its
  provider before any operation and returns `{:vault_not_started, vault}` or
  `{:provider_not_started, module}`. Both are checks, not rescues.
- A configuration the vault refuses is an `{:error, %Encryptor.Error{}}` from
  `start_link/1`, resolved before the supervisor process exists, rather than
  a started vault that fails at its first encrypt.
