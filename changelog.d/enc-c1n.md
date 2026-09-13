### Fixed

- `Encryptor.Provider.GcpKms`'s start-time check now names `:goth` when the
  `:goth` option is a `{module, name}` pair whose first element is not a
  module. It previously reported `{:invalid_config, :provider, :http_client}`,
  sending an operator to the option that was correct.
