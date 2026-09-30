### **Breaking**

- **Breaking:** a vault refuses to start on an option it does not read, where
  it used to ignore it. The refusal is `{:invalid_config, layer,
  {:unknown_options, keys}}`, naming the layer (`:use`, `:app_env`,
  `:start_link` or `:init`) and the sorted unknown keys. Rename or remove each
  listed option - the pre-rename `:telemetry_tenant_ref` is
  `:telemetry_scope_ref` - and set `:otp_app` only in `use Encryptor.Vault`.
