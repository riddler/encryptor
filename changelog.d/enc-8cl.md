### **Breaking**

- **Breaking:** the key's owner is now called a *scope*, and the Elixir names
  that said *tenant* are renamed with no deprecated aliases. The context
  profile `:tenant` is now `:scoped`; `:tenant` is refused at start as
  `{:invalid_config, :context_profile, :unknown}`, so change
  `context_profile: :tenant` to `context_profile: :scoped` in every vault's
  configuration. Nothing stored changes: every wire spelling, the
  `"tenant_ref"` context key included, keeps its 0.4.1 bytes, so every
  ciphertext and wrapped key 0.4.1 wrote decrypts and unwraps with no
  migration.
- **Breaking:** `Encryptor.Envelope.tenant_ref/2` is now
  `Encryptor.Envelope.scope_ref/2`, and `Encryptor.Context.tenant_ref_key/0`
  is now `Encryptor.Context.scope_ref_key/0`. Both return exactly what the old
  names returned; rename the calls.
- **Breaking:** the `:tenant_ref` field of `%Encryptor.Envelope.WrappedKey{}`
  and the `tenant_ref` key of `Encryptor.Provider.provisioned()` are now
  `:scope_ref`. Rename the field wherever a store builds a `WrappedKey` or a
  provider returns a provisioned row, including the rows a
  `Encryptor.Provider.GcpKms` `:store` function answers, which are otherwise
  refused as `{:invalid_key_descriptor, :invalid_row}`. The value, and any
  column a store keeps it in, is unchanged.
- **Breaking:** the vault option `:telemetry_tenant_ref` is now
  `:telemetry_scope_ref`, and the telemetry metadata key it adds, `:tenant_ref`,
  is now `:scope_ref`. Rename the option and any handler or metric tag that
  reads the key. The error terms follow: `{:invalid_config,
  :telemetry_tenant_ref, _}` is now `{:invalid_config, :telemetry_scope_ref, _}`,
  and `{:invalid_key_descriptor, {:invalid_wrapped_key_field, :tenant_ref}}` is
  now `{:invalid_key_descriptor, {:invalid_wrapped_key_field, :scope_ref}}`.
- **Breaking:** a `:scoped` vault refuses a caller-supplied `"scope_id"`
  context key as `{:reserved_context_key, "scope_id"}`, beside `"tenant_id"`,
  which stays refused. Send neither; `:key` names the scope.
