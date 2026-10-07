### **Breaking**

- `Encryptor.Vault.derive/3` and a vault's generated `derive/2` now refuse the purposes `"root-wrap"`, `"scope-ref"` and the retired `"tenant-ref"` with `{:error, %Encryptor.Error{reason: {:invalid_config, :purpose, :reserved}}}`, before the key provider is consulted, as the function's docs already said they would; a caller that passed one of them derives under a purpose of its own instead, which yields different bytes, so an index or token built under a reserved purpose is rebuilt under the new one.
