### Fixed

- `Encryptor.Vault.derive/3` returns `{:error, %Encryptor.Error{}}` where it used to raise an `ArgumentError`: an out-of-range `:length` (`{:invalid_config, :length, :out_of_range}`), an empty purpose (`{:invalid_config, :purpose, :empty}`) and a purpose holding `"/"` (`{:invalid_config, :purpose, :contains_separator}`).
