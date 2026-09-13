### Fixed

- `Encryptor.Kdf.slow_hash/3` refuses a zero or negative `:memory_kib` with
  the documented `ArgumentError` instead of raising `ArithmeticError` out of
  the log-2 conversion.
