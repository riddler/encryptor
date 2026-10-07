# Wycheproof test vectors

These files are published test vectors from Project Wycheproof, copied byte
for byte and never edited here. The test suite runs them through this
package's code; they are fixtures only and are not part of the Hex package
(`package()`'s `files:` list in `mix.exs` ships no `test/` path).

## Source

- Repository: <https://github.com/C2SP/wycheproof>
- Pinned commit: `12fd3aaf33eb5fa1f52e026912ee00c054f9d984`
- Directory: `testvectors_v1/`
- Licence: Apache License 2.0, kept beside the files as `LICENSE`, copied
  from the repository root at the same commit.

Each file was fetched from
`https://raw.githubusercontent.com/C2SP/wycheproof/12fd3aaf33eb5fa1f52e026912ee00c054f9d984/testvectors_v1/<file>`
(and `LICENSE` from the same commit without the `testvectors_v1/` segment).

## Files and their SHA-256

| File | SHA-256 |
|---|---|
| `hkdf_sha256_test.json` | `bb2b462a38b251cb52a2aede706d6d4b62b26864f4e80c95497507ddb07c5f1e` |
| `hkdf_sha384_test.json` | `69ff6ea3657bb9c1b8cdffbbb4e7832353d08fd15c0d9997b03f7a6b180e3678` |
| `hkdf_sha512_test.json` | `bb9a21f4e86041caf5d7792b030349f8ff289087f195b2fbc0fc0afc39deca6f` |
| `aes_gcm_test.json` | `985e5ecc172e181eaf49e89508b9470dcf478002eb7e8559c707eb42dc97dfe7` |
| `LICENSE` | `58d1e17ffe5109a7ae296caafcadfdbe6a7d176f0bc4ab01e12a689b0499d8bd` |

Check them from the repository root with:

```bash
cd test/fixtures/wycheproof && shasum -a 256 -c <<'SUMS'
bb2b462a38b251cb52a2aede706d6d4b62b26864f4e80c95497507ddb07c5f1e  hkdf_sha256_test.json
69ff6ea3657bb9c1b8cdffbbb4e7832353d08fd15c0d9997b03f7a6b180e3678  hkdf_sha384_test.json
bb9a21f4e86041caf5d7792b030349f8ff289087f195b2fbc0fc0afc39deca6f  hkdf_sha512_test.json
985e5ecc172e181eaf49e89508b9470dcf478002eb7e8559c707eb42dc97dfe7  aes_gcm_test.json
58d1e17ffe5109a7ae296caafcadfdbe6a7d176f0bc4ab01e12a689b0499d8bd  LICENSE
SUMS
```

## Which tests read them

- `hkdf_sha256_test.json`: `test/encryptor/vectors/wycheproof_hkdf_sha256_test.exs`
  runs every case through `Encryptor.Kdf.extract/2` and `Encryptor.Kdf.expand/3`.
  The case counts are written in that test literally.
- `aes_gcm_test.json`, `hkdf_sha384_test.json` and `hkdf_sha512_test.json`:
  `test/encryptor/vectors/wycheproof_engine_test.exs` runs every AES-GCM
  case through the engine's `AwsEncryptionSdk.Crypto.AesGcm.encrypt/5` and
  `decrypt/6` (a case whose IV is not 96 bits is asserted refused by the
  wrapper's guard), and every HKDF case through the engine's
  `AwsEncryptionSdk.Crypto.HKDF.extract/3` and `expand/4`. The case counts
  are written in that test literally.

`Encryptor.Wycheproof` in `test/support/wycheproof.ex` decodes a file and
lists its cases without filtering any.

## Refreshing to a newer commit

1. Pick the new commit on `C2SP/wycheproof` and read the upstream changes to
   `testvectors_v1/` for these four files and to `LICENSE`.
2. Fetch each file from that commit, using the URL shape above with the new
   commit, over the existing copies. Do not reformat or edit them.
3. Compute `shasum -a 256` of each file and replace the pinned commit and
   every value in the table and in the check block above.
4. Update the literals in every test that reads a file whose cases
   changed: the case counts, from the new file's `numberOfTests` and its
   `result` values, and any case ids, flags or sizes a test pins.
5. Run the full gate (`mix quality`). A case that now fails is a finding to
   report and fix, never a case to filter out or skip.
