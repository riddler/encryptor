defmodule Encryptor.Vectors.WycheproofEngineTest do
  @moduledoc """
  Wycheproof's AES-GCM, HKDF-SHA384 and HKDF-SHA512 vectors, run through
  the engine functions every encryptor message reaches them through.

  What this covers and what it does not: encryptor has no AES-GCM code of
  its own. The AES-GCM primitive is OTP's `:crypto` (OpenSSL), and every
  AES-GCM operation an encryptor message involves goes through the engine's
  `AwsEncryptionSdk.Crypto.AesGcm.encrypt/5` and `decrypt/6`, so Wycheproof
  runs against those two functions, at the `aws_encryption_sdk` version
  `mix.lock` pins. encryptor's message path picks its own IVs, which a
  vector file cannot fix, so that path is not covered by this module.

  `test/fixtures/wycheproof/` holds the published files, unedited, at the
  commit its README names. Every AES-GCM case runs. A case with a 96-bit IV
  is encrypted and decrypted through the wrapper: a valid case must
  reproduce its published ciphertext and tag and decrypt to its message, an
  invalid one must fail authentication. A case with any other IV length is
  asserted refused by the wrapper's guard, which admits a 12-byte IV only.
  Every HKDF case runs through the engine's `AwsEncryptionSdk.Crypto.HKDF`
  `extract/3` then `expand/4` (SHA-512 is what the committing suites 0x0478
  and 0x0578 derive the data key with); an invalid case asks for more output
  than the hash allows and must be refused.

  The counts are written here literally, so a truncated, swapped or
  regenerated file fails a count test rather than passing with fewer cases.
  Nothing is filtered out: a case that fails stays failing, and a failure
  names it by `tcId` only, never by its key material.
  """

  use ExUnit.Case, async: true

  alias AwsEncryptionSdk.Crypto.AesGcm
  alias AwsEncryptionSdk.Crypto.HKDF
  alias Encryptor.Wycheproof

  @gcm_file "aes_gcm_test.json"

  # {file, the engine's hash, the file's algorithm, its largest output}
  @hkdf_sets [
    {"hkdf_sha384_test.json", :sha384, "HKDF-SHA-384", 12_240},
    {"hkdf_sha512_test.json", :sha512, "HKDF-SHA-512", 16_320}
  ]

  setup_all do
    gcm = Wycheproof.load!(@gcm_file)
    gcm_cases = Wycheproof.cases(gcm)
    {iv96, other_iv} = Enum.split_with(gcm_cases, &(byte_size(Wycheproof.hex!(&1["iv"])) == 12))

    hkdf =
      Map.new(@hkdf_sets, fn {file, _hash, _algorithm, _max} ->
        vectors = Wycheproof.load!(file)
        {file, %{vectors: vectors, cases: Wycheproof.cases(vectors)}}
      end)

    {:ok, gcm: gcm, gcm_cases: gcm_cases, iv96: iv96, other_iv: other_iv, hkdf: hkdf}
  end

  describe "AES-GCM through AwsEncryptionSdk.Crypto.AesGcm" do
    # sabotage: dropped the last case from the fixture file, whose header
    # still says 316 - red, 315 cases against the literal 316.
    test "the file is the published AES-GCM set: 316 cases, 197 with a 96-bit IV, 119 without",
         %{gcm: gcm, gcm_cases: cases, iv96: iv96, other_iv: other_iv} do
      assert %{"algorithm" => "AES-GCM", "numberOfTests" => 316} = gcm
      assert length(cases) == 316
      assert Enum.count(cases, &(&1["result"] == "valid")) == 229
      assert Enum.count(cases, &(&1["result"] == "invalid")) == 87

      assert length(iv96) == 197
      assert Enum.count(iv96, &(&1["result"] == "valid")) == 116
      assert Enum.count(iv96, &(&1["result"] == "invalid")) == 81

      assert length(other_iv) == 119
      assert Enum.count(other_iv, &(&1["result"] == "valid")) == 113
      assert Enum.count(other_iv, &(&1["result"] == "invalid")) == 6
    end

    # sabotage: flipped the first byte of every case's tag in
    # `Encryptor.Wycheproof.cases/1` - red, every valid case's tag differs.
    test "every valid 96-bit-IV case: encrypt/5 reproduces the published ciphertext and tag",
         %{iv96: iv96} do
      valid = Enum.filter(iv96, &(&1["result"] == "valid"))
      assert length(valid) == 116

      failing =
        for %{"tcId" => id} = vector <- valid,
            encrypt(vector) != {Wycheproof.hex!(vector["ct"]), Wycheproof.hex!(vector["tag"])},
            do: id

      assert failing == []
    end

    # sabotage: flipped the first byte of every case's tag in
    # `Encryptor.Wycheproof.cases/1` - red, no valid case authenticates.
    test "every valid 96-bit-IV case: decrypt/6 returns the published message",
         %{iv96: iv96} do
      valid = Enum.filter(iv96, &(&1["result"] == "valid"))
      assert length(valid) == 116

      failing =
        for %{"tcId" => id} = vector <- valid,
            decrypt(vector) != {:ok, Wycheproof.hex!(vector["msg"])},
            do: id

      assert failing == []
    end

    # sabotage: made the engine's decrypt/6 answer `{:ok, <<>>}` where
    # `:crypto` reports `:error` (in deps/, recompiled for the test env) -
    # red, every modified tag is accepted.
    test "every invalid 96-bit-IV case is a modified tag, and decrypt/6 refuses it",
         %{iv96: iv96} do
      invalid = Enum.filter(iv96, &(&1["result"] == "invalid"))
      assert length(invalid) == 81
      assert Enum.all?(invalid, &(&1["flags"] == ["ModifiedTag"]))

      failing =
        for %{"tcId" => id} = vector <- invalid,
            decrypt(vector) != {:error, :authentication_failed},
            do: id

      assert failing == []
    end

    # sabotage: dropped `byte_size(iv) == @iv_length` from the engine's
    # encrypt/5 guard (in deps/, recompiled for the test env) - red, the
    # cases with an IV `:crypto` accepts are no longer refused.
    test "every case without a 96-bit IV is refused by the wrapper's guard, both ways",
         %{other_iv: other_iv} do
      assert length(other_iv) == 119

      assert other_iv
             |> Enum.filter(&(&1["result"] == "invalid"))
             |> Enum.map(& &1["flags"]) == List.duplicate(["ZeroLengthIv"], 6)

      failing =
        for %{"tcId" => id} = vector <- other_iv,
            not (refused?(fn -> encrypt(vector) end) and refused?(fn -> decrypt(vector) end)),
            do: id

      assert failing == []
    end
  end

  for {file, hash, algorithm, max} <- @hkdf_sets do
    describe "#{algorithm} through AwsEncryptionSdk.Crypto.HKDF" do
      # sabotage: dropped the last case from the fixture file, whose header
      # still says 83 - red, 82 cases against the literal 83.
      test "the file is the published #{algorithm} set, all 83 cases of it", %{hkdf: hkdf} do
        %{vectors: vectors, cases: cases} = hkdf[unquote(file)]

        assert %{"algorithm" => unquote(algorithm), "numberOfTests" => 83} = vectors
        assert length(cases) == 83
        assert Enum.count(cases, &(&1["result"] == "valid")) == 80
        assert Enum.count(cases, &(&1["result"] == "invalid")) == 3
      end

      # sabotage: swapped `:sha512` for `:sha384` in `@hkdf_sets` - red,
      # every valid HKDF-SHA-512 case derives a different output.
      test "every valid #{algorithm} case: expand(extract(salt, ikm), info, size) is the published okm",
           %{hkdf: hkdf} do
        valid = Enum.filter(hkdf[unquote(file)].cases, &(&1["result"] == "valid"))
        assert length(valid) == 80

        failing =
          for %{"tcId" => id} = vector <- valid,
              derive(unquote(hash), vector) != {:ok, Wycheproof.hex!(vector["okm"])},
              do: id

        assert failing == []
      end

      # sabotage: raised the engine's expand/4 limit from `255 * hash_len` to
      # `256 * hash_len` (in deps/, recompiled for the test env) - red, the
      # oversized cases are no longer refused.
      test "every invalid #{algorithm} case asks for #{max + 1} bytes, and expand/4 refuses it",
           %{hkdf: hkdf} do
        invalid = Enum.filter(hkdf[unquote(file)].cases, &(&1["result"] == "invalid"))

        assert Enum.map(invalid, & &1["tcId"]) == [22, 45, 68]
        assert Enum.map(invalid, & &1["flags"]) == List.duplicate(["SizeTooLarge"], 3)
        assert Enum.map(invalid, & &1["size"]) == List.duplicate(unquote(max) + 1, 3)

        for vector <- invalid do
          assert derive(unquote(hash), vector) == {:error, :output_length_exceeded}
        end
      end
    end
  end

  defp encrypt(%{"key" => key, "iv" => iv, "msg" => msg, "aad" => aad}) do
    key = Wycheproof.hex!(key)

    AesGcm.encrypt(
      cipher(key),
      key,
      Wycheproof.hex!(iv),
      Wycheproof.hex!(msg),
      Wycheproof.hex!(aad)
    )
  end

  defp decrypt(%{"key" => key, "iv" => iv, "ct" => ct, "aad" => aad, "tag" => tag}) do
    key = Wycheproof.hex!(key)

    AesGcm.decrypt(
      cipher(key),
      key,
      Wycheproof.hex!(iv),
      Wycheproof.hex!(ct),
      Wycheproof.hex!(aad),
      Wycheproof.hex!(tag)
    )
  end

  defp cipher(key) when byte_size(key) == 16, do: :aes_128_gcm
  defp cipher(key) when byte_size(key) == 24, do: :aes_192_gcm
  defp cipher(key) when byte_size(key) == 32, do: :aes_256_gcm

  # Only the guard's own refusal counts: a FunctionClauseError raised by
  # the wrapper itself. Anything else, or no raise at all, is not refused.
  defp refused?(call) do
    call.()
    false
  rescue
    error in FunctionClauseError -> error.module == AesGcm
    _other -> false
  end

  defp derive(hash, %{"salt" => salt, "ikm" => ikm, "info" => info, "size" => size}) do
    prk = HKDF.extract(hash, Wycheproof.hex!(salt), Wycheproof.hex!(ikm))
    HKDF.expand(hash, prk, Wycheproof.hex!(info), size)
  end
end
