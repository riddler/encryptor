defmodule Encryptor.KdfTest do
  use ExUnit.Case, async: true

  alias Encryptor.Kdf

  doctest Encryptor.Kdf

  # RFC 5869 appendix A, the three SHA-256 cases. Each case states the PRK
  # directly, so they exercise HKDF-Expand on its own - which is the whole of
  # what this module implements, and why the SHA-1 cases (4, 5, 6) are absent
  # rather than skipped.
  @rfc_5869_sha256 [
    %{
      name: "A.1 basic test case with SHA-256",
      prk: "077709362C2E32DF0DDC3F0DC47BBA6390B6C73BB50F9C3122EC844AD7C2B3E5",
      info: "F0F1F2F3F4F5F6F7F8F9",
      length: 42,
      okm:
        "3CB25F25FAACD57A90434F64D0362F2A" <>
          "2D2D0A90CF1A5A4C5DB02D56ECC4C5BF" <>
          "34007208D5B887185865"
    },
    %{
      name: "A.2 test with SHA-256 and longer inputs/outputs",
      prk: "06A6B88C5853361A06104C9CEB35B45CEF760014904671014A193F40C15FC244",
      info:
        "B0B1B2B3B4B5B6B7B8B9BABBBCBDBEBF" <>
          "C0C1C2C3C4C5C6C7C8C9CACBCCCDCECF" <>
          "D0D1D2D3D4D5D6D7D8D9DADBDCDDDEDF" <>
          "E0E1E2E3E4E5E6E7E8E9EAEBECEDEEEF" <>
          "F0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF",
      length: 82,
      okm:
        "B11E398DC80327A1C8E7F78C596A4934" <>
          "4F012EDA2D4EFAD8A050CC4C19AFA97C" <>
          "59045A99CAC7827271CB41C65E590E09" <>
          "DA3275600C2F09B8367793A9ACA3DB71" <>
          "CC30C58179EC3E87C14C01D5C1F3434F" <>
          "1D87"
    },
    %{
      name: "A.3 test with SHA-256 and zero-length salt/info",
      prk: "19EF24A32C717B167F33A91D6F648BDF96596776AFDB6377AC434C1C293CCB04",
      info: "",
      length: 42,
      okm:
        "8DA4E775A563C18F715F802A063C5A31" <>
          "B8A11F5C5EE1879EC3454E5F3C738D2D" <>
          "9D201395FAA4B61A96C8"
    }
  ]

  describe "expand/3 against RFC 5869" do
    # sabotage: changed the HMAC input from `previous | info | counter` to
    # `info | previous | counter` in okm/3 - all three vectors go red, and the
    # 82-byte one is the one that catches a single-block-only mistake.
    for vector <- @rfc_5869_sha256 do
      test "matches #{vector.name}" do
        vector = unquote(Macro.escape(vector))

        assert Base.decode16!(vector.okm) ==
                 Kdf.expand(
                   Base.decode16!(vector.prk),
                   Base.decode16!(vector.info),
                   vector.length
                 )
      end
    end
  end

  describe "expand/3" do
    setup do
      %{prk: :binary.copy(<<0x0B>>, 32)}
    end

    # sabotage: made the default length 16 instead of @hash_length - red here.
    test "defaults to a 32-byte output", %{prk: prk} do
      assert byte_size(Kdf.expand(prk, "info")) == 32
    end

    # sabotage: dropped the binary_part/3 truncation and returned whole blocks
    # - red for every length that is not a multiple of 32.
    test "returns exactly the requested number of bytes", %{prk: prk} do
      for length <- [1, 31, 32, 33, 64, 100, 8160] do
        assert byte_size(Kdf.expand(prk, "info", length)) == length
      end
    end

    # sabotage: dropped the truncation as above - red, because a 16-byte
    # request would then return the full first block rather than its prefix.
    test "a short output is the prefix of a longer one", %{prk: prk} do
      long = Kdf.expand(prk, "info", 64)

      assert Kdf.expand(prk, "info", 16) == binary_part(long, 0, 16)
    end

    # sabotage: replaced the info argument with a constant in the HMAC input -
    # red, because both derivations would collapse to the same output.
    test "different info strings give different output", %{prk: prk} do
      refute Kdf.expand(prk, "one") == Kdf.expand(prk, "two")
    end

    # sabotage: removed the length check - red, since the 8161-byte call would
    # return a value instead of raising.
    test "refuses to expand past the RFC 5869 bound", %{prk: prk} do
      assert_raise ArgumentError, fn -> Kdf.expand(prk, "info", 8161) end
    end

    # sabotage: removed the byte_size check - red, because the short key would
    # then expand instead of raising.
    test "refuses a pseudorandom key shorter than 32 bytes" do
      error =
        assert_raise ArgumentError, fn ->
          Kdf.expand(:binary.copy(<<0x0B>>, 31), "info")
        end

      # The repo rule: an exception message never carries key-shaped material.
      assert Exception.message(error) == "a pseudorandom key must be at least 32 bytes"
    end

    # sabotage: dropped the `length < 1` half of the check - red, since a
    # zero-length request would return an empty binary rather than raising.
    test "refuses a non-positive length", %{prk: prk} do
      assert_raise ArgumentError, fn -> Kdf.expand(prk, "info", 0) end
    end
  end

  describe "label/1" do
    # sabotage: changed @label_version to "v2" - red on every label below,
    # which is the point: the version is not a value an edit gets to move
    # quietly (ADR-0003 decision 6).
    test "composes ADR-0003 decision 6's two fixed labels" do
      assert Kdf.label("root-wrap") == "encryptor/v1/root-wrap"
      assert Kdf.label("tenant-ref") == "encryptor/v1/tenant-ref"
    end

    # sabotage: same version change - red. ADR-0003 decision 7 names this
    # label as the reserved space for downstream index keys.
    test "composes the reserved blind-index label" do
      assert Kdf.label("blind-index") == "encryptor/v1/blind-index"
    end

    # sabotage: dropped the String.contains?/2 raise - red, because the
    # purpose would compose into "encryptor/v1/v1/root-wrap" instead.
    test "refuses a purpose containing the separator" do
      assert_raise ArgumentError, fn -> Kdf.label("v1/root-wrap") end
    end

    # sabotage: removed the empty check - red, since an empty purpose would
    # compose "encryptor/v1/" rather than failing.
    test "refuses an empty purpose" do
      assert_raise ArgumentError, fn -> Kdf.label("") end
    end
  end

  describe "derive_subkey/3" do
    setup do
      %{material: :crypto.strong_rand_bytes(32)}
    end

    # sabotage: had derive_subkey/3 pass `purpose` to expand/3 instead of
    # `label(purpose)` - red, because the unlabelled expansion differs.
    test "is expand/3 under the composed label", %{material: material} do
      assert Kdf.derive_subkey(material, "root-wrap") ==
               Kdf.expand(material, "encryptor/v1/root-wrap", 32)
    end

    # sabotage: made the default length 16 - red.
    test "defaults to 32 bytes, as both decisions specify", %{material: material} do
      assert byte_size(Kdf.derive_subkey(material, "tenant-ref")) == 32
    end

    # sabotage: collapsed the info argument in okm/3 to a constant - red, and
    # this is the assertion that matters most: decision 6's whole lifecycle
    # split rests on these two subkeys being independent.
    test "separates the two root subkeys of decision 6", %{material: material} do
      refute Kdf.derive_subkey(material, "root-wrap") ==
               Kdf.derive_subkey(material, "tenant-ref")
    end

    # sabotage: seeded okm/3 with :crypto.strong_rand_bytes/1 instead of <<>>
    # - red, because the derivation would stop being reproducible, which is
    # what lets ADR-0003 decision 7 say a subkey is never stored.
    test "is deterministic, so a subkey never needs storing", %{material: material} do
      assert Kdf.derive_subkey(material, "blind-index") ==
               Kdf.derive_subkey(material, "blind-index")
    end

    # sabotage: removed derive_subkey/3's own byte_size check - red on the
    # message assertion, which is why it is there. Without it the test stays
    # green off `expand/3`'s check one call further down, and the sabotage
    # passes unnoticed.
    test "refuses key material shorter than 32 bytes, in its own check" do
      error =
        assert_raise ArgumentError, fn ->
          Kdf.derive_subkey(:binary.copy(<<0x0B>>, 16), "root-wrap")
        end

      assert Exception.message(error) ==
               "key material for a labelled derivation must be at least 32 bytes"
    end

    # The D2 nesting: a downstream tree derives its key under this package's
    # label, then expands again under its own info string. Both steps are
    # HKDF-Expand and the outer label stays this package's.
    #
    # sabotage: had expand/3 prepend the label grammar to `info` rather than
    # using it verbatim - red, because the inner derivation would no longer be
    # expressible with a caller-owned info string.
    test "supports a nested derivation under a reserved label", %{material: material} do
      index_key = Kdf.derive_subkey(material, "blind-index")
      field_key = Kdf.expand(index_key, "downstream/records/notes", 32)

      assert byte_size(field_key) == 32
      refute field_key == index_key
      refute field_key == Kdf.expand(material, "downstream/records/notes", 32)
    end
  end
end
