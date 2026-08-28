defmodule Encryptor.KdfTest do
  use ExUnit.Case, async: true

  alias Encryptor.Kdf

  doctest Encryptor.Kdf

  # RFC 5869 appendix A, the three SHA-256 cases. Each case states the PRK
  # directly, so they exercise HKDF-Expand on its own. The SHA-1 cases (4, 5,
  # 6) are absent rather than skipped: this module is SHA-256 only.
  #
  # The extract half of the same three cases is `@rfc_5869_extract_sha256`
  # below, added with ADR-0003 amendment A.
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

  # The same three cases, on the extract side. Each states the salt and the
  # input key material, and the PRK the `@rfc_5869_sha256` cases above take as
  # given - so the two tables together cover HKDF end to end against the RFC's
  # own numbers rather than against a reimplementation of it (ADR-0003
  # amendment A decision 1).
  #
  # A.1's salt is 13 bytes and A.3's is empty. Both are shorter than the
  # 32-byte deployment guard, which is exactly why that guard lives on
  # `salted_subkey/5` and on the vault configuration rather than on this
  # primitive: a guard here would make these vectors unrunnable.
  @rfc_5869_extract_sha256 [
    %{
      name: "A.1 basic test case with SHA-256",
      ikm: String.duplicate("0B", 22),
      salt: "000102030405060708090A0B0C",
      prk: "077709362C2E32DF0DDC3F0DC47BBA6390B6C73BB50F9C3122EC844AD7C2B3E5"
    },
    %{
      name: "A.2 test with SHA-256 and longer inputs/outputs",
      ikm:
        "000102030405060708090A0B0C0D0E0F" <>
          "101112131415161718191A1B1C1D1E1F" <>
          "202122232425262728292A2B2C2D2E2F" <>
          "303132333435363738393A3B3C3D3E3F" <>
          "404142434445464748494A4B4C4D4E4F",
      salt:
        "606162636465666768696A6B6C6D6E6F" <>
          "707172737475767778797A7B7C7D7E7F" <>
          "808182838485868788898A8B8C8D8E8F" <>
          "909192939495969798999A9B9C9D9E9F" <>
          "A0A1A2A3A4A5A6A7A8A9AAABACADAEAF",
      prk: "06A6B88C5853361A06104C9CEB35B45CEF760014904671014A193F40C15FC244"
    },
    %{
      name: "A.3 test with SHA-256 and zero-length salt/info",
      ikm: String.duplicate("0B", 22),
      salt: "",
      prk: "19EF24A32C717B167F33A91D6F648BDF96596776AFDB6377AC434C1C293CCB04"
    }
  ]

  describe "extract/2 against RFC 5869" do
    # sabotage: swapped the HMAC key and message in extract/2, so the input
    # key material became the key - all three vectors go red, and A.2 is the
    # one that catches it even when both arguments happen to be 32 bytes.
    for vector <- @rfc_5869_extract_sha256 do
      test "matches #{vector.name}" do
        vector = unquote(Macro.escape(vector))

        assert Base.decode16!(vector.prk) ==
                 Kdf.extract(Base.decode16!(vector.salt), Base.decode16!(vector.ikm))
      end
    end

    # sabotage: returned the first 16 bytes of the MAC - red, and it is worth
    # its own test because a short PRK would still satisfy expand/3's guard
    # nowhere and fail confusingly one call later.
    test "always returns HashLen bytes" do
      for salt <- ["", :binary.copy(<<0x5A>>, 4), :binary.copy(<<0x5A>>, 1000)] do
        assert byte_size(Kdf.extract(salt, "input key material")) == 32
      end
    end
  end

  describe "salted_subkey/5" do
    setup do
      %{material: :binary.copy(<<0x0B>>, 32), salt: :binary.copy(<<0x5A>>, 32)}
    end

    # sabotage: dropped the extract step and expanded directly from the
    # material - red, because the salt then makes no difference.
    test "the salt separates two deployments holding the same key", context do
      %{material: material} = context

      a = Kdf.salted_subkey(material, :binary.copy(<<0x5A>>, 32), "blind-index", "orders", 32)
      b = Kdf.salted_subkey(material, :binary.copy(<<0x5B>>, 32), "blind-index", "orders", 32)

      assert a != b
    end

    # sabotage: concatenated the label and the info into one expansion - red,
    # because purpose "a"/info "b" then collides with purpose "ab"/info "".
    test "the label and the caller info cannot collide", context do
      %{material: material, salt: salt} = context

      assert Kdf.salted_subkey(material, salt, "a", "b", 32) !=
               Kdf.salted_subkey(material, salt, "ab", "", 32)
    end

    # sabotage: returned the intermediate purpose key when info was empty -
    # red. Amendment A decision 4: the middle value never leaves the package.
    test "an empty info still runs the final expansion", context do
      %{material: material, salt: salt} = context

      purpose_key = Kdf.expand(Kdf.extract(salt, material), "encryptor/v1/blind-index", 32)

      assert Kdf.salted_subkey(material, salt, "blind-index", "", 32) != purpose_key
    end

    # sabotage: dropped the salt guard - red.
    test "refuses a salt short enough to be a placeholder", context do
      %{material: material} = context

      assert_raise ArgumentError, "a derivation salt must be at least 32 bytes", fn ->
        Kdf.salted_subkey(material, :binary.copy(<<0x5A>>, 31), "blind-index", "", 32)
      end
    end

    # sabotage: dropped the key-material guard - red.
    test "refuses key material shorter than 32 bytes", context do
      %{salt: salt} = context

      assert_raise ArgumentError,
                   "key material for a labelled derivation must be at least 32 bytes",
                   fn ->
                     Kdf.salted_subkey(:binary.copy(<<0x0B>>, 31), salt, "blind-index", "", 32)
                   end
    end

    # sabotage: made the default length 16 - red.
    test "defaults to a 32-byte output", context do
      %{material: material, salt: salt} = context

      assert byte_size(Kdf.salted_subkey(material, salt, "blind-index", "orders")) == 32
    end

    # The whole composition against an implementation that is not this one.
    # RFC 5869's own vectors cover extract and expand separately, and the
    # tests above check that this function is consistent with those two -
    # which would stay true if the three steps were composed wrongly. These
    # two constants come from OpenSSL 3.6.3:
    #
    #   IKM=0x0b*32  SALT=0x5a*32
    #   openssl kdf -keylen 32 -kdfopt digest:SHA256 \
    #     -kdfopt mode:EXTRACT_AND_EXPAND -kdfopt hexkey:$IKM \
    #     -kdfopt hexsalt:$SALT -kdfopt hexinfo:<"encryptor/v1/blind-index"> HKDF
    #   openssl kdf -keylen 32 -kdfopt digest:SHA256 \
    #     -kdfopt mode:EXPAND_ONLY -kdfopt hexkey:<the above> \
    #     -kdfopt hexinfo:<"orders.email"> HKDF
    #
    # sabotage: reordered the extract and the first expand - red, which is
    # the class of mistake the self-consistent tests above cannot see.
    test "matches OpenSSL over the whole construction", context do
      %{material: material, salt: salt} = context

      assert Kdf.expand(Kdf.extract(salt, material), "encryptor/v1/blind-index", 32) ==
               Base.decode16!("F6BC17CD8603EA4DDD1880A859413CB6951237E8592A41E142BDBD8E53212653")

      assert Kdf.salted_subkey(material, salt, "blind-index", "orders.email", 32) ==
               Base.decode16!("F265F58A45FF6B43ABCE983036859DEC57B2ECBD9595A90DB9ACE0B47DB4F31F")
    end

    # sabotage: expanded the caller's info under the PRK rather than under the
    # purpose key, which drops the purpose from the derivation - red.
    test "is exactly extract, expand under the label, expand under the info", context do
      %{material: material, salt: salt} = context

      expected =
        salt
        |> Kdf.extract(material)
        |> Kdf.expand("encryptor/v1/blind-index", 32)
        |> Kdf.expand("orders.email", 64)

      assert Kdf.salted_subkey(material, salt, "blind-index", "orders.email", 64) == expected
    end
  end

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
