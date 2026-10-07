defmodule Encryptor.GcmConstructionTest do
  @moduledoc """
  The AES-GCM IV and tag construction of the messages encryptor writes,
  read from the bytes against NIST SP 800-38D.

  Every AES-GCM call in an encryptor message is the engine's, so these tests
  do not ask the engine what it did: they parse the message encryptor wrote,
  unwrap its data key with the scope key, re-derive the message key with
  HKDF-SHA512 themselves, and check each GCM invocation the wire carries
  with OTP's `:crypto` directly. The header is parsed with
  `AwsEncryptionSdk.Format.Header.deserialize/1`, as `Encryptor.Message`
  parses it; the body and the footer are parsed here by hand. Both
  committing suites run (0x0478, and 0x0578 with its signature footer), each
  with the vault's cache off and on.

  What the bytes show, per message:

    * the scope key wraps the data key under a random IV whose length the
      raw AES provider info records as 12 bytes, with a 128-bit tag
      (SP 800-38D 5.2.1.1 recommends 96-bit IVs; 5.2.1.2 the tag lengths;
      8.2.2 RBG-based construction);
    * a 256-bit message id, which salts the message key's derivation, so
      every message has its own GCM key even when the cache hands two
      messages the same data key;
    * the header tag is GCM over the empty string under the all-zero 96-bit
      IV, used once per message key (8.2.1, deterministic construction);
    * frame i is encrypted under IV i, big-endian in 96 bits, i counting from
      1, so no IV repeats under one message key (8.2.1), and every body tag
      is 16 bytes.

  What the bytes cannot show, and is therefore written down here rather
  than asserted:

    * SP 800-38D 8.3 bounds the RBG-based construction at 2^32 invocations
      per key. Every wrap under one scope key version is such an invocation,
      so a scope key version should wrap fewer than 2^32 data keys; the
      10_000-wrap test below is a smoke check that the wrap IVs are not
      repeating, not a proof of that bound.
    * Frame IVs are deterministic under a per-message key (8.2.1), and 8.3
      lifts its 2^32 invocation limit for 96-bit deterministic IVs, so the
      limit there is the IV space the format gives the sequence number: 2^32 - 1
      frames per message key (the 32-bit sequence number field, with
      0xFFFFFFFF reserved to mark the final frame). The engine at the version
      `mix.lock` pins has no maximum-frames guard; a message reaching that
      many frames (at the 4096-byte default frame length, about 16 TiB) is
      outside what these tests can write.
  """

  use ExUnit.Case, async: false

  alias AwsEncryptionSdk.Format.EncryptionContext
  alias AwsEncryptionSdk.Format.Header
  alias Encryptor.GcmConstructionVaults, as: Fixture
  alias Encryptor.GcmConstructionVaults.Scoped

  @context %{"table" => "records", "column" => "body"}

  # The final-frame marker and the two body AAD content strings of the
  # message format.
  @final_marker 0xFFFFFFFF
  @frame_aad "AWSKMSEncryptionClient Frame"
  @final_frame_aad "AWSKMSEncryptionClient Final Frame"

  # Three full 4096-byte frames and a short final one.
  @plaintext :binary.copy("p", 3 * 4096 + 100)

  @cases (for suite <- [0x0478, 0x0578], cache <- [false, [max_age: 60]] do
            {suite, cache}
          end)

  for {suite, cache} <- @cases do
    label = "suite 0x0#{Integer.to_string(suite, 16)}, cache #{if cache, do: "on", else: "off"}"

    describe label do
      setup do
        start_supervised!(
          Supervisor.child_spec(
            {Scoped, algorithm_suite_id: unquote(suite), cache: unquote(cache)},
            restart: :temporary
          )
        )

        :ok
      end

      # sabotage: made the engine's `RawAes` `@tag_length_bits` 96 - red here.
      test "the raw AES provider info records a 12-byte IV and a 128-bit tag" do
        message = encrypt!(@plaintext)
        %{header: header} = parse(message)
        name = Fixture.key_name()
        name_size = byte_size(name)

        assert [edk] = header.encrypted_data_keys
        assert edk.key_provider_id == "encryptor-scope"

        assert <<^name::binary-size(name_size), 128::32-big, 12::32-big, _iv::binary-size(12)>> =
                 edk.key_provider_info

        # The wrapped key is the 32-byte data key and its 16-byte tag.
        assert byte_size(edk.ciphertext) == 32 + 16
      end

      # sabotage: made the engine's `AesGcm.zero_iv/0` answer
      # `<<1, 0::88>>` - red here, while a round trip through the vault stays
      # green because the engine verifies under the IV it wrote under.
      test "the header tag verifies under the all-zero 96-bit IV" do
        message = encrypt!(@plaintext)
        parsed = parse(message)
        key = message_key(parsed)

        aad = parsed.header_body <> EncryptionContext.serialize(required_context())

        assert :crypto.crypto_one_time_aead(
                 :aes_256_gcm,
                 key,
                 <<0::96>>,
                 <<>>,
                 aad,
                 parsed.header.header_auth_tag,
                 false
               ) == <<>>
      end

      # sabotage: made the engine's `AesGcm.sequence_number_to_iv/1` lay the
      # sequence number out as `<<seq::32, 0::64>>` - red here; the vault
      # still decrypts its own messages. The 16-byte tag is pinned by the
      # shared body parse, which binds each tag at 16 bytes; sabotage: cut
      # each body tag to 12 bytes in the engine's `Encrypt` and `Body`
      # together - red here (and in every test, through that parse).
      test "frame i is encrypted under IV i, with a 16-byte tag" do
        message = encrypt!(@plaintext)
        parsed = parse(message)
        key = message_key(parsed)

        assert Enum.map(parsed.frames, & &1.seq) == [1, 2, 3, 4]
        assert Enum.map(parsed.frames, & &1.final?) == [false, false, false, true]

        plaintext =
          for frame <- parsed.frames, into: <<>> do
            assert frame.iv == <<0::64, frame.seq::32-big>>

            content = if frame.final?, do: @final_frame_aad, else: @frame_aad

            aad =
              parsed.header.message_id <>
                content <> <<frame.seq::32-big, byte_size(frame.ciphertext)::64-big>>

            opened =
              :crypto.crypto_one_time_aead(
                :aes_256_gcm,
                key,
                frame.iv,
                frame.ciphertext,
                aad,
                frame.tag,
                false
              )

            assert is_binary(opened), "frame #{frame.seq} did not open under its wire IV"
            opened
          end

        # Compared by digest, so a failure never prints plaintext.
        assert :crypto.hash(:sha256, plaintext) == :crypto.hash(:sha256, @plaintext)
      end

      # sabotage: made the engine's `Header.generate_message_id(2)` answer
      # 32 zero bytes - red here, every message carrying the same id.
      test "every message carries its own 256-bit message id and its own GCM key" do
        messages = for _ <- 1..4, do: parse(encrypt!("short"))

        # The 32-byte size is pinned by `raw_message_id/1`'s match on the
        # wire layout; the engine's parse must agree with it.
        ids = Enum.map(messages, &raw_message_id/1)
        assert length(Enum.uniq(ids)) == 4
        assert Enum.map(messages, & &1.header.message_id) == ids

        keys = Enum.map(messages, &message_key/1)
        assert length(Enum.uniq(keys)) == 4
      end

      if cache do
        # The cache hands the same data key, wrapped once, to every message
        # inside its bounds; the message id is what keeps each message's GCM
        # key apart. The first assertion pins the cache hit. sabotage: the
        # constant message id above - red here, on the distinct ids.
        test "cached data keys still give every message its own GCM key" do
          [a, b] = for _ <- 1..2, do: parse(encrypt!("short"))

          assert a.header.encrypted_data_keys == b.header.encrypted_data_keys
          assert raw_message_id(a) != raw_message_id(b)
          assert length(Enum.uniq([message_key(a), message_key(b)])) == 2
        end
      end
    end
  end

  describe "wrap IVs under one scope key" do
    setup do
      start_supervised!(
        Supervisor.child_spec({Scoped, algorithm_suite_id: 0x0478, cache: false},
          restart: :temporary
        )
      )

      :ok
    end

    # A smoke check, not a proof: SP 800-38D 8.3's bound for random IVs is
    # 2^32 invocations per key, which no test reaches. sabotage: made the
    # engine's `RawAes` wrap under a constant 12-byte IV - red here.
    test "10_000 wraps show no repeated wrap IV" do
      ivs =
        for _ <- 1..10_000 do
          %{header: %{encrypted_data_keys: [edk]}} = parse(encrypt!(""))
          wrap_iv(edk.key_provider_info)
        end

      # The 12-byte length is pinned by the provider-info test above.
      assert ivs |> Enum.uniq() |> length() == 10_000
    end
  end

  defp encrypt!(plaintext) do
    {:ok, message} =
      Scoped.encrypt(plaintext, key: Fixture.selector(), encryption_context: @context)

    message
  end

  defp required_context do
    Map.put(@context, Encryptor.Context.scope_ref_key(), Fixture.reference())
  end

  # The header as the engine reads it, the header's authenticated bytes as
  # they sit on the wire (everything before the 16-byte header tag; a v2
  # header carries no IV), and the body and footer parsed by hand.
  defp parse(message) do
    {:ok, header, rest} = Header.deserialize(message)
    header_size = byte_size(message) - byte_size(rest)
    <<header_bytes::binary-size(header_size), _rest::binary>> = message
    body_size = header_size - 16
    <<header_body::binary-size(body_size), tag::binary-size(16)>> = header_bytes
    assert tag == header.header_auth_tag

    assert {:ok, frames, footer} = frames(header.frame_length, rest, [])
    assert_footer(header.algorithm_suite.id, footer)

    %{message: message, header: header, header_body: header_body, frames: frames}
  end

  defp frames(
         _frame_length,
         <<@final_marker::32-big, seq::32-big, iv::binary-size(12), size::32-big, rest::binary>>,
         acc
       ) do
    case rest do
      <<ciphertext::binary-size(size), tag::binary-size(16), footer::binary>> ->
        frame = %{seq: seq, iv: iv, ciphertext: ciphertext, tag: tag, final?: true}
        {:ok, Enum.reverse([frame | acc]), footer}

      _short ->
        {:malformed, frame: length(acc) + 1, bytes_left: byte_size(rest)}
    end
  end

  # Anything else must split into frames of the header's frame length, each
  # closed by a 16-byte tag, ahead of a final frame.
  defp frames(frame_length, bytes, acc) do
    case bytes do
      <<seq::32-big, iv::binary-size(12), ciphertext::binary-size(frame_length),
        tag::binary-size(16), rest::binary>> ->
        frame = %{seq: seq, iv: iv, ciphertext: ciphertext, tag: tag, final?: false}
        frames(frame_length, rest, [frame | acc])

      _malformed ->
        {:malformed, frame: length(acc) + 1, bytes_left: byte_size(bytes)}
    end
  end

  # 0x0478 is unsigned and ends at the final frame; 0x0578 carries a
  # length-prefixed signature and nothing after it.
  defp assert_footer(0x0478, footer), do: assert(footer == <<>>)

  defp assert_footer(0x0578, footer) do
    assert <<size::16-big, signature::binary>> = footer
    assert byte_size(signature) == size
  end

  # The message id as it sits on the wire: a v2 header is the version byte,
  # the two-byte suite id, then the id.
  defp raw_message_id(%{message: <<2, _suite::16, id::binary-size(32), _::binary>>}), do: id

  defp wrap_iv(provider_info) do
    trailer = byte_size(provider_info) - 12
    <<_::binary-size(trailer), iv::binary-size(12)>> = provider_info
    iv
  end

  # The message's GCM key, derived here rather than asked of the engine:
  # unwrap the data key with the scope key (AES-256-GCM under the IV the
  # provider info records, the serialized encryption context as AAD), then
  # HKDF-SHA512 with the message id as salt and the suite id followed by
  # "DERIVEKEY" as info. Never rendered: a failure names the step only.
  defp message_key(%{header: header}) do
    [edk] = header.encrypted_data_keys
    size = byte_size(edk.ciphertext) - 16
    <<wrapped::binary-size(size), wrap_tag::binary-size(16)>> = edk.ciphertext
    full_context = Map.merge(header.encryption_context, required_context())

    data_key =
      :crypto.crypto_one_time_aead(
        :aes_256_gcm,
        Fixture.scope_key(),
        wrap_iv(edk.key_provider_info),
        wrapped,
        EncryptionContext.serialize(full_context),
        wrap_tag,
        false
      )

    assert is_binary(data_key), "the data key did not unwrap under the scope key"
    hkdf_sha512(header.message_id, data_key, <<header.algorithm_suite.id::16-big>> <> "DERIVEKEY")
  end

  defp hkdf_sha512(salt, ikm, info) do
    prk = :crypto.mac(:hmac, :sha512, salt, ikm)
    <<key::binary-size(32), _::binary>> = :crypto.mac(:hmac, :sha512, prk, info <> <<1>>)
    key
  end
end
