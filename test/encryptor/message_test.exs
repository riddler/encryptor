defmodule Encryptor.MessageTest do
  use ExUnit.Case, async: true

  alias AwsEncryptionSdk.AlgorithmSuite
  alias AwsEncryptionSdk.Client
  alias AwsEncryptionSdk.Format.Header
  alias AwsEncryptionSdk.Keyring.Multi
  alias AwsEncryptionSdk.Keyring.RawAes
  alias AwsEncryptionSdk.Materials.EncryptedDataKey
  alias Encryptor.Message
  alias Encryptor.Message.Info

  doctest Encryptor.Message

  # A committed suite (0x0478) and an uncommitted one (0x0178), named here so
  # the assertions below read as the values ADR-0004 decision 12 promises
  # rather than as `header.algorithm_suite.id`.
  @committed_suite_id 0x0478
  @uncommitted_suite_id 0x0178

  # The card-processing domain. The key names are shaped like ADR-0003
  # decision 5's derived names - a keyed reference, not a tenant slug - so a
  # reader of these tests sees the pseudonym the record actually puts in a
  # header.
  @provider_id "acme-tenant"
  @key_name "t/6Qk2_1xZaR8/v3"
  @context %{
    "tenant_ref" => "6Qk2_1xZaR8",
    "table" => "payments",
    "column" => "card_last_four",
    "app" => "my_app"
  }

  describe "describe/1 on a message this package could have written" do
    # sabotage: returned `header.encrypted_data_keys` from info/1 unmapped -
    # the encrypted_data_keys assertion goes red on the raw
    # %EncryptedDataKey{} struct, which is the shape ADR-0004 decision 12 says
    # must not escape (it carries the wrapped key).
    test "reports the context, the suite, commitment, and the EDK pair" do
      {:ok, info} = Message.describe(committed_message())

      assert %Info{
               encryption_context: @context,
               algorithm_suite_id: @committed_suite_id,
               committed?: true,
               encrypted_data_keys: [%{provider_id: @provider_id, key_name: @key_name}]
             } = info
    end

    # sabotage: hard-coded `committed?: true` in info/1 - this test goes red
    # while the committed one above still passes, which is the pair that makes
    # the field mean something.
    test "reports an uncommitted legacy suite as uncommitted" do
      {:ok, info} = Message.describe(uncommitted_message())

      assert %Info{algorithm_suite_id: @uncommitted_suite_id, committed?: false} = info
    end

    # sabotage: dropped the `Enum.map` in info/1 so only the first EDK is
    # carried - the two-element match goes red. A rotation census reads every
    # EDK, not the first one.
    test "reports every encrypted data key, in header order" do
      {:ok, info} = Message.describe(two_keyring_message())

      assert %Info{
               encrypted_data_keys: [
                 %{provider_id: @provider_id, key_name: @key_name},
                 %{provider_id: @provider_id, key_name: "t/6Qk2_1xZaR8/v2"}
               ]
             } = info
    end

    # sabotage: returned the whole `key_provider_info` from key_name/1 - the
    # key name grows the engine's 20-byte raw-AES trailer and every key_name
    # assertion in this file goes red.
    test "strips the raw-AES provider info trailer from the key name" do
      {:ok, info} = Message.describe(committed_message())

      [%{key_name: key_name}] = info.encrypted_data_keys

      assert key_name == @key_name
      assert String.valid?(key_name)
    end

    # sabotage: made key_name/1 remove the trailing 20 bytes whenever the
    # provider info is long enough - the ARN comes back truncated and this
    # goes red. A KMS provider writes the key ARN with no trailer at all, and
    # truncating it would silently rename every key in a census of a
    # KMS-backed vault.
    test "returns a foreign provider's key name whole when there is no trailer" do
      arn = "arn:aws:kms:us-east-1:111122223333:key/6a2b-not-a-real-key"

      {:ok, info} =
        Message.describe(
          foreign_message([
            EncryptedDataKey.new("aws-kms", arn, <<1, 2, 3>>),
            EncryptedDataKey.new("acme-hsm", "slot-4", <<4, 5, 6>>)
          ])
        )

      assert info.encrypted_data_keys == [
               %{provider_id: "aws-kms", key_name: arn},
               %{provider_id: "acme-hsm", key_name: "slot-4"}
             ]
    end

    # sabotage: added `:message_id` to the struct and populated it from the
    # header - this goes red. The struct's field set is the disclosure
    # argument, so it is asserted rather than left to the moduledoc.
    test "carries exactly the four fields the record fixes" do
      {:ok, info} = Message.describe(committed_message())

      assert info |> Map.from_struct() |> Map.keys() |> Enum.sort() ==
               [:algorithm_suite_id, :committed?, :encrypted_data_keys, :encryption_context]
    end

    # sabotage: made describe/1 require the body by matching `{:ok, header,
    # <<>>}` - this goes red. Describing a corrupted row is the support case
    # the function exists for.
    test "describes a message whose body was truncated away" do
      message = committed_message()
      header_only = binary_part(message, 0, byte_size(message) - 32)

      assert {:ok, %Info{encryption_context: @context}} = Message.describe(header_only)
    end

    # sabotage: replaced `header.encryption_context` with `%{}` - this goes
    # red. An empty context is a legal message, so the empty case is asserted
    # from a message that really has one.
    test "reports an empty context as empty" do
      assert {:ok, %Info{encryption_context: %{}}} = Message.describe(message(context: %{}))
    end
  end

  describe "describe/1 on bytes that are not a message" do
    # sabotage: returned the engine's `{:error, term}` unwrapped - the
    # %Encryptor.Error{} match goes red. Every non-bang entry point in this
    # package returns one error shape.
    test "returns the package's error struct, collapsed and unattributed" do
      assert {:error, error} = Message.describe(<<0x03, 0x00, 0x00>>)

      assert %Encryptor.Error{
               reason: :decrypt_failed,
               vault: nil,
               operation: nil,
               engine: {:unsupported_version, 3}
             } = error
    end

    # sabotage: dropped the `:engine` field from unreadable/1 - this goes red.
    # The operator's half of the split is the only place the detail survives.
    test "carries the engine's term unchanged for an operator" do
      assert {:error, %Encryptor.Error{engine: :incomplete_header}} = Message.describe(<<>>)
    end

    # sabotage: rendered `:engine` in Encryptor.Error.message/1 - this goes
    # red. A header this package cannot parse is a header it also cannot
    # prove holds no key-shaped bytes, so the engine term stays out of the
    # rendered string.
    test "renders a message that names no bytes from the input" do
      {:error, error} = Message.describe(<<0x01, 0x81, 0x00>>)

      assert Exception.message(error) == "decryption failed"
    end
  end

  # A header assembled by hand rather than encrypted, because no keyring in
  # this package's dependency tree writes a provider info without the raw-AES
  # trailer except the KMS ones, and reaching those would pull the AWS stack
  # into this suite. The header is serialized by the engine, so what
  # `describe/1` reads is a real message header; only the EDKs are fictional,
  # and their wrapped bytes are never looked at.
  defp foreign_message(edks) do
    header = %Header{
      version: 2,
      algorithm_suite: AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key(),
      message_id: :binary.copy(<<0>>, 32),
      encryption_context: %{"table" => "payments"},
      encrypted_data_keys: edks,
      content_type: :framed,
      frame_length: 4096,
      algorithm_suite_data: :binary.copy(<<0>>, 32),
      header_auth_tag: :binary.copy(<<0>>, 16)
    }

    {:ok, bytes} = Header.serialize(header)

    bytes
  end

  # A tenant vault's message: one raw-AES keyring, a committed suite, the
  # canonical per-column context.
  defp committed_message, do: message([])

  defp uncommitted_message do
    message(
      commitment_policy: :forbid_encrypt_allow_decrypt,
      algorithm_suite: AlgorithmSuite.aes_256_gcm_iv12_tag16_hkdf_sha256()
    )
  end

  # Two key versions on one message: what a rekey pass reads mid-rotation.
  defp two_keyring_message do
    {:ok, generator} = raw_keyring(@key_name)
    {:ok, child} = raw_keyring("t/6Qk2_1xZaR8/v2")
    {:ok, multi} = Multi.new(generator: generator, children: [child])

    encrypt(multi, [])
  end

  defp message(opts) do
    {:ok, keyring} = raw_keyring(@key_name)

    encrypt(keyring, opts)
  end

  defp encrypt(keyring, opts) do
    {context, opts} = Keyword.pop(opts, :context, @context)

    opts =
      opts
      |> Keyword.put_new(:commitment_policy, :require_encrypt_require_decrypt)
      # The unsigned committed suite, deliberately: the signed one (0x0578) is
      # the engine's default and puts its own "aws-crypto-public-key" entry
      # into the context, which would make every context assertion below a
      # statement about the engine's signing scheme rather than about the
      # caller's context.
      |> Keyword.put_new(:algorithm_suite, AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key())
      |> Keyword.put(:encryption_context, context)

    {:ok, %{ciphertext: ciphertext}} =
      Client.encrypt_with_keyring(keyring, "4111 1111 1111 1111", opts)

    ciphertext
  end

  # The fixture wrapping key is derived rather than written down, so no
  # key-shaped literal appears in this file or in a failure report from it.
  defp raw_keyring(key_name) do
    RawAes.new(@provider_id, key_name, fixture_key(), :aes_256_gcm)
  end

  defp fixture_key, do: :crypto.hash(:sha256, "encryptor test fixture wrapping key")
end
