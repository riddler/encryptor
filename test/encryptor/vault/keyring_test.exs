defmodule Encryptor.Vault.KeyringTest do
  use ExUnit.Case, async: true

  alias AwsEncryptionSdk.Keyring.Multi
  alias AwsEncryptionSdk.Keyring.RawAes
  alias Encryptor.Error
  alias Encryptor.Key.Aes
  alias Encryptor.Key.Kms
  alias Encryptor.Vault.Keyring

  defmodule TestVault do
    @moduledoc false
  end

  describe "build/3 with a valid AES descriptor" do
    # sabotage: swapped the namespace and name arguments in the RawAes.new/4
    # call - the namespace/name assertions go red. They are compared
    # byte-for-byte on unwrap, so a swap makes every message written under it
    # undecryptable.
    test "maps namespace, name, and material onto a RawAes keyring" do
      material = key_bytes(32)
      key = %Aes{namespace: "myapp", name: "card/v7", material: material, bits: 256}

      assert {:ok, keyring} = Keyring.build(TestVault, :encrypt, key)

      assert %RawAes{
               key_namespace: "myapp",
               key_name: "card/v7",
               wrapping_key: ^material,
               wrapping_algorithm: :aes_256_gcm
             } = keyring
    end

    # sabotage: made wrapping_algorithm/1 return :aes_256_gcm for every size -
    # the 128 and 192 cases go red on the algorithm, and the engine rejects
    # them on key length too.
    test "picks the wrapping algorithm from the declared size" do
      for {bits, algorithm} <- [{128, :aes_128_gcm}, {192, :aes_192_gcm}, {256, :aes_256_gcm}] do
        key = %Aes{
          namespace: "myapp",
          name: "signup/v1",
          material: key_bytes(div(bits, 8)),
          bits: bits
        }

        assert {:ok, %RawAes{wrapping_algorithm: ^algorithm}} =
                 Keyring.build(TestVault, :encrypt, key)
      end
    end
  end

  describe "build/3 validation" do
    # sabotage: deleted the validate_namespace/1 step from the with chain -
    # this goes red with the engine's bare :reserved_provider_id arriving as
    # the detail instead of this package's own term, which is the whole reason
    # the check is repeated here.
    test "rejects a namespace in the engine's reserved prefix" do
      for namespace <- ["aws-kms", "aws-kms-mrk", "aws-kmsanything"] do
        assert {:error, error} = Keyring.build(TestVault, :encrypt, aes(namespace: namespace))
        assert %Error{reason: {:invalid_key_descriptor, {:reserved_namespace, "aws-kms"}}} = error
      end
    end

    test "accepts a namespace that merely contains the reserved prefix" do
      assert {:ok, %RawAes{}} = Keyring.build(TestVault, :encrypt, aes(namespace: "not-aws-kms"))
    end

    # sabotage: dropped the `value == ""` branch from validate_header_string/2
    # - the empty cases go red. An empty namespace passes the engine's own
    # reserved-prefix check, so nothing below catches it.
    test "rejects an empty, non-string, or unprintable namespace or name" do
      cases = [
        {[namespace: ""], {:invalid_key_field, :namespace, :empty}},
        {[namespace: :myapp], {:invalid_key_field, :namespace, :not_a_string}},
        {[namespace: <<0xFF, 0xFE>>], {:invalid_key_field, :namespace, :not_printable}},
        {[name: ""], {:invalid_key_field, :name, :empty}},
        {[name: nil], {:invalid_key_field, :name, :not_a_string}},
        {[name: <<0xFF, 0xFE>>], {:invalid_key_field, :name, :not_printable}}
      ]

      for {overrides, detail} <- cases do
        assert {:error, %Error{reason: {:invalid_key_descriptor, ^detail}}} =
                 Keyring.build(TestVault, :encrypt, aes(overrides))
      end
    end

    # sabotage: widened the validate_bits/1 guard to any integer - the 512 and
    # 8 cases go red, since the engine then rejects them by key length under a
    # detail that names the wrong constraint.
    test "rejects a size outside the three the engine accepts" do
      for bits <- [8, 64, 255, 512, :two_fifty_six] do
        assert {:error, %Error{reason: reason}} =
                 Keyring.build(TestVault, :encrypt, aes(bits: bits, material: key_bytes(32)))

        assert reason == {:invalid_key_descriptor, {:invalid_key_field, :bits, :unsupported}}
      end
    end

    # sabotage: changed the length comparison to `>=` - the too-long case goes
    # red. Truncating silently to the declared size is the failure mode this
    # check exists to prevent.
    test "rejects material whose length does not match the declared size" do
      cases = [
        {256, 16, {:key_length_mismatch, 256, 128}},
        {256, 48, {:key_length_mismatch, 256, 384}},
        {128, 32, {:key_length_mismatch, 128, 256}},
        {192, 0, {:key_length_mismatch, 192, 0}}
      ]

      for {bits, bytes, detail} <- cases do
        assert {:error, %Error{reason: {:invalid_key_descriptor, ^detail}}} =
                 Keyring.build(TestVault, :encrypt, aes(bits: bits, material: key_bytes(bytes)))
      end
    end

    test "rejects material that is not a binary" do
      assert {:error, %Error{reason: {:invalid_key_descriptor, detail}}} =
               Keyring.build(TestVault, :encrypt, aes(material: :from_the_environment))

      assert detail == {:invalid_key_field, :material, :not_a_binary}
    end
  end

  describe "build/3 with a descriptor it cannot build from" do
    # sabotage: deleted the %Kms{} clause so the catch-all handles it - this
    # goes red. "Recognized, no mapping yet" and "not a descriptor at all" are
    # different facts and the detail has to keep them apart.
    test "declines a KMS descriptor without calling it unrecognized" do
      key = %Kms{key_id: "arn:aws:kms:us-east-1:111122223333:key/abcd1234"}

      assert {:error, %Error{reason: {:invalid_key_descriptor, detail}}} =
               Keyring.build(TestVault, :encrypt, key)

      assert detail == {:no_keyring_mapping, Encryptor.Key.Kms}
    end

    test "names the struct of an unrecognized descriptor" do
      assert {:error, %Error{reason: {:invalid_key_descriptor, detail}}} =
               Keyring.build(TestVault, :decrypt, %RawAes{
                 key_namespace: "myapp",
                 key_name: "card/v7",
                 wrapping_key: key_bytes(32),
                 wrapping_algorithm: :aes_256_gcm
               })

      assert detail == {:not_a_descriptor, AwsEncryptionSdk.Keyring.RawAes}
    end

    # sabotage: made shape/1 return the term itself for a non-struct - this
    # goes red on the map case, and the failure it prevents is a bare map of
    # key material landing inside an error struct a host will log.
    test "carries no part of a non-struct term into the detail" do
      for term <- [%{material: "not-a-key", secret: "not-a-key"}, "myapp", nil, {:aes, 256}] do
        assert {:error, %Error{reason: {:invalid_key_descriptor, detail}}} =
                 Keyring.build(TestVault, :encrypt, term)

        assert detail == {:not_a_descriptor, :not_a_struct}
      end
    end
  end

  describe "build_all/3" do
    # sabotage: deleted the single-element clause so every list built a Multi
    # - this goes red. A Multi of one is an extra struct and an extra
    # error-wrapping layer for the single-key vault, which is most of them.
    test "builds a bare RawAes from a one-element candidate list" do
      assert {:ok, %RawAes{key_name: "card/v1"}} =
               Keyring.build_all(TestVault, :decrypt, [aes(name: "card/v1")])
    end

    # sabotage: passed the head as generator: instead of nil - this goes red.
    # A generator wraps the data key on encrypt, so a decrypt-side candidate
    # list with one would emit an extra encrypted data key per message.
    test "builds a Multi with no generator from a longer one, in order" do
      candidates = [aes(name: "card/v3"), aes(name: "card/v2"), aes(name: "card/v1")]

      assert {:ok, %Multi{generator: nil, children: children}} =
               Keyring.build_all(TestVault, :decrypt, candidates)

      assert Enum.map(children, & &1.key_name) == ["card/v3", "card/v2", "card/v1"]
    end

    # sabotage: made build_each/3 skip descriptors it could not build - this
    # goes red. A candidate list quietly missing an entry is a message that
    # stops decrypting for a reason nothing reports.
    test "fails on the first candidate the vault cannot build" do
      candidates = [aes(name: "card/v2"), aes(namespace: ""), aes(name: "card/v1")]

      assert {:error, %Error{reason: reason, operation: :decrypt}} =
               Keyring.build_all(TestVault, :decrypt, candidates)

      assert reason == {:invalid_key_descriptor, {:invalid_key_field, :namespace, :empty}}
    end

    # sabotage: deleted the [] and catch-all clauses of build_all/3 - this
    # goes red with a FunctionClauseError. An empty candidate list is a
    # provider defect and has to arrive as one, not as a keyring built from
    # nothing.
    test "refuses an empty list and a term that is not a list" do
      assert {:error, %Error{reason: {:invalid_key_descriptor, :empty_candidate_list}}} =
               Keyring.build_all(TestVault, :decrypt, [])

      assert {:error, %Error{reason: {:invalid_key_descriptor, detail}}} =
               Keyring.build_all(TestVault, :decrypt, aes([]))

      assert detail == {:not_a_candidate_list, Encryptor.Key.Aes}
    end
  end

  describe "build/3 failure reporting" do
    # sabotage: hardcoded :encrypt as the operation in invalid/3 - the
    # :decrypt, :rekey and :start cases go red. The operation is what the
    # caller asked for, and a rekey reported as an encrypt sends an operator
    # to the wrong half of the runbook.
    test "carries the vault and the operation it was asked for" do
      for operation <- [:encrypt, :decrypt, :rekey, :start] do
        assert {:error, error} = Keyring.build(TestVault, operation, aes(namespace: ""))
        assert %Error{vault: TestVault, operation: ^operation, engine: nil} = error
      end
    end

    # sabotage: put the descriptor's :material into the invalid/3 detail - this
    # goes red on every case. It is the repo's key-material rule asserted
    # rather than remembered, on the one path that sees material and fails.
    test "never renders key material, and never carries it in the error" do
      material = key_bytes(32)

      failing = [
        %Aes{namespace: "aws-kms", name: "card/v7", material: material, bits: 256},
        %Aes{namespace: "", name: "card/v7", material: material, bits: 256},
        %Aes{namespace: "myapp", name: "", material: material, bits: 256},
        %Aes{namespace: "myapp", name: "card/v7", material: material, bits: 512},
        %Aes{namespace: "myapp", name: "card/v7", material: material, bits: 128}
      ]

      for key <- failing do
        assert {:error, error} = Keyring.build(TestVault, :encrypt, key)

        refute inspect(error) =~ Base.encode16(material)
        refute inspect(error) =~ inspect(material)
        refute Exception.message(error) =~ Base.encode16(material)
        refute Exception.message(error) =~ inspect(material)

        assert Exception.message(error) ==
                 "the provider returned a key descriptor this vault cannot use " <>
                   "(Encryptor.Vault.KeyringTest.TestVault, encrypt)"
      end
    end
  end

  defp aes(overrides) do
    defaults = [namespace: "myapp", name: "card/v7", material: key_bytes(32), bits: 256]

    struct!(Aes, Keyword.merge(defaults, overrides))
  end

  # Not a key. Bytes shaped like one, for descriptors that are rejected before
  # anything cryptographic happens to them.
  defp key_bytes(0), do: ""
  defp key_bytes(bytes), do: :crypto.strong_rand_bytes(bytes)
end
