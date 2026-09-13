defmodule Encryptor.Provider.KmsTest do
  @moduledoc """
  ADR-0008: the keyring-backed provider.

  The shared conformance suite runs first, against the fixture tenants the
  fake client holds keys for - which is the record's in-repo proof obligation
  that the suite is shape-aware rather than Aes-shaped.

  Every KMS call goes through `Encryptor.AwsKms.Fake` at the engine's client
  boundary, or through the engine's own `KmsClient.Mock` where a refusal is
  the subject. Nothing here reaches AWS.
  """

  use Encryptor.Provider.Conformance

  alias AwsEncryptionSdk.Keyring.AwsKms
  alias AwsEncryptionSdk.Keyring.AwsKmsMrk
  alias AwsEncryptionSdk.Keyring.KmsClient
  alias AwsEncryptionSdk.Keyring.Multi
  alias AwsEncryptionSdk.Keyring.RawAes
  alias Encryptor.AwsKms.Fake
  alias Encryptor.Error
  alias Encryptor.Key.Aes
  alias Encryptor.Key.Kms
  alias Encryptor.Provider
  alias Encryptor.Vault.Keyring

  @impl true
  def provider_case do
    %{
      provider: Provider.Kms,
      opts: [client: Fake.new(), keys: keys()],
      selectors: ["acme", "globex"],
      unknown: ["nobody"]
    }
  end

  describe "init/1" do
    test "freezes the client onto every descriptor it answers with" do
      client = Fake.new()
      {:ok, state} = Provider.Kms.init(client: client, keys: keys())

      {:ok, descriptors} = Provider.Kms.decryption_keys(state, "acme")

      assert Enum.all?(descriptors, &(&1.client == client))
    end

    # sabotage: made `:keys` win over `:key_id` instead of refusing the pair -
    # this goes red. The two shapes answer the same question and there is no
    # reading of the pair that is not a mistake.
    test "refuses both key shapes at once" do
      assert {:error, {:invalid_config, :provider, :keys_and_key_id}} =
               Provider.Kms.init(client: Fake.new(), keys: keys(), key_id: Fake.acme())
    end

    test "refuses neither" do
      assert {:error, {:missing_config, [:provider, :keys]}} =
               Provider.Kms.init(client: Fake.new())
    end

    test "refuses a client that is not a struct" do
      assert {:error, {:invalid_config, :provider, :client_not_a_struct}} =
               Provider.Kms.init(client: :from_the_environment, keys: keys())
    end

    test "refuses a client and a region together" do
      assert {:error, {:invalid_config, :provider, :client_and_region}} =
               Provider.Kms.init(client: Fake.new(), region: "us-east-1", keys: keys())
    end

    test "refuses neither a client nor a region" do
      assert {:error, {:missing_config, [:provider, :client]}} =
               Provider.Kms.init(keys: keys())
    end

    # ADR-0008 decision 9. This package declares none of the AWS deps, so the
    # engine's shipped client module is not compiled here and this is what a
    # host that asked for it without adding them sees - at start, not on a
    # customer's first write.
    #
    # sabotage: moved the check to first use - this goes red at start and the
    # vault boots into a deploy that fails later.
    test "refuses the shipped client when the optional dependency is absent" do
      refute Code.ensure_loaded?(AwsEncryptionSdk.Keyring.KmsClient.ExAws)

      assert {:error, {:missing_optional_dependency, :ex_aws_kms}} =
               Provider.Kms.init(region: "us-east-1", keys: keys())
    end

    # sabotage: dropped the distinctness check - this goes red. On this path
    # the ARN is the version identity, so two entries sharing one is the
    # failure the identity contract exists to prevent, caught at start.
    test "refuses two candidates sharing a key id" do
      assert {:error, {:invalid_config, :provider, :duplicate_key_ids}} =
               Provider.Kms.init(
                 client: Fake.new(),
                 keys: %{"acme" => [Fake.acme(), Fake.acme()]}
               )
    end

    test "refuses an empty candidate list, a malformed entry, and a non-map :keys" do
      client = Fake.new()

      assert {:error, {:invalid_config, :provider, :empty_key_list}} =
               Provider.Kms.init(client: client, keys: %{"acme" => []})

      assert {:error, {:invalid_config, :provider, :malformed_key_entry}} =
               Provider.Kms.init(client: client, keys: %{"acme" => [%{arn: Fake.acme()}]})

      assert {:error, {:invalid_config, :provider, :malformed_key_entry}} =
               Provider.Kms.init(client: client, keys: %{"acme" => ""})

      assert {:error, {:invalid_config, :provider, :keys_not_a_map}} =
               Provider.Kms.init(client: client, keys: [Fake.acme()])
    end

    test "refuses a non-boolean :mrk" do
      assert {:error, {:invalid_config, :provider, :mrk}} =
               Provider.Kms.init(client: Fake.new(), keys: keys(), mrk: :maybe)
    end
  end

  describe "the key shapes" do
    test "the selector-ignoring shape answers every selector with one key" do
      {:ok, state} = Provider.Kms.init(client: Fake.new(), key_id: Fake.acme())

      assert {:ok, %Kms{key_id: arn}} = Provider.Kms.encryption_key(state, "anyone")
      assert arn == Fake.acme()
      assert {:ok, [%Kms{key_id: ^arn}]} = Provider.Kms.decryption_keys(state, :default)
    end

    test "the map shape refuses a selector it does not hold" do
      {:ok, state} = Provider.Kms.init(client: Fake.new(), keys: keys())

      assert {:error, {:unknown_key, "nobody"}} = Provider.Kms.encryption_key(state, "nobody")
      assert {:error, {:unknown_key, "nobody"}} = Provider.Kms.decryption_keys(state, "nobody")
    end

    test "the closure shape resolves through the host's function" do
      client = Fake.new()

      {:ok, state} =
        Provider.Kms.init(
          client: client,
          keys: fn
            "acme" -> {:ok, [Fake.acme(), Fake.acme_previous()]}
            selector -> {:error, {:unknown_key, selector}}
          end
        )

      assert {:ok, [first, second]} = Provider.Kms.decryption_keys(state, "acme")
      assert [first.key_id, second.key_id] == [Fake.acme(), Fake.acme_previous()]
      assert {:error, {:unknown_key, "nobody"}} = Provider.Kms.decryption_keys(state, "nobody")
    end

    test "a closure answering outside the vocabulary is named as a provider bug" do
      {:ok, state} =
        Provider.Kms.init(client: Fake.new(), keys: fn _selector -> {:error, :who_knows} end)

      assert {:error, {:invalid_key_descriptor, {:unrecognized_reason, :who_knows}}} =
               Provider.Kms.decryption_keys(state, "acme")
    end

    test "a closure answering a shape that is not a candidate list is too" do
      {:ok, state} = Provider.Kms.init(client: Fake.new(), keys: fn _selector -> Fake.acme() end)

      assert {:error, {:invalid_key_descriptor, :not_a_candidate_list}} =
               Provider.Kms.decryption_keys(state, "acme")
    end

    # sabotage: made `:mrk` a per-provider constant with no entry override -
    # this goes red. A host migrating one key to a multi-region key runs both
    # for the length of the window.
    test "an entry may override the provider-wide :mrk" do
      {:ok, state} =
        Provider.Kms.init(
          client: Fake.new(),
          keys: %{"acme" => [[key_id: Fake.mrk(), mrk: true], Fake.acme()]}
        )

      assert {:ok, [%Kms{mrk: true}, %Kms{mrk: false}]} =
               Provider.Kms.decryption_keys(state, "acme")
    end
  end

  describe "the descriptor's keyring mapping" do
    # sabotage: swapped the two `:mrk` clauses in the builder - this goes red.
    # The engine dispatches on the struct type, and at v1.0.0 the two are the
    # same code path, so the struct type is the only observable there is.
    test ":mrk selects the engine struct, and nothing else is asserted about it" do
      client = Fake.new()

      assert {:ok, %AwsKms{}} =
               Keyring.build(__MODULE__, :encrypt, %Kms{key_id: Fake.acme(), client: client})

      assert {:ok, %AwsKmsMrk{}} =
               Keyring.build(__MODULE__, :encrypt, %Kms{
                 key_id: Fake.mrk(),
                 mrk: true,
                 client: client
               })
    end

    # sabotage: deleted the dedicated `client: nil` clause so `checks/1`
    # answers - this goes red. The two failures name different culprits: the
    # provider forgot to copy the client it built, or the descriptor's author
    # supplied a bad one.
    test "a descriptor with no client names the provider, not the field" do
      assert {:error, %Error{reason: {:invalid_key_descriptor, detail}}} =
               Keyring.build(__MODULE__, :encrypt, %Kms{key_id: Fake.acme()})

      assert detail == {:missing_client, Kms}
    end

    test "a client that is not a struct is a field failure in this package's words" do
      assert {:error, %Error{reason: {:invalid_key_descriptor, detail}}} =
               Keyring.build(__MODULE__, :encrypt, %Kms{
                 key_id: Fake.acme(),
                 client: :from_the_environment
               })

      assert detail == {:invalid_key_field, :client, :not_a_struct}
    end

    # sabotage: dropped `checks/1` from the `%Kms{}` build clauses and let the
    # engine answer - this goes red with the engine's own `:key_id_empty`,
    # `:invalid_key_id_type` and `:key_id_required` atoms, which is the defect
    # the module's moduledoc says it would be.
    test "an unusable key id fails in this package's vocabulary, never the engine's" do
      client = Fake.new()

      cases = [
        {"", :empty},
        {<<0xFF, 0xFE>>, :not_printable},
        {:an_atom, :not_a_string},
        {nil, :not_a_string}
      ]

      for {key_id, expected} <- cases do
        assert {:error, %Error{reason: {:invalid_key_descriptor, detail}}} =
                 Keyring.build(__MODULE__, :encrypt, %Kms{key_id: key_id, client: client})

        assert detail == {:invalid_key_field, :key_id, expected}
      end
    end

    # ADR-0008 decision 6: the decrypt-side Multi takes both shapes, and the
    # engine's own dispatch is what accepts them.
    test "a mixed candidate list builds one Multi over both shapes" do
      descriptors = [
        %Kms{key_id: Fake.acme(), client: Fake.new()},
        %Aes{namespace: "acme-app", name: "acme/v1", material: material(), bits: 256}
      ]

      assert {:ok, %Multi{generator: nil, children: [%AwsKms{}, %RawAes{}]}} =
               Keyring.build_all(__MODULE__, :decrypt, descriptors)
    end

    # The partition between the two shapes' encrypted data keys, one layer
    # before a keyring exists. A future relaxation of this is what would make
    # the mixed list unsound, and no test in either package would catch it.
    test "an AES descriptor can never claim the engine's own provider id" do
      key = %Aes{namespace: "aws-kms", name: "acme/v1", material: material(), bits: 256}

      assert {:error, %Error{reason: {:invalid_key_descriptor, detail}}} =
               Keyring.build(__MODULE__, :encrypt, key)

      assert detail == {:reserved_namespace, "aws-kms"}
    end
  end

  describe "what this provider never does" do
    # ADR-0008 decision 7: `provisioned()` is shaped around a wrapped master
    # key and none of its fields has a value here.
    test "it does not implement provision/2" do
      refute function_exported?(Provider.Kms, :provision, 2)
    end

    test "it declares no AWS dependency of its own" do
      refute Enum.any?(Mix.Project.config()[:deps], fn dep ->
               dep |> elem(0) |> Atom.to_string() |> String.starts_with?("ex_aws")
             end)
    end
  end

  describe "a KMS refusal" do
    # The engine's canned-response client, where the refusal is the subject:
    # an IAM denial and a timeout are the same fact to a caller.
    test "reaches the caller as an engine failure rather than a wrong plaintext" do
      {:ok, client} =
        KmsClient.Mock.new(%{
          {:generate_data_key, Fake.acme()} =>
            {:error, {:kms_error, :access_denied, "not authorized"}}
        })

      {:ok, keyring} =
        Keyring.build(__MODULE__, :encrypt, %Kms{key_id: Fake.acme(), client: client})

      assert %AwsKms{kms_client: ^client} = keyring
    end
  end

  defp keys do
    %{"acme" => [Fake.acme(), Fake.acme_previous()], "globex" => Fake.globex()}
  end

  defp material, do: :binary.copy(<<0xD1>>, 32)
end
