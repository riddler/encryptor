defmodule Encryptor.Provider.StaticTest do
  use ExUnit.Case, async: true

  alias Encryptor.Key.Aes
  alias Encryptor.Provider.Static

  describe "init/1 with :key" do
    # sabotage: swapped the :namespace and :name defaults in descriptor/2 -
    # this goes red. Both are written into the message header and compared
    # byte-for-byte on unwrap, so a swapped pair is a vault that cannot read
    # what it wrote.
    test "builds one descriptor from the material, namespace, and name" do
      material = key_bytes(32)

      assert {:ok, state} =
               Static.init(key: material, namespace: "myapp", name: "card/v7")

      assert %{keys: [%Aes{namespace: "myapp", name: "card/v7", bits: 256} = key]} = state
      assert key.material == material
    end

    # sabotage: changed @default_name to "v2" - this goes red. The defaults
    # are part of the configured surface: a host that omits them and later
    # changes the package's mind about them has rotated its key without
    # meaning to.
    test "defaults the namespace and the name" do
      assert {:ok, %{keys: [%Aes{namespace: "encryptor", name: "v1"}]}} =
               Static.init(key: key_bytes(32))
    end

    # sabotage: hardcoded bits: 256 in descriptor/2 - the 128 and 192 cases go
    # red, and the vault would then reject material that is perfectly valid.
    test "derives the declared size from the material" do
      for {bytes, bits} <- [{16, 128}, {24, 192}, {32, 256}] do
        assert {:ok, %{keys: [%Aes{bits: ^bits}]}} = Static.init(key: key_bytes(bytes))
      end
    end
  end

  describe "init/1 with :keys" do
    # sabotage: made encryption_key/2 return List.last/1 of the candidates -
    # the head assertion goes red. The list is newest first, so the last entry
    # is the key being retired, and writes under it are writes that a later
    # shred silently destroys.
    test "answers the head on encrypt and the whole list on decrypt" do
      new_material = key_bytes(32)
      old_material = key_bytes(32)

      assert {:ok, state} =
               Static.init(
                 keys: [
                   [key: new_material, namespace: "myapp", name: "card/v2"],
                   [key: old_material, namespace: "myapp", name: "card/v1"]
                 ]
               )

      assert {:ok, %Aes{name: "card/v2"}} = Static.encryption_key(state, :default)

      assert {:ok, [%Aes{name: "card/v2"}, %Aes{name: "card/v1"}]} =
               Static.decryption_keys(state, :default)
    end

    # sabotage: dropped the Enum.reverse/1 from descriptors/1 - this goes red.
    # A reversed candidate list makes the outgoing key the encryption key,
    # which is the staged-rotation failure the order exists to prevent.
    test "keeps the configured order" do
      assert {:ok, state} =
               Static.init(
                 keys: [
                   [key: key_bytes(32), name: "signup/v3"],
                   [key: key_bytes(32), name: "signup/v2"],
                   [key: key_bytes(32), name: "signup/v1"]
                 ]
               )

      assert {:ok, keys} = Static.decryption_keys(state, :default)
      assert Enum.map(keys, & &1.name) == ["signup/v3", "signup/v2", "signup/v1"]
    end

    test "applies the namespace default per entry" do
      assert {:ok, state} =
               Static.init(
                 keys: [
                   [key: key_bytes(32), name: "card/v2"],
                   [key: key_bytes(32), namespace: "myapp", name: "card/v1"]
                 ]
               )

      assert {:ok, [%Aes{namespace: "encryptor"}, %Aes{namespace: "myapp"}]} =
               Static.decryption_keys(state, :default)
    end
  end

  describe "init/1 refusals" do
    # sabotage: removed the {true, {:ok, _keys}} clause from entries/1 so :key
    # won - this goes red. The two shapes answer the same question and there
    # is no reading of the pair that is not a misconfiguration.
    test "refuses both :key and :keys" do
      assert {:error, {:invalid_config, :provider, :key_and_keys}} =
               Static.init(key: key_bytes(32), keys: [[key: key_bytes(32)]])
    end

    test "refuses neither" do
      assert {:error, {:missing_config, [:provider, :key]}} = Static.init(namespace: "myapp")
    end

    test "refuses an empty or malformed :keys list" do
      cases = [
        {[keys: []], :empty_key_list},
        {[keys: "card/v1"], :keys_not_a_list},
        {[keys: [[namespace: "myapp", name: "card/v1"]]], :malformed_key_entry},
        {[keys: [%{key: "material"}]], :malformed_key_entry}
      ]

      for {opts, detail} <- cases do
        assert {:error, {:invalid_config, :provider, ^detail}} = Static.init(opts)
      end
    end

    # sabotage: deleted the distinct_names/1 step from init/1's with chain -
    # this goes red. Two entries under one name is the exact condition that
    # makes an already-written message undecryptable at some later date, and
    # start is the only place it is cheap to catch.
    test "refuses two entries sharing a name" do
      assert {:error, {:invalid_config, :provider, :duplicate_key_names}} =
               Static.init(
                 keys: [
                   [key: key_bytes(32), name: "card/v1"],
                   [key: key_bytes(32), name: "card/v1"]
                 ]
               )
    end

    # sabotage: widened the byte_size guard in descriptor/2 to accept any
    # size - this goes red on every case, and the failure moves from start to
    # the host's first encrypt.
    test "refuses material that is not a binary of a size the engine accepts" do
      for key <- [key_bytes(20), key_bytes(0), :from_the_environment, nil] do
        assert {:error, {:invalid_config, :provider, :key_size}} = Static.init(key: key)
      end
    end
  end

  describe "the selector" do
    # sabotage: added a selector guard to encryption_key/2 that matched only
    # :default - the tenant cases go red. A single-key vault resolves anything
    # identically, which is what lets the vault omit a special case.
    test "is ignored, not rejected" do
      assert {:ok, state} = Static.init(key: key_bytes(32))

      for selector <- [:default, "merchant-42", "signup-cohort-b"] do
        assert {:ok, %Aes{name: "v1"}} = Static.encryption_key(state, selector)
        assert {:ok, [%Aes{name: "v1"}]} = Static.decryption_keys(state, selector)
      end
    end
  end

  describe "key material" do
    # sabotage: dropped the @derive {Inspect, except: [:material]} from
    # Encryptor.Key.Aes - this goes red. The state is frozen into the vault
    # config, and a config a host inspects must not print its keys.
    test "never reaches an inspect of the resolved state" do
      material = key_bytes(32)

      assert {:ok, state} = Static.init(key: material)

      refute inspect(state) =~ Base.encode16(material)
      refute inspect(state) =~ inspect(material)
    end
  end

  # Not a key. Bytes shaped like one, for a provider that only counts them.
  defp key_bytes(0), do: ""
  defp key_bytes(bytes), do: :crypto.strong_rand_bytes(bytes)
end

defmodule Encryptor.Provider.StaticSingleKeyConformanceTest do
  @moduledoc """
  The single-key vault: one entry, so the vault builds a bare `RawAes`.
  """

  use Encryptor.Provider.Conformance

  @impl true
  def provider_case do
    %{
      provider: Encryptor.Provider.Static,
      opts: [key: :crypto.strong_rand_bytes(32), namespace: "myapp", name: "card/v1"]
    }
  end
end

defmodule Encryptor.Provider.StaticCandidateListConformanceTest do
  @moduledoc """
  A root vault mid-rotation: two entries, so the vault builds a `Multi` with
  no generator.
  """

  use Encryptor.Provider.Conformance

  @impl true
  def provider_case do
    %{
      provider: Encryptor.Provider.Static,
      opts: [
        keys: [
          [key: :crypto.strong_rand_bytes(32), namespace: "myapp", name: "card/v2"],
          [key: :crypto.strong_rand_bytes(32), namespace: "myapp", name: "card/v1"]
        ]
      ],
      selectors: [:default, "merchant-42"]
    }
  end
end
