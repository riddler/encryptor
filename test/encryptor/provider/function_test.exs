defmodule Encryptor.Provider.FunctionTest do
  use ExUnit.Case, async: true

  alias AwsEncryptionSdk.Keyring.RawAes
  alias Encryptor.Key.Aes
  alias Encryptor.Key.Kms
  alias Encryptor.Provider.Function, as: FunctionProvider

  describe "init/1" do
    # sabotage: made closure/2 accept any term for :encryption_key - the
    # not-a-closure cases go red, and the failure moves from vault start to a
    # BadFunctionError on the host's first encrypt.
    test "requires both closures, each of arity one" do
      cases = [
        {[decryption_keys: &live/1], {:missing_config, [:provider, :encryption_key]}},
        {[encryption_key: &current/1], {:missing_config, [:provider, :decryption_keys]}},
        {[encryption_key: "current", decryption_keys: &live/1],
         {:invalid_config, :provider, {:not_a_closure, :encryption_key}}},
        {[encryption_key: &current/1, decryption_keys: fn -> [] end],
         {:invalid_config, :provider, {:not_a_closure, :decryption_keys}}}
      ]

      for {opts, reason} <- cases do
        assert {:error, ^reason} = FunctionProvider.init(opts)
      end
    end

    test "holds both closures when they are well formed" do
      assert {:ok, state} =
               FunctionProvider.init(encryption_key: &current/1, decryption_keys: &live/1)

      assert is_function(state.encryption_key, 1)
      assert is_function(state.decryption_keys, 1)
    end
  end

  describe "resolution" do
    # sabotage: made encryption_key/2 ignore the selector and call the closure
    # with :default - the merchant assertion goes red. The selector is the
    # only thing the vault gives a provider to answer with.
    test "hands the selector to the host's closure" do
      state = provider(fn selector -> {:ok, aes(name: "t/#{selector}/v1")} end, &live/1)

      assert {:ok, %Aes{name: "t/merchant-42/v1"}} =
               FunctionProvider.encryption_key(state, "merchant-42")
    end

    test "answers a candidate list the vault can build a Multi from" do
      state =
        provider(&current/1, fn _selector ->
          {:ok, [aes(name: "card/v2"), aes(name: "card/v1")]}
        end)

      assert {:ok, [%Aes{name: "card/v2"}, %Aes{name: "card/v1"}]} =
               FunctionProvider.decryption_keys(state, :default)
    end

    test "accepts a KMS descriptor as a member of the closed set" do
      state = provider(fn _selector -> {:ok, %Kms{key_id: "mrk-abcd1234"}} end, &live/1)

      assert {:ok, %Kms{}} = FunctionProvider.encryption_key(state, :default)
    end
  end

  describe "validating the answer on the way back" do
    # sabotage: deleted the validate_one/1 catch-all clause - this goes red
    # with a FunctionClauseError from inside the provider instead of a named
    # reason. A closure returning an engine keyring is the exact mistake the
    # descriptor split exists to prevent, and it has to be legible.
    test "refuses a descriptor that is not a member of the closed set" do
      keyring = %RawAes{
        key_namespace: "myapp",
        key_name: "card/v7",
        wrapping_key: key_bytes(32),
        wrapping_algorithm: :aes_256_gcm
      }

      state = provider(fn _selector -> {:ok, keyring} end, &live/1)

      assert {:error, {:invalid_key_descriptor, {:not_a_descriptor, RawAes}}} =
               FunctionProvider.encryption_key(state, :default)
    end

    test "refuses an answer that is not a result tuple" do
      for answer <- [aes(), nil, %{key: "material"}, [aes()]] do
        state = provider(fn _selector -> answer end, &live/1)

        assert {:error, {:invalid_key_descriptor, {:not_a_result, _shape}}} =
                 FunctionProvider.encryption_key(state, :default)
      end
    end

    # sabotage: replaced the {:ok, []} clause in decryption_keys/2 with the
    # general {:ok, list} one - this goes red. An empty candidate list would
    # otherwise build no keyring at all and report "this provider serves no
    # key" as "this ciphertext is wrong" one layer later.
    test "refuses an empty candidate list" do
      state = provider(&current/1, fn _selector -> {:ok, []} end)

      assert {:error, {:invalid_key_descriptor, :empty_candidate_list}} =
               FunctionProvider.decryption_keys(state, :default)
    end

    # sabotage: made validate_all/1 check only the first element - this goes
    # red. A candidate list is checked entry by entry because the entry that
    # is wrong is usually not the newest one.
    test "refuses a candidate list with a non-descriptor anywhere in it" do
      state = provider(&current/1, fn _selector -> {:ok, [aes(), :from_the_store]} end)

      assert {:error, {:invalid_key_descriptor, {:not_a_descriptor, :from_the_store}}} =
               FunctionProvider.decryption_keys(state, :default)
    end
  end

  describe "the closure's own refusals" do
    # sabotage: replaced translate/1 with an identity function - the
    # unrecognized case goes red. The vocabulary is closed so a case over it
    # is exhaustive, and a host term inside it reaches a renderer with no
    # clause for it.
    test "passes a reason from the closed vocabulary through unchanged" do
      reasons = [
        {:unknown_key, "no-such-merchant"},
        {:key_unavailable, "merchant-42"},
        {:invalid_key_descriptor, :from_the_store},
        {:provider_not_started, MyApp.KeyServer},
        {:missing_optional_dependency, :ecto}
      ]

      for reason <- reasons do
        state = provider(fn _selector -> {:error, reason} end, &live/1)

        assert {:error, ^reason} = FunctionProvider.encryption_key(state, :default)
      end
    end

    test "names a reason outside the vocabulary without carrying it" do
      state = provider(fn _selector -> {:error, {:ecto_error, "material"}} end, &live/1)

      assert {:error, {:invalid_key_descriptor, {:unrecognized_reason, :ecto_error}}} =
               FunctionProvider.encryption_key(state, :default)
    end

    # sabotage: made shape/1 return the term itself - this goes red on the map
    # and string cases. A reason term from a host closure resolves key
    # material and lands in an error a host may well log.
    test "carries no part of an unnameable reason" do
      for reason <- [%{material: "not-a-key"}, "material", 42, {"material", 1}] do
        state = provider(&current/1, fn _selector -> {:error, reason} end)

        assert {:error, {:invalid_key_descriptor, {:unrecognized_reason, :unnameable}}} =
                 FunctionProvider.decryption_keys(state, :default)
      end
    end
  end

  describe "key material" do
    test "never reaches the error a refused answer produces" do
      material = key_bytes(32)
      state = provider(fn _selector -> {:error, {:leaky, material}} end, &live/1)

      assert {:error, reason} = FunctionProvider.encryption_key(state, :default)

      refute inspect(reason) =~ Base.encode16(material)
      refute inspect(reason) =~ inspect(material)
    end
  end

  defp provider(encryption_key, decryption_keys) do
    {:ok, state} =
      FunctionProvider.init(encryption_key: encryption_key, decryption_keys: decryption_keys)

    state
  end

  defp current(_selector), do: {:ok, aes()}
  defp live(_selector), do: {:ok, [aes()]}

  defp aes(overrides \\ []) do
    defaults = [namespace: "myapp", name: "card/v7", material: key_bytes(32), bits: 256]

    struct!(Aes, Keyword.merge(defaults, overrides))
  end

  # Not a key. Bytes shaped like one, for closures that never look at them.
  defp key_bytes(bytes), do: :crypto.strong_rand_bytes(bytes)
end

defmodule Encryptor.Provider.FunctionConformanceTest do
  @moduledoc """
  A per-tenant vault on the day-one path: two live versions per merchant, and
  a merchant the store does not serve.
  """

  use Encryptor.Provider.Conformance

  alias Encryptor.Key.Aes

  @served "merchant-42"

  @impl true
  def provider_case do
    root = :crypto.strong_rand_bytes(32)

    %{
      provider: Encryptor.Provider.Function,
      opts: [
        encryption_key: fn
          @served -> {:ok, derive(root, @served, 2)}
          selector -> {:error, {:unknown_key, selector}}
        end,
        decryption_keys: fn
          @served -> {:ok, [derive(root, @served, 2), derive(root, @served, 1)]}
          selector -> {:error, {:unknown_key, selector}}
        end
      ],
      selectors: [@served],
      unknown: ["no-such-merchant"]
    }
  end

  # Illustrative only. The real wrapping structure is the envelope record's.
  defp derive(root, selector, version) do
    reference =
      :sha256
      |> :crypto.hash(selector)
      |> Base.url_encode64(padding: false)
      |> binary_part(0, 16)

    %Aes{
      namespace: "myapp",
      name: "t/#{reference}/v#{version}",
      material: :crypto.mac(:hmac, :sha256, root, "#{selector}/#{version}"),
      bits: 256
    }
  end
end
