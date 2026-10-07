defmodule Encryptor.Vault.InspectRedactionTest do
  # A provider's own failure term rides in an error's `:engine`, and a
  # provider-supplied reason detail rides in `:reason`. Both can hold anything,
  # key material included. These tests start real vaults over providers whose
  # failures carry a key-shaped value and check that neither `inspect/2` of the
  # error nor the text a supervisor reports when the vault fails to start ever
  # renders it.
  use ExUnit.Case, async: false

  alias Encryptor.Error

  # Not a key: a fixed, obviously synthetic 32-byte value with a key's shape,
  # so a rendering of it is unmistakable in a string.
  @key_shaped :binary.copy(<<0xAB>>, 32)

  def key_shaped, do: @key_shaped

  defmodule LeakyInit do
    @moduledoc "A provider whose `init/1` fails with a term holding a key-shaped value."

    @behaviour Encryptor.Provider

    alias Encryptor.Vault.InspectRedactionTest

    @doc "Fails at start: in its own words, or in the package's vocabulary with a leaky detail."
    @impl Encryptor.Provider
    def init(opts) do
      value = InspectRedactionTest.key_shaped()

      case Keyword.fetch!(opts, :mode) do
        :own_term -> {:error, {:rejected, value}}
        :invalid_config -> {:error, {:invalid_config, :material, value}}
      end
    end

    @doc "Never reached: the vault does not start."
    @impl Encryptor.Provider
    def encryption_key(_state, _selector), do: {:error, {:unknown_key, :default}}

    @doc "Never reached: the vault does not start."
    @impl Encryptor.Provider
    def decryption_keys(_state, _selector), do: {:error, {:unknown_key, :default}}
  end

  defmodule LeakyResolve do
    @moduledoc "A provider that starts, then fails every resolution with a key-shaped value."

    @behaviour Encryptor.Provider

    alias Encryptor.Vault.InspectRedactionTest

    @doc "Fails off the contract, or in it with a leaky descriptor detail."
    @impl Encryptor.Provider
    def encryption_key(_state, _selector), do: fail()

    @doc "The same, on the read side."
    @impl Encryptor.Provider
    def decryption_keys(_state, _selector), do: fail()

    defp fail do
      value = InspectRedactionTest.key_shaped()

      case Process.get(:leaky_resolve_mode, :off_contract) do
        :off_contract -> {:error, {:rejected, value}}
        :bare -> {:bare, value}
        :descriptor -> {:error, {:invalid_key_descriptor, %{material: value}}}
      end
    end
  end

  defmodule OwnTermVault do
    @moduledoc "A vault whose provider fails at start in its own words."

    use Encryptor.Vault, otp_app: :encryptor, context_profile: :single

    @doc "Layer 5: names the failing provider."
    def init(config) do
      {:ok,
       Keyword.put(
         config,
         :provider,
         {Encryptor.Vault.InspectRedactionTest.LeakyInit, mode: :own_term}
       )}
    end
  end

  defmodule InvalidConfigVault do
    @moduledoc "A vault whose provider fails at start with a leaky `:invalid_config` detail."

    use Encryptor.Vault, otp_app: :encryptor, context_profile: :single

    @doc "Layer 5: names the failing provider."
    def init(config) do
      {:ok,
       Keyword.put(
         config,
         :provider,
         {Encryptor.Vault.InspectRedactionTest.LeakyInit, mode: :invalid_config}
       )}
    end
  end

  defmodule ResolveVault do
    @moduledoc "A vault that starts over a provider that fails every resolution."

    use Encryptor.Vault,
      otp_app: :encryptor,
      context_profile: :single,
      algorithm_suite_id: 0x0478

    @doc "Layer 5: names the failing provider."
    def init(config) do
      {:ok,
       Keyword.put(config, :provider, {Encryptor.Vault.InspectRedactionTest.LeakyResolve, []})}
    end
  end

  # Every way the value could show up in a rendering: inspect's byte list,
  # the hex an operator might have encoded it to, and the raw bytes.
  defp refute_rendered(text) do
    refute text =~ inspect(@key_shaped)
    refute text =~ "171, 171"
    refute text =~ Base.encode16(@key_shaped)
    refute text =~ @key_shaped
  end

  describe "a vault whose provider fails at start" do
    # sabotage: deleted the Inspect implementation in Encryptor.Error - red;
    # rendering the engine term unredacted - red.
    test "keeps a provider's own init term out of inspect/2" do
      assert {:error, %Error{reason: {:invalid_config, :provider, :init}} = error} =
               OwnTermVault.start_link([])

      # The struct still carries the term, unchanged, for code that asks.
      assert error.engine == {:rejected, @key_shaped}

      refute_rendered(inspect(error))
      assert inspect(error) =~ "#Encryptor.Error<"
    end

    # sabotage: removed the {:invalid_config, _, _} clause of the Inspect
    # implementation's reason redaction - red.
    test "keeps a leaky :invalid_config detail out of inspect/2" do
      assert {:error, %Error{reason: {:invalid_config, :material, @key_shaped}} = error} =
               InvalidConfigVault.start_link([])

      refute_rendered(inspect(error))
      assert inspect(error) =~ ":material"
    end

    # sabotage: deleted the Inspect implementation - red; removing the
    # {:invalid_config, _, _} redaction clause - red, on the second vault.
    test "keeps the term out of a parent supervisor's failed-start exit" do
      Process.flag(:trap_exit, true)

      for vault <- [OwnTermVault, InvalidConfigVault] do
        assert {:error, reason} = Supervisor.start_link([{vault, []}], strategy: :one_for_one)
        assert {:shutdown, {:failed_to_start_child, ^vault, %Error{}}} = reason

        refute_rendered(inspect(reason))
        refute_rendered(Exception.format_exit(reason))
      end
    end
  end

  describe "a vault whose provider fails a resolution" do
    setup do
      start_supervised!(Supervisor.child_spec({ResolveVault, []}, restart: :temporary))
      :ok
    end

    # sabotage: rendered the engine term unredacted - red on the off-contract
    # mode; removed the {:invalid_key_descriptor, _} redaction clause - red on
    # the descriptor mode.
    test "keeps the provider's term out of inspect/2 on every failure shape" do
      for mode <- [:off_contract, :bare, :descriptor] do
        Process.put(:leaky_resolve_mode, mode)

        assert {:error, %Error{operation: :encrypt} = error} = ResolveVault.encrypt("plaintext")
        assert {:invalid_key_descriptor, _detail} = error.reason

        refute_rendered(inspect(error))
        refute_rendered(Exception.message(error))
      end
    end
  end
end
