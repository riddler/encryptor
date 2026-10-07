defmodule Encryptor.Vault.InspectRedactionTest do
  # A provider's failure can hold anything, key material included. The vault
  # carries a provider's own term in an error's `:engine`, and a provider's
  # `:invalid_config` or `:invalid_key_descriptor` detail in `:reason`, and
  # renders neither; every other value beside a reason's tag is the vault's
  # own. These tests start real vaults over providers whose failures carry a
  # key-shaped value and check that neither `inspect/2` nor
  # `Exception.message/1` of the error, nor the text a supervisor reports when
  # the vault fails to start, ever renders it.
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
        :missing_config -> {:error, {:missing_config, value}}
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

    @doc "Fails off the contract, or in it with a key-shaped value beside the tag."
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
        :unknown_key -> {:error, {:unknown_key, value}}
        :key_unavailable -> {:error, {:key_unavailable, value}}
        :not_started -> {:error, {:provider_not_started, value}}
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

  defmodule MissingConfigVault do
    @moduledoc "A vault whose provider fails at start with a `:missing_config` holding no path."

    use Encryptor.Vault, otp_app: :encryptor, context_profile: :single

    @doc "Layer 5: names the failing provider."
    def init(config) do
      {:ok,
       Keyword.put(
         config,
         :provider,
         {Encryptor.Vault.InspectRedactionTest.LeakyInit, mode: :missing_config}
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

    # sabotage: carried any {:missing_config, _} from a provider's init/1 into
    # :reason as it was - red.
    test "carries a :missing_config that is not a path of option names in :engine" do
      assert {:error, %Error{reason: {:invalid_config, :provider, :init}} = error} =
               MissingConfigVault.start_link([])

      assert error.engine == {:missing_config, @key_shaped}

      refute_rendered(inspect(error))
      refute_rendered(Exception.message(error))
    end

    # sabotage: deleted the Inspect implementation - red; removing the
    # {:invalid_config, _, _} redaction clause - red, on the second vault;
    # carrying a provider's {:missing_config, _} into :reason - red, on the
    # third.
    test "keeps the term out of a parent supervisor's failed-start exit" do
      Process.flag(:trap_exit, true)

      for vault <- [OwnTermVault, InvalidConfigVault, MissingConfigVault] do
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
    # the descriptor mode; accepted a {:provider_not_started, _} of any shape
    # as in contract - red on the not-started mode.
    test "keeps the provider's term out of off-contract and descriptor failures" do
      for mode <- [:off_contract, :bare, :descriptor, :not_started] do
        Process.put(:leaky_resolve_mode, mode)

        assert {:error, %Error{operation: :encrypt} = error} = ResolveVault.encrypt("plaintext")
        assert {:invalid_key_descriptor, _detail} = error.reason

        refute_rendered(inspect(error))
        refute_rendered(Exception.message(error))
      end
    end

    # sabotage: carried the provider's own second element in place of the
    # vault's selector - red, on both tags.
    test "a selector term carries the vault's selector, not the provider's value" do
      for tag <- [:unknown_key, :key_unavailable] do
        Process.put(:leaky_resolve_mode, tag)

        assert {:error, %Error{reason: reason} = error} = ResolveVault.encrypt("plaintext")
        assert reason == {tag, :default}

        refute_rendered(inspect(error))
        refute_rendered(Exception.message(error))
      end
    end
  end
end
