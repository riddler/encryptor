defmodule Encryptor.ProviderTest do
  use ExUnit.Case, async: true

  alias Encryptor.Provider

  doctest Encryptor.Provider

  defmodule WithInit do
    @moduledoc false
    @behaviour Encryptor.Provider

    @impl true
    def init(opts), do: {:ok, %{namespace: Keyword.fetch!(opts, :namespace)}}

    @impl true
    def encryption_key(_state, _selector), do: {:error, {:unknown_key, :default}}

    @impl true
    def decryption_keys(_state, _selector), do: {:error, {:unknown_key, :default}}
  end

  defmodule RefusingInit do
    @moduledoc false
    @behaviour Encryptor.Provider

    @impl true
    def init(_opts), do: {:error, {:missing_config, [:provider, :key]}}

    @impl true
    def encryption_key(_state, _selector), do: {:error, {:unknown_key, :default}}

    @impl true
    def decryption_keys(_state, _selector), do: {:error, {:unknown_key, :default}}
  end

  defmodule NoInit do
    @moduledoc false
    @behaviour Encryptor.Provider

    @impl true
    def encryption_key(state, _selector), do: {:ok, state}

    @impl true
    def decryption_keys(state, _selector), do: {:ok, [state]}
  end

  describe "init/2" do
    # sabotage: made init/2 call module.init/1 unconditionally - the NoInit
    # case goes red with an UndefinedFunctionError. The fallback is the
    # contract clause that lets a provider with nothing to resolve omit the
    # callback entirely.
    test "falls back to the option list for a provider that exports no init/1" do
      assert {:ok, [namespace: "myapp"]} = Provider.init(NoInit, namespace: "myapp")
    end

    # sabotage: made init/2 return {:ok, opts} in both branches - this goes
    # red. A provider whose init/1 is skipped is a provider whose state is its
    # raw options, which is not what any configured adapter expects.
    test "calls init/1 when the provider exports one" do
      assert {:ok, %{namespace: "myapp"}} = Provider.init(WithInit, namespace: "myapp")
    end

    # sabotage: wrapped the module.init/1 call so a refusal became {:ok, opts}
    # - this goes red. A provider that refuses its own configuration has to
    # stop the vault from starting, not be started with the options it just
    # rejected.
    test "passes a provider's refusal through unchanged" do
      assert {:error, {:missing_config, [:provider, :key]}} = Provider.init(RefusingInit, [])
    end

    test "treats a module that does not exist as one with no init/1" do
      assert {:ok, [key: "opaque"]} = Provider.init(Encryptor.NoSuchProviderModule, key: "opaque")
    end
  end

  describe "the behaviour itself" do
    # sabotage: removed :init and :child_spec from @optional_callbacks -
    # compiling NoInit warns about a missing callback, and warnings are errors
    # in this repo's gate, so this goes red at compile time.
    test "declares init/1 and child_spec/1 optional" do
      assert Enum.sort(Encryptor.Provider.behaviour_info(:optional_callbacks)) ==
               [child_spec: 1, init: 1]
    end

    test "declares the two resolution callbacks required" do
      required =
        Encryptor.Provider.behaviour_info(:callbacks) --
          Encryptor.Provider.behaviour_info(:optional_callbacks)

      assert Enum.sort(required) == [decryption_keys: 2, encryption_key: 2]
    end
  end
end
