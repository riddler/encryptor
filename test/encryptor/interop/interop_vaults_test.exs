defmodule Encryptor.InteropVaultsTest do
  use ExUnit.Case, async: false

  alias Encryptor.InteropVaults
  alias Encryptor.PythonInterop

  defmodule FailingVault do
    @moduledoc false
    # Fails to start with the run's wrapping key in the reason, the way a
    # vault whose provider config carries the key could.
    def child_spec(_), do: %{id: __MODULE__, start: {__MODULE__, :start_link, []}}

    def start_link, do: {:error, {:bad_config, Encryptor.PythonInterop.key(:wrapping_key)}}
  end

  setup do
    :ok = PythonInterop.generate_keys()
  end

  test "a vault start failure raises naming the vault and prints no key material" do
    key = PythonInterop.key(:wrapping_key)

    error = assert_raise RuntimeError, fn -> InteropVaults.start_vault!(FailingVault) end

    assert error.message =~ inspect(FailingVault)
    refute error.message =~ key
    refute error.message =~ inspect(key)
    refute error.message =~ inspect(key, binaries: :as_binaries)
  end

  test "the stock start_supervised! message does print the key (the control)" do
    key = PythonInterop.key(:wrapping_key)

    error = assert_raise RuntimeError, fn -> start_supervised!(FailingVault) end

    assert error.message =~ inspect(key, binaries: :as_binaries)
  end

  # sabotage: made start_vault!/1 call start_supervised!/1 (its message
  # carries the reason) - red, the first test, key bytes in the message.
end
