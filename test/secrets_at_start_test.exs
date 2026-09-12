defmodule Encryptor.SecretsAtStartTest do
  @moduledoc """
  Executes the claims `guides/secrets-at-start.md` makes about start.

  The guide's subject is the failure as much as the success: what a vault does
  when the variable holding its key is absent, when it holds something that is
  not the form the guide decodes, and when a lenient read lets `nil` travel
  past the mistake. None of those is visible by reading an example, so each
  one is asserted here against the landed surface, and the vaults are
  transcribed in `Encryptor.SecretSourcingVaults`.

  What is deliberately *not* re-asserted here: the precedence chain itself,
  the `{:invalid_config, :init, :bad_return}` refusal, and the compile-time
  key-material refusal. All three are `Encryptor.Vault.ConfigTest`'s, and a
  second copy of them is a second place for them to drift.
  """

  use ExUnit.Case, async: false

  alias Encryptor.Error
  alias Encryptor.SecretSourcingVaults
  alias Encryptor.SecretSourcingVaults.LenientVault
  alias Encryptor.SecretSourcingVaults.Vault
  alias Encryptor.Vault.Config

  @context %{"table" => "ledger_entries", "column" => "amount"}

  setup do
    SecretSourcingVaults.put_env()
    on_exit(&SecretSourcingVaults.put_env/0)
    :ok
  end

  defp start(vault), do: start_supervised(Supervisor.child_spec({vault, []}, restart: :temporary))

  defp start!(vault) do
    start_supervised!(Supervisor.child_spec({vault, []}, restart: :temporary))
    vault
  end

  describe "reading the secret from the environment" do
    # sabotage: made `Encryptor.Vault.Config.apply_init/2` return the merged
    # list unchanged - red, because the vault then has no provider at all.
    test "the key init/1 read is the key the vault froze" do
      start!(Vault)

      assert {:ok, %Config{provider_state: %{keys: [key]}}} = Vault.config()
      assert key.namespace == "acme_payments"
      assert key.name == "ledger/v1"
      assert SecretSourcingVaults.fixture_key?(key.material)
    end

    # sabotage: made `Encryptor.Vault.encrypt/3` return the plaintext instead
    # of calling the encrypt path; red.
    test "a vault configured from the environment encrypts and decrypts" do
      start!(Vault)

      assert {:ok, ciphertext} = Vault.encrypt("120.00", encryption_context: @context)
      refute ciphertext == "120.00"
      assert {:ok, "120.00"} = Vault.decrypt(ciphertext, encryption_context: @context)
    end
  end

  describe "refusing to start without the secret" do
    # sabotage: made `Encryptor.Vault.Config.apply_init/2` rescue the
    # callback and keep the merge - red, because the start then fails as
    # `{:missing_config, [:provider]}` rather than surfacing the exception
    # the guide prints.
    test "a deployment that never set the variable does not start" do
      SecretSourcingVaults.delete_env()

      assert {:error, {{:EXIT, {exception, _stacktrace}}, _child_spec}} = start(Vault)
      assert is_struct(exception, System.EnvError)
      refute Vault.started?()
    end

    # sabotage: as above; red for the same reason.
    test "a variable holding something other than base64 does not start" do
      SecretSourcingVaults.put_env("not base64, and not a key either")

      assert {:error, {{:EXIT, {exception, _stacktrace}}, _child_spec}} = start(Vault)
      assert is_struct(exception, ArgumentError)
      refute Vault.started?()
    end

    # sabotage: removed `Encryptor.Provider.Static`'s key-size check - red,
    # because a `nil` key then reaches the keyring builder instead of the
    # start refusing.
    test "System.get_env/1 lets a missing secret travel as far as the provider" do
      SecretSourcingVaults.delete_env()

      assert {:error, {%Error{} = error, _child_spec}} = start(LenientVault)
      assert error.reason == {:invalid_config, :provider, :key_size}
      refute LenientVault.started?()
    end
  end
end
