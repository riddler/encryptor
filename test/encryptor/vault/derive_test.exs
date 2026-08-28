defmodule Encryptor.Vault.DeriveTest do
  use ExUnit.Case, async: false

  alias Encryptor.DeriveVaults
  alias Encryptor.Error
  alias Encryptor.Kdf
  alias Encryptor.Vault

  defp start_vault(vault) do
    start_supervised!(Supervisor.child_spec({vault, []}, restart: :temporary))
    vault
  end

  describe "derive/3 on a single-key vault" do
    # Sabotage: replaced `Kdf.salted_subkey/5` with `Kdf.derive_subkey/3` in
    # `Derive.call/3`, dropping the extract step. Red.
    test "derives the salted construction, and nothing else" do
      vault = start_vault(DeriveVaults.App)

      assert {:ok, derived} = Vault.derive(vault, "blind-index", info: "orders.email")

      expected =
        Kdf.salted_subkey(
          DeriveVaults.app_key(),
          DeriveVaults.salt(),
          "blind-index",
          "orders.email",
          32
        )

      assert derived == expected
    end

    # Sabotage: made `out_length/2` ignore `:length` and always answer 32. Red.
    test "honours :length, and defaults it to 32" do
      vault = start_vault(DeriveVaults.App)

      assert {:ok, long} = Vault.derive(vault, "blind-index", info: "x", length: 64)
      assert {:ok, default} = Vault.derive(vault, "blind-index", info: "x")

      assert byte_size(long) == 64
      assert byte_size(default) == 32
    end

    # Sabotage: made `info/2` default to the purpose instead of `""`. Red.
    test "an absent :info is a scope of its own, not the purpose key" do
      vault = start_vault(DeriveVaults.App)

      assert {:ok, derived} = Vault.derive(vault, "blind-index")

      purpose_key =
        DeriveVaults.salt()
        |> Kdf.extract(DeriveVaults.app_key())
        |> Kdf.expand(Kdf.label("blind-index"), 32)

      refute derived == purpose_key
      assert derived == Kdf.expand(purpose_key, "", 32)
    end

    # Sabotage: derived under a fixed purpose instead of the caller's. Red.
    test "distinct purposes and distinct infos yield distinct keys" do
      vault = start_vault(DeriveVaults.App)

      assert {:ok, index} = Vault.derive(vault, "blind-index", info: "orders.email")
      assert {:ok, other_purpose} = Vault.derive(vault, "search-token", info: "orders.email")
      assert {:ok, other_info} = Vault.derive(vault, "blind-index", info: "orders.pan")

      assert index != other_purpose
      assert index != other_info
      assert other_purpose != other_info
    end

    # Sabotage: made `derive/3` return the resolved descriptor's material
    # alongside the derived bytes. Red - and this is the assertion the whole
    # surface exists for (ADR-0003 amendment A decision 4).
    test "the key material never appears in what the caller receives" do
      vault = start_vault(DeriveVaults.App)

      assert {:ok, derived} = Vault.derive(vault, "blind-index", info: "orders.email")

      refute derived == DeriveVaults.app_key()
      assert :binary.match(derived, DeriveVaults.app_key()) == :nomatch
    end
  end

  describe "derive/3 and the deployment salt" do
    # Sabotage: took the salt from `opts[:salt]` with the config as fallback,
    # so a caller could override it. Red on the second clause.
    test "the same key material under two salts derives unrelated keys" do
      production = start_vault(DeriveVaults.Deployment)
      staging = start_vault(DeriveVaults.Restored)

      assert {:ok, from_production} =
               Vault.derive(production, "blind-index", info: "orders.email")

      assert {:ok, from_staging} = Vault.derive(staging, "blind-index", info: "orders.email")

      assert from_production != from_staging
    end

    # Sabotage: had `salt/1` fall back to a constant when the config held
    # `nil`. Red.
    test "a vault with no salt starts, and fails only the derivation" do
      vault = start_vault(DeriveVaults.Unsalted)

      assert Vault.started?(vault)
      assert {:ok, _ciphertext} = Vault.encrypt(vault, "4111111111111111")

      assert {:error, %Error{} = error} = Vault.derive(vault, "blind-index", info: "x")
      assert error.reason == {:missing_config, [:derivation_salt]}
      assert error.operation == :derive
      assert error.vault == vault
    end

    # Sabotage: let a caller-supplied `:salt` option through into the
    # derivation. Red.
    test "a caller cannot supply or override the salt" do
      vault = start_vault(DeriveVaults.App)

      assert {:ok, with_option} =
               Vault.derive(vault, "blind-index",
                 info: "orders.email",
                 salt: DeriveVaults.other_salt()
               )

      assert {:ok, without_option} = Vault.derive(vault, "blind-index", info: "orders.email")

      assert with_option == without_option
    end
  end

  describe "derive/3 on a tenant vault" do
    # Sabotage: resolved every selector to the first merchant. Red.
    test "two merchants derive unrelated keys for one scope" do
      vault = start_vault(DeriveVaults.Merchant)

      assert {:ok, a} =
               Vault.derive(vault, "blind-index", key: "merchant_a", info: "orders.email")

      assert {:ok, b} =
               Vault.derive(vault, "blind-index", key: "merchant_b", info: "orders.email")

      assert a != b

      assert a ==
               Kdf.salted_subkey(
                 DeriveVaults.merchant_key("merchant_a"),
                 DeriveVaults.salt(),
                 "blind-index",
                 "orders.email",
                 32
               )
    end

    # Sabotage: dropped the `Resolve.selector/3` step, so an absent `:key`
    # reached the provider as `:default`. Red.
    test "an absent selector is refused before the provider is consulted" do
      vault = start_vault(DeriveVaults.Merchant)

      assert {:error, %Error{} = error} = Vault.derive(vault, "blind-index", info: "x")
      assert error.reason == {:invalid_selector, :default}
      assert error.operation == :derive
    end

    # Sabotage: mapped an unknown selector onto `:decrypt_failed`. Red.
    test "an unknown merchant is the provider's own refusal" do
      vault = start_vault(DeriveVaults.Merchant)

      assert {:error, %Error{} = error} =
               Vault.derive(vault, "blind-index", key: "merchant_z", info: "x")

      assert error.reason == {:unknown_key, "merchant_z"}
      assert error.operation == :derive
    end
  end

  describe "derive/3 refusals" do
    # Sabotage: made `derivable/2` fall through to a `<<>>` material for a
    # non-AES descriptor. Red.
    test "a KMS descriptor is refused rather than exported" do
      vault = start_vault(DeriveVaults.Managed)

      assert {:error, %Error{} = error} = Vault.derive(vault, "blind-index", info: "x")
      assert error.reason == {:invalid_key_descriptor, :not_derivable}
      assert error.operation == :derive
      assert error.engine == nil
    end

    # Sabotage: passed `:length` through without checking it, so a non-integer
    # raised a FunctionClauseError from inside the KDF. Red.
    test "a non-positive-integer length is a typed error, not a raise" do
      vault = start_vault(DeriveVaults.App)

      assert {:error, %Error{reason: {:invalid_config, :length, :not_a_positive_integer}}} =
               Vault.derive(vault, "blind-index", length: 0)

      assert {:error, %Error{reason: {:invalid_config, :length, :not_a_positive_integer}}} =
               Vault.derive(vault, "blind-index", length: :thirty_two)
    end

    # Sabotage: accepted a non-binary `:info` and let it reach `expand/3`. Red.
    test "a non-binary info is a typed error, not a raise" do
      vault = start_vault(DeriveVaults.App)

      assert {:error, %Error{reason: {:invalid_config, :info, :not_a_binary}}} =
               Vault.derive(vault, "blind-index", info: :orders_email)
    end

    # Sabotage: removed the `Vault.ready/2` step. Red.
    test "an unstarted vault is refused with :derive as the operation" do
      assert {:error, %Error{} = error} = Vault.derive(DeriveVaults.App, "blind-index")
      assert error.reason == {:vault_not_started, DeriveVaults.App}
      assert error.operation == :derive
    end

    # Sabotage: dropped `label/1`'s separator guard on this path. Red.
    test "a purpose that could spell another label raises" do
      vault = start_vault(DeriveVaults.App)

      assert_raise ArgumentError, ~s(a derivation purpose may not contain "/"), fn ->
        Vault.derive(vault, "v1/root-wrap")
      end
    end
  end

  describe "the generated derive/2" do
    # Sabotage: had the generated clause call `Vault.derive/3` with a
    # hard-coded module. Red.
    test "delegates to Encryptor.Vault.derive/3 with its own module" do
      vault = start_vault(DeriveVaults.App)

      assert DeriveVaults.App.derive("blind-index", info: "orders.email") ==
               Vault.derive(vault, "blind-index", info: "orders.email")
    end
  end
end
