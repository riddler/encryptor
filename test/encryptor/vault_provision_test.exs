defmodule Encryptor.VaultProvisionTest do
  @moduledoc """
  ADR-0007 decision 2's vault-level entry point.

  Hosts do not hold the provider state, so `provision/1` on the vault is the
  only way to reach `c:Encryptor.Provider.provision/2` - and a provider that
  has no such callback has to answer a settled term rather than raising.
  """

  use ExUnit.Case, async: true

  alias Encryptor.Error
  alias Encryptor.GcpKmsCase
  alias Encryptor.GcpKmsVaults
  alias Encryptor.Vault.Reference

  @selector "tenant-42"

  setup do
    start_supervised!(Supervisor.child_spec({GcpKmsVaults.Tenant, []}, restart: :temporary))

    start_supervised!(
      Supervisor.child_spec({GcpKmsVaults.NotProvisionable, []}, restart: :temporary)
    )

    :ok
  end

  # mutation: call the provider directly with the host's own options - the
  # state the vault froze at start is the only state the callback may see.
  test "provisions through the vault's frozen provider state" do
    assert {:ok, row} = GcpKmsVaults.Tenant.provision(@selector)

    assert row.tenant_ref == Reference.derive(GcpKmsCase.subkey(), @selector)
    assert row.version == 1
    assert row.bits == 256
  end

  # mutation: call the callback without checking that it is exported - a host
  # that configured a provider whose keys arrive some other way gets an
  # UndefinedFunctionError instead of a configuration answer.
  test "answers not_provisionable for a provider with no provision callback" do
    assert {:error, %Error{reason: {:not_provisionable, Encryptor.Provider.Static}} = error} =
             GcpKmsVaults.NotProvisionable.provision(:default)

    assert error.operation == :provision
    assert Exception.message(error) =~ "cannot provision key material"
  end

  # mutation: skip the selector check - a tenant vault would mint an
  # undeletable GCP key for a selector that names no tenant.
  test "types the selector against the vault's context profile" do
    assert {:error, %Error{reason: {:invalid_selector, :default}}} =
             GcpKmsVaults.Tenant.provision(:default)

    assert {:error, %Error{reason: {:invalid_selector, "anything"}}} =
             GcpKmsVaults.NotProvisionable.provision("anything")
  end

  test "reports a vault that is not started" do
    assert {:error, %Error{reason: {:vault_not_started, _vault}, operation: :provision}} =
             Encryptor.Vault.provision(Encryptor.GcpKmsVaults.Unstarted, @selector)
  end
end
