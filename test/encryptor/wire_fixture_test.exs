defmodule Encryptor.WireFixtureTest do
  @moduledoc """
  What encryptor 0.4.1 wrote does not open under wire format v2.

  ADR-0009 Amendment A respells every owner-noun wire constant and keeps no
  v1 read path (A3). These tests read bytes 0.4.1 produced -
  `Encryptor.WireFixtureVaults` records how - and pin that clean cut: the v1
  row is refused, and so is the v1 ciphertext even when the vault is handed
  the very key it was written under. Each sabotage note names the respelling
  back to v1 that turns its test red, so a v1 read path cannot come back
  without a test saying so.
  """

  use ExUnit.Case, async: false

  alias Encryptor.Envelope
  alias Encryptor.Error
  alias Encryptor.Message
  alias Encryptor.WireFixtureVaults, as: Fixture
  alias Encryptor.WireFixtureVaults.RootVault
  alias Encryptor.WireFixtureVaults.ScopedVault

  setup do
    start_supervised!(Supervisor.child_spec({RootVault, []}, restart: :temporary))
    :ok
  end

  # An `{:ok, _}` here would be key material under a sabotage, and key
  # material must not reach a failure report.
  defp no_value({:ok, _material}), do: :opened
  defp no_value(error), do: error

  describe "a wrapped-key row written by 0.4.1" do
    # A3, rows 3 and 4: the row's binding spells them in v1. sabotage:
    # respelled `@scope_ref_key` and `@wrap_purpose` in `Encryptor.Envelope`
    # back to "encryptor-tenant-ref" and "tenant-key-wrap" - red, the row
    # unwraps.
    test "does not unwrap under the root vault" do
      assert {:error, %Error{reason: :decrypt_failed}} =
               Envelope.unwrap(RootVault, Fixture.row())
    end

    # A3, rows 3 and 4. sabotage: the same two respellings - red, because the
    # rewrap re-applies the binding and the blob then carries a matching one.
    test "does not rewrap either" do
      assert {:error, %Error{reason: :decrypt_failed}} =
               Envelope.rewrap(RootVault, Fixture.row())
    end

    # Its binding carries pairs under the package prefix in either spelling,
    # so the root vault's own doors refuse it as they refuse a v2 wrapping.
    # sabotage: removed the package-reserved clause from `compare/4` in
    # `Encryptor.Vault.Decrypt` - red: the decrypt and the rekey open it.
    test "is not opened by the root vault's public decrypt or rekey" do
      assert {:error, %Error{reason: :decrypt_failed}} =
               no_value(RootVault.decrypt(Fixture.row().wrapped))

      assert {:error, %Error{reason: :decrypt_failed}} =
               no_value(RootVault.rekey(Fixture.row().wrapped))
    end
  end

  describe "a ciphertext written by 0.4.1" do
    setup do
      start_supervised!(Supervisor.child_spec({ScopedVault, []}, restart: :temporary))
      :ok
    end

    # A3, rows 1 and 7: the context pair is spelled in v1 and the reference
    # was derived under the retired label, and `ScopedVault` holds the right
    # key, so nothing else can be what refuses it. sabotage: respelled
    # `@scope_ref` in `Encryptor.Context` back to "tenant_ref" and derived the
    # fixture's reference subkey under "tenant-ref" - red, it decrypts. Either
    # respelling alone stays refused: the pair is then under the right key
    # with the wrong reference, or the wrong key with the right one.
    test "does not decrypt on a :scoped vault, even holding the key it was written under" do
      assert {:error, %Error{reason: :decrypt_failed}} =
               ScopedVault.decrypt(Fixture.ciphertext(),
                 key: Fixture.selector(),
                 encryption_context: Fixture.context()
               )
    end

    # A3, row 1. sabotage: respelled `@scope_ref` in `Encryptor.Context` back
    # to "tenant_ref" - red on the refute: the key the current build writes
    # is then the one the 0.4.1 header carries.
    test "carries its reference under the v1 context key, which the current build does not write" do
      assert {:ok, info} = Message.describe(Fixture.ciphertext())

      assert info.encryption_context["tenant_ref"] == Fixture.reference()
      refute Map.has_key?(info.encryption_context, Encryptor.Context.scope_ref_key())
    end

    # A3, row 7. sabotage: changed `Encryptor.Kdf.label/1` to compose the
    # retired purpose for "scope-ref" - red: the subkey a host derives under
    # the v2 purpose then yields the 0.4.1 reference.
    test "was written under a reference the current build's subkey does not derive" do
      refute {:ok, Fixture.reference()} ==
               Envelope.scope_ref(Fixture.reference_subkey(), Fixture.selector())
    end
  end
end
