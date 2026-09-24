defmodule Encryptor.WireFixtureTest do
  @moduledoc """
  What encryptor 0.4.1 wrote still opens under the Scope names.

  ADR-0009 renames the Elixir surface and pins every v1 wire spelling behind
  it (decision 4). A green suite that only round-trips its own output cannot
  see a changed constant, so these tests read bytes 0.4.1 produced -
  `Encryptor.WireFixtureVaults` records how - and name the row of decision
  4's table each assertion stands on.
  """

  use ExUnit.Case, async: false

  alias Encryptor.Envelope
  alias Encryptor.Envelope.WrappedKey
  alias Encryptor.Key.Aes
  alias Encryptor.Message
  alias Encryptor.WireFixtureVaults, as: Fixture
  alias Encryptor.WireFixtureVaults.RootVault
  alias Encryptor.WireFixtureVaults.ScopedVault

  setup do
    start_supervised!(Supervisor.child_spec({RootVault, []}, restart: :temporary))
    :ok
  end

  describe "a wrapped-key row written by 0.4.1" do
    # sabotage: respelled `@scope_ref_key` in `Encryptor.Envelope` as
    # "encryptor-scope-ref" - red, the binding no longer matches the blob
    # (row 3); respelling `@wrap_purpose` as "scope-key-wrap" is red the same
    # way (row 4).
    test "unwraps unchanged under the root vault" do
      assert {:ok, %Aes{bits: 256, namespace: "encryptor-tenant", name: name}} =
               Envelope.unwrap(RootVault, Fixture.row())

      assert name == "t/" <> Fixture.reference() <> "/v1"
    end

    # sabotage: same two respellings - red, because the rewrap re-applies the
    # binding and the blob it reads carries the 0.4.1 one.
    test "rewraps unchanged, keeping every identity field" do
      row = Fixture.row()

      assert {:ok, %WrappedKey{} = rewrapped} = Envelope.rewrap(RootVault, row)
      assert %{rewrapped | wrapped: nil} == %{row | wrapped: nil}
      assert {:ok, %Aes{}} = Envelope.unwrap(RootVault, rewrapped)
    end

    # sabotage: respelled the `"t/"` prefix in `Envelope.key_name/2` - red
    # (row 2); respelled `@default_namespace` - red on the provisioned row
    # (row 5).
    test "is the row the current build would provision for the same selector" do
      assert {:ok, provisioned} =
               Envelope.provision(RootVault, Fixture.selector(),
                 reference_subkey: Fixture.reference_subkey()
               )

      row = Fixture.row()
      assert provisioned.scope_ref == row.scope_ref
      assert provisioned.namespace == row.namespace
      assert provisioned.name == row.name
      assert Envelope.key_name(row.scope_ref, row.version) == row.name
    end

    # sabotage: changed `Encryptor.Kdf`'s `@label_namespace` - red, every
    # reference moves (row 7); the host's `"tenant-ref"` purpose is row 6.
    test "is found by the reference the current build derives" do
      assert {:ok, Fixture.reference()} ==
               Envelope.scope_ref(Fixture.reference_subkey(), Fixture.selector())
    end
  end

  describe "a ciphertext written by 0.4.1" do
    setup do
      start_supervised!(Supervisor.child_spec({ScopedVault, []}, restart: :temporary))
      :ok
    end

    # sabotage: respelled `@scope_ref` in `Encryptor.Context` as "scope_ref" -
    # red, the vault-supplied pair no longer matches the stored one (row 1).
    test "decrypts unchanged on a :scoped vault" do
      assert {:ok, plaintext} =
               ScopedVault.decrypt(Fixture.ciphertext(),
                 key: Fixture.selector(),
                 encryption_context: Fixture.context()
               )

      assert plaintext == Fixture.plaintext()
    end

    # sabotage: same respelling as above - red, `Context.scope_ref_key/0`
    # returns the new spelling and the lookup misses.
    test "carries the reference under the v1 context key" do
      assert {:ok, info} = Message.describe(Fixture.ciphertext())

      assert info.encryption_context[Encryptor.Context.scope_ref_key()] == Fixture.reference()
      assert info.encryption_context["tenant_ref"] == Fixture.reference()

      assert [%{provider_id: "encryptor-tenant", key_name: key_name}] =
               info.encrypted_data_keys

      assert key_name == "t/" <> Fixture.reference() <> "/v1"
    end

    # sabotage: same respelling - red, the rekey reproduces the context
    # before it re-encrypts and the stored pair no longer matches.
    test "rekeys under the current build, keeping the stored context" do
      assert {:ok, rekeyed} = ScopedVault.rekey(Fixture.ciphertext(), key: Fixture.selector())

      assert {:ok, before} = Message.describe(Fixture.ciphertext())
      assert {:ok, after_rekey} = Message.describe(rekeyed)
      assert after_rekey.encryption_context == before.encryption_context
    end
  end
end
