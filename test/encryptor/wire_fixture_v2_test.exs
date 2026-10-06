defmodule Encryptor.WireFixtureV2Test do
  @moduledoc """
  What wire format v2 wrote opens under the current build, byte for byte.

  ADR-0009 Amendment A pins every spelling in its A1 table from 0.7.0 on. A
  green suite that only round-trips its own output cannot see a changed
  constant, so these tests read bytes recorded once from the build that
  introduced v2 - `Encryptor.WireFixtureV2Vaults` records how - and name the
  A1 row each assertion stands on.
  """

  use ExUnit.Case, async: false

  alias Encryptor.Envelope
  alias Encryptor.Envelope.WrappedKey
  alias Encryptor.Key.Aes
  alias Encryptor.Message
  alias Encryptor.WireFixtureV2Vaults, as: Fixture
  alias Encryptor.WireFixtureV2Vaults.RootVault
  alias Encryptor.WireFixtureV2Vaults.ScopedVault

  setup do
    start_supervised!(Supervisor.child_spec({RootVault, []}, restart: :temporary))
    :ok
  end

  describe "a wrapped-key row written under v2" do
    # Rows 3 and 4. sabotage: respelled `@scope_ref_key` in
    # `Encryptor.Envelope` as "encryptor-tenant-ref" - red, the binding no
    # longer matches the blob; respelling `@wrap_purpose` as
    # "tenant-key-wrap" is red the same way.
    test "unwraps under the root vault" do
      assert {:ok, %Aes{bits: 256, namespace: "encryptor-scope", name: name}} =
               Envelope.unwrap(RootVault, Fixture.row())

      assert name == "s/" <> Fixture.reference() <> "/v1"
    end

    # Rows 3, 4 and 5, read out of the recorded blob rather than from the
    # module under test, so this pins the record, not `lib/`. sabotage:
    # respelled the purpose value in the expected map as "tenant-key-wrap" -
    # red, the recorded header carries the v2 spelling.
    test "carries the v2 binding in its own header" do
      assert {:ok, info} = Message.describe(Fixture.row().wrapped)

      assert info.encryption_context == %{
               "encryptor-purpose" => "scope-key-wrap",
               "encryptor-scope-ref" => Fixture.reference(),
               "encryptor-key-version" => "1",
               "encryptor-key-namespace" => "encryptor-scope"
             }
    end

    # Rows 3 and 4. sabotage: the same two respellings - red, because the
    # rewrap re-applies the binding and the blob it reads carries the v2 one.
    test "rewraps, keeping every identity field" do
      row = Fixture.row()

      assert {:ok, %WrappedKey{} = rewrapped} = Envelope.rewrap(RootVault, row)
      assert %{rewrapped | wrapped: nil} == %{row | wrapped: nil}
      assert {:ok, %Aes{}} = Envelope.unwrap(RootVault, rewrapped)
    end

    # Rows 2 and 5. sabotage: respelled the `"s/"` prefix in
    # `Envelope.key_name/2` as "t/" - red; respelled `Encryptor.Envelope`'s
    # `@default_namespace` as "encryptor-tenant" - red on the provisioned row.
    test "is the row the current build provisions for the same selector" do
      assert {:ok, provisioned} =
               Envelope.provision(RootVault, Fixture.selector(),
                 reference_subkey: Fixture.reference_subkey()
               )

      row = Fixture.row()
      assert provisioned.scope_ref == row.scope_ref
      assert provisioned.namespace == "encryptor-scope"
      assert provisioned.namespace == row.namespace
      assert provisioned.name == "s/" <> row.scope_ref <> "/v1"
      assert provisioned.name == row.name
      assert Envelope.key_name(row.scope_ref, row.version) == row.name
    end

    # Rows 6 and 7. sabotage: changed `Encryptor.Kdf`'s `@label_namespace` -
    # red, every reference moves (row 7); deriving the fixture's subkey under
    # the retired "tenant-ref" is red the same way (row 6).
    test "is found by the reference the current build derives" do
      assert {:ok, Fixture.reference()} ==
               Envelope.scope_ref(Fixture.reference_subkey(), Fixture.selector())
    end
  end

  describe "a ciphertext written under v2" do
    setup do
      start_supervised!(Supervisor.child_spec({ScopedVault, []}, restart: :temporary))
      :ok
    end

    # Row 1. sabotage: respelled `@scope_ref` in `Encryptor.Context` as
    # "tenant_ref" - red, the vault-supplied pair no longer matches the
    # stored one.
    test "decrypts on a :scoped vault" do
      assert {:ok, plaintext} =
               ScopedVault.decrypt(Fixture.ciphertext(),
                 key: Fixture.selector(),
                 encryption_context: Fixture.context()
               )

      assert plaintext == Fixture.plaintext()
    end

    # Rows 1, 2 and 5. sabotage: same respelling of `@scope_ref` - red on the
    # `scope_ref_key/0` lookup, which then misses.
    test "carries the reference under the v2 context key and the v2 key name" do
      assert {:ok, info} = Message.describe(Fixture.ciphertext())

      assert info.encryption_context[Encryptor.Context.scope_ref_key()] == Fixture.reference()

      assert info.encryption_context == %{
               "scope_ref" => Fixture.reference(),
               "table" => "fixtures",
               "column" => "secret"
             }

      assert [%{provider_id: "encryptor-scope", key_name: key_name}] =
               info.encrypted_data_keys

      assert key_name == "s/" <> Fixture.reference() <> "/v1"
    end

    # Row 1. sabotage: same respelling - red, the rekey reproduces the context
    # before it re-encrypts and the stored pair no longer matches.
    test "rekeys under the current build, keeping the stored context" do
      assert {:ok, rekeyed} = ScopedVault.rekey(Fixture.ciphertext(), key: Fixture.selector())

      assert {:ok, before} = Message.describe(Fixture.ciphertext())
      assert {:ok, after_rekey} = Message.describe(rekeyed)
      assert after_rekey.encryption_context == before.encryption_context
    end
  end
end
