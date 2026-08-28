defmodule Encryptor.GuidesTest do
  @moduledoc """
  Executes the code the guides print.

  `guides/getting-started.md` and `guides/rotation-runbook.md` are the
  highest-visibility example surface in the package, and an example that does
  not run reads exactly like one that does. Every assertion here corresponds to
  a block or a claim in one of the two guides, named in the test description,
  so a guide that drifts from the landed surface fails the gate rather than
  misleading a reader.

  The vaults, the store and the provider are transcribed in
  `Encryptor.GuideVaults`; the two deliberate differences from the printed
  text are recorded there.
  """

  use ExUnit.Case, async: false

  alias Encryptor.Envelope
  alias Encryptor.Envelope.WrappedKey
  alias Encryptor.Error
  alias Encryptor.GuideVaults
  alias Encryptor.GuideVaults.MerchantKeys
  alias Encryptor.GuideVaults.MerchantVault
  alias Encryptor.GuideVaults.RootVault
  alias Encryptor.GuideVaults.StagedRootVault
  alias Encryptor.GuideVaults.Vault
  alias Encryptor.Key.Aes
  alias Encryptor.Message
  alias Encryptor.Vault.Config

  @pan "4111111111111111"
  @merchant "merchant-42"
  @column_context %{"table" => "payment_methods", "column" => "number"}

  setup do
    GuideVaults.put_env()
    :ok
  end

  defp start_vault(vault) do
    start_supervised!(Supervisor.child_spec({vault, []}, restart: :temporary))
    vault
  end

  defp start_store do
    start_supervised!(MerchantKeys)
    :ok
  end

  defp reason({:error, %Error{reason: reason}}), do: reason

  describe "getting started, part 1: the single-key vault" do
    setup do
      start_vault(Vault)
      :ok
    end

    # sabotage: made `Encryptor.Vault.encrypt/3` return the plaintext instead
    # of calling the encrypt path; red.
    test "encrypts and decrypts a card number under the printed context" do
      assert {:ok, ciphertext} = Vault.encrypt(@pan, encryption_context: @column_context)
      assert ciphertext != @pan
      assert {:ok, @pan} = Vault.decrypt(ciphertext, encryption_context: @column_context)
    end

    # sabotage: dropped the required-context CMM from the encrypt stack; red.
    test "refuses a call that omits a required context key" do
      result = Vault.encrypt(@pan, encryption_context: %{"table" => "payment_methods"})

      assert {:missing_required_context_keys, ["column"]} = reason(result)
    end

    # sabotage: added "blob" to `Context.reserved_key?/2`; red.
    test "composes the signup-wizard payload example: blob and purpose" do
      {:ok, config} = Vault.config()

      assert {:ok, composed} =
               Encryptor.Context.compose(config, %{
                 "blob" => "signup_wizard_variant_b",
                 "purpose" => "pii"
               })

      assert composed["blob"] == "signup_wizard_variant_b"
      assert composed["purpose"] == "pii"
      assert composed["app"] == "acme_payments"
    end

    # sabotage: mapped 0x0478 to the signing suite in `Encrypt.suite/1`; red.
    test "writes 0x0478, key-committed and unsigned, as the guide's suite section says" do
      {:ok, ciphertext} = Vault.encrypt(@pan, encryption_context: @column_context)
      {:ok, info} = Message.describe(ciphertext)

      assert info.algorithm_suite_id == 0x0478
      assert info.committed?
    end

    # sabotage: dropped the static layer from `Context.merge/4`; red.
    test "carries the static app pair and the caller's pairs in the clear" do
      {:ok, ciphertext} = Vault.encrypt(@pan, encryption_context: @column_context)
      {:ok, info} = Message.describe(ciphertext)

      assert info.encryption_context["app"] == "acme_payments"
      assert info.encryption_context["table"] == "payment_methods"
      assert info.encryption_context["column"] == "number"
    end

    # sabotage: blanked `provider_id` in `Message.describe/1`'s edk; red.
    test "describe/1 names the key that wrote the row, without a key of its own" do
      {:ok, ciphertext} = Vault.encrypt(@pan, encryption_context: @column_context)
      {:ok, info} = Message.describe(ciphertext)

      assert [%{provider_id: "acme_payments", key_name: "card/v1"}] = info.encrypted_data_keys
    end

    # sabotage: made a `:single` vault resolve any selector to `:default`;
    # red.
    test "refuses a per-tenant selector" do
      result = Vault.encrypt(@pan, key: @merchant, encryption_context: @column_context)

      assert {:invalid_selector, @merchant} = reason(result)
    end
  end

  describe "getting started: key material never arrives through use options" do
    # sabotage: removed `:key` from `Config`'s `@key_material_options`; red.
    test "a use option naming key material is a compile-time refusal" do
      assert_raise ArgumentError, ~r/key material/, fn ->
        Code.eval_string("""
        defmodule Encryptor.GuidesTest.CompileTimeRefusal do
          use Encryptor.Vault, otp_app: :encryptor, key: "hunter2"
        end
        """)
      end
    end
  end

  describe "getting started: max_age is required and has no default" do
    # sabotage: gave `:max_age` a default of 60 in `cache_bounds/2`; red.
    test "a cache configured without max_age does not start" do
      assert {:error, %Error{reason: {:missing_config, [:cache, :max_age]}}} =
               Config.resolve(NoCacheAgeVault, :encryptor, [],
                 context_profile: :single,
                 provider: {Encryptor.Provider.Static, key: :binary.copy(<<1>>, 32)},
                 cache: [max_messages: 500]
               )
    end
  end

  describe "getting started, part 2: the per-tenant vault" do
    setup do
      start_store()
      start_vault(RootVault)
      {:ok, wrapped} = GuideVaults.onboard(@merchant)
      start_vault(MerchantVault)
      %{wrapped: wrapped}
    end

    # sabotage: replaced the derived key name with a constant in `mint/4`;
    # red.
    test "onboarding returns a wrapping and never a bare key", %{wrapped: wrapped} do
      assert %WrappedKey{
               tenant_ref: ref,
               version: 1,
               namespace: "acme-merchant",
               bits: 256,
               wrapped: blob
             } = wrapped

      assert is_binary(blob)
      assert wrapped.name == "t/" <> ref <> "/v1"
      refute Map.has_key?(wrapped, :material)
    end

    # sabotage: made `unwrap/2` return the namespace rather than the
    # descriptor; red.
    test "unwrap/2 returns a descriptor, never a binary", %{wrapped: wrapped} do
      assert {:ok, %Aes{namespace: "acme-merchant", bits: 256}} =
               Envelope.unwrap(RootVault, wrapped)
    end

    # sabotage: made a `:tenant` vault resolve every selector to one fixed
    # string; red.
    test "encrypts and decrypts under the merchant named by key:" do
      assert {:ok, ciphertext} =
               MerchantVault.encrypt(@pan, key: @merchant, encryption_context: @column_context)

      assert {:ok, @pan} =
               MerchantVault.decrypt(ciphertext,
                 key: @merchant,
                 encryption_context: @column_context
               )
    end

    # sabotage: dropped the vault-supplied `tenant_ref` pair in
    # `Resolve.vault_supplied/2`; red.
    test "the vault supplies tenant_ref and the caller may not" do
      {:ok, ciphertext} =
        MerchantVault.encrypt(@pan, key: @merchant, encryption_context: @column_context)

      {:ok, info} = Message.describe(ciphertext)
      {:ok, expected} = Envelope.tenant_ref(GuideVaults.reference_subkey(), @merchant)

      assert info.encryption_context["tenant_ref"] == expected

      result =
        MerchantVault.encrypt(@pan,
          key: @merchant,
          encryption_context: Map.put(@column_context, "tenant_ref", "mine")
        )

      assert {:reserved_context_key, "tenant_ref"} = reason(result)
    end

    # sabotage: made a `:tenant` vault default an absent `key:` to a tenant;
    # red.
    test "a tenant vault refuses a call with no key:" do
      result = MerchantVault.encrypt(@pan, encryption_context: @column_context)

      assert {:invalid_selector, :default} = reason(result)
    end

    # sabotage: removed `:unknown_key` from `Resolve`'s provider vocabulary;
    # red.
    test "resolution never provisions: an unknown merchant is unknown_key" do
      result =
        MerchantVault.encrypt(@pan, key: "merchant-999", encryption_context: @column_context)

      assert {:unknown_key, "merchant-999"} = reason(result)
    end

    # sabotage: keyed `Reference.derive/2` with a constant instead of the
    # subkey; red.
    test "tenant_ref is a keyed derivation of the documented shape" do
      subkey = GuideVaults.reference_subkey()
      {:ok, ref} = Envelope.tenant_ref(subkey, @merchant)

      expected =
        Base.url_encode64(
          binary_part(:crypto.mac(:hmac, :sha256, subkey, @merchant), 0, 16),
          padding: false
        )

      assert ref == expected
      assert byte_size(ref) == 22
    end
  end

  describe "getting started: the two root secrets, and the known-answer check" do
    # sabotage: made `Kdf.label/1` ignore the purpose, collapsing the two
    # labels; red.
    test "the reference and wrapping roots hold the same bytes at install" do
      wrapping = Base.decode64!(System.fetch_env!("MY_APP_WRAPPING_ROOT_KEY"))
      reference = Base.decode64!(System.fetch_env!("MY_APP_REFERENCE_ROOT_KEY"))

      assert wrapping == reference

      # And they still expand to different subkeys, which is the whole reason
      # the two labels exist: rotating one leaves the other alone.
      assert Envelope.root_subkey(wrapping, "root-wrap") !=
               Envelope.root_subkey(reference, "tenant-ref")
    end

    # sabotage: made the known-answer comparison trivially true; red.
    test "a pinned known-answer value refuses a node with the wrong subkey" do
      subkey = GuideVaults.reference_subkey()
      pinned = Config.known_answer(subkey)

      assert byte_size(pinned) == 22

      assert {:ok, %Config{reference_check: ^pinned}} =
               Config.resolve(PinnedVault, :encryptor, [],
                 context_profile: :tenant,
                 provider: {Encryptor.Provider.Static, key: :binary.copy(<<1>>, 32)},
                 reference_subkey: subkey,
                 reference_check: pinned
               )

      assert {:error,
              %Error{reason: {:invalid_config, :reference_subkey, :known_answer_mismatch}}} =
               Config.resolve(PinnedVault, :encryptor, [],
                 context_profile: :tenant,
                 provider: {Encryptor.Provider.Static, key: :binary.copy(<<1>>, 32)},
                 reference_subkey: :binary.copy(<<0xAB>>, 32),
                 reference_check: pinned
               )
    end
  end

  describe "the runbook, P1: root rotation" do
    setup do
      start_store()
      start_vault(RootVault)
      {:ok, wrapped} = GuideVaults.onboard(@merchant)
      %{wrapped: wrapped}
    end

    # sabotage: made `Keyring.build_all/3` keep only the newest candidate;
    # red.
    test "step 2's staged vault reads either generation", %{wrapped: wrapped} do
      GuideVaults.rotate_wrapping_root()
      start_vault(StagedRootVault)

      assert {:ok, %Aes{}} = Envelope.unwrap(StagedRootVault, wrapped)
    end

    # sabotage: made `rewrap/2` return the row unchanged; red.
    test "step 3's pass is resumable and idempotent in effect, never in bytes" do
      GuideVaults.rotate_wrapping_root()
      start_vault(StagedRootVault)

      before = MerchantKeys.all_live()
      {:ok, expected} = Envelope.unwrap(StagedRootVault, hd(before))

      for row <- before do
        {:ok, rewrapped} = Envelope.rewrap(StagedRootVault, row)
        MerchantKeys.update_wrapping(row, rewrapped)
      end

      [rewrapped] = MerchantKeys.all_live()
      [original] = before

      # Only :wrapped moves; every identity field is carried across.
      assert rewrapped.tenant_ref == original.tenant_ref
      assert rewrapped.version == original.version
      assert rewrapped.namespace == original.namespace
      assert rewrapped.name == original.name
      assert rewrapped.wrapped != original.wrapped

      # Idempotent in effect: the descriptor is identical.
      assert {:ok, ^expected} = Envelope.unwrap(StagedRootVault, rewrapped)

      # Re-running the pass is safe, and still produces different bytes.
      {:ok, again} = Envelope.rewrap(StagedRootVault, rewrapped)
      assert again.wrapped != rewrapped.wrapped
      assert {:ok, ^expected} = Envelope.unwrap(StagedRootVault, again)
    end

    # sabotage: made `Kdf.derive_subkey/3` ignore the key material, so both
    # root generations expand to one subkey; red.
    test "step 4 dropped early: a wrapping the pass never reached stops unwrapping", %{
      wrapped: wrapped
    } do
      GuideVaults.rotate_wrapping_root()

      # `RootVault`'s init reads the wrapping-root secret, which now holds
      # generation 2 alone - which is exactly the post-step-4 configuration.
      stop_supervised!(RootVault)
      start_vault(RootVault)

      assert :decrypt_failed = reason(Envelope.unwrap(RootVault, wrapped))
    end
  end

  describe "the runbook, P2 and P4: tenant rotation and version retire" do
    setup do
      start_store()
      start_vault(RootVault)
      {:ok, v1} = GuideVaults.onboard(@merchant, 1)
      start_vault(MerchantVault)
      %{v1: v1}
    end

    # sabotage: made `key_name/2` always name v1; red.
    test "step 1 opens the window: both versions resolve, new writes take n+1", %{v1: v1} do
      {:ok, old_ciphertext} =
        MerchantVault.encrypt(@pan, key: @merchant, encryption_context: @column_context)

      {:ok, _v2} = GuideVaults.onboard(@merchant, 2)

      # The vault caches resolved materials, so a fresh vault is what a new
      # node would see. Restarting is one of the runbook's two drain levers.
      stop_supervised!(MerchantVault)
      start_vault(MerchantVault)

      {:ok, new_ciphertext} =
        MerchantVault.encrypt(@pan, key: @merchant, encryption_context: @column_context)

      # The old row still opens: the window is what makes the rewrite pass
      # runnable against live traffic.
      assert {:ok, @pan} =
               MerchantVault.decrypt(old_ciphertext,
                 key: @merchant,
                 encryption_context: @column_context
               )

      assert {:ok, @pan} =
               MerchantVault.decrypt(new_ciphertext,
                 key: @merchant,
                 encryption_context: @column_context
               )

      # New writes are under v2, and the header says so in the clear.
      {:ok, info} = Message.describe(new_ciphertext)
      assert [%{key_name: name}] = info.encrypted_data_keys
      assert name == "t/" <> v1.tenant_ref <> "/v2"
    end

    # sabotage: changed the collapsed reason in `Error.decrypt_failed/3`; red.
    test "P4 retires one version, and a row the pass missed is indistinguishable", %{v1: v1} do
      {:ok, missed_row} =
        MerchantVault.encrypt(@pan, key: @merchant, encryption_context: @column_context)

      {:ok, _v2} = GuideVaults.onboard(@merchant, 2)

      # P4 step 1, then step 2's drain - here by restart, the lever available
      # to a test.
      MerchantKeys.delete_version(v1.tenant_ref, 1)
      stop_supervised!(MerchantVault)
      start_vault(MerchantVault)

      result =
        MerchantVault.decrypt(missed_row, key: @merchant, encryption_context: @column_context)

      assert :decrypt_failed = reason(result)
    end

    # sabotage: removed `:unknown_key` from `Resolve`'s provider vocabulary;
    # red.
    test "P3 shreds the tenant, and the failure is specific rather than an oracle", %{v1: v1} do
      {:ok, ciphertext} =
        MerchantVault.encrypt(@pan, key: @merchant, encryption_context: @column_context)

      MerchantKeys.delete_tenant(v1.tenant_ref)
      stop_supervised!(MerchantVault)
      start_vault(MerchantVault)

      assert {:unknown_key, @merchant} =
               reason(
                 MerchantVault.decrypt(ciphertext,
                   key: @merchant,
                   encryption_context: @column_context
                 )
               )

      assert {:unknown_key, @merchant} =
               reason(
                 MerchantVault.encrypt(@pan, key: @merchant, encryption_context: @column_context)
               )
    end

    # sabotage: dropped the tenant-ref pair from `Envelope.binding/3`; red.
    # (Removing `require_binding/4` alone is NOT red - the vault-side
    # comparison catches it too, which is the double defence being confirmed.)
    test "a wrapping copied into another merchant's row does not unwrap", %{v1: v1} do
      {:ok, _other} = GuideVaults.onboard("merchant-77", 1)
      [other_row] = Enum.filter(MerchantKeys.all_live(), &(&1.tenant_ref != v1.tenant_ref))

      forged = %WrappedKey{other_row | wrapped: v1.wrapped}

      assert :decrypt_failed = reason(Envelope.unwrap(RootVault, forged))
    end
  end
end
