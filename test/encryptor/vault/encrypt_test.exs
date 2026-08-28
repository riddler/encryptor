defmodule Encryptor.Vault.EncryptTest do
  use ExUnit.Case, async: false

  alias AwsEncryptionSdk.Client
  alias AwsEncryptionSdk.Cmm.Caching
  alias AwsEncryptionSdk.Cmm.Default
  alias AwsEncryptionSdk.Cmm.RequiredEncryptionContext
  alias AwsEncryptionSdk.Keyring.RawAes
  alias Encryptor.EncryptVaults
  alias Encryptor.Error
  alias Encryptor.TestVaults
  alias Encryptor.Vault
  alias Encryptor.Vault.Config
  alias Encryptor.Vault.Encrypt
  alias Encryptor.Vault.Partition
  alias Encryptor.Vault.Reference

  @pan "4111111111111111"
  @columns %{"table" => "payment_methods", "column" => "pan"}

  defp start_vault(vault) do
    start_supervised!(Supervisor.child_spec({vault, []}, restart: :temporary))
    vault
  end

  defp config(vault) do
    {:ok, config} = Config.fetch(vault)
    config
  end

  # The test's own reader, built from the same material the provider resolves
  # to. It reads the message with the engine directly, which is what makes the
  # round trip evidence that this package writes an ordinary ESDK message
  # rather than evidence that it agrees with itself.
  #
  # It mirrors the writer's CMM stack, because this engine mixes the
  # required subset of the context into the header AAD: a reader that does not
  # know which keys were required computes a different tag and fails the
  # header authentication. That is the engine's own deviation from the
  # specification, and it is the decrypt path's problem to carry; here it only
  # means the test's reader is built from the same two facts the vault was.
  defp read(ciphertext, material, namespace, name, opts) do
    {:ok, keyring} = RawAes.new(namespace, name, material, :aes_256_gcm)
    {required, decrypt_opts} = Keyword.pop(opts, :required, [])

    keyring
    |> reader_cmm(required)
    |> Client.new()
    |> Client.decrypt(ciphertext, decrypt_opts)
  end

  defp reader_cmm(keyring, []), do: Default.new(keyring)
  defp reader_cmm(keyring, keys), do: RequiredEncryptionContext.new_with_keyring(keys, keyring)

  defp read_app(ciphertext) do
    read(ciphertext, EncryptVaults.single_key(), "acme-app", "app/v1", [])
  end

  defp read_bound(ciphertext) do
    read(ciphertext, EncryptVaults.rotated_key(), "acme-app", "app/v2",
      required: ["table", "column"],
      encryption_context: @columns
    )
  end

  defp merchant_context(selector) do
    Map.put(
      @columns,
      "tenant_ref",
      Reference.derive(EncryptVaults.reference_subkey(), selector)
    )
  end

  defp read_merchant(ciphertext, selector) do
    descriptor = EncryptVaults.merchant_descriptor(selector)

    read(ciphertext, descriptor.material, descriptor.namespace, descriptor.name,
      required: ["tenant_ref", "table", "column"],
      encryption_context: merchant_context(selector)
    )
  end

  defp reason({:error, %Error{reason: reason}}), do: reason

  describe "the round trip" do
    # sabotage: returned `result` instead of `result.ciphertext` from
    # engine_encrypt/4 - red, because a caller then stores a map holding the
    # header, the context and the suite beside the one binary the message
    # already carries them in.
    test "returns the complete engine message and nothing else" do
      vault = start_vault(EncryptVaults.App)

      assert {:ok, ciphertext} = vault.encrypt(@pan)
      assert is_binary(ciphertext)
      assert {:ok, %{plaintext: @pan}} = read_app(ciphertext)
    end

    # sabotage: froze the provider's option list as its state instead of its
    # `init/1` return - red, because the first resolution then fails a
    # function clause inside a library rather than answering a descriptor.
    test "a cached vault round trips too" do
      vault = start_vault(EncryptVaults.Cached)

      assert {:ok, ciphertext} = vault.encrypt(@pan, encryption_context: @columns)
      assert {:ok, %{plaintext: @pan}} = read_app(ciphertext)
    end

    # sabotage: made vault_supplied/2 return %{} on a :tenant vault - red,
    # because the merchant's own key then writes a message with no tenant
    # attribution in it at all.
    test "a per-merchant vault writes under the merchant's own key" do
      vault = start_vault(EncryptVaults.Merchant)

      assert {:ok, ciphertext} =
               vault.encrypt(@pan, key: "merchant_a", encryption_context: @columns)

      assert {:ok, %{plaintext: @pan}} = read_merchant(ciphertext, "merchant_a")

      # The other merchant's keyring cannot open it: the encrypted data key
      # names a key that is not theirs.
      assert {:error, _engine} = read_merchant(ciphertext, "merchant_b")
    end

    # sabotage: made suite/1 answer 0x0578 for both ids - red, because a host
    # that chose the unsigned suite then pays an ECDSA P-384 signature per
    # write and per read anyway.
    test "the configured algorithm suite is what reaches the message" do
      signed = start_vault(EncryptVaults.App)
      unsigned = start_vault(EncryptVaults.Cached)

      assert {:ok, signed_ct} = signed.encrypt(@pan)
      assert {:ok, unsigned_ct} = unsigned.encrypt(@pan)

      assert {:ok, %{header: %{algorithm_suite: %{id: 0x0578}}}} = read_app(signed_ct)
      assert {:ok, %{header: %{algorithm_suite: %{id: 0x0478}}}} = read_app(unsigned_ct)
    end
  end

  describe "the CMM stack order" do
    # sabotage: swapped maybe_caching/3 and maybe_required/2 in stack/3 so
    # caching wrapped the required-context CMM - red. That arrangement is the
    # silently unsafe one: a decryption cache hit returns the stored materials
    # without calling the wrapped CMM, so the reproduced-context presence
    # check is skipped for exactly the messages that are read often.
    test "required is outermost, caching is in the middle, default is innermost" do
      vault = start_vault(EncryptVaults.Merchant)
      config = config(vault)
      {:ok, keyring} = RawAes.new("ns", "name", EncryptVaults.single_key(), :aes_256_gcm)

      assert %RequiredEncryptionContext{
               required_encryption_context_keys: ["tenant_ref", "table", "column"],
               underlying_cmm: %Caching{underlying_cmm: %Default{}}
             } = Encrypt.stack(config, keyring, "merchant_a")
    end

    # sabotage: dropped the `maybe_required/2` guard on an empty list so the
    # wrap was always applied - red, because a required-context CMM over an
    # empty list is an extra struct and an extra dispatch for nothing.
    test "the outer wrap is skipped when the required set is empty" do
      vault = start_vault(EncryptVaults.Cached)
      config = config(vault)
      {:ok, keyring} = RawAes.new("ns", "name", EncryptVaults.single_key(), :aes_256_gcm)

      assert %Caching{underlying_cmm: %Default{}} = Encrypt.stack(config, keyring, :default)
    end

    # sabotage: made maybe_caching/3 wrap unconditionally - red, because a
    # vault configured `cache: false` starts no cache process and the caching
    # CMM would then call a name nobody registered.
    test "a cacheless vault with a required set is required over default" do
      vault = start_vault(EncryptVaults.Bound)
      config = config(vault)
      {:ok, keyring} = RawAes.new("ns", "name", EncryptVaults.single_key(), :aes_256_gcm)

      assert %RequiredEncryptionContext{underlying_cmm: %Default{}} =
               Encrypt.stack(config, keyring, :default)
    end

    # sabotage: dropped the `cache: false` clause of maybe_caching/3 - red,
    # because a vault that runs no cache process then gets a caching CMM
    # pointing at a registered name nobody holds.
    test "a vault with neither is a bare default CMM" do
      vault = start_vault(EncryptVaults.App)
      config = config(vault)
      {:ok, keyring} = RawAes.new("ns", "name", EncryptVaults.single_key(), :aes_256_gcm)

      assert %Default{} = Encrypt.stack(config, keyring, :default)
    end

    # sabotage: dropped the `:partition_id` option, letting the engine
    # generate a UUID per call - red, because two merchants then share a
    # cache partition boundary the vault no longer controls at all.
    test "the caching CMM is partitioned by the same selector that chose the key" do
      vault = start_vault(EncryptVaults.Merchant)
      config = config(vault)
      {:ok, keyring} = RawAes.new("ns", "name", EncryptVaults.single_key(), :aes_256_gcm)

      a = Encrypt.stack(config, keyring, "merchant_a").underlying_cmm
      b = Encrypt.stack(config, keyring, "merchant_b").underlying_cmm

      assert a.partition_id == Partition.id(EncryptVaults.Merchant, "merchant_a")
      assert byte_size(a.partition_id) == 16
      refute a.partition_id == b.partition_id
    end

    # sabotage: passed the engine's own ceilings instead of the resolved
    # bounds - red, because a wrapper that inherits 2^63-1 bytes and 2^32
    # messages has, in practice, no data key rotation at all.
    test "the caching CMM carries the vault's resolved bounds, not the engine's ceilings" do
      vault = start_vault(EncryptVaults.Cached)
      config = config(vault)
      {:ok, keyring} = RawAes.new("ns", "name", EncryptVaults.single_key(), :aes_256_gcm)

      assert %Caching{max_age: 60, max_messages: 100, max_bytes: 1_073_741_824} =
               Encrypt.stack(config, keyring, :default)
    end

    # sabotage: dropped :max_encrypted_data_keys from the Client.new/2 options
    # - red, because the engine reads nil as unlimited and an unlimited EDK
    # count is a work-amplification lever handed to whoever supplies bytes.
    test "the client carries the frozen commitment policy and EDK limit" do
      vault = start_vault(EncryptVaults.App)
      config = config(vault)
      {:ok, keyring} = RawAes.new("ns", "name", EncryptVaults.single_key(), :aes_256_gcm)

      assert %Client{
               commitment_policy: :require_encrypt_require_decrypt,
               max_encrypted_data_keys: 10
             } = Encrypt.client(config, keyring, :default)
    end
  end

  describe "the selector profile check" do
    # sabotage: relaxed the tenant guard to `is_atom(selector) or
    # is_binary(selector)` - red, because a per-tenant provider handed
    # `:default` is the failure ADR-0004 decision 3 exists to catch one layer
    # above the provider.
    test "a tenant vault refuses :default, and refuses it before the provider is consulted" do
      vault = start_vault(EncryptVaults.MerchantCacheless)

      # The provider would have answered {:unknown_key, :default} had it been
      # asked, so the reason itself is the evidence of ordering.
      assert {:invalid_selector, :default} = reason(vault.encrypt(@pan))
      assert {:invalid_selector, :default} = reason(vault.encrypt(@pan, key: :default))
    end

    # sabotage: relaxed the tenant guard to `is_atom(selector) or
    # is_binary(selector)` - red, because an empty tenant identifier is the
    # selector every caller who forgot to resolve one shares.
    test "a tenant vault refuses an empty selector" do
      vault = start_vault(EncryptVaults.MerchantCacheless)

      assert {:invalid_selector, ""} = reason(vault.encrypt(@pan, key: ""))
    end

    # sabotage: made the :single clause return whatever `:key` held - red,
    # because a single-key vault handed a merchant id would then quietly
    # encrypt every merchant's data under one key.
    test "a single vault refuses a string" do
      vault = start_vault(EncryptVaults.App)

      assert {:invalid_selector, "merchant_a"} = reason(vault.encrypt(@pan, key: "merchant_a"))
    end

    # sabotage: made the :single clause return whatever `:key` held - red,
    # because `key: nil` from a resolver that returned nothing would then
    # reach the provider as a selector.
    test "a single vault refuses a selector that is neither :default nor absent" do
      vault = start_vault(EncryptVaults.App)

      assert {:invalid_selector, nil} = reason(vault.encrypt(@pan, key: nil))
    end
  end

  describe "the encryption context" do
    # sabotage: dropped the `supplied:` option from context/3 - red, because
    # the tenant pair then has to come from a caller, which is the one place
    # ADR-0004 decision 4 refuses to let it come from.
    test "the vault injects tenant_ref, derived from the :key selector" do
      vault = start_vault(EncryptVaults.Merchant)
      expected = Reference.derive(EncryptVaults.reference_subkey(), "merchant_a")

      assert {:ok, ciphertext} =
               vault.encrypt(@pan, key: "merchant_a", encryption_context: @columns)

      assert {:ok, %{encryption_context: context}} = read_merchant(ciphertext, "merchant_a")

      assert context["tenant_ref"] == expected
      assert context["table"] == "payment_methods"
      refute Map.has_key?(context, "tenant_id")
    end

    # sabotage: passed `%{}` to Context.compose/3 in place of the caller's
    # own context - red, because the merchant's required column pair then
    # never arrives and the write is refused before a reference is written.
    test "two merchants get different references" do
      vault = start_vault(EncryptVaults.Merchant)

      assert {:ok, a} = vault.encrypt(@pan, key: "merchant_a", encryption_context: @columns)
      assert {:ok, b} = vault.encrypt(@pan, key: "merchant_b", encryption_context: @columns)

      assert {:ok, %{encryption_context: %{"tenant_ref" => ref_a}}} =
               read_merchant(a, "merchant_a")

      assert {:ok, %{encryption_context: %{"tenant_ref" => ref_b}}} =
               read_merchant(b, "merchant_b")

      refute ref_a == ref_b
    end

    # sabotage: passed `%{}` to Context.compose/3 in place of the caller's
    # own context - red, because a refusal that never sees the caller's map
    # is a refusal that cannot fire, and a merchant named twice can disagree
    # with itself.
    test "a caller may not name the merchant a second time" do
      vault = start_vault(EncryptVaults.Merchant)

      assert {:reserved_context_key, "tenant_ref"} =
               reason(
                 vault.encrypt(@pan,
                   key: "merchant_a",
                   encryption_context: %{"tenant_ref" => "mine"}
                 )
               )

      assert {:reserved_context_key, "tenant_id"} =
               reason(
                 vault.encrypt(@pan,
                   key: "merchant_a",
                   encryption_context: %{"tenant_id" => "merchant_b"}
                 )
               )
    end

    # sabotage: passed `%{}` to Context.compose/3 in place of the caller's
    # own context - red, because the column pair the call site supplied then
    # never reaches the message.
    test "the static layer is merged under the caller's" do
      vault = start_vault(EncryptVaults.Cached)

      assert {:ok, ciphertext} = vault.encrypt(@pan, encryption_context: @columns)
      assert {:ok, %{encryption_context: context}} = read_app(ciphertext)

      assert context["app"] == "acme_checkout"
      assert context["column"] == "pan"
    end

    # sabotage: passed `%{}` to Context.compose/3 in place of the caller's
    # own context - red, because a conflict the composer never sees is a
    # conflict a call site wins silently, per row.
    test "a caller that contradicts the static context is refused" do
      vault = start_vault(EncryptVaults.Cached)

      assert {:encryption_context_conflict, "app"} =
               reason(vault.encrypt(@pan, encryption_context: %{"app" => "something_else"}))
    end
  end

  describe "the required set" do
    # sabotage: dropped the {:missing_required_encryption_context_keys, _}
    # clause of engine_encrypt/4 - red, because the one encrypt-side failure a
    # caller can actually fix would arrive as an opaque configuration error.
    test "a call site that omits a required key is told which one" do
      vault = start_vault(EncryptVaults.Bound)

      assert {:missing_required_context_keys, ["column"]} =
               reason(vault.encrypt(@pan, encryption_context: %{"table" => "payment_methods"}))
    end

    # sabotage: passed `%{}` to Context.compose/3 in place of the caller's
    # own context - red, because the pair the call site did supply is then
    # missing from the composed context and the required-context CMM refuses.
    test "the same call succeeds once the pair is complete" do
      vault = start_vault(EncryptVaults.Bound)

      assert {:ok, ciphertext} = vault.encrypt(@pan, encryption_context: @columns)

      assert {:ok, %{plaintext: @pan}} = read_bound(ciphertext)
    end

    # sabotage: built required_keys/2 from :required_context alone - red,
    # because a :tenant vault's required set is the profile's key plus the
    # host's, and dropping the profile's makes tenant binding optional.
    test "a tenant vault requires tenant_ref, which it supplies itself" do
      vault = start_vault(EncryptVaults.Merchant)

      assert config(vault).required_keys == ["tenant_ref", "table", "column"]

      assert {:missing_required_context_keys, ["column"]} =
               reason(
                 vault.encrypt(@pan, key: "merchant_a", encryption_context: %{"table" => "t"})
               )
    end
  end

  describe "failures the caller owns" do
    # sabotage: reported every provider failure as a provider defect - red,
    # because a settled negative answer about a selector is the caller's to
    # act on, and calling it a defect sends an operator to the wrong code.
    test "a selector the provider does not serve is an unknown key" do
      vault = start_vault(EncryptVaults.Merchant)

      assert {:unknown_key, "merchant_z"} =
               reason(vault.encrypt(@pan, key: "merchant_z", encryption_context: @columns))
    end

    # sabotage: reported an off-vocabulary provider failure as a settled
    # `{:unknown_key, _}` - red, because a provider that failed in its own
    # words has not answered "no key for that selector", and telling a caller
    # it did sends them to fix a selector that was never the problem.
    test "a provider that fails outside the vocabulary is a provider defect" do
      vault = start_vault(EncryptVaults.OffContract)

      assert {:error, %Error{reason: reason, operation: :encrypt, engine: engine}} =
               vault.encrypt(@pan)

      assert reason == {:invalid_key_descriptor, :provider_off_contract}
      assert engine == :weird_and_unenumerated
    end

    # sabotage: reported a bare provider return as a settled
    # `{:unknown_key, _}` - red, for the same reason, on the clause that
    # catches a provider answering with something that is not a result at all.
    test "a provider that answers with something that is not a result is too" do
      vault = start_vault(EncryptVaults.Silent)

      assert {:error, %Error{reason: reason, engine: :i_have_no_idea}} = vault.encrypt(@pan)
      assert reason == {:invalid_key_descriptor, :provider_off_contract}
    end

    # sabotage: replaced Vault.ready/2 with a bare Config.fetch/1 at the head
    # of the path - red, because the failure then carries `:start` rather
    # than the operation the caller asked for, and the provider liveness
    # check is skipped besides.
    test "a vault that is not running is a typed error stamped with the operation" do
      assert {:error, %Error{reason: reason, operation: :encrypt}} =
               EncryptVaults.Unstarted.encrypt(@pan)

      assert reason == {:vault_not_started, EncryptVaults.Unstarted}
    end
  end

  describe "the bang variant" do
    # sabotage: made encrypt!/3 return the {:ok, _} tuple - red, because the
    # bang variant exists precisely so a caller does not unwrap.
    test "returns the ciphertext" do
      vault = start_vault(EncryptVaults.App)

      assert is_binary(vault.encrypt!(@pan))
    end

    # sabotage: made the :single clause return whatever `:key` held - red,
    # because the refusal this rescues is then never raised at all.
    test "raises the same struct the non-bang variant returns" do
      vault = start_vault(EncryptVaults.App)

      error = assert_raise Error, fn -> vault.encrypt!(@pan, key: "merchant_a") end

      assert error.reason == {:invalid_selector, "merchant_a"}
      assert error.operation == :encrypt
    end
  end

  describe "the frozen provider state" do
    # sabotage: stored the provider's option list as its state - red, because
    # Static.encryption_key/2 matches on %{keys: _} and every resolution then
    # fails a function clause inside a library.
    test "the provider's init/1 runs once, at start, and its return is frozen" do
      vault = start_vault(EncryptVaults.App)
      names = vault |> config() |> Map.get(:provider_state, %{}) |> Map.get(:keys, [])

      assert Enum.map(names, & &1.name) == ["app/v1"]
    end

    # sabotage: ignored the {:error, _} half of Provider.init/2 - red,
    # because a provider that cannot configure itself would then start a
    # vault that fails at its first encrypt instead.
    test "a provider that cannot configure itself is a vault that does not start" do
      assert {:error, %Error{reason: {:missing_config, [:provider, :decryption_keys]}}} =
               Config.resolve(TestVaults.NoInit, :encryptor, [],
                 provider:
                   {Encryptor.Provider.Function, encryption_key: fn _selector -> :never end},
                 context_profile: :single
               )
    end

    # sabotage: promoted the provider's own term into :reason - red, because
    # a provider's failure term is not a member of this package's closed
    # vocabulary and can hold key material besides.
    test "a provider failing outside the vocabulary is carried in :engine" do
      assert {:error, %Error{reason: reason, operation: :start, engine: engine}} =
               Config.resolve(TestVaults.NoInit, :encryptor, [],
                 provider: {EncryptVaults.BadInit, []},
                 context_profile: :single
               )

      assert reason == {:invalid_config, :provider, :init}
      assert engine == :weird_and_unenumerated
    end
  end

  describe "the tenant reference" do
    # sabotage: dropped the binary_part/3 truncation - red, because the
    # reference's width is what a key name and a context value are budgeted
    # for, and the vault's own known-answer check pins it.
    test "is stable, and is the value the known-answer check pins" do
      subkey = EncryptVaults.reference_subkey()

      assert Reference.derive(subkey, "merchant_a") == Reference.derive(subkey, "merchant_a")
      refute Reference.derive(subkey, "merchant_a") == Reference.derive(subkey, "merchant_b")
      assert byte_size(Reference.derive(subkey, "merchant_a")) == 22
    end

    # sabotage: derived without the subkey - red, because two deployments
    # would then agree on every reference, and a reference confirmable by
    # anyone who can guess a slug is the property the keying buys away.
    test "depends on the subkey" do
      other = :binary.copy(<<0x66>>, 32)

      refute Reference.derive(EncryptVaults.reference_subkey(), "merchant_a") ==
               Reference.derive(other, "merchant_a")
    end
  end

  describe "the vault surface" do
    # sabotage: renamed the `encrypt/2` callback on the behaviour - red,
    # because the vault module is the entire public surface, and a surface a
    # host cannot see declared is a surface it reaches past.
    test "a vault module answers encrypt/2 and encrypt!/2" do
      assert function_exported?(EncryptVaults.App, :encrypt, 2)
      assert function_exported?(EncryptVaults.App, :encrypt!, 2)
      assert Vault.behaviour_info(:callbacks) |> Enum.member?({:encrypt, 2})
    end
  end
end
