defmodule Encryptor.Vault.SuspensionTest do
  @moduledoc """
  ADR-0005 amendment A: suspend, the third verb.

  The verb is defined by its observable rather than by its implementation
  (A1), so these tests assert the observable: a suspended selector is refused
  with `{:key_unavailable, selector}` on every entry point that resolves key
  material, the wrappings behind it are untouched, and `reinstate/2` puts the
  reads back. The mechanism - the gate's position relative to the cache (A5),
  the whole-table drop (A6), the owner of the set (A8) - is asserted where the
  record makes a claim a round trip could not distinguish.
  """

  use ExUnit.Case, async: false

  alias AwsEncryptionSdk.AlgorithmSuite
  alias AwsEncryptionSdk.Cache.CacheEntry
  alias AwsEncryptionSdk.Cache.LocalCache
  alias AwsEncryptionSdk.Cmm.Caching
  alias AwsEncryptionSdk.Materials.EncryptionMaterials
  alias Encryptor.Context
  alias Encryptor.DecryptVaults
  alias Encryptor.DeriveVaults
  alias Encryptor.EncryptVaults
  alias Encryptor.Error
  alias Encryptor.GcpKmsVaults
  alias Encryptor.LifecycleVaults
  alias Encryptor.Vault
  alias Encryptor.Vault.Partition
  alias Encryptor.Vault.Reference
  alias Encryptor.Vault.Suspension

  @pan "4111111111111111"
  @columns %{"table" => "payment_methods", "column" => "pan"}
  @suspended "merchant_a"
  @serving "merchant_b"
  @unknown "merchant_c"

  defp start_vault(vault) do
    start_supervised!(Supervisor.child_spec({vault, []}, restart: :temporary))
    vault
  end

  defp reason({:error, %Error{reason: reason}}), do: reason

  defp cache_pid(vault), do: Process.whereis(Vault.cache_name(vault))

  defp suite, do: AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()

  # An entry written where the engine would write one, so a test can hold
  # materials resident for a partition without going through an encrypt.
  #
  # The cache id is computed over the composed context, not over the caller's
  # half of it: `Encryptor.Vault.Resolve.context/5` adds the tenant reference
  # on a `:tenant` vault, and the required-context CMM passes the whole map
  # down to the caching one. Planting under `%{}` would leave a resident entry
  # at an id the asserted call never looks up, and a test that means "the
  # materials are still there" would pass on an empty partition.
  defp put_entry(vault, selector) do
    context = composed_context(selector)
    id = Caching.compute_encryption_cache_id(Partition.id(vault, selector), suite(), context)
    entry = CacheEntry.new(EncryptionMaterials.new_for_encrypt(suite(), context), 300)

    :ok = LocalCache.put_cache_entry(Vault.cache_name(vault), id, entry)
  end

  defp composed_context(selector) do
    reference = Reference.derive(EncryptVaults.reference_subkey(), selector)

    Map.put(@columns, Context.tenant_ref_key(), reference)
  end

  describe "the observable (A1)" do
    # sabotage: dropped the `allowed/3` guard from Resolve.encryption_key/3 -
    # red. The write half is half the observable, and a suspension that let
    # writes through would leave a suspended tenant accumulating rows nobody
    # can read.
    test "a suspended selector cannot encrypt" do
      vault = start_vault(EncryptVaults.Merchant)

      assert :ok = Vault.suspend(vault, @suspended)

      result = vault.encrypt(@pan, key: @suspended, encryption_context: @columns)

      assert reason(result) == {:key_unavailable, @suspended}
    end

    # sabotage: dropped the guard from Resolve.decryption_keys/3 - red, and
    # this is the half an operator actually runs P5 for.
    test "a suspended selector cannot decrypt" do
      vault = start_vault(EncryptVaults.Merchant)
      ciphertext = vault.encrypt!(@pan, key: @suspended, encryption_context: @columns)

      assert :ok = Vault.suspend(vault, @suspended)

      result = vault.decrypt(ciphertext, key: @suspended, encryption_context: @columns)

      assert reason(result) == {:key_unavailable, @suspended}
    end

    # sabotage: stamped the gate's error with a hardcoded :encrypt operation -
    # red. `rekey/2` reaches both callbacks, and an operator reading the log
    # line must see the call the caller made.
    test "a suspended selector cannot rekey, and the operation is the caller's" do
      vault = start_vault(EncryptVaults.Merchant)
      ciphertext = vault.encrypt!(@pan, key: @suspended, encryption_context: @columns)

      assert :ok = Vault.suspend(vault, @suspended)

      assert {:error, %Error{} = error} = vault.rekey(ciphertext, key: @suspended)
      assert error.reason == {:key_unavailable, @suspended}
      assert error.operation == :rekey
      assert error.vault == vault
    end

    # sabotage: dropped the guard from Resolve.encryption_key/3 - red here as
    # well as at encrypt, which is why derive has a test of its own: A1 lists
    # four verbs, and `derive/2` is the one that reaches the write-side
    # callback without writing a message.
    test "a suspended selector cannot derive" do
      vault = start_vault(DeriveVaults.Merchant)

      assert :ok = Vault.suspend(vault, @suspended)

      assert reason(vault.derive("blind_index", key: @suspended)) ==
               {:key_unavailable, @suspended}
    end

    # sabotage: suspended the whole vault rather than the selector - red. A
    # suspension that took every tenant down with one is an outage, not a
    # verb.
    test "no other selector on the vault is affected" do
      vault = start_vault(EncryptVaults.Merchant)

      assert :ok = Vault.suspend(vault, @suspended)

      assert {:ok, _ciphertext} =
               vault.encrypt(@pan, key: @serving, encryption_context: @columns)
    end

    # sabotage: keyed the suspended set by selector alone in one global table
    # - red. A8 puts the set in the vault's own tree, and two vaults over one
    # provider must not suspend each other's reads.
    test "a suspension is this vault's, not the provider's" do
      suspended = start_vault(EncryptVaults.Merchant)
      serving = start_vault(EncryptVaults.MerchantCacheless)

      assert :ok = Vault.suspend(suspended, @suspended)

      assert reason(suspended.encrypt(@pan, key: @suspended, encryption_context: @columns)) ==
               {:key_unavailable, @suspended}

      assert {:ok, _ciphertext} = serving.encrypt(@pan, key: @suspended)
    end

    # sabotage: made reinstate/2 a no-op - red. "Unreadable and intact" is the
    # whole of A1, and this is the assertion that would still fail if the verb
    # had destroyed something: reading the *original* ciphertext back is what
    # proves the wrappings behind it were never touched.
    test "the wrappings are untouched: the same ciphertext reads back after reinstatement" do
      vault = start_vault(EncryptVaults.Merchant)
      ciphertext = vault.encrypt!(@pan, key: @suspended, encryption_context: @columns)

      assert :ok = Vault.suspend(vault, @suspended)
      assert :ok = Vault.reinstate(vault, @suspended)

      assert {:ok, @pan} =
               vault.decrypt(ciphertext, key: @suspended, encryption_context: @columns)
    end
  end

  describe "the three states kept apart (A4)" do
    # sabotage: answered a suspension with {:unknown_key, selector} - red.
    # Decision 9's rule is that a whole-tenant shred is loud and specific;
    # an operator who cannot tell a suspension from a shred cannot tell a
    # reversible state from an irreversible one.
    test "suspended, shredded and retired are three distinguishable reasons" do
      tenant = start_vault(EncryptVaults.Merchant)

      assert :ok = Vault.suspend(tenant, @suspended)

      # Suspended: reversible, and the store still holds the rows.
      assert reason(tenant.encrypt(@pan, key: @suspended, encryption_context: @columns)) ==
               {:key_unavailable, @suspended}

      # A whole tenant with no live version - what P3 leaves behind.
      assert reason(tenant.encrypt(@pan, key: @unknown, encryption_context: @columns)) ==
               {:unknown_key, @unknown}

      # A retired version: per message, and collapsed, because it depends on
      # the bytes rather than on the caller's arguments.
      writer = start_vault(EncryptVaults.Bound)
      reader = start_vault(DecryptVaults.Retired)
      message = writer.encrypt!(@pan, encryption_context: @columns)

      assert reason(reader.decrypt(message, encryption_context: @columns)) == :decrypt_failed
    end
  end

  describe "the gate's position (A5)" do
    # sabotage: had the gate answer `:ok` when the partition already has a
    # cached entry - red here and green in every other test in this file,
    # which is exactly the failure A5 is a decision about: a suspension only
    # as prompt as its eviction.
    test "a suspension denies a warm partition, with the materials still resident" do
      vault = start_vault(EncryptVaults.Merchant)

      assert :ok = Vault.suspend(vault, @suspended)

      # Written *after* the suspension, so the drop of A6 cannot be what makes
      # this call fail: the entry is there when the call runs.
      put_entry(vault, @suspended)

      assert reason(vault.encrypt(@pan, key: @suspended, encryption_context: @columns)) ==
               {:key_unavailable, @suspended}
    end

    # sabotage: added the guard to Resolve.provision/3 - red. A1 lists the
    # four verbs that read key material; provisioning creates it and reads
    # none, and a suspension that blocked onboarding would be a different
    # decision than the one recorded.
    test "provisioning is not on A1's list" do
      vault = start_vault(GcpKmsVaults.Tenant)

      assert :ok = Vault.suspend(vault, "tenant-42")

      assert {:ok, _row} = vault.provision("tenant-42")
    end
  end

  describe "the cache half (A6)" do
    # sabotage: returned :ok from suspend/2 without calling the recycler -
    # red. The drop is hygiene rather than correctness, but a suspended
    # tenant's data keys sitting resident for the length of the suspension is
    # the thing the decision refuses.
    test "suspending drops the vault's materials cache" do
      vault = start_vault(EncryptVaults.Merchant)
      before = cache_pid(vault)

      assert :ok = Vault.suspend(vault, @suspended)

      assert is_pid(cache_pid(vault))
      assert cache_pid(vault) != before
    end

    # sabotage: matched the recycler's answer with `:ok = recycle(...)` - red.
    # A vault with `cache: false` has neither child, and the gate is the verb.
    test "a vault with no cache suspends anyway" do
      vault = start_vault(EncryptVaults.MerchantCacheless)

      assert :ok = Vault.suspend(vault, @suspended)

      assert reason(vault.encrypt(@pan, key: @suspended)) == {:key_unavailable, @suspended}
    end

    # sabotage: dropped the cache by killing the child and letting the
    # supervisor react - red on the third suspension, because a supervisor's
    # restart intensity is a defence against a failing child and spending it
    # on maintenance takes the vault down.
    test "repeated suspensions do not spend the supervisor's restart intensity" do
      vault = start_vault(EncryptVaults.Merchant)

      for selector <- [@suspended, @serving, @unknown, "merchant_d", "merchant_e"] do
        assert :ok = Vault.suspend(vault, selector)
      end

      assert Vault.started?(vault)
      assert is_pid(cache_pid(vault))
    end
  end

  describe "reinstate/2 (A7)" do
    # sabotage: made reinstate/2 a no-op - red. The inverse is the reason the
    # verb is worth having at all.
    test "reinstating restores reads" do
      vault = start_vault(EncryptVaults.Merchant)

      assert :ok = Vault.suspend(vault, @suspended)
      assert :ok = Vault.reinstate(vault, @suspended)

      assert {:ok, _ciphertext} =
               vault.encrypt(@pan, key: @suspended, encryption_context: @columns)
    end

    # sabotage: guarded reinstate/2 on membership and returned an error
    # otherwise - red. Suspension is a set membership, so both verbs are
    # idempotent and a runbook may repeat either.
    test "both verbs are total: repeating either succeeds" do
      vault = start_vault(EncryptVaults.Merchant)

      assert :ok = Vault.reinstate(vault, @suspended)
      assert :ok = Vault.suspend(vault, @suspended)
      assert :ok = Vault.suspend(vault, @suspended)
      assert :ok = Vault.reinstate(vault, @suspended)
      assert :ok = Vault.reinstate(vault, @suspended)
    end

    # sabotage: had reinstate/2 answer {:ok, :readable} - red. Reinstating
    # restores the gate and nothing else: where there is no live version the
    # provider's own answer is what comes back, which is A4's table read
    # downward and is why no runbook may treat a suspension as a backup.
    test "reinstating recovers no key material" do
      vault = start_vault(EncryptVaults.Merchant)

      assert :ok = Vault.suspend(vault, @unknown)
      assert :ok = Vault.reinstate(vault, @unknown)

      assert reason(vault.encrypt(@pan, key: @unknown, encryption_context: @columns)) ==
               {:unknown_key, @unknown}
    end
  end

  describe "the set's owner and its volatility (A8)" do
    # sabotage: created the table in a process that outlives the vault rather
    # than in the Lifecycle child - red, because the set then outlives the
    # configuration it belongs to and a restarted vault denies a selector no
    # record says is suspended.
    test "a restarted vault serves the selector again" do
      vault = start_vault(LifecycleVaults.Cached)

      assert :ok = Vault.suspend(vault, :default)
      assert :ok = Vault.stop(vault)

      start_vault(LifecycleVaults.Cached)

      refute Suspension.suspended?(vault, :default)
    end

    # sabotage: raised from suspended?/2 when the table is missing - red. The
    # gate is on the hot path of every call, and a vault between a crash and
    # its restart must not report a restart as the caller's error.
    test "a vault with no suspended set denies nothing" do
      refute Suspension.suspended?(LifecycleVaults.Unstarted, :default)
    end

    # sabotage: removed both guards - the not-started check in `suspend/2` and
    # `reinstate/2`, and the table check behind them - red with an
    # ArgumentError out of `:ets` instead of this package's one error shape.
    # Both are removed because either one alone answers, which is the point:
    # a verb an operator runs from a console reaches the table twice and
    # cannot raise on either path.
    test "both verbs answer the not-started check on a vault that is down" do
      vault = LifecycleVaults.Unstarted

      assert reason(Vault.suspend(vault, :default)) == {:vault_not_started, vault}
      assert reason(Vault.reinstate(vault, :default)) == {:vault_not_started, vault}
    end
  end
end
