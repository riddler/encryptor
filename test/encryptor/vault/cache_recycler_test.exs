defmodule Encryptor.Vault.CacheRecyclerTest do
  use ExUnit.Case, async: false

  alias AwsEncryptionSdk.AlgorithmSuite
  alias AwsEncryptionSdk.Cache.CacheEntry
  alias AwsEncryptionSdk.Cache.LocalCache
  alias AwsEncryptionSdk.Cmm.Caching
  alias AwsEncryptionSdk.Materials.EncryptionMaterials
  alias Encryptor.LifecycleVaults
  alias Encryptor.Vault
  alias Encryptor.Vault.CacheRecycler
  alias Encryptor.Vault.Partition

  defp start_vault(vault, opts \\ []) do
    start_supervised!(Supervisor.child_spec({vault, opts}, restart: :temporary))
  end

  defp child_ids(vault) do
    vault
    |> Vault.supervisor_name()
    |> Supervisor.which_children()
    |> Enum.map(fn {id, _pid, _type, _modules} -> id end)
  end

  defp cache_pid(vault), do: Process.whereis(Vault.cache_name(vault))

  # The cache id for one partition of one vault, computed the way the engine
  # computes it, so the entries this test writes sit where real ones would.
  defp cache_id(vault, selector) do
    Caching.compute_encryption_cache_id(Partition.id(vault, selector), suite(), %{})
  end

  defp suite, do: AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()

  defp put_entry(vault, selector) do
    entry = CacheEntry.new(EncryptionMaterials.new_for_encrypt(suite(), %{}), 300)

    :ok = LocalCache.put_cache_entry(Vault.cache_name(vault), cache_id(vault, selector), entry)
  end

  # Deliberately a boolean rather than the entry: a failure message must not
  # print cached materials.
  defp cached?(vault, selector) do
    match?(
      {:ok, %CacheEntry{}},
      LocalCache.get_cache_entry(Vault.cache_name(vault), cache_id(vault, selector))
    )
  end

  # Polls rather than sleeps a fixed span, so the test is neither flaky under
  # load nor slower than the recycle it is waiting for.
  defp await_recycle(vault, was, deadline \\ 2_000) do
    now = cache_pid(vault)

    cond do
      is_pid(now) and now != was ->
        now

      deadline <= 0 ->
        flunk("the cache was not recycled within the deadline")

      true ->
        Process.sleep(10)
        await_recycle(vault, was, deadline - 10)
    end
  end

  describe "the recycler as a supervised child" do
    # sabotage: returned only the cache child from cache_child/1 - red,
    # because an unbounded cache then grows one entry per tenant per context
    # forever, which is the defect ADR-0001 decision 6 exists to bound.
    test "a cached vault runs a recycler under its own derived name" do
      start_vault(LifecycleVaults.Cached)

      assert :cache_recycler in child_ids(LifecycleVaults.Cached)
      assert is_pid(Process.whereis(Vault.recycler_name(LifecycleVaults.Cached)))
    end

    # sabotage: moved the recycler child out of cache_child/1 and appended it
    # unconditionally - red, because a vault with no cache then runs a process
    # whose every tick looks for a child that does not exist.
    test "a vault with caching disabled runs no recycler" do
      start_vault(LifecycleVaults.Cacheless)

      refute :cache_recycler in child_ids(LifecycleVaults.Cacheless)
      assert Process.whereis(Vault.recycler_name(LifecycleVaults.Cacheless)) == nil
    end

    # sabotage: passed bounds.recycle_after straight through as the interval -
    # red, because :recycle_after is in seconds and the timer is in
    # milliseconds, so the cache would recycle a thousand times too often.
    test "the interval is the configured recycle_after, in milliseconds" do
      start_vault(LifecycleVaults.Cached, cache: [max_age: 60])

      state = :sys.get_state(Vault.recycler_name(LifecycleVaults.Cached))

      assert state.interval == 20 * 60 * 1_000
      assert state.supervisor == Vault.supervisor_name(LifecycleVaults.Cached)
    end
  end

  describe "recycling" do
    setup do
      start_vault(LifecycleVaults.Cached)

      :ok
    end

    # sabotage: made recycle/1 call Supervisor.terminate_child/2 and stop -
    # red on the second assertion, because the cache is then never started
    # again and the vault runs on without one.
    test "a recycle empties every partition at once" do
      put_entry(LifecycleVaults.Cached, "tenant-42")
      put_entry(LifecycleVaults.Cached, "tenant-43")

      assert cached?(LifecycleVaults.Cached, "tenant-42")
      assert cached?(LifecycleVaults.Cached, "tenant-43")

      before = cache_pid(LifecycleVaults.Cached)

      start_supervised!(
        {CacheRecycler, [supervisor: Vault.supervisor_name(LifecycleVaults.Cached), interval: 25]}
      )

      after_recycle = await_recycle(LifecycleVaults.Cached, before)

      assert is_pid(after_recycle)
      refute cached?(LifecycleVaults.Cached, "tenant-42")
      refute cached?(LifecycleVaults.Cached, "tenant-43")
    end

    # sabotage: removed the reschedule from handle_info/2 - red, because the
    # recycler then bounds the cache exactly once and never again.
    test "recycling repeats on the interval" do
      first = cache_pid(LifecycleVaults.Cached)

      start_supervised!(
        {CacheRecycler, [supervisor: Vault.supervisor_name(LifecycleVaults.Cached), interval: 25]}
      )

      second = await_recycle(LifecycleVaults.Cached, first)
      third = await_recycle(LifecycleVaults.Cached, second)

      assert first != second
      assert second != third
    end

    # sabotage: made recycle/1 kill the cache child and let the supervisor
    # react, instead of driving the restart itself - red under a short
    # interval, because the vault supervisor's restart intensity is then spent
    # on scheduled maintenance and the whole vault comes down with it.
    test "recycling does not take the vault down" do
      start_supervised!(
        {CacheRecycler, [supervisor: Vault.supervisor_name(LifecycleVaults.Cached), interval: 10]}
      )

      first = await_recycle(LifecycleVaults.Cached, cache_pid(LifecycleVaults.Cached))
      second = await_recycle(LifecycleVaults.Cached, first)
      third = await_recycle(LifecycleVaults.Cached, second)
      fourth = await_recycle(LifecycleVaults.Cached, third)

      assert is_pid(fourth)
      assert LifecycleVaults.Cached.started?()
      assert is_pid(Process.whereis(Vault.lifecycle_name(LifecycleVaults.Cached)))
    end
  end

  describe "a recycler whose cache child is missing" do
    # sabotage: made recycle/1 match only on :ok from terminate_child/2 - red,
    # because a missing cache child then crashes the recycler on every tick
    # instead of leaving a missed bound to the next one.
    test "keeps running instead of crashing the vault" do
      start_vault(LifecycleVaults.Cacheless)

      recycler =
        start_supervised!(
          {CacheRecycler,
           [supervisor: Vault.supervisor_name(LifecycleVaults.Cacheless), interval: 10]}
        )

      Process.sleep(60)

      assert Process.alive?(recycler)
      assert LifecycleVaults.Cacheless.started?()
    end
  end
end
