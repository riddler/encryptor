defmodule Encryptor.Vault.SuspensionStoreTest do
  @moduledoc """
  ADR-0010: the suspended set is agreed through a store and read from a
  per-node view.

  The default store must change nothing, so its tests assert the absence of
  every new moving part. The shared store is a fake over an agent the test
  owns, which is how a suspension "set elsewhere" is written: straight into
  the store, never through this vault.
  """

  use ExUnit.Case, async: false

  alias Encryptor.EncryptVaults
  alias Encryptor.Error
  alias Encryptor.LifecycleVaults
  alias Encryptor.SuspensionStoreFakes
  alias Encryptor.SuspensionStoreFakes.NotAStore
  alias Encryptor.SuspensionStoreFakes.Shared
  alias Encryptor.Vault
  alias Encryptor.Vault.Suspension.Refresher
  alias Encryptor.Vault.Suspension.Store

  @pan "4111111111111111"
  @columns %{"table" => "payment_methods", "column" => "pan"}
  @vault EncryptVaults.Merchant
  @agent Encryptor.Vault.SuspensionStoreTest.Store
  @poll 100
  # A refresh is scheduled when the previous one returns, so a write that
  # lands just after a refresh is read one interval later plus the list's
  # own duration. The slack is that duration and the scheduler's.
  @within @poll + 150

  defp start_default(vault, opts \\ []) do
    start_supervised!(Supervisor.child_spec({vault, opts}, restart: :temporary))
    vault
  end

  defp start_shared(opts \\ []) do
    store = [suspension_store: {Shared, agent: @agent}, suspension_poll_interval: @poll]
    start_supervised!(Supervisor.child_spec({@vault, store ++ opts}, restart: :temporary))
    @vault
  end

  defp start_store(context) do
    start_supervised!(%{id: :store, start: {SuspensionStoreFakes, :start, [@agent]}})
    context
  end

  defp capture(_context) do
    parent = self()
    id = "enc-0o8-#{System.unique_integer([:positive])}"

    :telemetry.attach(
      id,
      [:encryptor, :suspension, :changed],
      &__MODULE__.forward/4,
      parent
    )

    on_exit(fn -> :telemetry.detach(id) end)

    :ok
  end

  @doc false
  @spec forward([atom()], map(), map(), pid()) :: :ok
  def forward(_name, measurements, metadata, parent) do
    send(parent, {:changed, measurements, metadata})

    :ok
  end

  defp encrypt(vault, selector),
    do: vault.encrypt(@pan, key: selector, encryption_context: @columns)

  defp reason({:error, %Error{reason: reason}}), do: reason

  defp refresher, do: Process.whereis(Refresher.name(@vault))

  # The first successful list/1 is a change even when the set is empty: it
  # takes the view out of its deny-all state.
  defp await_first_refresh do
    assert_receive {:changed, %{count: _}, %{action: :refresh, outcome: :ok}}, @within
  end

  describe "the default store changes nothing (decision 4)" do
    # sabotage: put the refresher in every vault's child list - red, because
    # under the default store it would read back the table it writes.
    test "a vault that names no store takes Store.Ets and runs no refresher" do
      vault = start_default(@vault)

      assert {:ok, config} = Vault.config(vault)
      assert config.suspension_store == {Store.Ets, []}
      assert config.suspension_poll_interval == 5_000
      assert refresher() == nil
    end

    # sabotage: made Store.Ets.list/1 answer an empty set - red, because the
    # default store's set *is* the view the gate reads.
    test "the default store's set is the view the gate reads" do
      vault = start_default(@vault)

      assert :ok = Vault.suspend(vault, "merchant_a")

      assert {:ok, ["merchant_a"]} = Store.Ets.list(vault)
      assert reason(encrypt(vault, "merchant_a")) == {:key_unavailable, "merchant_a"}

      assert :ok = Vault.reinstate(vault, "merchant_a")

      assert {:ok, []} = Store.Ets.list(vault)
    end

    # sabotage: made Store.Ets.init/2 accept any option list - red. The
    # default takes no options, and an option it ignored would be a setting
    # an operator believes is in force.
    test "the default store refuses options at start" do
      assert {:error, %Error{} = error} =
               @vault.start_link(suspension_store: {Store.Ets, table: :mine})

      assert error.reason == {:invalid_config, :suspension_store, :init}
      assert error.engine == {:unknown_options, [:table]}
    end
  end

  describe "configuration (decision 2)" do
    # sabotage: dropped the store_module?/1 check - red on the NotAStore
    # case, which then raises out of start instead of being refused.
    test "a store that is not a {module, keyword} store pair is refused" do
      for store <- [Shared, {Shared, :agent}, {"Shared", []}, {NotAStore, []}] do
        assert {:error, %Error{reason: reason}} =
                 LifecycleVaults.Cached.start_link(suspension_store: store)

        assert reason == {:invalid_config, :suspension_store, :shape}
      end
    end

    # sabotage: ignored init/2's {:error, term} and froze the options instead
    # - red. A store that cannot configure itself is a vault that does not
    # start.
    test "a store whose init/2 refuses refuses the vault's start" do
      assert {:error, %Error{} = error} =
               LifecycleVaults.Cached.start_link(suspension_store: {Shared, []})

      assert error.reason == {:invalid_config, :suspension_store, :init}
      assert error.engine == :no_agent
      assert error.operation == :start
    end

    # sabotage: accepted any integer - red on zero.
    test "the poll interval is a positive integer of milliseconds" do
      for interval <- [0, -1, 1.5, "5s", nil] do
        assert {:error, %Error{reason: reason}} =
                 LifecycleVaults.Cached.start_link(suspension_poll_interval: interval)

        assert reason == {:invalid_config, :suspension_poll_interval, interval}
      end
    end

    # sabotage: removed the :suspension_store redaction from the Inspect
    # implementation - red.
    test "a store's options and state are redacted when the configuration is inspected" do
      start_store(%{})
      start_shared()

      assert {:ok, config} = Vault.config(@vault)

      rendered = inspect(config)

      refute rendered =~ inspect(@agent)
      assert rendered =~ "Encryptor.SuspensionStoreFakes.Shared"
    end
  end

  describe "a shared store (decisions 5 and 6)" do
    setup [:start_store, :capture]

    # sabotage: dropped the Process.send_after/3 that schedules the next
    # refresh - red, because the view then only ever holds the set read at
    # start.
    test "a suspension set elsewhere is honoured within the poll interval" do
      vault = start_shared()
      await_first_refresh()

      assert {:ok, _ciphertext} = encrypt(vault, "merchant_a")

      :ok = SuspensionStoreFakes.put_elsewhere(@agent, "merchant_a")

      assert_receive {:changed, %{count: 1}, %{action: :refresh, outcome: :ok}}, @within
      assert reason(encrypt(vault, "merchant_a")) == {:key_unavailable, "merchant_a"}
      assert {:ok, _ciphertext} = encrypt(vault, "merchant_b")
    end

    # sabotage: skipped the departed members' delete in apply_view - red.
    test "a reinstatement made elsewhere is honoured within the poll interval" do
      :ok = SuspensionStoreFakes.put_elsewhere(@agent, "merchant_a")
      vault = start_shared()

      assert_receive {:changed, %{count: 1}, %{action: :refresh, outcome: :ok}}, @within
      assert reason(encrypt(vault, "merchant_a")) == {:key_unavailable, "merchant_a"}

      :ok = SuspensionStoreFakes.delete_elsewhere(@agent, "merchant_a")

      assert_receive {:changed, %{count: 0}, %{action: :refresh, outcome: :ok}}, @within
      assert {:ok, _ciphertext} = encrypt(vault, "merchant_a")
    end

    # sabotage: made perform/3 skip the store call under a shared store - red
    # on the store's membership, because the other nodes never learn of it.
    test "suspend/2 writes through the store, and holds on this node at once" do
      vault = start_shared()
      await_first_refresh()

      assert :ok = Vault.suspend(vault, "merchant_a")

      assert SuspensionStoreFakes.members(@agent) == ["merchant_a"]
      assert reason(encrypt(vault, "merchant_a")) == {:key_unavailable, "merchant_a"}
    end

    # sabotage: made update_view/3 insert on :reinstate too - red.
    test "reinstate/2 writes through the store, and holds on this node at once" do
      :ok = SuspensionStoreFakes.put_elsewhere(@agent, "merchant_a")
      vault = start_shared()
      assert_receive {:changed, %{count: 1}, %{action: :refresh, outcome: :ok}}, @within

      assert :ok = Vault.reinstate(vault, "merchant_a")

      assert SuspensionStoreFakes.members(@agent) == []
      assert {:ok, _ciphertext} = encrypt(vault, "merchant_a")
    end

    # sabotage: took the refresher out of the supervisor's child list for a
    # shared store - red, on the refresher and on every write.
    test "the refresher is a child of the vault's supervisor, after Lifecycle" do
      start_shared()

      ids =
        @vault
        |> Vault.supervisor_name()
        |> Supervisor.which_children()
        |> Enum.map(fn {id, _pid, _type, _modules} -> id end)
        |> Enum.reverse()

      assert [Encryptor.Vault.Lifecycle, Refresher | _rest] = ids
      assert is_pid(refresher())
    end
  end

  describe "the failure mode (decision 7)" do
    setup [:start_store, :capture]

    # sabotage: applied the write to the view before calling the store - red,
    # on the view, for every mode: a suspension the store did not accept
    # would lift itself at the next refresh.
    test "a write the store does not accept changes nothing locally" do
      vault = start_shared()
      await_first_refresh()

      for mode <- [:error, :raise, :exit] do
        :ok = SuspensionStoreFakes.answer(@agent, :write, mode)

        assert {:error, %Error{} = error} = Vault.suspend(vault, "merchant_a")
        assert error.reason == {:suspension_store_unavailable, Shared}
        assert error.vault == vault
        assert error.engine != nil

        assert {:ok, _ciphertext} = encrypt(vault, "merchant_a")
        assert SuspensionStoreFakes.members(@agent) == []
      end
    end

    # sabotage: applied the write to the view before calling the store - red,
    # because the failed reinstatement then lifts the suspension locally.
    test "a reinstatement the store does not accept leaves the suspension in force" do
      vault = start_shared()
      await_first_refresh()
      assert :ok = Vault.suspend(vault, "merchant_a")

      :ok = SuspensionStoreFakes.answer(@agent, :write, :error)

      assert {:error,
              %Error{reason: {:suspension_store_unavailable, Shared}, engine: :unreachable}} =
               Vault.reinstate(vault, "merchant_a")

      assert reason(encrypt(vault, "merchant_a")) == {:key_unavailable, "merchant_a"}
    end

    # sabotage: skipped the marker row in Suspension.create/1 - red, because
    # a node that has not read the store then serves every suspended scope.
    test "before the first successful list, every scope is denied" do
      :ok = SuspensionStoreFakes.put_elsewhere(@agent, "merchant_a")
      :ok = SuspensionStoreFakes.answer(@agent, :list, :error)
      vault = start_shared()

      assert_receive {:changed, _m, %{action: :refresh, outcome: :error}}, @within
      assert reason(encrypt(vault, "merchant_a")) == {:key_unavailable, "merchant_a"}
      assert reason(encrypt(vault, "merchant_b")) == {:key_unavailable, "merchant_b"}

      :ok = SuspensionStoreFakes.answer(@agent, :list, :ok)

      assert_receive {:changed, %{count: 1}, %{action: :refresh, outcome: :ok}}, @within
      assert reason(encrypt(vault, "merchant_a")) == {:key_unavailable, "merchant_a"}
      assert {:ok, _ciphertext} = encrypt(vault, "merchant_b")
    end

    # sabotage: cleared the view on a failed refresh - red on the suspended
    # scope, under the first failing mode.
    test "after it, a failed refresh keeps the last known set" do
      :ok = SuspensionStoreFakes.put_elsewhere(@agent, "merchant_a")
      vault = start_shared()
      assert_receive {:changed, %{count: 1}, %{action: :refresh, outcome: :ok}}, @within

      for mode <- [:error, :raise, :exit] do
        :ok = SuspensionStoreFakes.answer(@agent, :list, mode)

        assert_receive {:changed, _m, %{action: :refresh, outcome: :error}}, @within
        assert reason(encrypt(vault, "merchant_a")) == {:key_unavailable, "merchant_a"}
        assert {:ok, _ciphertext} = encrypt(vault, "merchant_b")
      end
    end

    # sabotage: skipped the marker row in Suspension.create/1 - red here too:
    # a recreated view would serve the suspended scope until the store
    # answered, which is A8's volatility back in through the side door.
    test "a view recreated by a Lifecycle restart denies every scope until the store answers" do
      :ok = SuspensionStoreFakes.put_elsewhere(@agent, "merchant_a")
      vault = start_shared()
      assert_receive {:changed, %{count: 1}, %{action: :refresh, outcome: :ok}}, @within

      :ok = SuspensionStoreFakes.answer(@agent, :list, :error)
      lifecycle = Process.whereis(Vault.lifecycle_name(vault))
      Process.exit(lifecycle, :kill)
      :ok = await_restart(Vault.lifecycle_name(vault), lifecycle)

      assert reason(encrypt(vault, "merchant_b")) == {:key_unavailable, "merchant_b"}

      :ok = SuspensionStoreFakes.answer(@agent, :list, :ok)

      assert_receive {:changed, %{count: 1}, %{action: :refresh, outcome: :ok}}, @within
      assert reason(encrypt(vault, "merchant_a")) == {:key_unavailable, "merchant_a"}
      assert {:ok, _ciphertext} = encrypt(vault, "merchant_b")
    end
  end

  describe "[:encryptor, :suspension, :changed] (decision 8)" do
    setup [:start_store, :capture]

    # sabotage: emitted only on success - red on the failed write.
    test "every suspend/2 and reinstate/2 emits, successful or not" do
      vault = start_shared()
      await_first_refresh()

      assert :ok = Vault.suspend(vault, "merchant_a")

      assert_receive {:changed, %{count: 1, system_time: _},
                      %{vault: @vault, action: :suspend, store: Shared, outcome: :ok} = metadata}

      assert Map.keys(metadata) |> Enum.sort() == [:action, :outcome, :store, :vault]

      :ok = SuspensionStoreFakes.answer(@agent, :write, :error)
      assert {:error, %Error{}} = Vault.reinstate(vault, "merchant_a")

      assert_receive {:changed, measurements,
                      %{
                        action: :reinstate,
                        store: Shared,
                        outcome: :error,
                        reason_tag: :suspension_store_unavailable
                      }}

      refute Map.has_key?(measurements, :count)
    end

    # sabotage: emitted after every successful refresh - red, because a
    # healthy vault is then never silent between operator actions.
    test "a refresh that changes nothing emits nothing" do
      start_shared()
      await_first_refresh()

      refute_receive {:changed, _m, _md}, @poll * 3
    end

    # sabotage: dropped the `or failing?` from refresh/2 - red, because the
    # recovery is then invisible whenever the set did not change meanwhile.
    test "the first success after a failure emits, even when nothing changed" do
      start_shared()
      await_first_refresh()

      :ok = SuspensionStoreFakes.answer(@agent, :list, :error)
      assert_receive {:changed, _m, %{action: :refresh, outcome: :error}}, @within

      :ok = SuspensionStoreFakes.answer(@agent, :list, :ok)
      assert_receive {:changed, %{count: 0}, %{action: :refresh, outcome: :ok}}, @within
    end

    # sabotage: named the default store's state (the vault) as :store - red.
    test "the default store emits too, naming Store.Ets" do
      vault = start_default(@vault)

      assert :ok = Vault.suspend(vault, "merchant_a")

      assert_receive {:changed, %{count: 1},
                      %{vault: @vault, action: :suspend, store: Store.Ets, outcome: :ok}}
    end
  end

  describe "the error term" do
    # sabotage: dropped the store module from the message - red.
    test "names the store and never its term" do
      error = %Error{
        reason: {:suspension_store_unavailable, Shared},
        vault: @vault,
        operation: :start,
        engine: {:connection_refused, "db.internal:5432"}
      }

      assert Error.message(error) ==
               "suspension store Encryptor.SuspensionStoreFakes.Shared is unavailable " <>
                 "(Encryptor.EncryptVaults.Merchant, start)"
    end
  end

  defp await_restart(name, old, attempts \\ 50)
  defp await_restart(_name, _old, 0), do: :timeout

  defp await_restart(name, old, attempts) do
    case Process.whereis(name) do
      pid when is_pid(pid) and pid != old ->
        :ok

      _other ->
        receive do
        after
          10 -> await_restart(name, old, attempts - 1)
        end
    end
  end
end
