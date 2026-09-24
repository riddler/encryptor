defmodule Encryptor.Vault.Suspension do
  @moduledoc false

  # The suspended set: which selectors this vault refuses to resolve, and the
  # two writes that move a selector in and out of it.
  #
  # ADR-0005 amendment A is this module's contract, with ADR-0010 deciding
  # where the set is agreed (below). A selector is
  # *suspended* when every entry point fails with
  # `{:key_unavailable, selector}` while the wrappings it resolves to are
  # untouched in the key store (A1): the data is unreadable and intact. The
  # refusal itself is one lookup in `Encryptor.Vault.Resolve`, ahead of the
  # provider and therefore ahead of the materials cache, which is what makes a
  # suspension immediate rather than as prompt as a cache turnover (A5).
  #
  # ## Where the set lives, and why here rather than anywhere else
  #
  # An ETS table owned by the vault's `Encryptor.Vault.Lifecycle` child,
  # created in its `init/1` beside the configuration freeze and dying with it
  # (A8). Every other candidate was refused by a rule this package already
  # holds:
  #
  #   * not `%Encryptor.Vault.Config{}`, which is frozen at start;
  #   * not `:persistent_term`, whose writes and erases trigger a global scan
  #     that `Lifecycle` deliberately confines to a vault's lifecycle
  #     boundary;
  #   * not a `GenServer.call`, which would put a serialization point in front
  #     of the pure function every encrypt and decrypt runs through - the
  #     shape ADR-0001 decision 5 exists to avoid.
  #
  # The table is `:public` because the writes are the caller's: `suspend/2` is
  # invoked from a console or a release task on whatever process the operator
  # has, not on the `Lifecycle` process. It is `read_concurrency: true`
  # because the read is on the hot path of every call and the writes are
  # operational, which is exactly the ratio that option is for.
  #
  # Two properties follow from the owner under the default store, and are
  # decisions rather than accidents (A8, ADR-0010 decision 4). The set is
  # **not durable**: a restarted vault serves the selector again, because the
  # table went with the process. It is **not cluster-wide**: a host running
  # four nodes has four vaults and suspends on each.
  #
  # ## The table is a view; the store is where the set is agreed
  #
  # ADR-0010 puts a behaviour, `Encryptor.Vault.Suspension.Store`, between
  # the two verbs and the set. The table above stays where the gate reads
  # (decision 3): the store is where the set is *agreed*, the table is where
  # it is *read*. Under the default `Encryptor.Vault.Suspension.Store.Ets` the
  # two are the same table, and nothing above changes. Under any other store
  # a host has distribution and persistence of its own making, and
  # `Encryptor.Vault.Suspension.Refresher` keeps the table in step with the
  # store once per poll interval (decision 5). Until its first successful
  # read, the table carries one marker row that denies every scope (decision
  # 7). A deny that must bind more than this vault - a second client, a node
  # configured with a different store - still belongs at the provider locus of
  # A3: an IAM binding revoked on the key material itself (decision 9).
  #
  # ## The cache half is hygiene, not correctness
  #
  # A5 puts the gate in front of resolution, so nothing can be read through
  # the vault under a suspension whatever the cache holds. Dropping the table
  # anyway keeps a suspended scope's data keys from sitting resident for the
  # length of the suspension, and A6 fixes the mechanism: the partition id is
  # a cache-key *input* and not an index, nothing maps a partition to the
  # entries derived from it, so the only eviction this package has is the
  # whole-table recycle `Encryptor.Vault.CacheRecycler` already performs. The
  # cost is one cold miss for every other selector on the vault, which is the
  # recycler's own argument: every entry is derived material that can be
  # re-fetched.

  alias Encryptor.Error
  alias Encryptor.Telemetry
  alias Encryptor.Vault
  alias Encryptor.Vault.CacheRecycler
  alias Encryptor.Vault.Config
  alias Encryptor.Vault.Suspension.Refresher
  alias Encryptor.Vault.Suspension.Store

  # The marker row a shared store's view carries until its first successful
  # `list/1`. A selector is a string or `:default`, so a tuple key cannot
  # collide with one.
  @unloaded {__MODULE__, :unloaded}

  @typedoc false
  @type action :: :suspend | :reinstate

  @doc false
  # Named after the vault, like every other per-vault process and table, so
  # two vaults in one node never share a suspended set.
  @spec table(module()) :: atom()
  def table(vault), do: Module.concat(vault, "Suspended")

  @doc false
  # Called from `Encryptor.Vault.Lifecycle.init/1`, so the table exists before
  # the cache, the provider, or any call that reads it. Under a shared store
  # it is born denying every scope (ADR-0010 decision 7): a table recreated
  # empty by a `Lifecycle` restart must not serve a suspended scope until the
  # refresher has read the store again.
  @spec create(Config.t()) :: :ets.table()
  def create(%Config{vault: vault} = config) do
    tid = :ets.new(table(vault), [:set, :public, :named_table, read_concurrency: true])

    if shared?(config), do: true = :ets.insert(tid, {@unloaded})

    tid
  end

  @doc false
  # Whether the vault's store is one other than the default, and so needs a
  # refresher (ADR-0010 decisions 4 and 5).
  @spec shared?(Config.t()) :: boolean()
  def shared?(%Config{suspension_store: {Store.Ets, _opts}}), do: false
  def shared?(%Config{}), do: true

  @doc false
  # The gate's read. `:ets.whereis/1` rather than a bare lookup because a
  # vault whose `Lifecycle` child is between a crash and its restart has no
  # table, and a library that raised from the hot path there would report a
  # restart as a caller's error. Under the default store `false` is the
  # honest answer: A8 makes the set die with the process, so a vault that
  # restarted is serving the selector again by decision. Under a shared store
  # it is `true`, because a node that has not read the store does not know
  # what is suspended (ADR-0010 decision 7).
  #
  # The default store's read is one lookup, as before. A shared store's view
  # adds the marker's lookup on the same table, only when the selector itself
  # is not in it.
  @spec suspended?(Config.t(), Error.selector()) :: boolean()
  def suspended?(%Config{vault: vault} = config, selector) do
    case :ets.whereis(table(vault)) do
      :undefined -> shared?(config)
      tid -> :ets.member(tid, selector) or (shared?(config) and :ets.member(tid, @unloaded))
    end
  end

  @doc false
  # The selectors a view holds, without the marker.
  @spec members(:ets.table()) :: [Error.selector()]
  def members(tid) do
    tid
    |> :ets.select([{{:"$1"}, [], [:"$1"]}])
    |> Enum.reject(&(&1 == @unloaded))
  end

  @doc false
  # The not-started check, then the write. Under the default store the write
  # runs here, on the caller's process; under a shared store it is a call into
  # the refresher, so a local write and a refresh never interleave (ADR-0010
  # decision 5).
  @spec suspend(Config.t(), Error.selector()) :: :ok | {:error, Error.t()}
  def suspend(%Config{} = config, selector), do: write(config, :suspend, selector)

  @doc false
  # A7: total, idempotent, and it restores nothing but the gate. It evicts
  # nothing because A5 means no materials were served under the suspension in
  # the first place, and it undoes nothing else - a selector whose wrappings
  # were shredded while it was suspended reads back as
  # `{:unknown_key, selector}` from the provider, which is A4's table read
  # downward and is correct.
  @spec reinstate(Config.t(), Error.selector()) :: :ok | {:error, Error.t()}
  def reinstate(%Config{} = config, selector), do: write(config, :reinstate, selector)

  defp write(%Config{vault: vault} = config, action, selector) do
    with {:ok, _tid} <- live(vault) do
      if shared?(config),
        do: Refresher.write(config, action, selector),
        else: perform(config, action, selector)
    end
  end

  @doc false
  # One write through the store, on whichever process performs it.
  #
  # The store first, then the view, then the eviction. A write the store did
  # not accept changes nothing locally (ADR-0010 decision 7): a suspension
  # applied to the view alone would be taken out again by the next refresh,
  # and a suspension that lifts itself a few seconds after succeeding is worse
  # than a loud refusal the operator can retry. Under the default store the
  # store's write *is* the view's, so the view step is skipped.
  #
  # The eviction follows a suspension only: the gate is the verb and the drop
  # is hygiene, so a failure to find a cache child must not leave a selector
  # un-denied. A6's `cache: false` case arrives here as exactly that - no
  # child, nothing dropped, still `:ok`.
  @spec perform(Config.t(), action(), Error.selector()) :: :ok | {:error, Error.t()}
  def perform(%Config{vault: vault, suspension_store: {store, _opts}} = config, action, selector) do
    case call_store(store, action, [config.suspension_store_state, selector]) do
      :ok ->
        if shared?(config), do: update_view(vault, action, selector)
        if action == :suspend, do: _ = CacheRecycler.recycle(vault, Vault.supervisor_name(vault))
        Telemetry.suspension_changed(vault, action, store, {:ok, count(vault)})

        :ok

      {:error, engine} ->
        failed(config, action, engine)
    end
  end

  @doc false
  # A write that never reached `perform/3` - the call into the refresher
  # exited - is reported exactly as one the store refused.
  @spec failed(Config.t(), action(), term()) :: {:error, Error.t()}
  def failed(%Config{vault: vault, suspension_store: {store, _opts}}, action, engine) do
    Telemetry.suspension_changed(vault, action, store, :error)

    {:error,
     %Error{
       reason: {:suspension_store_unavailable, store},
       vault: vault,
       operation: :start,
       engine: engine
     }}
  end

  @doc false
  # One refresh: read the store and make the view equal to it. Returns
  # whether the refresh failed, which is the one thing the refresher carries
  # from one refresh to the next (ADR-0010 decision 8: the first success
  # after a failure is a change, and says so).
  @spec refresh(Config.t(), boolean()) :: boolean()
  def refresh(%Config{vault: vault, suspension_store: {store, _opts}} = config, failing?) do
    case call_store(store, :list, [config.suspension_store_state]) do
      {:ok, selectors} ->
        if apply_view(vault, selectors) or failing?,
          do: Telemetry.suspension_changed(vault, :refresh, store, {:ok, count(vault)})

        false

      {:error, _engine} ->
        Telemetry.suspension_changed(vault, :refresh, store, :error)

        true
    end
  end

  # ADR-0010 decision 7 decides that an `{:error, term}`, an exit and a raise
  # out of a store callback are one outcome, a store that could not answer.
  # This is that decision, not a rescue-to-default: every branch becomes the
  # failure the caller reports, and the store's own term rides in `:engine`.
  defp call_store(store, callback, args) do
    store
    |> apply(callback, args)
    |> store_answer(callback)
  rescue
    exception -> {:error, exception}
  catch
    :exit, reason -> {:error, {:exit, reason}}
  end

  defp store_answer(:ok, callback) when callback in [:suspend, :reinstate], do: :ok
  defp store_answer({:ok, selectors}, :list) when is_list(selectors), do: {:ok, selectors}
  defp store_answer({:error, term}, _callback), do: {:error, term}
  defp store_answer(other, _callback), do: {:error, {:bad_return, other}}

  defp update_view(vault, action, selector) do
    case :ets.whereis(table(vault)) do
      :undefined -> :ok
      tid when action == :suspend -> true = :ets.insert(tid, {selector})
      tid -> true = :ets.delete(tid, selector)
    end
  end

  # Makes the view equal to the store's set, and answers whether its
  # membership changed. New members go in before the departed ones come out,
  # and the marker comes out between the two, so a scope suspended both before
  # and after is never momentarily absent (ADR-0010 decision 5). A view with
  # no table - a `Lifecycle` restart in progress - is left to the next
  # refresh.
  defp apply_view(vault, selectors) do
    case :ets.whereis(table(vault)) do
      :undefined ->
        false

      tid ->
        wanted = MapSet.new(selectors)
        current = MapSet.new(members(tid))
        added = MapSet.difference(wanted, current)
        departed = MapSet.difference(current, wanted)
        unloaded? = :ets.member(tid, @unloaded)

        true = :ets.insert(tid, Enum.map(added, &{&1}))
        true = :ets.delete(tid, @unloaded)
        Enum.each(departed, &(true = :ets.delete(tid, &1)))

        unloaded? or MapSet.size(added) > 0 or MapSet.size(departed) > 0
    end
  end

  defp count(vault) do
    case :ets.whereis(table(vault)) do
      :undefined -> 0
      tid -> length(members(tid))
    end
  end

  # A vault whose supervisor answered the lifecycle check a moment ago can
  # still be mid-restart by the time the write lands, and the set is the
  # vault's: with no table there is nothing to write to and nothing that would
  # survive if there were. It is reported as the same not-started error every
  # other entry point gives, so an operator's console session reads one
  # vocabulary.
  @spec live(module()) :: {:ok, :ets.table()} | {:error, Error.t()}
  defp live(vault) do
    case :ets.whereis(table(vault)) do
      :undefined ->
        {:error, %Error{reason: {:vault_not_started, vault}, vault: vault, operation: :start}}

      tid ->
        {:ok, tid}
    end
  end
end
