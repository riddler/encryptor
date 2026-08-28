defmodule Encryptor.Vault.CacheRecycler do
  @moduledoc """
  Bounds a vault's materials cache by throwing the whole table away, on an
  interval.

  This is a crude mechanism and it is documented as one. `LocalCache` has no
  capacity limit, no sweeper, and no way for outside code to measure how large
  it has grown: it deletes an entry when a read finds it expired, or when
  someone deletes it by its 48-byte cache id, and nothing else. The caching
  CMM also calls the cache module by name rather than through the cache
  behaviour, so a bounded implementation cannot be substituted for it either.
  Recycling the process is therefore not one option among several - it is the
  only bound the engine currently permits (ADR-0001 decision 6).

  ## Why dropping the entire table is safe

  Every entry is derived material that can be re-fetched, so the worst outcome
  of a recycle is a cold miss: the next call does the key-provider work it
  would have done anyway. There is no entry whose loss is an error, which is
  what makes an unconditional periodic drop an acceptable answer at all.

  ## Why anything needs dropping

  Decision 7 partitions the cache per tenant. Without a bound, a per-tenant
  partitioning scheme accumulates one entry per tenant per encryption context,
  forever - including for tenants that were offboarded months ago. Expiry does
  not help: `LocalCache` only notices an entry has expired if something reads
  it, and nothing ever reads a departed tenant's entry again.

  ## The mechanism

  The recycler asks the vault's supervisor to terminate the cache child and
  then to start it again, which is what produces the fresh empty table. It
  drives the restart itself rather than killing the cache and letting the
  supervisor react, because a supervisor's restart intensity is a defence
  against a child that keeps failing: spending it on scheduled maintenance
  would mean a short `:recycle_after` takes the whole vault down.

  There is a window, between the terminate and the restart, in which the
  cache's registered name resolves to nothing and a concurrent call through
  the caching CMM would exit with `:noproc`. It is microseconds wide and it is
  inherent to bounding the cache this way - the durable fix is upstream, in
  the engine, and is tracked as the open question decision 6 records.

  ## Retiring this module

  It goes away, entirely, the day the engine grows either a bounded cache or a
  real substitution seam for the cache behaviour. That is the point of keeping
  it in one small module reached from exactly one place, the vault
  supervisor's child list: retiring it deletes a module and a child spec, and
  nothing else has to change.
  """

  use GenServer

  @cache_child_id :cache

  @typedoc """
  Start options.

    * `:supervisor` - the vault supervisor holding the cache child.
    * `:interval` - milliseconds between recycles.
    * `:name` - optional registered name.
  """
  @type option ::
          {:supervisor, Supervisor.supervisor()}
          | {:interval, pos_integer()}
          | {:name, GenServer.name()}

  @doc """
  Starts a recycler for one vault supervisor's cache child.

  The interval is in **milliseconds**, while `:recycle_after` configuration is
  in seconds: the conversion happens where the child spec is built, so this
  process speaks the same unit as the timer it sets.
  """
  @spec start_link([option()]) :: GenServer.on_start()
  def start_link(opts) do
    {name, opts} = Keyword.pop(opts, :name)

    if name do
      GenServer.start_link(__MODULE__, opts, name: name)
    else
      GenServer.start_link(__MODULE__, opts)
    end
  end

  @impl GenServer
  def init(opts) do
    state = %{
      supervisor: Keyword.fetch!(opts, :supervisor),
      interval: Keyword.fetch!(opts, :interval)
    }

    {:ok, schedule(state)}
  end

  @impl GenServer
  def handle_info(:recycle, state) do
    recycle(state.supervisor)

    {:noreply, schedule(state)}
  end

  defp schedule(state) do
    Process.send_after(self(), :recycle, state.interval)

    state
  end

  # A recycle that cannot find its cache child is a missed bound, not a
  # correctness failure, and crashing here would spend the vault supervisor's
  # restart intensity on it. The next tick tries again.
  defp recycle(supervisor) do
    case Supervisor.terminate_child(supervisor, @cache_child_id) do
      :ok -> Supervisor.restart_child(supervisor, @cache_child_id)
      {:error, reason} -> {:error, reason}
    end
  end
end
