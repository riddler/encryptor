defmodule Encryptor.Vault.Suspension.Refresher do
  @moduledoc false

  # Keeps a vault's suspension view in step with a shared store (ADR-0010
  # decision 5). One per vault, started by `Encryptor.Vault.Supervisor` after
  # `Encryptor.Vault.Lifecycle` and only when the vault's store is not the
  # default: under `Encryptor.Vault.Suspension.Store.Ets` a refresh would read
  # back the table it would write (decision 4).
  #
  # It is a child of its own rather than a part of `Lifecycle`, so a
  # refresher that crashes does not take the view table with it. The
  # supervisor restarts it, and its first act is to read the store again.
  #
  # It calls `list/1` once at start, then again `suspension_poll_interval`
  # milliseconds after each call returns: a fixed delay rather than a fixed
  # rate, so a slow store is never asked twice at once. The first read is a
  # `handle_continue/2` so a slow store never holds up the vault's start.
  #
  # `suspend/2` and `reinstate/2` under a shared store are calls into this
  # process, so a local write and a refresh never interleave: a refresh that
  # listed the store before a local write landed can never remove what that
  # write just added. They are operator verbs, so serializing them costs
  # nothing on the call path A8 protects.
  #
  # A write carries its deadline, five seconds after the caller made it, and
  # this process drops a request it takes up after that deadline: it answers
  # `:expired`, writes nothing and emits nothing, so a write its caller was
  # told had failed is never performed later and never emits a second event
  # (ADR-0010 decisions 7 and 8, and the dated Note on them). A request taken
  # up in time gives the store what is left of its deadline and no more.
  # Every refresh is bounded too (`Encryptor.Vault.Suspension.refresh/2`), so
  # a hung store holds a queued write for at most one bounded list. The
  # caller waits the deadline plus `@reply_slack` for the answer; a call that
  # exits all the same - this process is restarting, or stuck in something
  # no bound covers - is decision 7's failed write.

  use GenServer

  alias Encryptor.Error
  alias Encryptor.Vault.Config
  alias Encryptor.Vault.Suspension

  # How long a caller's write may take, from the call to the store's answer.
  @write_timeout 5_000

  # How long past the deadline the caller still waits for this process's
  # answer, which covers the view update and the event after the store's.
  @reply_slack 1_000

  @doc false
  @spec name(module()) :: atom()
  def name(vault), do: Module.concat(vault, "SuspensionRefresher")

  @doc false
  @spec start_link(Config.t()) :: GenServer.on_start()
  def start_link(%Config{vault: vault} = config) do
    GenServer.start_link(__MODULE__, config, name: name(vault))
  end

  @doc false
  # One write, serialized with the refreshes, under a deadline `timeout`
  # milliseconds from now. A request dropped at its deadline, and a call that
  # exits - it timed out, or this process is restarting - are reported as a
  # write the store did not accept (ADR-0010 decisions 5 and 7), and the
  # event is emitted here, on the caller's process. For a dropped request,
  # and for a call that exits before the refresher took it up, that is the
  # call's one event. A write the refresher performed in time whose answer
  # still arrives past the deadline plus `@reply_slack` - the view update,
  # the cache drop or a synchronous event handler ran long - is the
  # exception: `perform/4` has emitted its own outcome and the write stands,
  # and this emits `:error` as well. A retry is safe (decision 7).
  @spec write(Config.t(), Suspension.action(), Error.selector(), pos_integer()) ::
          :ok | {:error, Error.t()}
  def write(%Config{vault: vault} = config, action, selector, timeout \\ @write_timeout) do
    deadline = System.monotonic_time(:millisecond) + timeout

    case GenServer.call(name(vault), {action, selector, deadline}, timeout + @reply_slack) do
      :expired -> Suspension.failed(config, action, {:timeout, timeout})
      answer -> answer
    end
  catch
    :exit, reason -> Suspension.failed(config, action, {:exit, reason})
  end

  @impl GenServer
  def init(%Config{} = config) do
    {:ok, %{config: config, failing?: false}, {:continue, :refresh}}
  end

  @impl GenServer
  def handle_continue(:refresh, state), do: {:noreply, refresh(state)}

  @impl GenServer
  def handle_info(:refresh, state), do: {:noreply, refresh(state)}

  @impl GenServer
  def handle_call({action, selector, deadline}, _from, %{config: config} = state)
      when action in [:suspend, :reinstate] do
    case deadline - System.monotonic_time(:millisecond) do
      left when left > 0 -> {:reply, Suspension.perform(config, action, selector, left), state}
      _expired -> {:reply, :expired, state}
    end
  end

  defp refresh(%{config: config} = state) do
    failing? = Suspension.refresh(config, state.failing?)
    Process.send_after(self(), :refresh, config.suspension_poll_interval)

    %{state | failing?: failing?}
  end
end
