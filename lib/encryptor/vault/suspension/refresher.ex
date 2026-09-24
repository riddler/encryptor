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
  # nothing on the call path A8 protects. The call waits the `GenServer`
  # default of five seconds; one that exits is decision 7's failed write.

  use GenServer

  alias Encryptor.Error
  alias Encryptor.Vault.Config
  alias Encryptor.Vault.Suspension

  @doc false
  @spec name(module()) :: atom()
  def name(vault), do: Module.concat(vault, "SuspensionRefresher")

  @doc false
  @spec start_link(Config.t()) :: GenServer.on_start()
  def start_link(%Config{vault: vault} = config) do
    GenServer.start_link(__MODULE__, config, name: name(vault))
  end

  @doc false
  # One write, serialized with the refreshes. A call that exits - it timed
  # out, or this process is restarting - is reported as a write the store did
  # not accept (ADR-0010 decision 5).
  @spec write(Config.t(), Suspension.action(), Error.selector()) :: :ok | {:error, Error.t()}
  def write(%Config{vault: vault} = config, action, selector) do
    GenServer.call(name(vault), {action, selector})
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
  def handle_call({action, selector}, _from, %{config: config} = state)
      when action in [:suspend, :reinstate] do
    {:reply, Suspension.perform(config, action, selector), state}
  end

  defp refresh(%{config: config} = state) do
    failing? = Suspension.refresh(config, state.failing?)
    Process.send_after(self(), :refresh, config.suspension_poll_interval)

    %{state | failing?: failing?}
  end
end
