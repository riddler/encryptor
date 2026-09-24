defmodule Encryptor.SuspensionStoreFakes do
  @moduledoc """
  Suspension stores for the ADR-0010 tests.

  `Shared` stands in for a store a host would build over its own database:
  its set lives in an `Agent` outside the vault, so a test can write to it
  "from another node" by writing to the agent directly, and can make any
  callback fail by an `{:error, term}`, a raise or an exit.
  """

  alias Encryptor.Vault.Suspension.Store

  defmodule Shared do
    @moduledoc "A shared store over an agent the test owns."

    @behaviour Store

    @impl true
    def init(_vault, opts) do
      case Keyword.fetch(opts, :agent) do
        {:ok, agent} -> {:ok, agent}
        :error -> {:error, :no_agent}
      end
    end

    @impl true
    def suspend(agent, selector), do: write(agent, &MapSet.put(&1, selector))

    @impl true
    def reinstate(agent, selector), do: write(agent, &MapSet.delete(&1, selector))

    @impl true
    def list(agent) do
      case Agent.get(agent, & &1.list) do
        :ok -> {:ok, agent |> Agent.get(& &1.set) |> MapSet.to_list()}
        mode -> fail(mode)
      end
    end

    defp write(agent, change) do
      case Agent.get(agent, & &1.write) do
        :ok -> Agent.update(agent, fn state -> %{state | set: change.(state.set)} end)
        mode -> fail(mode)
      end
    end

    defp fail(:error), do: {:error, :unreachable}
    defp fail(:raise), do: raise(RuntimeError, "store unreachable")
    defp fail(:exit), do: exit(:store_unreachable)
  end

  defmodule NotAStore do
    @moduledoc "A module that implements none of the store's callbacks."
  end

  @doc "Starts the agent behind a `Shared` store, answering every callback."
  @spec start(atom()) :: Agent.on_start()
  def start(name) do
    Agent.start_link(fn -> %{set: MapSet.new(), list: :ok, write: :ok} end, name: name)
  end

  @doc "Writes a suspension the way another node sharing the store would."
  @spec put_elsewhere(atom(), String.t()) :: :ok
  def put_elsewhere(agent, selector),
    do: Agent.update(agent, fn state -> %{state | set: MapSet.put(state.set, selector)} end)

  @doc "Lifts a suspension the way another node sharing the store would."
  @spec delete_elsewhere(atom(), String.t()) :: :ok
  def delete_elsewhere(agent, selector),
    do: Agent.update(agent, fn state -> %{state | set: MapSet.delete(state.set, selector)} end)

  @doc "What the store holds."
  @spec members(atom()) :: [String.t()]
  def members(agent), do: agent |> Agent.get(& &1.set) |> MapSet.to_list() |> Enum.sort()

  @doc "Makes `:list` or `:write` answer `:ok`, `:error`, `:raise` or `:exit`."
  @spec answer(atom(), :list | :write, :ok | :error | :raise | :exit) :: :ok
  def answer(agent, callback, mode),
    do: Agent.update(agent, &Map.put(&1, callback, mode))
end
