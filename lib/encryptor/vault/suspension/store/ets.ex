defmodule Encryptor.Vault.Suspension.Store.Ets do
  @moduledoc """
  The default `Encryptor.Vault.Suspension.Store`: the vault's own per-node
  table, and nothing else.

  Its set *is* the view the suspension gate reads, so it changes nothing
  about how a suspension behaves (ADR-0010 decision 4):

    * a suspension is **per node**: a suspension set on one node is not seen
      by another, and a host running four nodes suspends on each;
    * it is **volatile**: it is lost when the vault restarts, including at
      every deploy;
    * a vault whose table is absent, between a crash and its restart, serves
      every scope.

  No refresher runs under it, because a refresh would read back the table it
  would write. The vault's `:suspension_poll_interval` is accepted and has no
  effect.

  It takes no options; any option is refused at start as
  `{:invalid_config, :suspension_store, :init}`.
  """

  @behaviour Encryptor.Vault.Suspension.Store

  alias Encryptor.Vault.Suspension

  @impl true
  def init(vault, []), do: {:ok, vault}
  def init(_vault, opts), do: {:error, {:unknown_options, Keyword.keys(opts)}}

  @impl true
  def suspend(vault, selector), do: write(vault, {:suspend, selector})

  @impl true
  def reinstate(vault, selector), do: write(vault, {:reinstate, selector})

  @impl true
  def list(vault) do
    with {:ok, tid} <- table(vault) do
      {:ok, Suspension.members(tid)}
    end
  end

  # The table is `:protected`, so the write is its owner's, the vault's
  # `Lifecycle` process. The vault checks that its table exists before it
  # writes, so `:no_table` answers only for a vault whose `Lifecycle` child
  # restarted in between.
  defp write(vault, write) do
    case Suspension.write_view(vault, write) do
      :ok -> :ok
      :none -> {:error, :no_table}
    end
  end

  defp table(vault) do
    case :ets.whereis(Suspension.table(vault)) do
      :undefined -> {:error, :no_table}
      tid -> {:ok, tid}
    end
  end
end
