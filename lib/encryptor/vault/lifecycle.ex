defmodule Encryptor.Vault.Lifecycle do
  @moduledoc """
  Owns the lifetime of a vault's frozen configuration.

  `Encryptor.Vault.Config` publishes the resolved struct into
  `:persistent_term` and erases it again, but a `:persistent_term` entry has
  no owner of its own: nothing removes it when the vault that wrote it goes
  away. This process is that owner. It freezes on the way up and erases on the
  way down, which is what keeps `{:vault_not_started, vault}` an honest answer
  after a vault stops rather than a stale struct a later call would encrypt
  against.

  It is the vault supervisor's first child, so the configuration is published
  before the cache or the provider starts and a provider's `child_spec/1` can
  read it.

  The process holds no other state and answers no calls. `:persistent_term` is
  what the hot path reads - lock-free and allocating nothing - and routing
  configuration reads through a `GenServer` would put a serialization point in
  front of a pure function, which is the shape ADR-0001 decision 5 exists to
  avoid.

  `:persistent_term.erase/1` triggers a global scan, which is why it happens
  here, on a vault's lifecycle boundary, and never on a call path.
  """

  use GenServer

  alias Encryptor.Vault
  alias Encryptor.Vault.Config

  @doc "Starts the owner process for a resolved configuration."
  @spec start_link(Config.t()) :: GenServer.on_start()
  def start_link(%Config{vault: vault} = config) do
    GenServer.start_link(__MODULE__, config, name: Vault.lifecycle_name(vault))
  end

  @impl GenServer
  def init(%Config{} = config) do
    # Without trapping exits the supervisor's shutdown kills this process
    # brutally and `terminate/2` never runs, which would leave the frozen
    # configuration behind after the vault stopped.
    Process.flag(:trap_exit, true)
    Config.freeze(config)
    {:ok, config}
  end

  @impl GenServer
  def terminate(_reason, %Config{vault: vault}) do
    Config.erase(vault)
    :ok
  end
end
