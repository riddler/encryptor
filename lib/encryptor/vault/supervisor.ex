defmodule Encryptor.Vault.Supervisor do
  @moduledoc """
  The supervisor a vault starts, and the only place a vault has processes.

  The engine is data, not a service: keyrings, CMMs and clients are structs,
  and encrypt and decrypt are pure functions over them. Exactly one component
  in the whole library owns a process, the materials cache, so this supervisor
  is deliberately small and its child list is deliberately short (ADR-0001
  decision 2).

  ## The children, in order

    1. `Encryptor.Vault.Lifecycle` - owns the frozen configuration's lifetime.
       It is **first** so that the configuration is published before anything
       that might read it starts.
    2. The materials cache, when `:cache` is configured. Registered under
       `Encryptor.Vault.cache_name/1`, so two vaults never share one.
    3. The key provider, when its module exports `child_spec/1`. Its child id
       is set to the provider module here, which is what lets
       `Encryptor.Vault.ensure_provider_started/2` ask this supervisor whether
       the provider is alive without knowing anything about how the provider
       registered itself.

  A vault configured with `cache: false` still starts, with the cache child
  simply absent: a provider may need supervision even when the cache does not
  exist.

  ## Configuration resolves here, once

  `start_link/2` runs the five-layer precedence chain and every start-time
  check `Encryptor.Vault.Config` owns, **before** the supervisor process
  exists. A configuration the vault refuses is an ordinary
  `{:error, %Encryptor.Error{}}` from `start_link/2` rather than a running
  vault that fails at its first encrypt - and rather than a supervisor that
  starts and immediately dies, which would report a design decision as a
  crash. It re-runs on a restart, so a vault brought back up reads its
  configuration again.

  ## What is not here yet

  The cache recycler, which bounds the cache the only way the engine permits
  by stopping the cache child on an interval and letting this supervisor
  restart it with a fresh table, is the next child in this list. It is not a
  refinement of the cache and it may not be simplified away: the engine's
  cache has no capacity limit, no sweeper, and no way for outside code to
  measure it (ADR-0001 decision 6).
  """

  use Supervisor

  alias Encryptor.Vault
  alias Encryptor.Vault.Config
  alias Encryptor.Vault.Lifecycle

  @doc """
  Resolves a vault's configuration, then starts its supervisor registered
  under `Encryptor.Vault.supervisor_name/1`.

  `start_opts` are layer 4 of the configuration precedence chain.
  """
  @spec start_link(module(), keyword()) :: Supervisor.on_start()
  def start_link(vault, start_opts \\ []) do
    otp_app = vault.__vault__(:otp_app)
    use_opts = vault.__vault__(:use_opts)

    with {:ok, config} <- Config.resolve(vault, otp_app, use_opts, start_opts) do
      Supervisor.start_link(__MODULE__, config, name: Vault.supervisor_name(vault))
    end
  end

  @impl Supervisor
  def init(%Config{} = config) do
    Supervisor.init(children(config), strategy: :one_for_one)
  end

  defp children(%Config{} = config) do
    [{Lifecycle, config}] ++ cache_child(config) ++ provider_child(config)
  end

  defp cache_child(%Config{cache: false}), do: []

  defp cache_child(%Config{vault: vault, cache: bounds}) when is_map(bounds) do
    [
      %{
        id: :cache,
        start: {AwsEncryptionSdk.Cache.LocalCache, :start_link, [[name: Vault.cache_name(vault)]]}
      }
    ]
  end

  defp provider_child(%Config{provider: {module, opts}}) do
    if Vault.supervised_provider?(module),
      do: [Supervisor.child_spec({module, opts}, id: module)],
      else: []
  end
end
