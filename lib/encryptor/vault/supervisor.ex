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
    2. The suspension refresher, when - and only when - the vault's
       `:suspension_store` is not the default
       `Encryptor.Vault.Suspension.Store.Ets`. It reads the store once per
       `:suspension_poll_interval` into the view `Lifecycle` owns, so it
       starts after `Lifecycle` and is a child of its own: a refresher that
       crashes does not take the view with it (ADR-0010 decision 5).
    3. The materials cache, when `:cache` is configured. Registered under
       `Encryptor.Vault.cache_name/1`, so two vaults never share one.
    4. `Encryptor.Vault.CacheRecycler`, when - and only when - there is a
       cache. It stops the cache child on the configured `:recycle_after`
       interval and starts it again, which is the only bound the engine
       permits on a cache that has no capacity limit, no sweeper, and no way
       for outside code to measure it (ADR-0001 decision 6). It is not a
       refinement of the cache and it may not be simplified away.
    5. The key provider, when its module exports `child_spec/1`. Its child id
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

  The strategy is `:one_for_one`, so a recycled cache does not take the
  provider or the frozen configuration down with it.
  """

  use Supervisor

  alias Encryptor.Error
  alias Encryptor.Telemetry
  alias Encryptor.Vault
  alias Encryptor.Vault.CacheRecycler
  alias Encryptor.Vault.Config
  alias Encryptor.Vault.Lifecycle
  alias Encryptor.Vault.Suspension
  alias Encryptor.Vault.Suspension.Refresher

  @doc """
  Resolves a vault's configuration, then starts its supervisor registered
  under `Encryptor.Vault.supervisor_name/1`.

  `start_opts` are layer 4 of the configuration precedence chain.

  ## Telemetry

  A resolved configuration whose supervisor comes up emits
  `[:encryptor, :vault, :started]`, and a configuration the vault refuses
  emits `[:encryptor, :vault, :start_refused]` (ADR-0006 decision 10). Both
  fire here rather than in `init/1` because resolution happens here, before
  any process exists, and because `Encryptor.Vault.Lifecycle` is the first
  child - so by the time `Supervisor.start_link/3` returns, the configuration
  is frozen and `:started` is telling the truth.

  The refusal event is the one whose usefulness is bounded by when it fires:
  a vault started from the host's application supervisor is refused before
  the host's own handlers are attached, and the event goes nowhere. It still
  fires for a vault started later.
  """
  @spec start_link(module(), keyword()) :: Supervisor.on_start()
  def start_link(vault, start_opts \\ []) do
    otp_app = vault.__vault__(:otp_app)
    use_opts = vault.__vault__(:use_opts)

    case Config.resolve(vault, otp_app, use_opts, start_opts) do
      {:ok, config} ->
        started(
          config,
          Supervisor.start_link(__MODULE__, config, name: Vault.supervisor_name(vault))
        )

      {:error, %Error{} = error} ->
        Telemetry.vault_start_refused(vault, error)

        {:error, error}
    end
  end

  # A supervisor that did not come up did not start a vault, so it gets no
  # `:started`. What it reports is a supervisor failure rather than a
  # configuration one, and `:start_refused` is decision 3's name for the
  # latter only.
  defp started(%Config{} = config, {:ok, pid}) do
    Telemetry.vault_started(config)

    {:ok, pid}
  end

  defp started(%Config{}, other), do: other

  @impl Supervisor
  def init(%Config{} = config) do
    Supervisor.init(children(config), strategy: :one_for_one)
  end

  defp children(%Config{} = config) do
    [{Lifecycle, config}] ++
      refresher_child(config) ++ cache_child(config) ++ provider_child(config)
  end

  # ADR-0010 decision 5: one refresher per vault, after `Lifecycle` so the
  # view it writes exists, and only under a store other than the default.
  defp refresher_child(%Config{} = config) do
    if Suspension.shared?(config), do: [{Refresher, config}], else: []
  end

  defp cache_child(%Config{cache: false}), do: []

  # The recycler is listed here rather than beside the provider so that the
  # thing it recycles and the thing recycling it are added and removed
  # together: a vault with `cache: false` has neither. `:recycle_after` is in
  # seconds, like `:max_age` it is derived from; the recycler's timer is in
  # milliseconds, and this is the only place the two units meet.
  defp cache_child(%Config{vault: vault, cache: bounds}) when is_map(bounds) do
    [
      %{
        id: :cache,
        start: {AwsEncryptionSdk.Cache.LocalCache, :start_link, [[name: Vault.cache_name(vault)]]}
      },
      %{
        id: :cache_recycler,
        start:
          {CacheRecycler, :start_link,
           [
             [
               vault: vault,
               supervisor: Vault.supervisor_name(vault),
               interval: bounds.recycle_after * 1_000,
               name: Vault.recycler_name(vault)
             ]
           ]}
      }
    ]
  end

  defp provider_child(%Config{provider: {module, opts}}) do
    if Vault.supervised_provider?(module),
      do: [Supervisor.child_spec({module, opts}, id: module)],
      else: []
  end
end
