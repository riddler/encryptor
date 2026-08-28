defmodule Encryptor.Vault do
  @moduledoc """
  The vault: a host-owned module that wraps the engine completely.

  A host writes one module and calls it from then on:

      defmodule MyApp.Vault do
        use Encryptor.Vault, otp_app: :my_app
      end

  and adds it to a supervision tree:

      children = [MyApp.Vault]

  No host code names `AwsEncryptionSdk` or any module under it, no vault
  function accepts an engine struct, and no vault function returns one. The
  reason for total wrapping is not aesthetics: every decision the accepted
  records make - which suite, which commitment policy, which context keys are
  required, how a selector maps to a cache partition - is enforceable only if
  there is exactly one door (ADR-0001 decision 1).

  ## What `use` captures

  `:otp_app` and the module name, and nothing else. Everything else is read
  when the vault **starts**, through the five-layer precedence chain
  `Encryptor.Vault.Config` owns, and frozen into `:persistent_term`. Options
  written at `use` are layer 2 of that chain, not a configuration of their
  own: they are carried forward and can be overridden by application
  environment, by `start_link/1`, and by `init/1`.

  Key material passed to `use` is a **compile-time error**, not a warning. A
  secret in `use` options is a secret compiled into a `.beam` file and
  committed to the host's build artifacts, and the vault refuses to be the
  reason that happens. The refusal is
  `Encryptor.Vault.Config.validate_use_opts!/2`, called while this macro
  expands (ADR-0001 decision 5).

  ## What a vault supervises

  Starting a vault starts a `Supervisor` (see `Encryptor.Vault.Supervisor`)
  whose children are:

    1. `Encryptor.Vault.Lifecycle`, which owns the frozen configuration's
       lifetime: it publishes the resolved struct when the vault starts and
       erases it when the vault stops,
    2. the vault's materials cache, when caching is configured on,
    3. the key provider, when the provider module exports `child_spec/1`.

  Two consequences are deliberate. A vault configured with `cache: false`
  still starts, because a provider may need supervision even when the cache
  does not exist. And **two vaults never share a cache process**: the pair
  `{otp_app, vault_module}` is the whole configuration key, so nothing here is
  global and one vault's `max_age` never applies to another vault's materials
  (ADR-0001 decisions 2 and 3).

  ## The lifecycle checks

  A vault that is not running is a **typed error, not a crash**. Every entry
  point calls `ready/2` first, which checks that the vault's supervisor is
  alive and reads the frozen configuration, and returns
  `{:error, %Encryptor.Error{reason: {:vault_not_started, MyApp.Vault}}}`
  rather than letting a call to an unregistered name raise an exit from inside
  a library. `ensure_provider_started/2` is its sibling for a provider that
  has a process: `{:provider_not_started, module}` (ADR-0001 decision 2;
  ADR-0002 decision 6).

  Neither is a rescue. Both are checks, which is what keeps them compatible
  with ADR-0001 decision 10's rule that this package never rescues an
  exception into an `{:error, _}`.

  ## Generated functions

  `use Encryptor.Vault` defines, on the host's module:

    * `child_spec/1` and `start_link/1` - the supervision-tree surface,
    * `stop/0` - stops the vault and erases its frozen configuration,
    * `config/0` - the frozen configuration, or `{:vault_not_started, _}`,
    * `started?/0` - whether the vault's supervisor is alive.

  The optional `init/1` callback is layer 5 of the precedence chain and the
  intended place to read key material out of the environment or a secrets
  manager, following the pattern hosts already know from `Ecto.Repo.init/2`.

  The `encrypt/2`, `decrypt/2` and `rekey/2` entry points are **not** defined
  yet: their bodies are the work of later beads, and each is built on `ready/2`
  from here.

  Records: ADR-0001 decisions 1, 2, 3, 5 and 10; ADR-0002 decision 6.
  """

  alias Encryptor.Error
  alias Encryptor.Vault.Config

  @typedoc """
  A key selector.

  An alias of `t:Encryptor.Error.selector/0` rather than a restatement of it:
  the selector vocabulary is fixed once, by ADR-0004 decision 3, and a second
  copy of it is a second place for it to drift.
  """
  @type selector :: Error.selector()

  @doc """
  Layer 5 of the precedence chain: the runtime configuration escape hatch.

  Receives the merged keyword list and returns the configuration the vault
  starts with. Its return **replaces** the merge rather than being merged over
  it, with the package defaults re-applied underneath so a callback that
  builds a fresh list does not silently drop the commitment policy floor.

  Optional. A vault that exports none is configured entirely from the layers
  below it.
  """
  @callback init(config :: keyword()) :: {:ok, keyword()}

  @optional_callbacks init: 1

  @doc false
  defmacro __using__(opts) do
    quote bind_quoted: [opts: opts] do
      @behaviour Encryptor.Vault

      # Layer 2 of the precedence chain, checked for key material while this
      # module compiles. `validate_use_opts!/2` raises here rather than at
      # start, because by the time a vault starts the secret is already in the
      # .beam file.
      @encryptor_vault_opts Encryptor.Vault.Config.validate_use_opts!(__MODULE__, opts)
      @encryptor_vault_otp_app Encryptor.Vault.__otp_app__!(__MODULE__, @encryptor_vault_opts)
      @encryptor_vault_use_opts Keyword.delete(@encryptor_vault_opts, :otp_app)

      @doc false
      def __vault__(:otp_app), do: @encryptor_vault_otp_app
      def __vault__(:use_opts), do: @encryptor_vault_use_opts

      @doc """
      The supervision-tree child specification for this vault.

      `opts` are layer 4 of the configuration precedence chain.
      """
      @spec child_spec(keyword()) :: Supervisor.child_spec()
      def child_spec(opts) do
        %{id: __MODULE__, start: {__MODULE__, :start_link, [opts]}, type: :supervisor}
      end

      @doc """
      Starts this vault: resolves and freezes its configuration, then starts
      its cache and its provider.
      """
      @spec start_link(keyword()) :: Supervisor.on_start()
      def start_link(opts \\ []), do: Encryptor.Vault.start_link(__MODULE__, opts)

      @doc "Stops this vault and erases its frozen configuration."
      @spec stop() :: :ok | {:error, Encryptor.Error.t()}
      def stop, do: Encryptor.Vault.stop(__MODULE__)

      @doc "This vault's frozen configuration, or `{:vault_not_started, _}`."
      @spec config() :: {:ok, Encryptor.Vault.Config.t()} | {:error, Encryptor.Error.t()}
      def config, do: Encryptor.Vault.config(__MODULE__)

      @doc "Whether this vault's supervisor is alive."
      @spec started?() :: boolean()
      def started?, do: Encryptor.Vault.started?(__MODULE__)
    end
  end

  @doc false
  @spec __otp_app__!(module(), keyword()) :: atom()
  def __otp_app__!(vault, opts) do
    case Keyword.fetch(opts, :otp_app) do
      {:ok, otp_app} when is_atom(otp_app) and not is_nil(otp_app) ->
        otp_app

      _other ->
        raise ArgumentError, """
        #{inspect(vault)}: `use Encryptor.Vault` requires an `:otp_app`.

        The pair {otp_app, vault_module} is the whole configuration key, so a \
        vault without one has nowhere to read `config :my_app, #{inspect(vault)}` \
        from (ADR-0001 decision 3):

            use Encryptor.Vault, otp_app: :my_app
        """
    end
  end

  @doc """
  Starts a vault. The generated `start_link/1` calls this.

  `start_opts` are layer 4 of the precedence chain. A configuration the vault
  refuses is an `{:error, %Encryptor.Error{}}` from here, not a started vault
  that fails at the first encrypt.
  """
  @spec start_link(module(), keyword()) :: Supervisor.on_start()
  def start_link(vault, start_opts \\ []) do
    Encryptor.Vault.Supervisor.start_link(vault, start_opts)
  end

  @doc """
  Stops a running vault.

  Stopping erases the frozen configuration, so a subsequent call returns
  `{:vault_not_started, vault}` rather than reading a stale struct.
  """
  @spec stop(module(), term()) :: :ok | {:error, Error.t()}
  def stop(vault, reason \\ :normal) do
    case Process.whereis(supervisor_name(vault)) do
      nil -> {:error, error(vault, {:vault_not_started, vault}, :start)}
      pid -> Supervisor.stop(pid, reason)
    end
  end

  @doc """
  Whether a vault's supervisor is alive.

  This is the liveness half of the not-started check. It reads a registered
  name and allocates nothing, so an entry point can afford it per call.
  """
  @spec started?(module()) :: boolean()
  def started?(vault), do: is_pid(Process.whereis(supervisor_name(vault)))

  @doc """
  A vault's frozen configuration, with the not-started check in front of it.
  """
  @spec config(module()) :: {:ok, Config.t()} | {:error, Error.t()}
  def config(vault), do: ensure_started(vault, :start)

  @doc """
  The lifecycle check every entry point runs before it does anything else.

  Returns the frozen configuration when the vault is running and its provider,
  if it has a process, is alive. Every later bead's `encrypt/2`, `decrypt/2`
  and `rekey/2` is built on this function, which is why the checks live in one
  place rather than three.

  `operation` is stamped onto the error so an operator reading a log line
  knows which call failed, not merely that a vault was down.
  """
  @spec ready(module(), Error.operation()) :: {:ok, Config.t()} | {:error, Error.t()}
  def ready(vault, operation) do
    with {:ok, config} <- ensure_started(vault, operation),
         :ok <- ensure_provider_started(config, operation) do
      {:ok, config}
    end
  end

  @doc """
  Checks that a vault is running, and reads its frozen configuration.

  Both halves matter. The registered name answers whether the supervisor is
  alive; the `:persistent_term` entry answers whether a configuration was ever
  published under it. A vault brought down abnormally can leave the second
  without the first, and an entry point that read only the frozen struct would
  encrypt against the configuration of a vault that is no longer there.
  """
  @spec ensure_started(module(), Error.operation()) :: {:ok, Config.t()} | {:error, Error.t()}
  def ensure_started(vault, operation) do
    if started?(vault) do
      with {:error, %Error{} = failure} <- Config.fetch(vault) do
        {:error, %{failure | operation: operation}}
      end
    else
      {:error, error(vault, {:vault_not_started, vault}, operation)}
    end
  end

  @doc """
  Checks that a vault's provider is alive, when the provider has a process.

  A provider only has a process when it exports `child_spec/1`, and ADR-0002
  decision 1 makes that process an implementation detail of the provider's own
  callbacks - the vault never talks to it and does not know what name, if any,
  it registered under. The authoritative answer is therefore the vault
  supervisor's own child list, where the child's id is the provider module
  because `Encryptor.Vault.Supervisor` sets it.

  A provider with no `child_spec/1` - the common encrypted-column case - skips
  the check entirely, which is what keeps the supervisor round trip off the
  hot path for every vault that does not need it.
  """
  @spec ensure_provider_started(Config.t(), Error.operation()) :: :ok | {:error, Error.t()}
  def ensure_provider_started(%Config{vault: vault, provider: {module, _opts}}, operation) do
    if supervised_provider?(module) and not provider_alive?(vault, module) do
      {:error, error(vault, {:provider_not_started, module}, operation)}
    else
      :ok
    end
  end

  @doc """
  Whether a provider module supplies its own process.

  `child_spec/1` is optional on `Encryptor.Provider`, and its presence is the
  only signal the vault has that a provider wants supervising.
  """
  @spec supervised_provider?(module()) :: boolean()
  def supervised_provider?(module) do
    Code.ensure_loaded?(module) and function_exported?(module, :child_spec, 1)
  end

  @doc """
  The registered name of a vault's supervisor.
  """
  @spec supervisor_name(module()) :: atom()
  def supervisor_name(vault), do: Module.concat(vault, "Supervisor")

  @doc """
  The registered name of a vault's materials cache.

  Derived from the vault module, because vaults do not share a cache process:
  the cache's bounds live on the caching CMM while eviction lives in the
  cache, and that combination is only coherent when one cache serves one bound
  set (ADR-0001 decision 3).
  """
  @spec cache_name(module()) :: atom()
  def cache_name(vault), do: Module.concat(vault, "Cache")

  @doc """
  The registered name of a vault's cache recycler.

  Derived the same way the cache name is, and for the same reason: the
  recycler bounds exactly one vault's cache (ADR-0001 decision 6).
  """
  @spec recycler_name(module()) :: atom()
  def recycler_name(vault), do: Module.concat(vault, "CacheRecycler")

  @doc """
  The registered name of the process that owns a vault's frozen configuration.
  """
  @spec lifecycle_name(module()) :: atom()
  def lifecycle_name(vault), do: Module.concat(vault, "Lifecycle")

  defp provider_alive?(vault, module) do
    case Process.whereis(supervisor_name(vault)) do
      nil ->
        false

      supervisor ->
        Enum.any?(Supervisor.which_children(supervisor), fn
          {^module, pid, _type, _modules} -> is_pid(pid)
          _child -> false
        end)
    end
  end

  @spec error(module(), Error.reason(), Error.operation()) :: Error.t()
  defp error(vault, reason, operation) do
    %Error{reason: reason, vault: vault, operation: operation, engine: nil}
  end
end
