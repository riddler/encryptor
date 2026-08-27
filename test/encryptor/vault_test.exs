defmodule Encryptor.VaultTest do
  use ExUnit.Case, async: false

  alias Encryptor.Error
  alias Encryptor.LifecycleVaults
  alias Encryptor.Vault
  alias Encryptor.Vault.Config

  defp start_vault(vault, opts \\ []) do
    start_supervised!(Supervisor.child_spec({vault, opts}, restart: :temporary))
  end

  defp child_ids(vault) do
    vault
    |> Vault.supervisor_name()
    |> Supervisor.which_children()
    |> Enum.map(fn {id, _pid, _type, _modules} -> id end)
  end

  defp live_child?(vault, id) do
    vault
    |> Vault.supervisor_name()
    |> Supervisor.which_children()
    |> Enum.any?(fn {child_id, pid, _type, _modules} -> child_id == id and is_pid(pid) end)
  end

  describe "the use macro" do
    # sabotage: made __vault__(:use_opts) return the full option list - red,
    # because :otp_app then appears among the layer 2 configuration options.
    test "captures the otp_app and the module name, and nothing else" do
      assert LifecycleVaults.Cached.__vault__(:otp_app) == :encryptor

      use_opts = LifecycleVaults.Cached.__vault__(:use_opts)

      refute Keyword.has_key?(use_opts, :otp_app)
      assert Keyword.fetch(use_opts, :cache) == {:ok, [max_age: 60]}
    end

    # sabotage: dropped `type: :supervisor` from the generated child_spec -
    # red, because a vault is a supervision tree and a host that adds it to
    # one must shut it down as a tree.
    test "child_spec/1 names the vault and threads the start options" do
      assert %{
               id: LifecycleVaults.Cacheless,
               start: {LifecycleVaults.Cacheless, :start_link, [[cache: false]]},
               type: :supervisor
             } = LifecycleVaults.Cacheless.child_spec(cache: false)
    end

    # sabotage: dropped the validate_use_opts!/2 call from the macro - red,
    # because the key material then compiles into the module's .beam file
    # instead of being refused.
    test "key material in use options is a compile-time error" do
      assert_raise ArgumentError, ~r/option :passphrase is key material/, fn ->
        Code.eval_string("""
        defmodule Encryptor.VaultTest.SecretInUseOpts do
          use Encryptor.Vault, otp_app: :encryptor, passphrase: "refused"
        end
        """)
      end
    end

    # sabotage: made __otp_app__!/2 fall back to nil - red, because the pair
    # {otp_app, vault} is the whole configuration key and a vault without one
    # has nowhere to read its application environment from.
    test "a vault without an otp_app is a compile-time error" do
      assert_raise ArgumentError, ~r/requires an `:otp_app`/, fn ->
        Code.eval_string("""
        defmodule Encryptor.VaultTest.NoOtpApp do
          use Encryptor.Vault
        end
        """)
      end
    end
  end

  describe "starting a vault" do
    # sabotage: removed the Config.freeze/1 call from Lifecycle.init/1 - red,
    # because the vault then runs with nothing published for the hot path to
    # read.
    test "start_link resolves the five layers and freezes the result" do
      start_vault(LifecycleVaults.Cacheless)

      assert {:ok, %Config{vault: LifecycleVaults.Cacheless, context_profile: :single}} =
               LifecycleVaults.Cacheless.config()

      assert LifecycleVaults.Cacheless.started?()
      assert is_pid(Process.whereis(Vault.lifecycle_name(LifecycleVaults.Cacheless)))
    end

    # sabotage: made cache_child/1 raise on `cache: false` instead of
    # returning no child - red, because a provider may need supervision even
    # when the cache does not exist.
    test "a vault with caching disabled still starts, and runs no cache" do
      start_vault(LifecycleVaults.Cacheless)

      assert LifecycleVaults.Cacheless.started?()
      assert Process.whereis(Vault.cache_name(LifecycleVaults.Cacheless)) == nil
      refute :cache in child_ids(LifecycleVaults.Cacheless)
    end

    # sabotage: dropped the `name:` option from the cache child's start
    # arguments - red, because the cache is then unreachable by the name the
    # vault derives for it.
    test "a vault with caching on runs a cache under its own derived name" do
      start_vault(LifecycleVaults.Cached)

      assert is_pid(Process.whereis(Vault.cache_name(LifecycleVaults.Cached)))
      assert live_child?(LifecycleVaults.Cached, :cache)
    end

    # sabotage: derived the cache name from a constant rather than from the
    # vault module - red, because the second vault then fails to start on a
    # name collision, which is the shared-cache defect this rule forbids.
    test "two vaults never share a cache process" do
      start_vault(LifecycleVaults.Cached)
      start_vault(LifecycleVaults.Second)

      first = Process.whereis(Vault.cache_name(LifecycleVaults.Cached))
      second = Process.whereis(Vault.cache_name(LifecycleVaults.Second))

      assert is_pid(first)
      assert is_pid(second)
      assert first != second
    end

    # sabotage: made provider_child/1 return no child - red, because a
    # provider that asked to be supervised is then never started.
    test "a provider exporting child_spec/1 is started beside the cache" do
      start_vault(LifecycleVaults.Supervised)

      assert live_child?(LifecycleVaults.Supervised, LifecycleVaults.SupervisedProvider)
    end

    # sabotage: made supervised_provider?/1 return true unconditionally - red,
    # because the vault then tries to start a provider that has no process.
    test "a provider with no child_spec/1 gets no child" do
      start_vault(LifecycleVaults.Cacheless)

      assert child_ids(LifecycleVaults.Cacheless) == [Encryptor.Vault.Lifecycle]
    end

    # sabotage: made start_link/2 discard the resolve failure and start the
    # supervisor anyway - red, because a vault that cannot be configured
    # correctly would then start and fail at its first encrypt instead.
    test "a configuration the vault refuses is an error, not a started vault" do
      assert {:error, %Error{reason: {:missing_config, [:provider]}, operation: :start}} =
               LifecycleVaults.Unconfigured.start_link()

      refute LifecycleVaults.Unconfigured.started?()

      assert {:error, %Error{reason: {:vault_not_started, _}}} =
               Config.fetch(LifecycleVaults.Unconfigured)
    end
  end

  describe "stopping a vault" do
    # sabotage: removed Process.flag(:trap_exit, true) from Lifecycle.init/1 -
    # red, because terminate/2 never runs and the frozen configuration
    # outlives the vault that published it.
    test "stopping erases the frozen configuration" do
      start_vault(LifecycleVaults.Cacheless)
      assert :ok = LifecycleVaults.Cacheless.stop()

      refute LifecycleVaults.Cacheless.started?()

      assert {:error, %Error{reason: {:vault_not_started, LifecycleVaults.Cacheless}}} =
               Config.fetch(LifecycleVaults.Cacheless)
    end

    # sabotage: removed the terminate/2 callback from Lifecycle - red,
    # because the frozen configuration then outlives the supervision tree
    # that published it, which is how a host shutting down leaves a vault's
    # configuration readable by whatever starts next.
    test "shutting down a host's supervision tree erases the configuration" do
      {:ok, tree} =
        Supervisor.start_link([{LifecycleVaults.Cacheless, []}], strategy: :one_for_one)

      assert {:ok, %Config{}} = Config.fetch(LifecycleVaults.Cacheless)

      Supervisor.stop(tree)

      assert {:error, %Error{reason: {:vault_not_started, LifecycleVaults.Cacheless}}} =
               Config.fetch(LifecycleVaults.Cacheless)
    end

    # sabotage: made Supervisor.start_link/2 resolve the configuration once
    # and memoize it - red, because a vault brought back up would then run
    # the configuration it was started with the first time.
    test "a restarted vault reads its configuration again" do
      start_vault(LifecycleVaults.Cacheless)
      assert {:ok, %Config{algorithm_suite_id: 0x0578}} = LifecycleVaults.Cacheless.config()
      assert :ok = LifecycleVaults.Cacheless.stop()

      Application.put_env(:encryptor, LifecycleVaults.Cacheless, algorithm_suite_id: 0x0478)
      on_exit(fn -> Application.delete_env(:encryptor, LifecycleVaults.Cacheless) end)

      start_vault(LifecycleVaults.Cacheless)

      assert {:ok, %Config{algorithm_suite_id: 0x0478}} = LifecycleVaults.Cacheless.config()
    end

    # sabotage: made stop/1 call Supervisor.stop on a nil pid - red with an
    # exit from inside a library, which is the shape decision 2 forbids.
    test "stopping a vault that is not running is a typed error, not a raise" do
      assert {:error,
              %Error{
                reason: {:vault_not_started, LifecycleVaults.Unstarted},
                vault: LifecycleVaults.Unstarted,
                operation: :start
              }} = LifecycleVaults.Unstarted.stop()
    end
  end

  describe "the lifecycle checks" do
    # sabotage: made ready/2 read the frozen config without the liveness
    # check - red, because an unstarted vault has no entry and the error
    # would carry the :start operation rather than the caller's.
    test "an unstarted vault is a typed error carrying the caller's operation" do
      assert {:error,
              %Error{
                reason: {:vault_not_started, LifecycleVaults.Unstarted},
                vault: LifecycleVaults.Unstarted,
                operation: :encrypt,
                engine: nil
              }} = Vault.ready(LifecycleVaults.Unstarted, :encrypt)
    end

    # sabotage: made ready/2 return the vault module rather than the frozen
    # config - red, because every entry point built on it reads the config it
    # hands back.
    test "a running vault answers with its frozen configuration" do
      start_vault(LifecycleVaults.Cacheless)

      assert {:ok, %Config{vault: LifecycleVaults.Cacheless}} =
               Vault.ready(LifecycleVaults.Cacheless, :encrypt)
    end

    # sabotage: made provider_alive?/1 answer false - red, because a provider
    # the vault supervisor is running then reads as not started.
    test "a running vault with a supervised provider is ready" do
      start_vault(LifecycleVaults.Supervised)

      assert {:ok, %Config{}} = Vault.ready(LifecycleVaults.Supervised, :decrypt)
    end

    # sabotage: made provider_alive?/1 answer true when the supervisor has no
    # such child - red, because provider_not_started is then unreachable.
    test "a provider with a process that is not running is provider_not_started" do
      start_vault(LifecycleVaults.Cacheless)

      {:ok, config} = LifecycleVaults.Cacheless.config()
      config = %{config | provider: {LifecycleVaults.SupervisedProvider, []}}

      assert {:error,
              %Error{
                reason: {:provider_not_started, LifecycleVaults.SupervisedProvider},
                vault: LifecycleVaults.Cacheless,
                operation: :encrypt
              }} = Vault.ensure_provider_started(config, :encrypt)
    end

    # sabotage: made ensure_provider_started/2 check liveness for every
    # provider - red, because a pure provider has no process and every vault
    # that uses one would refuse to work.
    test "the provider check is skipped for a provider with no process" do
      {:ok, config} =
        Config.resolve(
          LifecycleVaults.Unstarted,
          :encryptor,
          LifecycleVaults.Unstarted.__vault__(:use_opts),
          []
        )

      refute Vault.supervised_provider?(LifecycleVaults.PureProvider)
      assert :ok = Vault.ensure_provider_started(config, :encrypt)
    end

    # sabotage: made ensure_started/2 read only the :persistent_term entry -
    # red, because a frozen configuration whose vault is gone then reads as a
    # running vault.
    test "a frozen configuration without a live vault is not a running vault" do
      {:ok, config} =
        Config.resolve(
          LifecycleVaults.Unstarted,
          :encryptor,
          LifecycleVaults.Unstarted.__vault__(:use_opts),
          []
        )

      Config.freeze(config)
      on_exit(fn -> Config.erase(LifecycleVaults.Unstarted) end)

      assert {:ok, %Config{}} = Config.fetch(LifecycleVaults.Unstarted)

      assert {:error, %Error{reason: {:vault_not_started, LifecycleVaults.Unstarted}}} =
               Vault.ready(LifecycleVaults.Unstarted, :rekey)
    end
  end
end
