defmodule Encryptor.LifecycleVaults do
  @moduledoc """
  Vaults and providers the `use Encryptor.Vault` and supervision tests start
  for real.

  These differ from `Encryptor.TestVaults` in that they are built by the macro
  rather than standing in for it, and they are started: each one is a
  supervision tree the tests bring up and take down.
  """

  defmodule PureProvider do
    @moduledoc "A provider with no process. It exports no `child_spec/1`."
  end

  defmodule SupervisedProvider do
    @moduledoc "A provider that wants supervising, so it exports `child_spec/1`."

    use Agent

    @doc "Holds its options and nothing else; only its liveness is read here."
    @spec start_link(term()) :: Agent.on_start()
    def start_link(opts), do: Agent.start_link(fn -> opts end)
  end

  defmodule Cacheless do
    @moduledoc "A vault with caching off, configured through `init/1`."

    use Encryptor.Vault, otp_app: :encryptor

    @doc "Layer 5: supplies what a config file must not hold."
    def init(config) do
      {:ok,
       Keyword.merge(config,
         provider: {Encryptor.LifecycleVaults.PureProvider, []},
         context_profile: :single
       )}
    end
  end

  defmodule Cached do
    @moduledoc "A vault with caching on, so its supervisor runs a cache child."

    use Encryptor.Vault,
      otp_app: :encryptor,
      provider: {Encryptor.LifecycleVaults.PureProvider, []},
      context_profile: :single,
      cache: [max_age: 60]
  end

  defmodule Supervised do
    @moduledoc "A vault whose provider has a process of its own."

    use Encryptor.Vault,
      otp_app: :encryptor,
      provider: {Encryptor.LifecycleVaults.SupervisedProvider, []},
      context_profile: :single
  end

  defmodule Second do
    @moduledoc "A second cached vault, so the no-shared-cache rule is observable."

    use Encryptor.Vault,
      otp_app: :encryptor,
      provider: {Encryptor.LifecycleVaults.PureProvider, []},
      context_profile: :single,
      cache: [max_age: 60]
  end

  defmodule Unconfigured do
    @moduledoc "A vault that names no provider, so it refuses to start."

    use Encryptor.Vault, otp_app: :encryptor, context_profile: :single
  end

  defmodule Unstarted do
    @moduledoc "A vault that is never started, so the not-started check has a subject."

    use Encryptor.Vault,
      otp_app: :encryptor,
      provider: {Encryptor.LifecycleVaults.PureProvider, []},
      context_profile: :single
  end
end
