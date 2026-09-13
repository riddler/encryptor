defmodule Encryptor.TelemetryVaults do
  @moduledoc """
  Vaults whose *start* is the subject, because `[:encryptor, :vault, :started]`
  reports three things no other fixture set varies together: whether a cache
  child exists, which context profile resolved, and whether the known-answer
  check had a pinned value to check against.

  `Encryptor.LifecycleVaults` covers the `:single` halves of that already, so
  what is here is the tenant vault with a pinned `:reference_check` - the only
  configuration that reports `reference_check: :verified`.
  """

  alias Encryptor.Vault.Config

  @reference_subkey <<7::256>>

  @doc "The subkey the pinned vault below is provisioned with."
  @spec reference_subkey() :: binary()
  def reference_subkey, do: @reference_subkey

  @doc "The known-answer value a deployment running that subkey pins."
  @spec pinned_check() :: String.t()
  def pinned_check, do: Config.known_answer(@reference_subkey)

  defmodule Provider do
    @moduledoc "A provider with no process, so the start path is the only moving part."
  end

  defmodule Pinned do
    @moduledoc "A tenant vault whose reference subkey is checked against a pinned answer."

    use Encryptor.Vault, otp_app: :encryptor, context_profile: :tenant

    @doc "Layer 5: the provider, the reference subkey, and the answer it must reproduce."
    def init(config) do
      {:ok,
       Keyword.merge(config,
         provider: {Encryptor.TelemetryVaults.Provider, []},
         reference_subkey: Encryptor.TelemetryVaults.reference_subkey(),
         reference_check: Encryptor.TelemetryVaults.pinned_check()
       )}
    end
  end

  defmodule Unpinned do
    @moduledoc "The same tenant vault with nothing pinned, which is the finding :unpinned names."

    use Encryptor.Vault, otp_app: :encryptor, context_profile: :tenant

    @doc "Layer 5: the provider and the reference subkey, and no pinned answer."
    def init(config) do
      {:ok,
       Keyword.merge(config,
         provider: {Encryptor.TelemetryVaults.Provider, []},
         reference_subkey: Encryptor.TelemetryVaults.reference_subkey()
       )}
    end
  end
end
