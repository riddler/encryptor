defmodule Encryptor.TelemetryVaults do
  @moduledoc """
  Vaults whose *start* is the subject, because `[:encryptor, :vault, :started]`
  reports three things no other fixture set varies together: whether a cache
  child exists, which context profile resolved, and whether the known-answer
  check had a pinned value to check against.

  `Encryptor.LifecycleVaults` covers the `:single` halves of that already, so
  what is here is the tenant vault with a pinned `:reference_check` - the only
  configuration that reports `reference_check: :verified`.

  The vaults below `Pinned` and `Unpinned` are the span half's: three tenant
  vaults that differ only in whether they opted in to ADR-0006 amendment A's
  tenant dimension and in whether their key store answers, plus the single
  vault that may never carry the dimension at all. Their key material is
  `Encryptor.EncryptVaults`' - a second copy of a fixture key would be a
  second key-shaped constant for no gain.
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

  @doc """
  A provider whose store has gone away, which is ADR-0006's worked example.

  It answers in contract - `{:key_unavailable, selector}` is ADR-0002
  decision 6's own term - so what the provider span reports is a store that
  could not be reached rather than a provider that is broken.
  """
  @spec downed_provider() :: {module(), keyword()}
  def downed_provider do
    {Encryptor.Provider.Function,
     encryption_key: fn selector -> {:error, {:key_unavailable, selector}} end,
     decryption_keys: fn selector -> {:error, {:key_unavailable, selector}} end}
  end

  defmodule Merchant do
    @moduledoc "A tenant vault that opted in to the keyed tenant dimension."

    use Encryptor.Vault,
      otp_app: :encryptor,
      context_profile: :tenant,
      algorithm_suite_id: 0x0478,
      telemetry_tenant_ref: true

    @doc "Layer 5: the provider and the reference subkey, both key material."
    def init(config) do
      {:ok,
       Keyword.merge(config,
         provider: Encryptor.EncryptVaults.merchant_provider(),
         reference_subkey: Encryptor.EncryptVaults.reference_subkey()
       )}
    end
  end

  defmodule Quiet do
    @moduledoc """
    The same tenant vault with the dimension off, which is the default.

    It carries a `:derivation_salt` the opted-in vaults do not, so that
    `Encryptor.Vault.derive/3` reaches the provider callback here rather than
    stopping at `{:missing_config, [:derivation_salt]}` - which is what makes
    "a derivation emits no provider span" an assertion about the span and not
    about the salt.
    """

    use Encryptor.Vault,
      otp_app: :encryptor,
      context_profile: :tenant,
      algorithm_suite_id: 0x0478

    @doc "Layer 5: the provider, the reference subkey and the deployment salt."
    def init(config) do
      {:ok,
       Keyword.merge(config,
         provider: Encryptor.EncryptVaults.merchant_provider(),
         reference_subkey: Encryptor.EncryptVaults.reference_subkey(),
         derivation_salt: :binary.copy(<<0x66>>, 32)
       )}
    end
  end

  defmodule Downed do
    @moduledoc "A tenant vault, opted in, whose key store has gone away."

    use Encryptor.Vault,
      otp_app: :encryptor,
      context_profile: :tenant,
      algorithm_suite_id: 0x0478,
      telemetry_tenant_ref: true

    @doc "Layer 5: the unreachable store and the reference subkey."
    def init(config) do
      {:ok,
       Keyword.merge(config,
         provider: Encryptor.TelemetryVaults.downed_provider(),
         reference_subkey: Encryptor.EncryptVaults.reference_subkey()
       )}
    end
  end

  defmodule AppOptedIn do
    @moduledoc "A single-key vault asking for a dimension it has no tenant to fill."

    use Encryptor.Vault,
      otp_app: :encryptor,
      context_profile: :single,
      algorithm_suite_id: 0x0478,
      telemetry_tenant_ref: true

    @doc "Layer 5: the key material a config file must not hold."
    def init(config) do
      {:ok, Keyword.put(config, :provider, Encryptor.EncryptVaults.static_provider())}
    end
  end

  defmodule App do
    @moduledoc "A single-key vault, which amendment A decision 1 refuses the option to."

    use Encryptor.Vault,
      otp_app: :encryptor,
      context_profile: :single,
      algorithm_suite_id: 0x0478

    @doc "Layer 5: the key material a config file must not hold."
    def init(config) do
      {:ok, Keyword.put(config, :provider, Encryptor.EncryptVaults.static_provider())}
    end
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
