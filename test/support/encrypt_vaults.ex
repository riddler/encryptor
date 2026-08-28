defmodule Encryptor.EncryptVaults do
  @moduledoc """
  Vaults the encrypt-path tests start for real, and the providers behind them.

  Every one of them resolves offline: the keys are `Encryptor.Provider.Static`
  material or a closure over it, so the whole suite runs against `RawAes` with
  no AWS dependency, no network, and no optional dependency of the engine's.

  Key material arrives through each vault's `init/1`, never through `use`
  options - `Encryptor.Vault.Config.validate_use_opts!/2` refuses the latter
  at compile time, and a fixture key is still key-shaped.

  The worked domain is card processing: one merchant vault keyed by merchant
  reference, and one application vault holding a single key.
  """

  alias Encryptor.Vault.Reference

  # Fixture material, and the only place these bytes are written. They are
  # constants rather than `strong_rand_bytes/1` so a failing assertion is
  # reproducible; they are never rendered by a test.
  @single :binary.copy(<<0x11>>, 32)
  @rotated :binary.copy(<<0x22>>, 32)
  @merchant_a :binary.copy(<<0x33>>, 32)
  @merchant_b :binary.copy(<<0x44>>, 32)
  @reference_subkey :binary.copy(<<0x55>>, 32)

  @doc "The 256-bit key the single-key vaults are configured with."
  @spec single_key() :: binary()
  def single_key, do: @single

  @doc "The incoming key of the rotated candidate list, which writes are made under."
  @spec rotated_key() :: binary()
  def rotated_key, do: @rotated

  @doc "The material each merchant selector resolves to, for a test's own decrypt."
  @spec merchant_key(String.t()) :: binary()
  def merchant_key("merchant_a"), do: @merchant_a
  def merchant_key("merchant_b"), do: @merchant_b

  @doc "The reference subkey the tenant vaults derive `tenant_ref` under."
  @spec reference_subkey() :: binary()
  def reference_subkey, do: @reference_subkey

  @doc "The descriptor a merchant selector resolves to."
  @spec merchant_descriptor(String.t()) :: Encryptor.Key.Aes.t()
  def merchant_descriptor(selector) do
    reference = Reference.derive(@reference_subkey, selector)

    %Encryptor.Key.Aes{
      namespace: "encryptor-tenant",
      name: "t/" <> reference <> "/v1",
      material: merchant_key(selector),
      bits: 256
    }
  end

  @doc "The `Static` provider options the single-key vaults share."
  @spec static_provider() :: {module(), keyword()}
  def static_provider do
    {Encryptor.Provider.Static, key: @single, namespace: "acme-app", name: "app/v1"}
  end

  @doc "A `Static` provider holding two versions, newest first."
  @spec rotated_provider() :: {module(), keyword()}
  def rotated_provider do
    {Encryptor.Provider.Static,
     keys: [
       [key: @rotated, namespace: "acme-app", name: "app/v2"],
       [key: @single, namespace: "acme-app", name: "app/v1"]
     ]}
  end

  @doc "A `Function` provider resolving a merchant selector to its own key."
  @spec merchant_provider() :: {module(), keyword()}
  def merchant_provider do
    {Encryptor.Provider.Function,
     encryption_key: fn
       selector when selector in ["merchant_a", "merchant_b"] ->
         {:ok, merchant_descriptor(selector)}

       selector ->
         {:error, {:unknown_key, selector}}
     end,
     decryption_keys: fn selector -> {:ok, [merchant_descriptor(selector)]} end}
  end

  defmodule Rogue do
    @moduledoc """
    A provider that answers outside the contract, so the vault's own guard has
    a subject.

    `Encryptor.Provider.Function` normalizes a host closure's nonsense into
    `{:invalid_key_descriptor, _}` before the vault sees it, which is why this
    module is a provider in its own right rather than a closure.
    """

    @behaviour Encryptor.Provider

    @doc "Fails with a term that is not in the provider vocabulary."
    @impl Encryptor.Provider
    def encryption_key(_state, _selector), do: {:error, :weird_and_unenumerated}

    @doc "The same, on the read side."
    @impl Encryptor.Provider
    def decryption_keys(_state, _selector), do: {:error, :weird_and_unenumerated}
  end

  defmodule Mute do
    @moduledoc """
    A provider that answers with something that is not a result at all, so the
    vault's guard against a bare return has a subject too.
    """

    @behaviour Encryptor.Provider

    @doc "Answers with a bare atom."
    @impl Encryptor.Provider
    def encryption_key(_state, _selector), do: :i_have_no_idea

    @doc "The same, on the read side."
    @impl Encryptor.Provider
    def decryption_keys(_state, _selector), do: :i_have_no_idea
  end

  defmodule BadInit do
    @moduledoc """
    A provider whose `init/1` fails with a term of its own, outside this
    package's closed reason vocabulary.
    """

    @behaviour Encryptor.Provider

    @doc "Fails at start, in its own words."
    @impl Encryptor.Provider
    def init(_opts), do: {:error, :weird_and_unenumerated}

    @doc "Never reached: the vault does not start."
    @impl Encryptor.Provider
    def encryption_key(_state, _selector), do: {:error, {:unknown_key, :default}}

    @doc "Never reached: the vault does not start."
    @impl Encryptor.Provider
    def decryption_keys(_state, _selector), do: {:error, {:unknown_key, :default}}
  end

  defmodule App do
    @moduledoc "A single-key vault with no cache, on the signing suite."

    use Encryptor.Vault, otp_app: :encryptor, context_profile: :single

    @doc "Layer 5: the key material a config file must not hold."
    def init(config) do
      {:ok, Keyword.put(config, :provider, Encryptor.EncryptVaults.static_provider())}
    end
  end

  defmodule Cached do
    @moduledoc "A single-key vault with a cache, on the unsigned committed suite."

    use Encryptor.Vault,
      otp_app: :encryptor,
      context_profile: :single,
      algorithm_suite_id: 0x0478,
      static_encryption_context: %{"app" => "acme_checkout"},
      cache: [max_age: 60]

    @doc "Layer 5: the key material a config file must not hold."
    def init(config) do
      {:ok, Keyword.put(config, :provider, Encryptor.EncryptVaults.static_provider())}
    end
  end

  defmodule Bound do
    @moduledoc "A single-key vault that requires the column pair."

    use Encryptor.Vault,
      otp_app: :encryptor,
      context_profile: :single,
      algorithm_suite_id: 0x0478,
      required_context: ["table", "column"]

    @doc "Layer 5: the key material a config file must not hold."
    def init(config) do
      {:ok, Keyword.put(config, :provider, Encryptor.EncryptVaults.rotated_provider())}
    end
  end

  defmodule Merchant do
    @moduledoc "A per-merchant vault: a tenant profile, a cache, and a required column pair."

    use Encryptor.Vault,
      otp_app: :encryptor,
      context_profile: :tenant,
      algorithm_suite_id: 0x0478,
      required_context: ["table", "column"],
      cache: [max_age: 60]

    @doc "Layer 5: the provider and the reference subkey, both key material."
    def init(config) do
      {:ok,
       Keyword.merge(config,
         provider: Encryptor.EncryptVaults.merchant_provider(),
         reference_subkey: Encryptor.EncryptVaults.reference_subkey()
       )}
    end
  end

  defmodule MerchantCacheless do
    @moduledoc "The merchant vault without a cache, so the unwrapped stack has a subject."

    use Encryptor.Vault,
      otp_app: :encryptor,
      context_profile: :tenant,
      algorithm_suite_id: 0x0478

    @doc "Layer 5: the provider and the reference subkey, both key material."
    def init(config) do
      {:ok,
       Keyword.merge(config,
         provider: Encryptor.EncryptVaults.merchant_provider(),
         reference_subkey: Encryptor.EncryptVaults.reference_subkey()
       )}
    end
  end

  defmodule OffContract do
    @moduledoc "A vault whose provider answers outside the contract."

    use Encryptor.Vault,
      otp_app: :encryptor,
      context_profile: :single,
      algorithm_suite_id: 0x0478

    @doc "Layer 5: names the rogue provider."
    def init(config) do
      {:ok, Keyword.put(config, :provider, {Encryptor.EncryptVaults.Rogue, []})}
    end
  end

  defmodule Silent do
    @moduledoc "A vault whose provider answers with something that is not a result."

    use Encryptor.Vault,
      otp_app: :encryptor,
      context_profile: :single,
      algorithm_suite_id: 0x0478

    @doc "Layer 5: names the mute provider."
    def init(config) do
      {:ok, Keyword.put(config, :provider, {Encryptor.EncryptVaults.Mute, []})}
    end
  end

  defmodule Unstarted do
    @moduledoc "A vault nobody starts, so the not-started check has a subject."

    use Encryptor.Vault,
      otp_app: :encryptor,
      context_profile: :single,
      algorithm_suite_id: 0x0478

    @doc "Layer 5: the key material a config file must not hold."
    def init(config) do
      {:ok, Keyword.put(config, :provider, Encryptor.EncryptVaults.static_provider())}
    end
  end
end
