defmodule Encryptor.DeriveVaults do
  @moduledoc """
  Vaults the derived-subkey tests start for real, and the salts behind them.

  ADR-0003 amendment A's surface. Every vault here resolves offline against
  `Encryptor.Provider.Static` material or a closure over it, so the suite runs
  with no AWS dependency and no network - except `Kms`, which resolves to a
  KMS *descriptor* and never reaches a key manager, because the whole point of
  that fixture is that the derivation refuses before anything is asked.

  Key material arrives through `init/1`, and so does the salt: a salt is not
  secret, but it is per deployment, and
  `Encryptor.Vault.Config.validate_use_opts!/2` refuses it in `use` options
  for exactly that reason.

  The worked domain is card processing, matching the rest of the suite.
  `Deployment` and `Restored` are the pair that makes the salt observable:
  same key material, different salt, standing in for a production deployment
  and a staging environment restored from its backup.
  """

  alias Encryptor.Vault.Reference

  # Fixture material, and the only place these bytes are written. Constants
  # rather than `strong_rand_bytes/1` so a failing assertion is reproducible;
  # they are never rendered by a test.
  @app_key :binary.copy(<<0xA1>>, 32)
  @merchant_a :binary.copy(<<0xA2>>, 32)
  @merchant_b :binary.copy(<<0xA3>>, 32)
  @reference_subkey :binary.copy(<<0xA4>>, 32)

  # Not key material, and still not written anywhere else.
  @salt :binary.copy(<<0x51>>, 32)
  @other_salt :binary.copy(<<0x52>>, 32)

  @doc "The 256-bit key the single-key vaults here are configured with."
  @spec app_key() :: binary()
  def app_key, do: @app_key

  @doc "The material a merchant selector resolves to, for a test's own derivation."
  @spec merchant_key(String.t()) :: binary()
  def merchant_key("merchant_a"), do: @merchant_a
  def merchant_key("merchant_b"), do: @merchant_b

  @doc "The salt `App`, `Merchant` and `Deployment` are configured with."
  @spec salt() :: binary()
  def salt, do: @salt

  @doc "The salt `Restored` is configured with: the same keys, a second deployment."
  @spec other_salt() :: binary()
  def other_salt, do: @other_salt

  @doc "The reference subkey the tenant vault derives `tenant_ref` under."
  @spec reference_subkey() :: binary()
  def reference_subkey, do: @reference_subkey

  @doc "The `Static` provider options the single-key vaults share."
  @spec static_provider() :: {module(), keyword()}
  def static_provider do
    {Encryptor.Provider.Static, key: @app_key, namespace: "acme-app", name: "app/v1"}
  end

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
     decryption_keys: fn
       selector when selector in ["merchant_a", "merchant_b"] ->
         {:ok, [merchant_descriptor(selector)]}

       selector ->
         {:error, {:unknown_key, selector}}
     end}
  end

  defmodule KmsProvider do
    @moduledoc """
    A provider answering with a KMS descriptor.

    Amendment A decision 5's subject: the descriptor is well formed and the
    vault would happily encrypt with it, but its material is in a key manager
    rather than in this process, so a derivation refuses rather than asking
    the key manager to export a key. Nothing here reaches AWS.
    """

    @behaviour Encryptor.Provider

    @doc "A KMS key the vault cannot derive from."
    @impl Encryptor.Provider
    def encryption_key(_state, _selector),
      do: {:ok, %Encryptor.Key.Kms{key_id: "arn:aws:kms:us-east-1:111122223333:key/acme"}}

    @doc "The same, on the read side. Never reached by a derivation."
    @impl Encryptor.Provider
    def decryption_keys(_state, _selector),
      do: {:ok, [%Encryptor.Key.Kms{key_id: "arn:aws:kms:us-east-1:111122223333:key/acme"}]}
  end

  defmodule App do
    @moduledoc "A single-key vault with a derivation salt."

    use Encryptor.Vault, otp_app: :encryptor, context_profile: :single

    @doc "Layer 5: the key material and the per-deployment salt."
    def init(config) do
      {:ok,
       config
       |> Keyword.put(:provider, Encryptor.DeriveVaults.static_provider())
       |> Keyword.put(:derivation_salt, Encryptor.DeriveVaults.salt())}
    end
  end

  defmodule Unsalted do
    @moduledoc "The same vault with no salt: it starts, and only `derive/2` fails."

    use Encryptor.Vault, otp_app: :encryptor, context_profile: :single

    @doc "Layer 5: key material, and deliberately no salt."
    def init(config) do
      {:ok, Keyword.put(config, :provider, Encryptor.DeriveVaults.static_provider())}
    end
  end

  defmodule Merchant do
    @moduledoc "A per-merchant vault: the tenant profile, with a derivation salt."

    use Encryptor.Vault, otp_app: :encryptor, context_profile: :tenant

    @doc "Layer 5: the provider, the reference subkey, and the salt."
    def init(config) do
      {:ok,
       config
       |> Keyword.put(:provider, Encryptor.DeriveVaults.merchant_provider())
       |> Keyword.put(:reference_subkey, Encryptor.DeriveVaults.reference_subkey())
       |> Keyword.put(:derivation_salt, Encryptor.DeriveVaults.salt())}
    end
  end

  defmodule Deployment do
    @moduledoc "One deployment: the app key under the first salt."

    use Encryptor.Vault, otp_app: :encryptor, context_profile: :single

    @doc "Layer 5: key material and this deployment's salt."
    def init(config) do
      {:ok,
       config
       |> Keyword.put(:provider, Encryptor.DeriveVaults.static_provider())
       |> Keyword.put(:derivation_salt, Encryptor.DeriveVaults.salt())}
    end
  end

  defmodule Restored do
    @moduledoc "A second deployment restored from the first's backup: same key, second salt."

    use Encryptor.Vault, otp_app: :encryptor, context_profile: :single

    @doc "Layer 5: the same key material, under a different salt."
    def init(config) do
      {:ok,
       config
       |> Keyword.put(:provider, Encryptor.DeriveVaults.static_provider())
       |> Keyword.put(:derivation_salt, Encryptor.DeriveVaults.other_salt())}
    end
  end

  defmodule Managed do
    @moduledoc "A vault whose provider answers with a KMS descriptor."

    use Encryptor.Vault, otp_app: :encryptor, context_profile: :single

    @doc "Layer 5: the KMS-descriptor provider and a salt, so the refusal is the descriptor's."
    def init(config) do
      {:ok,
       config
       |> Keyword.put(:provider, {Encryptor.DeriveVaults.KmsProvider, []})
       |> Keyword.put(:derivation_salt, Encryptor.DeriveVaults.salt())}
    end
  end
end
