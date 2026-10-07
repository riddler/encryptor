defmodule Encryptor.RekeyVaults do
  @moduledoc """
  The vaults the rekey-path tests need that the two landed paths did not.

  A rekey is only observable as a *change of key*, so the suite needs a reader
  that holds the incoming key and not the outgoing one - the state a key store
  is in after ADR-0005's crypto-shred has run. Every other vault the rekey
  tests use is `Encryptor.EncryptVaults`' or `Encryptor.DecryptVaults`', and
  they share this one's key material and its worked domain, card processing.

  The `Signed*` vaults are three of those on the signing suite, `0x0578`, the
  package's default, so the rekey path is exercised on both suites a vault
  accepts.
  """

  defmodule Shredded do
    @moduledoc """
    A single-key vault holding only `app/v2`: the rotated vault after the
    outgoing version has been deleted from the key store.

    It cannot read `Encryptor.DecryptVaults.Retired`'s messages, and it can
    read what `Encryptor.EncryptVaults.Bound` rekeys from them. That pair is
    the rotate-then-shred sequence of ADR-0005 decision 1, run for real.
    """

    use Encryptor.Vault,
      otp_app: :encryptor,
      context_profile: :single,
      algorithm_suite_id: 0x0478,
      required_context: ["table", "column"]

    @doc "Layer 5: the key material a config file must not hold."
    def init(config) do
      {:ok,
       Keyword.put(
         config,
         :provider,
         {Encryptor.Provider.Static,
          key: Encryptor.EncryptVaults.rotated_key(), namespace: "acme-app", name: "app/v2"}
       )}
    end
  end

  defmodule SignedRetired do
    @moduledoc """
    `Encryptor.DecryptVaults.Retired` on the signing suite, `0x0578`.

    The engine adds its own verification-key pair to the context of every
    message it writes under this suite, which is what a rekey has to leave
    behind when it re-encrypts.
    """

    use Encryptor.Vault,
      otp_app: :encryptor,
      context_profile: :single,
      algorithm_suite_id: 0x0578,
      required_context: ["table", "column"]

    @doc "Layer 5: the key material a config file must not hold."
    def init(config) do
      {:ok, Keyword.put(config, :provider, Encryptor.EncryptVaults.static_provider())}
    end
  end

  defmodule SignedBound do
    @moduledoc "`Encryptor.EncryptVaults.Bound` on the signing suite, `0x0578`."

    use Encryptor.Vault,
      otp_app: :encryptor,
      context_profile: :single,
      algorithm_suite_id: 0x0578,
      required_context: ["table", "column"]

    @doc "Layer 5: the key material a config file must not hold."
    def init(config) do
      {:ok, Keyword.put(config, :provider, Encryptor.EncryptVaults.rotated_provider())}
    end
  end

  defmodule SignedMerchant do
    @moduledoc "`Encryptor.EncryptVaults.Merchant` on the signing suite, `0x0578`."

    use Encryptor.Vault,
      otp_app: :encryptor,
      context_profile: :scoped,
      algorithm_suite_id: 0x0578,
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
end
