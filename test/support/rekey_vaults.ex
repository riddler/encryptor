defmodule Encryptor.RekeyVaults do
  @moduledoc """
  The one vault the rekey-path tests need that the two landed paths did not.

  A rekey is only observable as a *change of key*, so the suite needs a reader
  that holds the incoming key and not the outgoing one - the state a key store
  is in after ADR-0005's crypto-shred has run. Every other vault the rekey
  tests use is `Encryptor.EncryptVaults`' or `Encryptor.DecryptVaults`', and
  they share this one's key material and its worked domain, card processing.
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
end
