defmodule Encryptor.DecryptVaults do
  @moduledoc """
  The three vaults the decrypt-path tests need that the encrypt path did not.

  Each of them exists to be a *reader of another vault's message*, which is
  the only way to build the failures the decrypt path is responsible for
  without hand-assembling an engine message and calling that evidence.

  All three share `Encryptor.EncryptVaults`' key material and its worked
  domain, card processing, so a message written by one vault there is read by
  one here with nothing but the configuration differing.

    * `Retired` holds only the outgoing key, so it writes messages the
      rotated vault must still be able to read - and cannot read the rotated
      vault's own, which is the wrong-key failure with everything else equal.
    * `Unbound` holds the same keys as the rotated vault and requires nothing,
      so it is a reader whose required set disagrees with the writer's.
    * `Loose` requires nothing and caches nothing, for the advisory-key cases
      where the point is what is *not* enforced.
  """

  defmodule Retired do
    @moduledoc """
    A single-key vault holding only `app/v1`: the outgoing half of a rotation.

    Its messages are what `Encryptor.EncryptVaults.Bound` must still read from
    its candidate list, and its own candidate list cannot read `Bound`'s.
    """

    use Encryptor.Vault,
      otp_app: :encryptor,
      context_profile: :single,
      algorithm_suite_id: 0x0478,
      required_context: ["table", "column"]

    @doc "Layer 5: the key material a config file must not hold."
    def init(config) do
      {:ok, Keyword.put(config, :provider, Encryptor.EncryptVaults.static_provider())}
    end
  end

  defmodule Unbound do
    @moduledoc """
    The rotated vault's keys with no required set at all.

    A reader configured this way computes a different header authentication
    tag than the writer did, because this engine mixes the required subset of
    the context into the AAD.
    """

    use Encryptor.Vault,
      otp_app: :encryptor,
      context_profile: :single,
      algorithm_suite_id: 0x0478

    @doc "Layer 5: the key material a config file must not hold."
    def init(config) do
      {:ok, Keyword.put(config, :provider, Encryptor.EncryptVaults.rotated_provider())}
    end
  end

  defmodule Loose do
    @moduledoc "A single-key vault that requires nothing and caches nothing."

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
