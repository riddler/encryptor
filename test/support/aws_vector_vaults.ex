defmodule Encryptor.AwsVectorVaults do
  @moduledoc """
  The vaults the AWS Encryption SDK decrypt vectors are read through.

  None of them names a key. Each is started by the vector test with an
  `Encryptor.Provider.Static` option list built from one entry of the
  corpus's `keys.json` and the provider id the vector's master key names,
  passed as a `start_link/1` option - the layer `Encryptor.Vault.Config`
  reads at start, never a `use` option. The material is the corpus's
  published test keys, and it is never rendered by a test.

    * `Committed` runs the package's default commitment policy,
      `:require_encrypt_require_decrypt`.
    * `Legacy` relaxes it to `:require_encrypt_allow_decrypt`, the one
      relaxation `Encryptor.Vault.Config` accepts, so a message written under
      a suite without key commitment can be read.
    * `Scoped` is a `:scoped` vault: it requires the `"scope_ref"` it injects
      into the reproduced context, which no vector's message carries.
  """

  defmodule Committed do
    @moduledoc "A `:single` vault under the default commitment policy."

    use Encryptor.Vault,
      otp_app: :encryptor,
      context_profile: :single
  end

  defmodule Legacy do
    @moduledoc "A `:single` vault that may read messages without key commitment."

    use Encryptor.Vault,
      otp_app: :encryptor,
      context_profile: :single,
      commitment_policy: :require_encrypt_allow_decrypt
  end

  defmodule Scoped do
    @moduledoc "A `:scoped` vault; its reference subkey arrives at start."

    use Encryptor.Vault,
      otp_app: :encryptor,
      context_profile: :scoped
  end
end
