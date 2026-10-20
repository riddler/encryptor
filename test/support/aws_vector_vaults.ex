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

  `Committed` and `Legacy` list every suite the corpus writes in
  `:accept_suites`, so the suite check of ADR-0001 Amendment D passes every
  vector and the rest of the read path is what the vectors test. The vector
  test starts `Committed` with `accept_suites: []` once, to show that check
  against the corpus too.
  """

  defmodule Committed do
    @moduledoc "A `:single` vault under the default commitment policy."

    use Encryptor.Vault,
      otp_app: :encryptor,
      context_profile: :single,
      accept_suites: [
        0x0578,
        0x0478,
        0x0378,
        0x0346,
        0x0214,
        0x0178,
        0x0146,
        0x0114,
        0x0078,
        0x0046,
        0x0014
      ]
  end

  defmodule Legacy do
    @moduledoc "A `:single` vault that may read messages without key commitment."

    use Encryptor.Vault,
      otp_app: :encryptor,
      context_profile: :single,
      commitment_policy: :require_encrypt_allow_decrypt,
      accept_suites: [
        0x0578,
        0x0478,
        0x0378,
        0x0346,
        0x0214,
        0x0178,
        0x0146,
        0x0114,
        0x0078,
        0x0046,
        0x0014
      ]
  end

  defmodule Scoped do
    @moduledoc "A `:scoped` vault; its reference subkey arrives at start."

    use Encryptor.Vault,
      otp_app: :encryptor,
      context_profile: :scoped
  end
end
