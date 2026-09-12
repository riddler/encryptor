defmodule Encryptor.SecretSourcingVaults do
  @moduledoc """
  The vaults `guides/secrets-at-start.md` prints, transcribed so the guide's
  claims about start-time secret sourcing run rather than merely read well.

  The guide is about one thing: where a vault's key material comes from, what
  happens when it is not there, and why that is the vault's decision rather
  than its provider's. Each claim it makes about a failure - a missing
  variable, a malformed one, a `nil` that travelled - is a start-time
  failure, and a start-time failure is exactly the kind of claim a reader
  cannot check by eye. `Encryptor.SecretsAtStartTest` checks them.

  One deliberate difference from the printed text, and it touches no
  cryptographic claim: the non-secret configuration the guide shows in
  `config/config.exs` (layer 3) is passed here as `use` options (layer 2). A
  test suite has no `config/config.exs` per vault, and the precedence chain
  itself is `Encryptor.Vault.ConfigTest`'s subject rather than this file's.
  Key material still arrives only through `init/1`, read from the environment
  exactly as printed, which is the rule the guide exists to make.

  The worked domain is the payments application the other guides use, with a
  ledger column instead of a card column so that no vault here shares an
  environment variable with `Encryptor.GuideVaults`.
  """

  @env "MY_APP_LEDGER_KEY"

  # Fixture material, and the only place these bytes are written. A constant
  # rather than `strong_rand_bytes/1` so a failing assertion is reproducible;
  # it is never rendered by a test.
  @key :binary.copy(<<0x44>>, 32)

  @doc "The variable the guide's vault reads."
  @spec env() :: String.t()
  def env, do: @env

  @doc """
  Puts the guide's secret into the environment, base64-encoded as printed.

  Base64 because that is the form the guide decodes, and because a raw key in
  an environment variable is a key in whatever wrote it there.
  """
  @spec put_env() :: :ok
  def put_env, do: System.put_env(@env, Base.encode64(@key))

  @doc "Puts an arbitrary value into the guide's variable, for the malformed cases."
  @spec put_env(String.t()) :: :ok
  def put_env(value) when is_binary(value), do: System.put_env(@env, value)

  @doc "Removes the guide's variable, for the case where the deployment forgot it."
  @spec delete_env() :: :ok
  def delete_env, do: System.delete_env(@env)

  @doc """
  Whether the material handed back is the material `put_env/0` wrote.

  A predicate rather than a comparison so that a failure renders `false`
  rather than two keys.
  """
  @spec fixture_key?(binary()) :: boolean()
  def fixture_key?(material) when is_binary(material), do: material == @key

  defmodule Vault do
    @moduledoc "The guide's vault: one key, read from the environment at start."

    use Encryptor.Vault,
      otp_app: :encryptor,
      context_profile: :single,
      algorithm_suite_id: 0x0478,
      required_context: ["table", "column"],
      static_encryption_context: %{"app" => "acme_payments"},
      cache: [max_age: 60]

    @impl true
    def init(config) do
      key = Base.decode64!(System.fetch_env!("MY_APP_LEDGER_KEY"))

      {:ok,
       Keyword.put(
         config,
         :provider,
         {Encryptor.Provider.Static, key: key, namespace: "acme_payments", name: "ledger/v1"}
       )}
    end
  end

  defmodule LenientVault do
    @moduledoc """
    The guide's counter-example: `System.get_env/1` where `fetch_env!/1`
    belongs.

    A variable that is not set reads as `nil` here, and `nil` travels down to
    the provider instead of stopping the start where the mistake was made.
    """

    use Encryptor.Vault,
      otp_app: :encryptor,
      context_profile: :single,
      algorithm_suite_id: 0x0478,
      cache: false

    @impl true
    def init(config) do
      key = System.get_env("MY_APP_LEDGER_KEY")

      {:ok,
       Keyword.put(
         config,
         :provider,
         {Encryptor.Provider.Static, key: key, namespace: "acme_payments", name: "ledger/v1"}
       )}
    end
  end
end
