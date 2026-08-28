defmodule Encryptor.GuideVaults do
  @moduledoc """
  The vaults, the key store and the provider that `guides/getting-started.md`
  and `guides/rotation-runbook.md` print, transcribed so the guides are
  executable rather than plausible.

  A guide is the highest-visibility example surface in the package, and an
  example that does not run is worse than no example: it is a promise about a
  function that reads exactly like a promise about a function that works. Every
  module here is a paste of a guide code block, with the identifiers the guides
  use, so `Encryptor.GuidesTest` fails the moment a guide drifts from the
  landed surface.

  Two deliberate differences from the printed text, and neither touches a
  cryptographic claim:

    * The non-secret configuration the guides show in `config/config.exs`
      (layer 3) is passed here as `use` options (layer 2). A test suite has no
      `config/config.exs` per vault, and the precedence chain itself is
      `Encryptor.Vault.ConfigTest`'s subject rather than this file's. Key
      material still arrives only through `init/1`, which is the rule the
      guides make, and it is read from the environment exactly as printed.
    * `MerchantKeys` is an `Agent` rather than a table. This package defines no
      storage at all, so the guides' `MyApp.MerchantKeys` is by construction
      the reader's own; what the suite needs from it is only that it can hand
      back a `WrappedKey`.

  The worked domain is card processing, matching the rest of the suite: a
  payments application encrypting its own columns, and then the same
  application serving merchants as tenants.
  """

  alias Encryptor.Envelope
  alias Encryptor.Envelope.WrappedKey

  # Fixture material, and the only place these bytes are written. Constants
  # rather than `strong_rand_bytes/1` so a failing assertion is reproducible;
  # they are never rendered by a test.
  @card_key :binary.copy(<<0x11>>, 32)
  @root :binary.copy(<<0x22>>, 32)
  @rotated_root :binary.copy(<<0x33>>, 32)

  @doc """
  Puts the three secrets the guides read into the environment.

  Base64 because that is the form the guides decode, and because a raw key in
  an environment variable is a key in whatever wrote it there.
  """
  @spec put_env() :: :ok
  def put_env do
    # Install-time: the wrapping root and the reference root hold the SAME
    # bytes, which is the getting-started guide's day-one rule.
    System.put_env("MY_APP_CARD_KEY", Base.encode64(@card_key))
    System.put_env("MY_APP_WRAPPING_ROOT_KEY", Base.encode64(@root))
    System.put_env("MY_APP_REFERENCE_ROOT_KEY", Base.encode64(@root))
    System.put_env("MY_APP_WRAPPING_ROOT_KEY_PREVIOUS", Base.encode64(@root))
    :ok
  end

  @doc "Rotates the wrapping-root secret and keeps the outgoing value, as P1 steps 0 and 1."
  @spec rotate_wrapping_root() :: :ok
  def rotate_wrapping_root do
    System.put_env("MY_APP_WRAPPING_ROOT_KEY_PREVIOUS", Base.encode64(@root))
    System.put_env("MY_APP_WRAPPING_ROOT_KEY", Base.encode64(@rotated_root))
    :ok
  end

  @doc "The reference subkey the guides derive wherever a tenant reference is needed."
  @spec reference_subkey() :: binary()
  def reference_subkey do
    "MY_APP_REFERENCE_ROOT_KEY"
    |> System.fetch_env!()
    |> Base.decode64!()
    |> Envelope.root_subkey("tenant-ref")
  end

  defmodule Vault do
    @moduledoc "Part 1 of the getting-started guide: the single-key vault."

    use Encryptor.Vault,
      otp_app: :encryptor,
      context_profile: :single,
      algorithm_suite_id: 0x0478,
      required_context: ["table", "column"],
      static_encryption_context: %{"app" => "acme_payments"},
      cache: [max_age: 60]

    @impl true
    def init(config) do
      key = Base.decode64!(System.fetch_env!("MY_APP_CARD_KEY"))

      {:ok,
       Keyword.put(
         config,
         :provider,
         {Encryptor.Provider.Static, key: key, namespace: "acme_payments", name: "card/v1"}
       )}
    end
  end

  defmodule RootVault do
    @moduledoc "Part 2 of the getting-started guide: the root vault, before any rotation."

    use Encryptor.Vault,
      otp_app: :encryptor,
      context_profile: :single,
      algorithm_suite_id: 0x0478,
      cache: false

    @impl true
    def init(config) do
      wrapping_root = Base.decode64!(System.fetch_env!("MY_APP_WRAPPING_ROOT_KEY"))

      {:ok,
       Keyword.put(
         config,
         :provider,
         {Encryptor.Provider.Static,
          key: Encryptor.Envelope.root_subkey(wrapping_root, "root-wrap"),
          namespace: "encryptor-root",
          name: "r/v1"}
       )}
    end
  end

  defmodule StagedRootVault do
    @moduledoc """
    The runbook's P1 step 2: both wrapping subkeys live, newest first.

    Writes go under generation 2 and reads resolve either, which is what makes
    step 3's rewrap pass safe to run against live traffic.
    """

    use Encryptor.Vault,
      otp_app: :encryptor,
      context_profile: :single,
      algorithm_suite_id: 0x0478,
      cache: false

    @impl true
    def init(config) do
      new_root = Base.decode64!(System.fetch_env!("MY_APP_WRAPPING_ROOT_KEY"))
      old_root = Base.decode64!(System.fetch_env!("MY_APP_WRAPPING_ROOT_KEY_PREVIOUS"))

      {:ok,
       Keyword.put(
         config,
         :provider,
         {Encryptor.Provider.Static,
          keys: [
            [
              key: Encryptor.Envelope.root_subkey(new_root, "root-wrap"),
              namespace: "encryptor-root",
              name: "r/v2"
            ],
            [
              key: Encryptor.Envelope.root_subkey(old_root, "root-wrap"),
              namespace: "encryptor-root",
              name: "r/v1"
            ]
          ]}
       )}
    end
  end

  defmodule MerchantKeys do
    @moduledoc """
    The reader's own key store, in memory.

    The guides call it `MyApp.MerchantKeys` and this package defines no
    storage, so every function here is one the reader writes. It exists so the
    runbook's passes - enumerate, update one wrapping, delete one version - are
    executed rather than described.
    """

    use Agent

    alias Encryptor.Envelope.WrappedKey

    @spec start_link(keyword()) :: Agent.on_start()
    def start_link(_opts), do: Agent.start_link(fn -> %{} end, name: __MODULE__)

    @doc "Inserts a freshly provisioned wrapping, keyed by reference and version."
    @spec insert(WrappedKey.t()) :: {:ok, WrappedKey.t()}
    def insert(%WrappedKey{} = wrapped) do
      Agent.update(__MODULE__, &Map.put(&1, {wrapped.tenant_ref, wrapped.version}, wrapped))
      {:ok, wrapped}
    end

    @doc "Every live wrapping, for P1 step 3's pass."
    @spec all_live() :: [WrappedKey.t()]
    def all_live, do: Agent.get(__MODULE__, &Map.values(&1))

    @doc "P1 step 3's single-row write."
    @spec update_wrapping(WrappedKey.t(), WrappedKey.t()) :: :ok
    def update_wrapping(%WrappedKey{} = row, %WrappedKey{} = rewrapped) do
      Agent.update(__MODULE__, &Map.put(&1, {row.tenant_ref, row.version}, rewrapped))
    end

    @doc "Every version for one tenant reference, newest first."
    @spec versions(String.t()) :: [WrappedKey.t()]
    def versions(tenant_ref) do
      Agent.get(__MODULE__, fn rows ->
        rows
        |> Enum.filter(fn {{ref, _version}, _row} -> ref == tenant_ref end)
        |> Enum.map(fn {_key, row} -> row end)
        |> Enum.sort_by(& &1.version, :desc)
      end)
    end

    @doc "P4 step 1: the delete that closes the window."
    @spec delete_version(String.t(), pos_integer()) :: :ok
    def delete_version(tenant_ref, version) do
      Agent.update(__MODULE__, &Map.delete(&1, {tenant_ref, version}))
    end

    @doc "P3 step 2: the delete that ends a tenant."
    @spec delete_tenant(String.t()) :: :ok
    def delete_tenant(tenant_ref) do
      Agent.update(__MODULE__, fn rows ->
        Enum.reject(rows, fn {{ref, _version}, _row} -> ref == tenant_ref end) |> Map.new()
      end)
    end
  end

  defmodule MerchantKeyProvider do
    @moduledoc """
    The store-backed provider the guides hand to the merchant vault.

    It derives the tenant reference from the selector with the same reference
    subkey the vault holds, reads the store, and unwraps. It never provisions:
    a selector with no live row is `{:unknown_key, selector}`, full stop.
    """

    @behaviour Encryptor.Provider

    alias Encryptor.Envelope
    alias Encryptor.GuideVaults.MerchantKeys

    @impl Encryptor.Provider
    def init(opts) do
      {:ok,
       %{
         root_vault: Keyword.fetch!(opts, :root_vault),
         reference_subkey: Keyword.fetch!(opts, :reference_subkey)
       }}
    end

    @impl Encryptor.Provider
    def encryption_key(state, selector) do
      with {:ok, [current | _older]} <- rows(state, selector) do
        unwrap(state, selector, current)
      end
    end

    @impl Encryptor.Provider
    def decryption_keys(state, selector) do
      with {:ok, rows} <- rows(state, selector) do
        unwrap_all(state, selector, rows)
      end
    end

    defp unwrap_all(state, selector, rows) do
      rows
      |> Enum.reduce_while({:ok, []}, &unwrap_into(state, selector, &1, &2))
      |> case do
        {:ok, reversed} -> {:ok, Enum.reverse(reversed)}
        {:error, reason} -> {:error, reason}
      end
    end

    defp unwrap_into(state, selector, row, {:ok, acc}) do
      case unwrap(state, selector, row) do
        {:ok, descriptor} -> {:cont, {:ok, [descriptor | acc]}}
        {:error, reason} -> {:halt, {:error, reason}}
      end
    end

    defp rows(state, selector) do
      with {:ok, ref} <- Envelope.tenant_ref(state.reference_subkey, selector) do
        case MerchantKeys.versions(ref) do
          [] -> {:error, {:unknown_key, selector}}
          rows -> {:ok, rows}
        end
      end
    end

    defp unwrap(state, selector, row) do
      case Envelope.unwrap(state.root_vault, row) do
        {:ok, descriptor} -> {:ok, descriptor}
        {:error, _error} -> {:error, {:key_unavailable, selector}}
      end
    end
  end

  defmodule MerchantVault do
    @moduledoc "Part 2 of the getting-started guide: the per-tenant vault."

    use Encryptor.Vault,
      otp_app: :encryptor,
      context_profile: :tenant,
      algorithm_suite_id: 0x0478,
      required_context: ["table", "column"],
      cache: [max_age: 60]

    @impl true
    def init(config) do
      reference_root = Base.decode64!(System.fetch_env!("MY_APP_REFERENCE_ROOT_KEY"))
      reference_subkey = Encryptor.Envelope.root_subkey(reference_root, "tenant-ref")

      {:ok,
       config
       |> Keyword.put(:reference_subkey, reference_subkey)
       |> Keyword.put(
         :provider,
         {Encryptor.GuideVaults.MerchantKeyProvider,
          root_vault: Encryptor.GuideVaults.RootVault, reference_subkey: reference_subkey}
       )}
    end
  end

  @doc """
  Onboards a merchant exactly as the getting-started guide does.

  Returns the stored wrapping so a test can assert on the row rather than only
  on the round trip.
  """
  @spec onboard(String.t(), pos_integer()) :: {:ok, WrappedKey.t()}
  def onboard(merchant_id, version \\ 1) do
    {:ok, wrapped} =
      Envelope.provision(RootVault, merchant_id,
        reference_subkey: reference_subkey(),
        namespace: "acme-merchant",
        version: version
      )

    MerchantKeys.insert(wrapped)
  end
end
