defmodule Encryptor.WireFixtureVaults do
  @moduledoc """
  A wrapped-key row and a ciphertext written by encryptor 0.4.1, and the two
  vaults that read them back under the current build.

  The bytes below were produced once, from a checkout of the `v0.4.1` tag, by
  a throwaway script run with `MIX_ENV=test mix run`. It started a root vault
  shaped like `RootVault` below and a per-owner vault under the 0.4.1 profile
  spelling `:tenant`, both built from the root material `@root`; provisioned
  a key for the selector `"workspace-7"` with `Encryptor.Envelope.provision/3`
  (default namespace, version 1, reference subkey
  `Envelope.root_subkey(@root, "tenant-ref")`); encrypted `@plaintext` with
  `key: "workspace-7"` and the per-call `@context`; and printed the row's
  fields and both blobs in Base64. The script is not kept: the fixture is the
  bytes, and a script that regenerated them under the current build would
  only round-trip its own output.

  They exist because a suite that only round-trips what the current build
  writes cannot see a changed wire constant (ADR-0009, "Consequences"). Every
  spelling in ADR-0009 decision 4's table is inside these bytes.
  """

  alias Encryptor.Envelope
  alias Encryptor.Envelope.WrappedKey

  # Fixture material, written only here and never rendered by a test.
  @root :binary.copy(<<0x5A>>, 32)

  @selector "workspace-7"
  @plaintext "fixture plaintext written by 0.4.1"
  @context %{"table" => "fixtures", "column" => "secret"}

  # The row's stored fields, as 0.4.1 printed them.
  @reference "RRQe_KCCdcy4BmZeGabcIg"
  @namespace "encryptor-tenant"
  @name "t/RRQe_KCCdcy4BmZeGabcIg/v1"

  @wrapped_b64 "AgR4xXFpA8IZR3tS517hBhVjKACOe6OurHzujzmoKi490UwAmQAEABdlbmNyeXB0" <>
                 "b3Ita2V5LW5hbWVzcGFjZQAQZW5jcnlwdG9yLXRlbmFudAAVZW5jcnlwdG9yLWtl" <>
                 "eS12ZXJzaW9uAAExABFlbmNyeXB0b3ItcHVycG9zZQAPdGVuYW50LWtleS13cmFw" <>
                 "ABRlbmNyeXB0b3ItdGVuYW50LXJlZgAWUlJRZV9LQ0NkY3k0Qm1aZUdhYmNJZwAB" <>
                 "AA5lbmNyeXB0b3Itcm9vdAAYci92MQAAAIAAAAAMygTgnEjlueRwhO6LADAgBhUq" <>
                 "CFflW0BjubNhl8DX1kQL/RFj8LPxxqk3uPK0QJTX7e+G0K7sZeH9oJrIxiACAAAQ" <>
                 "AEWd/zVjkINs5VrgMhU4YayafA9iGHQKV1T/oCLhGINBe+nTL3TvYDX7E4cLWJLo" <>
                 "Ff////8AAAABAAAAAAAAAAAAAAABAAAAIFHnoVvpSpb7pVjq3hUE46M1ZKDKC6Sy" <>
                 "yFXap8E+6yeiH9r75oFXPaPgAqUcyiOy9w=="

  @ciphertext_b64 "AgR4x/f/bP0kKfJGm9MCZEco7p3xX8FU6Lk1wjHGxFmaBisARwADAAZjb2x1bW4A" <>
                    "BnNlY3JldAAFdGFibGUACGZpeHR1cmVzAAp0ZW5hbnRfcmVmABZSUlFlX0tDQ2Rj" <>
                    "eTRCbVplR2FiY0lnAAEAEGVuY3J5cHRvci10ZW5hbnQAL3QvUlJRZV9LQ0NkY3k0" <>
                    "Qm1aZUdhYmNJZy92MQAAAIAAAAAMHeMiBHnO1PC1LZRFADBraHwYPIbGxaWNALOB" <>
                    "l2fVunOOrq5OUobrWWBviV7euxhTJ4rMZy6gw4jjg2VvPLUCAAAQAEM/Na1O3yYt" <>
                    "EzHxVB8pzQiWF6e0NIzEYlq683ryk9SzSleGgchghqtu9Ru5AFhQJ/////8AAAAB" <>
                    "AAAAAAAAAAAAAAABAAAAIpYzfS9u4KxItx3CUd8YjLVMeqZM4dPZ3wZI0ZSHUHn7" <>
                    "txlu6GpSVQAWT/6nRjrsd3Ec"

  @doc "The selector the fixture key was provisioned for."
  @spec selector() :: String.t()
  def selector, do: @selector

  @doc "The plaintext the fixture ciphertext decrypts to."
  @spec plaintext() :: String.t()
  def plaintext, do: @plaintext

  @doc "The per-call context the fixture ciphertext was written with."
  @spec context() :: %{String.t() => String.t()}
  def context, do: @context

  @doc "The reference 0.4.1 stored for the selector."
  @spec reference() :: String.t()
  def reference, do: @reference

  @doc "The reference subkey, derived from the root as a host derives it."
  @spec reference_subkey() :: binary()
  def reference_subkey, do: Envelope.root_subkey(@root, "tenant-ref")

  @doc "The ciphertext 0.4.1 wrote."
  @spec ciphertext() :: binary()
  def ciphertext, do: Base.decode64!(@ciphertext_b64)

  @doc "The wrapped-key row 0.4.1 returned, read into the current struct."
  @spec row() :: WrappedKey.t()
  def row do
    %WrappedKey{
      scope_ref: @reference,
      version: 1,
      namespace: @namespace,
      name: @name,
      bits: 256,
      wrapped: Base.decode64!(@wrapped_b64)
    }
  end

  @doc "The root material, for the root vault's `init/1`."
  @spec root() :: binary()
  def root, do: @root

  defmodule RootVault do
    @moduledoc "The root vault the fixture row was wrapped under."

    use Encryptor.Vault,
      otp_app: :encryptor,
      context_profile: :single,
      algorithm_suite_id: 0x0478,
      cache: false

    @impl true
    def init(config) do
      {:ok,
       Keyword.put(
         config,
         :provider,
         {Encryptor.Provider.Static,
          key: Encryptor.Envelope.root_subkey(Encryptor.WireFixtureVaults.root(), "root-wrap"),
          namespace: "encryptor-root",
          name: "r/v1"}
       )}
    end
  end

  defmodule ScopedVault do
    @moduledoc "The per-owner vault, under the renamed profile, reading the fixture row."

    use Encryptor.Vault,
      otp_app: :encryptor,
      context_profile: :scoped,
      algorithm_suite_id: 0x0478,
      required_context: ["table", "column"],
      cache: false

    alias Encryptor.WireFixtureVaults

    @impl true
    def init(config) do
      {:ok,
       config
       |> Keyword.put(:reference_subkey, WireFixtureVaults.reference_subkey())
       |> Keyword.put(
         :provider,
         {Encryptor.Provider.Function,
          encryption_key: &unwrap/1,
          decryption_keys: fn selector ->
            with {:ok, key} <- unwrap(selector), do: {:ok, [key]}
          end}
       )}
    end

    defp unwrap(selector) do
      case Encryptor.Envelope.unwrap(WireFixtureVaults.RootVault, WireFixtureVaults.row()) do
        {:ok, key} -> {:ok, key}
        {:error, _error} -> {:error, {:key_unavailable, selector}}
      end
    end
  end
end
