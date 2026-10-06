defmodule Encryptor.WireFixtureV2Vaults do
  @moduledoc """
  A wrapped-key row and a ciphertext written under wire format v2, and the
  two vaults that read them back under the current build.

  The bytes below were produced once, from the build that introduced wire
  format v2 (ADR-0009 Amendment A), by a throwaway script run with
  `MIX_ENV=test mix run`. It started a root vault shaped like `RootVault`
  below and a `:scoped` vault, both built from the root material `@root`;
  provisioned a key for the selector `"workspace-7"` with
  `Encryptor.Envelope.provision/3` (default namespace, version 1, reference
  subkey `Envelope.root_subkey(@root, "scope-ref")`); encrypted
  `@plaintext` with `key: "workspace-7"` and the per-call `@context`; and
  printed the row's fields and both blobs in Base64. The script is not kept:
  the fixture is the bytes, and a script that regenerated them under a later
  build would only round-trip its own output.

  They exist because a suite that only round-trips what the current build
  writes cannot see a changed wire constant (ADR-0009 Amendment A,
  "Consequences"). Rows 1 to 7 of the amendment's A1 table are inside these
  bytes; row 8, the Cloud KMS id prefix, is pinned by the GCP provider's
  tests. A later respelling of any row is a re-encrypt of every stored row
  (A2), and these bytes are what turns it red.
  """

  alias Encryptor.Envelope
  alias Encryptor.Envelope.WrappedKey

  # Fixture material, written only here and never rendered by a test.
  @root :binary.copy(<<0x5B>>, 32)

  @selector "workspace-7"
  @plaintext "fixture plaintext written by wire format v2"
  @context %{"table" => "fixtures", "column" => "secret"}

  # The row's stored fields, as the producing build printed them.
  @reference "TEmQcU6FHo8CCO3Xt2ZPrA"
  @namespace "encryptor-scope"
  @name "s/TEmQcU6FHo8CCO3Xt2ZPrA/v1"

  @wrapped_b64 "AgR44yQi4lt65Y1MzP4lEJhMSrn4h32IzbMx+Zb3qJMTx1wAlgAEABdlbmNyeXB0" <>
                 "b3Ita2V5LW5hbWVzcGFjZQAPZW5jcnlwdG9yLXNjb3BlABVlbmNyeXB0b3Ita2V5" <>
                 "LXZlcnNpb24AATEAEWVuY3J5cHRvci1wdXJwb3NlAA5zY29wZS1rZXktd3JhcAAT" <>
                 "ZW5jcnlwdG9yLXNjb3BlLXJlZgAWVEVtUWNVNkZIbzhDQ08zWHQyWlByQQABAA5l" <>
                 "bmNyeXB0b3Itcm9vdAAYci92MQAAAIAAAAAMh2G2Hsz8IhPHzb/RADDWGE8mxMnn" <>
                 "z7HCnezkVjFWmuf2QjOkLdw5kWOKXvKGSrsASdfd8qbMwyXtSgUacbQCAAAQAJoI" <>
                 "Hf2XYVQWEQpUdt6cuGPCAIQ9G/ZeOhKwswxCzgpAKZY+fMG6+7BdYdXknFWALf//" <>
                 "//8AAAABAAAAAAAAAAAAAAABAAAAIE9OQlm2Vn3ckmSb5jXvyxb6p1b+OolwVnov" <>
                 "YZTeXpyVovCSiDQNmzCeYWyoaxn2fQ=="

  @ciphertext_b64 "AgR4vfuOYjITE3SQu71ttJPy9t4TSO6eRA6Y5Q1lJ6XX6dgARgADAAZjb2x1bW4A" <>
                    "BnNlY3JldAAJc2NvcGVfcmVmABZURW1RY1U2RkhvOENDTzNYdDJaUHJBAAV0YWJs" <>
                    "ZQAIZml4dHVyZXMAAQAPZW5jcnlwdG9yLXNjb3BlAC9zL1RFbVFjVTZGSG84Q0NP" <>
                    "M1h0MlpQckEvdjEAAACAAAAADM/fquuxc/QMPZoPBgAw3FTgzG00F4kwbsBzKs8v" <>
                    "vdu9a4UEulZBb2QN4b5N+YYUyjQI468k/t8srfbK4xiNAgAAEAD0GsW0tXZo6Ta4" <>
                    "wze21HPQKV0kSAjihTUm1VRWGFlWxKCJgsZcc0n7vvgQWqsxzJn/////AAAAAQAA" <>
                    "AAAAAAAAAAAAAQAAACuO/mGo8917VZqLEqLaV9VqmAAAonixCQSpg5UrrsVhqHJl" <>
                    "zLh2e1rKhISzFxdwC5pN91QI0ayMx2STTg=="

  @doc "The selector the fixture key was provisioned for."
  @spec selector() :: String.t()
  def selector, do: @selector

  @doc "The plaintext the fixture ciphertext decrypts to."
  @spec plaintext() :: String.t()
  def plaintext, do: @plaintext

  @doc "The per-call context the fixture ciphertext was written with."
  @spec context() :: %{String.t() => String.t()}
  def context, do: @context

  @doc "The reference the producing build stored for the selector."
  @spec reference() :: String.t()
  def reference, do: @reference

  @doc "The reference subkey, derived from the root as a host derives it."
  @spec reference_subkey() :: binary()
  def reference_subkey, do: Envelope.root_subkey(@root, "scope-ref")

  @doc "The ciphertext the producing build wrote."
  @spec ciphertext() :: binary()
  def ciphertext, do: Base.decode64!(@ciphertext_b64)

  @doc "The wrapped-key row the producing build returned."
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
          key: Encryptor.Envelope.root_subkey(Encryptor.WireFixtureV2Vaults.root(), "root-wrap"),
          namespace: "encryptor-root",
          name: "r/v1"}
       )}
    end
  end

  defmodule ScopedVault do
    @moduledoc "The per-owner vault reading the fixture row."

    use Encryptor.Vault,
      otp_app: :encryptor,
      context_profile: :scoped,
      algorithm_suite_id: 0x0478,
      required_context: ["table", "column"],
      cache: false

    alias Encryptor.WireFixtureV2Vaults

    @impl true
    def init(config) do
      {:ok,
       config
       |> Keyword.put(:reference_subkey, WireFixtureV2Vaults.reference_subkey())
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
      case Encryptor.Envelope.unwrap(WireFixtureV2Vaults.RootVault, WireFixtureV2Vaults.row()) do
        {:ok, key} -> {:ok, key}
        {:error, _error} -> {:error, {:key_unavailable, selector}}
      end
    end
  end
end
