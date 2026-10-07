defmodule Encryptor.GcmConstructionVaults do
  @moduledoc """
  The vault `Encryptor.GcmConstructionTest` reads messages from, and the
  scope key behind it.

  The test opens what the vault writes by hand - it unwraps the data key and
  re-derives the message key itself - so the scope key's material has to be
  known to it. That is the only reason this file hands it out: a host never
  sees the material a provider resolves.

  One `:scoped` vault with a required column pair, started per test with the
  algorithm suite and the cache setting under test, both through
  `start_link/1` options (layer 4 of ADR-0001 decision 5).
  """

  alias Encryptor.Vault.Reference

  # Fixture material, and the only place these bytes are written. Constants
  # rather than `strong_rand_bytes/1` so a failing assertion is reproducible;
  # they are never rendered by a test.
  @scope_key :binary.copy(<<0x6C>>, 32)
  @reference_subkey :binary.copy(<<0x6D>>, 32)

  @selector "scope-a"

  @doc "The one selector the vault resolves."
  @spec selector() :: String.t()
  def selector, do: @selector

  @doc "The scope key's material, for the test's own unwrap."
  @spec scope_key() :: binary()
  def scope_key, do: @scope_key

  @doc "The reference the vault derives for the selector."
  @spec reference() :: String.t()
  def reference, do: Reference.derive(@reference_subkey, @selector)

  @doc "The raw-AES key name the scope key wraps under."
  @spec key_name() :: String.t()
  def key_name, do: "s/" <> reference() <> "/v1"

  @doc "The reference subkey, for the vault's `init/1`."
  @spec reference_subkey() :: binary()
  def reference_subkey, do: @reference_subkey

  @doc "The descriptor the selector resolves to."
  @spec descriptor() :: Encryptor.Key.Aes.t()
  def descriptor do
    %Encryptor.Key.Aes{
      namespace: "encryptor-scope",
      name: key_name(),
      material: @scope_key,
      bits: 256
    }
  end

  defmodule Scoped do
    @moduledoc "A per-scope vault requiring the column pair; suite and cache come at start."

    use Encryptor.Vault,
      otp_app: :encryptor,
      context_profile: :scoped,
      required_context: ["table", "column"]

    alias Encryptor.GcmConstructionVaults

    @doc "Layer 5: the provider and the reference subkey, both key material."
    def init(config) do
      selector = GcmConstructionVaults.selector()

      {:ok,
       Keyword.merge(config,
         provider:
           {Encryptor.Provider.Function,
            encryption_key: fn ^selector -> {:ok, GcmConstructionVaults.descriptor()} end,
            decryption_keys: fn ^selector -> {:ok, [GcmConstructionVaults.descriptor()]} end},
         reference_subkey: GcmConstructionVaults.reference_subkey()
       )}
    end
  end
end
