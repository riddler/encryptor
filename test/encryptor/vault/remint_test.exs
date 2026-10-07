defmodule Encryptor.Vault.RemintTest do
  @moduledoc """
  A scope shredded and then provisioned again under the same key name.

  The name a provider mints is bound to its bytes for good
  (`Encryptor.Key.Aes`), but nothing stops a host's store from holding new
  bytes under a name it used before: a whole-scope shred deletes the rows,
  and a provision for the same scope at the same version mints the same name
  again. The vault's cache must not mistake the new bytes for the old ones in
  either direction, so both cache partitions carry a fingerprint of the key
  material (ADR-0001 Amendment C):

    * the read side's, over the whole candidate list, so a message written
      under the shredded bytes is not served from a warm decryption entry
      once the name answers with other bytes;
    * the write side's, over the resolved key, so the next write does not
      reuse a warm encryption entry whose data key is wrapped under the
      shredded bytes - a message nobody can read once that entry is gone.

  The store is an ETS row per scope, read on every call by a `Function`
  provider, which is the shape the report was made on.
  """

  use ExUnit.Case, async: false

  alias Encryptor.Error
  alias Encryptor.Key.Aes
  alias Encryptor.Vault.Reference

  @store __MODULE__.Store
  @reference_subkey :binary.copy(<<0x5A>>, 32)
  @before_shred :binary.copy(<<0x31>>, 32)
  @after_shred :binary.copy(<<0x42>>, 32)
  @scope "scope-a"
  @plaintext "a value to keep"
  @context %{"table" => "items", "column" => "value"}

  defmodule Scoped do
    @moduledoc "A per-scope vault with a materials cache, over a store read per call."

    use Encryptor.Vault,
      otp_app: :encryptor,
      context_profile: :scoped,
      algorithm_suite_id: 0x0478,
      required_context: ["table", "column"],
      cache: [max_age: 60]

    alias Encryptor.Provider.Function
    alias Encryptor.Vault.RemintTest

    @doc "Layer 5: the provider and the reference subkey."
    def init(config) do
      {:ok,
       Keyword.merge(config,
         provider:
           {Function, encryption_key: &RemintTest.current/1, decryption_keys: &RemintTest.live/1},
         reference_subkey: RemintTest.reference_subkey()
       )}
    end
  end

  @doc false
  def reference_subkey, do: @reference_subkey

  @doc false
  def current(selector) do
    case live(selector) do
      {:ok, [newest | _older]} -> {:ok, newest}
      error -> error
    end
  end

  @doc false
  # One row per scope: version 1 and whatever bytes the last provision minted.
  def live(selector) do
    case :ets.lookup(@store, selector) do
      [{^selector, material}] -> {:ok, [descriptor(selector, material)]}
      _none -> {:error, {:unknown_key, selector}}
    end
  end

  defp descriptor(selector, material) do
    %Aes{
      namespace: "encryptor-scope",
      name: "s/" <> Reference.derive(@reference_subkey, selector) <> "/v1",
      material: material,
      bits: 256
    }
  end

  defp provision(selector, material), do: :ets.insert(@store, {selector, material})
  defp shred(selector), do: :ets.delete(@store, selector)

  defp start_vault do
    start_supervised!(Supervisor.child_spec({Scoped, []}, restart: :temporary), id: Scoped)
    Scoped
  end

  defp restart_vault do
    :ok = stop_supervised(Scoped)
    start_vault()
  end

  defp encrypt!(vault), do: vault.encrypt!(@plaintext, key: @scope, encryption_context: @context)

  defp decrypt(vault, ciphertext),
    do: vault.decrypt(ciphertext, key: @scope, encryption_context: @context)

  setup do
    :ets.new(@store, [:named_table, :public, :set])
    :ok
  end

  # The reported sequence: encrypt, warm, shred, provision the same name again.
  describe "a re-provision under a shredded name" do
    # sabotage: made identity/1 in Encryptor.Vault.Partition leave out the
    # material's fingerprint for both sides - red: the pre-shred message
    # decrypts again from the warm read entry.
    test "does not revive a message written under the shredded bytes" do
      vault = start_vault()
      provision(@scope, @before_shred)

      before = encrypt!(vault)
      assert {:ok, @plaintext} = decrypt(vault, before)

      shred(@scope)
      assert {:error, %Error{reason: {:unknown_key, @scope}}} = decrypt(vault, before)

      provision(@scope, @after_shred)

      assert {:error, %Error{reason: :decrypt_failed}} = decrypt(vault, before)
    end

    # sabotage: made encryption_id/3 in Encryptor.Vault.Partition leave out
    # the material's fingerprint - red: the write after the re-provision
    # reuses the warm entry wrapped under the shredded bytes, and once the
    # cache is recycled the message does not decrypt.
    test "writes a message that still decrypts after the cache is recycled" do
      vault = start_vault()
      provision(@scope, @before_shred)

      # The write that leaves a warm encryption entry for this context.
      _warm = encrypt!(vault)

      shred(@scope)
      provision(@scope, @after_shred)

      written = encrypt!(vault)

      # A fresh cache, as a recycle or a restart leaves it.
      vault = restart_vault()

      assert {:ok, @plaintext} = decrypt(vault, written)
    end
  end
end
