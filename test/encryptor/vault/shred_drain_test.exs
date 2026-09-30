defmodule Encryptor.Vault.ShredDrainTest do
  @moduledoc """
  Which of ADR-0005's two destructive procedures depends on the cache drain.

  Every read asks the provider before it builds the caching CMM
  (`Encryptor.Vault.Decrypt`'s step order), and the decryption cache id is
  computed from the partition, the suite, the message's EDKs and its stored
  context - never from the candidate list the provider answered. The two
  procedures fall on opposite sides of that:

    * P3, the whole-scope shred, leaves the provider answering
      `{:unknown_key, selector}`, and that answer arrives before the cache is
      consulted, so the next read fails at once, warm cache or cold.
    * P4, the single-version retire, leaves the provider answering a shorter
      list, which the resolution step accepts; the warm entry for a message
      written under the retired version is then found by its own cache id and
      serves until it expires or the cache is dropped.

  The mint that opens the window has a cache question of its own, on the
  write side. The engine's encryption cache id is computed from the
  partition, the suite and the context the caller passed - not from the key
  that wrapped the entry's data key - so the vault puts the key in the
  partition: the write side's partition id carries the resolved key as well
  as the selector (ADR-0001 Amendment B), and a write after P2 step 1 finds a
  cold partition and wraps under version *n+1* at once, with no drain. So
  does a rekey's write half.

  The store here is a host's key table reduced to an ETS row per scope, read
  on every call by a `Function` provider, which is the shape the claim is
  about: a provider that reads its store per call. The worked domain is
  patron registration, one scope per library branch.
  """

  use ExUnit.Case, async: false

  alias AwsEncryptionSdk.Format.Header
  alias Encryptor.Error
  alias Encryptor.Key.Aes
  alias Encryptor.Vault.Reference

  @store __MODULE__.Store
  @reference_subkey :binary.copy(<<0x66>>, 32)
  @v1 :binary.copy(<<0x77>>, 32)
  @v2 :binary.copy(<<0x88>>, 32)
  @branch "branch-north"
  @email "reader@example.org"
  @columns %{"table" => "patrons", "column" => "email"}

  defmodule Patrons do
    @moduledoc "A per-branch vault with a materials cache, over a store read per call."

    use Encryptor.Vault,
      otp_app: :encryptor,
      context_profile: :scoped,
      algorithm_suite_id: 0x0478,
      required_context: ["table", "column"],
      cache: [max_age: 60]

    alias Encryptor.Provider.Function
    alias Encryptor.Vault.ShredDrainTest

    @doc "Layer 5: the provider and the reference subkey."
    def init(config) do
      {:ok,
       Keyword.merge(config,
         provider:
           {Function,
            encryption_key: &ShredDrainTest.current/1, decryption_keys: &ShredDrainTest.live/1},
         reference_subkey: ShredDrainTest.reference_subkey()
       )}
    end
  end

  @doc false
  def reference_subkey, do: @reference_subkey

  @doc false
  # The newest live version, as a store-backed `encryption_key` closure reads it.
  def current(selector) do
    case live(selector) do
      {:ok, [newest | _older]} -> {:ok, newest}
      error -> error
    end
  end

  @doc false
  # Every live version, newest first, read from the store on every call.
  def live(selector) do
    case :ets.lookup(@store, selector) do
      [{^selector, [_ | _] = versions}] -> {:ok, Enum.map(versions, &descriptor(selector, &1))}
      _none -> {:error, {:unknown_key, selector}}
    end
  end

  defp descriptor(selector, version) do
    reference = Reference.derive(@reference_subkey, selector)

    %Aes{
      namespace: "encryptor-tenant",
      name: "t/" <> reference <> "/v" <> Integer.to_string(version),
      material: material(version),
      bits: 256
    }
  end

  defp material(1), do: @v1
  defp material(2), do: @v2

  defp put_versions(selector, versions), do: :ets.insert(@store, {selector, versions})

  # The key names a message's header says wrapped its data key.
  defp wrapped_under(ciphertext) do
    {:ok, info} = Encryptor.Message.describe(ciphertext)
    Enum.map(info.encrypted_data_keys, & &1.key_name)
  end

  defp key_name(selector, version), do: descriptor(selector, version).name

  # The wrapped data key bytes, which are equal across two messages only when
  # the second reused the first's cached materials.
  defp edk_bytes(ciphertext) do
    {:ok, header, _body} = Header.deserialize(ciphertext)
    Enum.map(header.encrypted_data_keys, & &1.ciphertext)
  end

  defp delete_scope(selector), do: :ets.delete(@store, selector)

  defp start_vault do
    start_supervised!(Supervisor.child_spec({Patrons, []}, restart: :temporary), id: Patrons)
    Patrons
  end

  defp restart_vault do
    :ok = stop_supervised(Patrons)
    start_vault()
  end

  setup do
    :ets.new(@store, [:named_table, :public, :set])
    :ok
  end

  describe "P3, the whole-scope shred" do
    # sabotage: had Resolve.decryption_keys/3 remember each selector's first
    # answer in :persistent_term and serve it on later calls - a cache in
    # front of the provider - red: the read after the delete returns the
    # plaintext. The claim holds only while nothing caches ahead of the ask.
    test "answers unknown_key at once on a warm cache, with no drain" do
      vault = start_vault()
      put_versions(@branch, [1])

      ciphertext = vault.encrypt!(@email, key: @branch, encryption_context: @columns)

      # The read that populates the decryption cache for this message.
      assert {:ok, @email} = vault.decrypt(ciphertext, key: @branch, encryption_context: @columns)

      delete_scope(@branch)

      assert {:error, %Error{reason: {:unknown_key, @branch}}} =
               vault.decrypt(ciphertext, key: @branch, encryption_context: @columns)

      assert {:error, %Error{reason: {:unknown_key, @branch}}} =
               vault.encrypt(@email, key: @branch, encryption_context: @columns)
    end
  end

  describe "P4, the single-version retire" do
    # sabotage: made maybe_caching/3 in Encryptor.Vault.Encrypt return the
    # uncached CMM for every vault - red on the warm read: with no materials
    # cache there is nothing to drain, and the retired version fails at once.
    test "keeps serving a retired version from a warm cache until the cache is dropped" do
      vault = start_vault()
      put_versions(@branch, [1])

      ciphertext = vault.encrypt!(@email, key: @branch, encryption_context: @columns)
      assert {:ok, @email} = vault.decrypt(ciphertext, key: @branch, encryption_context: @columns)

      # P2 step 1 mints version 2; P4 step 1 deletes version 1.
      put_versions(@branch, [2, 1])
      put_versions(@branch, [2])

      # Before the drain: the provider no longer names version 1, and the
      # message still decrypts, from the entry the first read left.
      assert {:ok, @email} = vault.decrypt(ciphertext, key: @branch, encryption_context: @columns)

      # P4 step 2, by restart: a fresh cache, and the retire takes effect.
      vault = restart_vault()

      assert {:error, %Error{reason: :decrypt_failed}} =
               vault.decrypt(ciphertext, key: @branch, encryption_context: @columns)
    end
  end

  describe "P2 step 1, the mint, on a warm encryption cache" do
    # sabotage: made partition_id/2 in Encryptor.Vault.Encrypt answer
    # Partition.id(vault, selector) for the write side too, dropping the key
    # from the partition - red on the write after the mint: the same context
    # finds the warm entry from before it, and the header names version 1.
    test "writes under the new version at once, from a warm cache, with no drain" do
      vault = start_vault()
      put_versions(@branch, [1])

      # The write that populates the encryption cache for this context.
      before_mint = vault.encrypt!(@email, key: @branch, encryption_context: @columns)
      assert wrapped_under(before_mint) == [key_name(@branch, 1)]

      # The cache is warm: a second write before the mint reuses the entry,
      # so the two messages share one data key and one encrypted data key.
      warm = vault.encrypt!(@email, key: @branch, encryption_context: @columns)
      assert edk_bytes(warm) == edk_bytes(before_mint)

      # P2 step 1: version 2 is minted and the provider now answers it first.
      put_versions(@branch, [2, 1])
      assert {:ok, %Aes{name: current}} = current(@branch)
      assert current == key_name(@branch, 2)

      # No drain: the write's partition carries version 2's name, so the warm
      # entry from before the mint is not found, and the data key is wrapped
      # under version 2.
      after_mint = vault.encrypt!(@email, key: @branch, encryption_context: @columns)
      assert wrapped_under(after_mint) == [key_name(@branch, 2)]
      assert {:ok, @email} = vault.decrypt(after_mint, key: @branch, encryption_context: @columns)
    end

    # sabotage: made rekey/2's write half call Encrypt.client/3 (the read
    # side's selector-only partition) instead of Encrypt.client/4 - red: the
    # rekey before the mint leaves a warm entry under that partition, the
    # rekey after it finds the entry, and the rewritten header still names
    # version 1.
    test "a rekey's write half rewrites under the new version at once, with no drain" do
      vault = start_vault()
      put_versions(@branch, [1])

      old = vault.encrypt!(@email, key: @branch, encryption_context: @columns)
      assert wrapped_under(old) == [key_name(@branch, 1)]

      # Two rewrites before the mint: the second reuses the materials the
      # first cached, so the rekey's write half runs through a warm cache.
      {:ok, first} = vault.rekey(old, key: @branch)
      {:ok, second} = vault.rekey(old, key: @branch)
      assert wrapped_under(second) == [key_name(@branch, 1)]
      assert edk_bytes(second) == edk_bytes(first)

      put_versions(@branch, [2, 1])

      assert {:ok, rewritten} = vault.rekey(old, key: @branch)
      assert wrapped_under(rewritten) == [key_name(@branch, 2)]
      assert {:ok, @email} = vault.decrypt(rewritten, key: @branch, encryption_context: @columns)
    end
  end
end
