defmodule Encryptor.Vault.PartitionTest do
  use ExUnit.Case, async: true

  alias Encryptor.Key.Aes
  alias Encryptor.Key.Kms
  alias Encryptor.LifecycleVaults
  alias Encryptor.Vault.Partition

  doctest Encryptor.Vault.Partition

  describe "the derived partition id" do
    # sabotage: changed @bytes from 16 to 20 - red, because the engine
    # concatenates the partition id into the cache id pre-image with no length
    # prefix, so a width other than the engine's own 16 reintroduces the
    # ambiguity decision 7 exists to remove.
    test "is exactly 16 bytes, for both selector shapes" do
      assert byte_size(Partition.id(LifecycleVaults.Cached, "tenant-42")) == 16
      assert byte_size(Partition.id(LifecycleVaults.Cacheless, :default)) == 16
      assert Partition.bytes() == 16
    end

    # sabotage: dropped the selector from the hash pre-image - red, because
    # every scope in a vault then shares one partition, which is two scopes
    # sharing a data key.
    test "two selectors in one vault produce distinct ids" do
      first = Partition.id(LifecycleVaults.Cached, "tenant-42")
      second = Partition.id(LifecycleVaults.Cached, "tenant-43")

      assert first != second
    end

    # sabotage: dropped the vault from the hash pre-image - red, because two
    # vaults then derive one partition for the same selector.
    test "two vaults produce distinct ids for the same selector" do
      first = Partition.id(LifecycleVaults.Cached, "tenant-42")
      second = Partition.id(LifecycleVaults.Second, "tenant-42")

      assert first != second
    end

    # sabotage: dropped the tag bytes from encoded/1, so `:default` encodes as
    # "default" and a string encodes as itself - red, because a scope
    # literally named "default" then collides with a single-key vault's own
    # partition.
    test "the :default selector does not collide with the string \"default\"" do
      assert Partition.id(LifecycleVaults.Cached, :default) !=
               Partition.id(LifecycleVaults.Cached, "default")
    end

    # sabotage: seeded the hash with :crypto.strong_rand_bytes/1 - red,
    # because a partition id that changes per call means every call is a cold
    # miss and the cache never serves anything.
    test "is deterministic" do
      assert Partition.id(LifecycleVaults.Cached, "tenant-42") ==
               Partition.id(LifecycleVaults.Cached, "tenant-42")
    end

    # sabotage: replaced sha256 with sha512 in the derivation - red, because
    # this pins the derivation itself rather than a property of it. A change
    # to the pre-image, the digest, or the truncation is an ADR-0001 decision
    # 7 amendment, so it should have to be made deliberately.
    test "matches the derivation ADR-0001 decision 7 fixes" do
      assert Base.encode16(Partition.id(LifecycleVaults.Cached, "tenant-42"), case: :lower) ==
               "99be8bdb1cdc8e238ab32a371962bcf7"

      assert Base.encode16(Partition.id(LifecycleVaults.Cacheless, :default), case: :lower) ==
               "2e9f88a21bf38fc83d660519fcb4af77"
    end
  end

  describe "the write side's partition id, which carries the resolved key" do
    defp aes(namespace, name),
      do: %Aes{namespace: namespace, name: name, material: :binary.copy(<<1>>, 32), bits: 256}

    defp kms(key_id), do: %Kms{key_id: key_id, client: %{}}

    # sabotage: dropped identity(key) from the encryption_id/3 pre-image - red,
    # because two versions of one scope's key then share a partition, and a
    # write after a mint finds the warm entry wrapped under the old version.
    test "two versions of one scope's key produce distinct ids" do
      v1 = Partition.encryption_id(LifecycleVaults.Cached, "tenant-42", aes("ns", "t/r/v1"))
      v2 = Partition.encryption_id(LifecycleVaults.Cached, "tenant-42", aes("ns", "t/r/v2"))

      assert byte_size(v1) == 16
      assert byte_size(v2) == 16
      refute v1 == v2
    end

    # sabotage: made prefixed/1 return the field without its length - red,
    # because the namespace and name then run together, and ("ab", "c") and
    # ("a", "bc") hash one pre-image.
    test "the key's fields are length-prefixed, so a moved boundary is a different id" do
      assert Partition.encryption_id(LifecycleVaults.Cached, "t", aes("ab", "c")) !=
               Partition.encryption_id(LifecycleVaults.Cached, "t", aes("a", "bc"))

      assert Partition.encryption_id(LifecycleVaults.Cached, "ab", aes("c", "d")) !=
               Partition.encryption_id(LifecycleVaults.Cached, "a", aes("bc", "d"))
    end

    # sabotage: set @kms_tag to @aes_tag's value and made the Aes identity a
    # single prefixed name - red, because an AES key named like a KMS key id
    # then shares that key's partition.
    test "an AES key and a KMS key are tagged apart" do
      assert Partition.encryption_id(LifecycleVaults.Cached, "t", aes("ns", "k")) !=
               Partition.encryption_id(LifecycleVaults.Cached, "t", kms("k"))
    end

    # sabotage: dropped the selector from the encryption_id/3 pre-image - red,
    # because two scopes resolving to one key name would share a partition.
    test "the vault and the selector still partition" do
      key = aes("ns", "t/r/v1")

      refute Partition.encryption_id(LifecycleVaults.Cached, "tenant-42", key) ==
               Partition.encryption_id(LifecycleVaults.Cached, "tenant-43", key)

      refute Partition.encryption_id(LifecycleVaults.Cached, "tenant-42", key) ==
               Partition.encryption_id(LifecycleVaults.Second, "tenant-42", key)

      refute Partition.encryption_id(LifecycleVaults.Cached, :default, key) ==
               Partition.encryption_id(LifecycleVaults.Cached, "default", key)
    end

    # sabotage: widened the length prefix from 32 to 16 bits - red, because
    # this pins the derivation itself: a change to the pre-image, the digest
    # or the truncation is an ADR-0001 amendment, made deliberately.
    test "matches the derivation ADR-0001 Amendment B fixes" do
      key = aes("ns", "t/r/v1")

      assert Base.encode16(Partition.encryption_id(LifecycleVaults.Cached, "tenant-42", key),
               case: :lower
             ) == "1e952266f389bcd5843a51c31d524ee0"

      assert Base.encode16(
               Partition.encryption_id(LifecycleVaults.Cacheless, :default, kms("key-1")),
               case: :lower
             ) == "4ed343ddc772fe6c11a50fd62bb718d6"
    end
  end
end
