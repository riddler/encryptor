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

    # sabotage: dropped the material's fingerprint from identity/1 - red,
    # because a name minted again over new bytes after a shred then shares
    # the partition of the shredded bytes, and the next write reuses a data
    # key wrapped under bytes nobody holds any more.
    test "one name over two byte strings produces distinct ids" do
      first = aes("ns", "t/r/v1")
      second = %{first | material: :binary.copy(<<2>>, 32)}

      refute Partition.encryption_id(LifecycleVaults.Cached, "tenant-42", first) ==
               Partition.encryption_id(LifecycleVaults.Cached, "tenant-42", second)
    end

    # sabotage: widened the length prefix from 32 to 16 bits - red, because
    # this pins the derivation itself: a change to the pre-image, the digest
    # or the truncation is an ADR-0001 amendment, made deliberately. The
    # expected values were computed outside this package from Amendment C's
    # formula; the KMS one is unchanged from Amendment B's.
    test "matches the derivation ADR-0001 Amendments B and C fix" do
      key = aes("ns", "t/r/v1")

      assert Base.encode16(Partition.encryption_id(LifecycleVaults.Cached, "tenant-42", key),
               case: :lower
             ) == "5f295f16a61eec58698b9b9fde5db39e"

      assert Base.encode16(
               Partition.encryption_id(LifecycleVaults.Cacheless, :default, kms("key-1")),
               case: :lower
             ) == "4ed343ddc772fe6c11a50fd62bb718d6"
    end
  end

  describe "the read side's partition id, which carries every candidate" do
    defp candidate(name, byte),
      do: %Aes{namespace: "ns", name: name, material: :binary.copy(<<byte>>, 32), bits: 256}

    # sabotage: dropped the material's fingerprint from identity/1 - red,
    # because a candidate list whose name came back over new bytes after a
    # shred then finds the decryption entries the shredded bytes left, and a
    # message written under them decrypts again.
    test "one name over two byte strings produces distinct ids" do
      refute Partition.decryption_id(LifecycleVaults.Cached, "t", [candidate("t/r/v1", 1)]) ==
               Partition.decryption_id(LifecycleVaults.Cached, "t", [candidate("t/r/v1", 2)])
    end

    # sabotage: hashed only the first candidate's identity - red, because a
    # list that loses or gains a version then keeps its partition.
    test "a list that gains, loses or reorders a candidate is a different id" do
      v1 = candidate("t/r/v1", 1)
      v2 = candidate("t/r/v2", 2)

      ids =
        Enum.map([[v1], [v2, v1], [v1, v2], [v2]], fn list ->
          Partition.decryption_id(LifecycleVaults.Cached, "t", list)
        end)

      assert length(Enum.uniq(ids)) == 4
      assert Enum.all?(ids, &(byte_size(&1) == 16))
    end

    # sabotage: dropped the selector from the decryption_id/3 pre-image - red,
    # because two scopes answering one candidate list would share a partition.
    test "the vault and the selector still partition" do
      list = [candidate("t/r/v1", 1)]

      refute Partition.decryption_id(LifecycleVaults.Cached, "tenant-42", list) ==
               Partition.decryption_id(LifecycleVaults.Cached, "tenant-43", list)

      refute Partition.decryption_id(LifecycleVaults.Cached, "tenant-42", list) ==
               Partition.decryption_id(LifecycleVaults.Second, "tenant-42", list)

      refute Partition.decryption_id(LifecycleVaults.Cached, :default, list) ==
               Partition.decryption_id(LifecycleVaults.Cached, "default", list)
    end

    # sabotage: dropped the candidate count from the pre-image - red, because
    # this pins the derivation itself. The expected values were computed
    # outside this package from ADR-0001 Amendment C's formula.
    test "matches the derivation ADR-0001 Amendment C fixes" do
      list = [candidate("t/r/v2", 2), candidate("t/r/v1", 1)]

      assert Base.encode16(Partition.decryption_id(LifecycleVaults.Cached, "tenant-42", list),
               case: :lower
             ) == "c3dc578639b2f207ff088d79c084447b"

      assert Base.encode16(
               Partition.decryption_id(LifecycleVaults.Cacheless, :default, [
                 %Kms{key_id: "key-1", client: %{}}
               ]),
               case: :lower
             ) == "59a8d5a86f87d5d5a2cfd8466a8b9153"
    end
  end
end
