defmodule Encryptor.Vault.PartitionTest do
  use ExUnit.Case, async: true

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
    # every tenant in a vault then shares one partition, which is two tenants
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
    # "default" and a string encodes as itself - red, because a tenant
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
end
