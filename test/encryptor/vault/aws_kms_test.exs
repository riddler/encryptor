defmodule Encryptor.Vault.AwsKmsTest do
  @moduledoc """
  ADR-0008 end to end: a vault whose tenant keys are AWS KMS keys.

  The point of these tests is that nothing above the descriptor changed. The
  same `encrypt/2` and `decrypt/2` calls, the same encryption context, the
  same message - and a data key that was generated inside KMS rather than
  locally, recorded in the header under the engine's own provider id.

  Every KMS call goes through `Encryptor.AwsKms.Fake`, a real AEAD at the
  engine's client boundary. Nothing here reaches AWS.
  """

  use ExUnit.Case, async: false

  alias Encryptor.AwsKms.Fake
  alias Encryptor.AwsKmsVaults
  alias Encryptor.Error
  alias Encryptor.Vault

  @pan "4111111111111111"
  @columns %{"table" => "payment_methods", "column" => "pan"}

  defp start_vault(vault) do
    start_supervised!(Supervisor.child_spec({vault, []}, restart: :temporary))
    vault
  end

  describe "the keyring-backed round trip" do
    test "encrypts and decrypts a tenant's data through KMS" do
      vault = start_vault(AwsKmsVaults.Tenant)

      assert {:ok, ciphertext} = vault.encrypt(@pan, key: "acme", encryption_context: @columns)
      refute ciphertext =~ @pan

      assert {:ok, @pan} = vault.decrypt(ciphertext, key: "acme", encryption_context: @columns)
    end

    # sabotage: dropped the engine's provider id check - this goes red. The
    # header records "aws-kms" and the key ARN, written by the engine, and
    # this package writes no header field at all on this path (decision 3).
    test "the header carries the engine's provider id and the key ARN" do
      vault = start_vault(AwsKmsVaults.Tenant)

      {:ok, ciphertext} = vault.encrypt(@pan, key: "acme", encryption_context: @columns)

      assert ciphertext =~ "aws-kms"
      assert ciphertext =~ Fake.acme()
    end

    test "one tenant's vault cannot read another tenant's message" do
      vault = start_vault(AwsKmsVaults.Tenant)

      {:ok, ciphertext} = vault.encrypt(@pan, key: "acme", encryption_context: @columns)

      assert {:error, %Error{}} =
               vault.decrypt(ciphertext, key: "globex", encryption_context: @columns)
    end

    test "a selector the provider does not hold is a settled unknown key" do
      vault = start_vault(AwsKmsVaults.Tenant)

      assert {:error, %Error{reason: {:unknown_key, "nobody"}}} =
               vault.encrypt(@pan, key: "nobody", encryption_context: @columns)
    end
  end

  describe "rotation, which is the candidate list doing what it always did" do
    # sabotage: dropped the older ARN from the candidate list - this goes red,
    # which is the mechanism. What it is *not* on this path is a shred: KMS
    # still holds the key and can still decrypt the message for anyone with
    # `kms:Decrypt` on it (decision 4, table row nine).
    test "a message written under the previous key still reads" do
      old = start_vault(AwsKmsVaults.Previous)
      {:ok, ciphertext} = old.encrypt(@pan, key: "acme", encryption_context: @columns)

      current = start_vault(AwsKmsVaults.Tenant)

      assert {:ok, @pan} = current.decrypt(ciphertext, key: "acme", encryption_context: @columns)
    end

    test "new writes go under the head of the list" do
      vault = start_vault(AwsKmsVaults.Tenant)

      {:ok, ciphertext} = vault.encrypt(@pan, key: "acme", encryption_context: @columns)

      assert ciphertext =~ Fake.acme()
      refute ciphertext =~ Fake.acme_previous()
    end
  end

  describe "the raw-to-KMS migration overlap (decision 6)" do
    test "a vault mid-migration reads what the raw-keyed vault wrote" do
      before = start_vault(AwsKmsVaults.Legacy)
      {:ok, ciphertext} = before.encrypt(@pan, key: "acme", encryption_context: @columns)

      during = start_vault(AwsKmsVaults.Migrating)

      assert {:ok, @pan} = during.decrypt(ciphertext, key: "acme", encryption_context: @columns)
    end

    # The encryption path cannot mix: one descriptor, one keyring. So there is
    # no state in which a message is written under both shapes.
    test "a vault mid-migration writes under KMS, and the raw-keyed vault cannot read it" do
      during = start_vault(AwsKmsVaults.Migrating)
      {:ok, ciphertext} = during.encrypt(@pan, key: "acme", encryption_context: @columns)

      assert ciphertext =~ "aws-kms"
      assert {:ok, @pan} = during.decrypt(ciphertext, key: "acme", encryption_context: @columns)

      before = start_vault(AwsKmsVaults.Legacy)

      assert {:error, %Error{}} =
               before.decrypt(ciphertext, key: "acme", encryption_context: @columns)
    end
  end

  describe "what a KMS-backed vault does not offer" do
    # ADR-0003 Amendment A decision 5, already shipped: obtaining the material
    # would mean asking a key manager to export a key, which is the property a
    # key manager exists to refuse.
    test "derive/3 refuses a keyring-backed descriptor" do
      vault = start_vault(AwsKmsVaults.Tenant)

      assert {:error, %Error{reason: {:invalid_key_descriptor, :not_derivable}}} =
               Vault.derive(vault, "blind-index", key: "acme", info: "orders.email")
    end

    # ADR-0008 decision 7: `provisioned()` is shaped around a wrapped master
    # key and this path has no wrapping.
    test "provision/2 answers that this provider is not provisionable" do
      vault = start_vault(AwsKmsVaults.Tenant)

      assert {:error, %Error{reason: {:not_provisionable, Encryptor.Provider.Kms}}} =
               Vault.provision(vault, "acme")
    end
  end

  describe "when KMS refuses" do
    # An IAM denial and a network timeout are the same fact to a caller, which
    # is why neither is distinguished in the reason.
    test "a write fails rather than falling back to anything" do
      vault = start_vault(AwsKmsVaults.Unreachable)

      assert {:error, %Error{}} =
               vault.encrypt(@pan, key: "acme", encryption_context: @columns)
    end
  end
end
