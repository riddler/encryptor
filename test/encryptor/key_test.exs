defmodule Encryptor.KeyTest do
  use ExUnit.Case, async: true

  alias Encryptor.Key.Aes
  alias Encryptor.Key.Kms

  describe "Encryptor.Key.Aes" do
    # sabotage: dropped :bits from @enforce_keys in lib/encryptor/key/aes.ex,
    # keeping the field in the defstruct - this goes red. A descriptor that can
    # be built without a declared size is one the vault validates the material
    # length against nil.
    test "enforces all four fields" do
      for missing <- [:namespace, :name, :material, :bits] do
        fields =
          [namespace: "myapp", name: "signup/v1", material: key_bytes(32), bits: 256]
          |> Keyword.delete(missing)

        assert_raise ArgumentError, fn -> struct!(Aes, fields) end
      end
    end

    test "carries the four fields it was built with" do
      material = key_bytes(32)

      assert %Aes{namespace: "myapp", name: "signup/v1", material: ^material, bits: 256} =
               %Aes{namespace: "myapp", name: "signup/v1", material: material, bits: 256}
    end

    # sabotage: removed the @derive {Inspect, except: [:material]} attribute -
    # the material assertion goes red. This is the mechanical half of the repo
    # rule that key material never reaches a log line.
    test "redacts :material from inspect/2 and keeps the public fields" do
      material = key_bytes(32)
      rendered = inspect(%Aes{namespace: "myapp", name: "card/v7", material: material, bits: 256})

      refute rendered =~ Base.encode16(material)
      refute rendered =~ inspect(material)
      assert rendered =~ "myapp"
      assert rendered =~ "card/v7"
      assert rendered =~ "256"
    end

    test "redaction survives a material whose byte pattern is printable" do
      # The redaction has to be structural, not a heuristic about what the
      # bytes look like: an all-ASCII wrapping key is still a wrapping key.
      printable = String.duplicate("A", 32)

      rendered =
        inspect(%Aes{namespace: "myapp", name: "card/v7", material: printable, bits: 256})

      refute rendered =~ printable
    end
  end

  describe "Encryptor.Key.Kms" do
    # sabotage: gave :key_id a default in the defstruct list - this goes red.
    test "requires :key_id" do
      assert_raise ArgumentError, fn -> struct!(Kms, mrk: true) end
    end

    # sabotage: changed the :mrk default to true - this goes red. The default
    # decides which of the two engine KMS keyrings a descriptor maps to, so it
    # is a behavioural constant rather than a convenience.
    test "defaults :mrk to false" do
      assert %Kms{key_id: "arn:aws:kms:us-east-1:111122223333:key/abcd1234", mrk: false} =
               %Kms{key_id: "arn:aws:kms:us-east-1:111122223333:key/abcd1234"}
    end

    test "accepts an explicit multi-region key" do
      assert %Kms{mrk: true} = %Kms{key_id: "mrk-abcd1234", mrk: true}
    end
  end

  # Not a key. Bytes shaped like one, for a struct that never looks at them.
  defp key_bytes(bytes), do: :crypto.strong_rand_bytes(bytes)
end
