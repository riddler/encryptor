defmodule Encryptor.Vectors.WycheproofHkdfSha256Test do
  @moduledoc """
  Wycheproof's HKDF-SHA256 vectors, run through `Encryptor.Kdf`.

  `test/fixtures/wycheproof/hkdf_sha256_test.json` is the published file,
  unedited, at the commit `test/fixtures/wycheproof/README.md` names. Every
  case runs: a valid case through `Kdf.extract/2` then `Kdf.expand/3`,
  compared with its published output; an invalid case is asked for an output
  longer than HKDF-SHA256 defines and must be refused.

  The counts are written here literally, so a truncated, swapped or
  regenerated file fails the count test rather than passing with fewer
  cases. Nothing is filtered out: a case that fails stays failing, and the
  failure names it by `tcId` only, never by its key material.
  """

  use ExUnit.Case, async: true

  alias Encryptor.Kdf
  alias Encryptor.Wycheproof

  @file_name "hkdf_sha256_test.json"

  setup_all do
    vectors = Wycheproof.load!(@file_name)
    {:ok, vectors: vectors, cases: Wycheproof.cases(vectors)}
  end

  # sabotage: dropped the last case from the fixture file, whose header still
  # says 86 - red, 85 cases against the literal 86.
  test "the file is the published HKDF-SHA-256 set, all 86 cases of it", %{
    vectors: vectors,
    cases: cases
  } do
    assert %{"algorithm" => "HKDF-SHA-256", "numberOfTests" => 86} = vectors
    assert length(cases) == 86
    assert Enum.count(cases, &(&1["result"] == "valid")) == 83
    assert Enum.count(cases, &(&1["result"] == "invalid")) == 3
  end

  # sabotage: sent `counter + 1` instead of `counter` as the block counter
  # byte in `Encryptor.Kdf`'s private `okm/3` - red, every valid case fails.
  test "every valid case: expand(extract(salt, ikm), info, size) is the published okm",
       %{cases: cases} do
    valid = Enum.filter(cases, &(&1["result"] == "valid"))
    assert length(valid) == 83

    failing =
      for %{"tcId" => id} = vector <- valid,
          derive(vector) != Wycheproof.hex!(vector["okm"]),
          do: id

    assert failing == []
  end

  # sabotage: raised the length guard in `Kdf.expand/3` from `@max_length`
  # to `@max_length + 1` - red, size 8161 is no longer refused.
  test "every invalid case is a size HKDF-SHA256 cannot produce, and is refused",
       %{cases: cases} do
    invalid = Enum.filter(cases, &(&1["result"] == "invalid"))

    assert Enum.map(invalid, & &1["tcId"]) == [25, 48, 74]

    assert Enum.map(invalid, & &1["flags"]) == [
             ["SizeTooLarge"],
             ["SizeTooLarge"],
             ["SizeTooLarge"]
           ]

    assert Enum.map(invalid, & &1["size"]) == [8161, 8161, 8161]

    for vector <- invalid do
      assert_raise ArgumentError,
                   "HKDF-SHA256 cannot expand more than 8160 bytes, or fewer than one",
                   fn -> derive(vector) end
    end
  end

  defp derive(%{"salt" => salt, "ikm" => ikm, "info" => info, "size" => size}) do
    salt
    |> Wycheproof.hex!()
    |> Kdf.extract(Wycheproof.hex!(ikm))
    |> Kdf.expand(Wycheproof.hex!(info), size)
  end
end
