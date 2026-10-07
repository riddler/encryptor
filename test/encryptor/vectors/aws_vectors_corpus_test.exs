defmodule Encryptor.Vectors.AwsVectorsCorpusTest do
  @moduledoc """
  The AWS Encryption SDK decrypt vectors corpus is on disk and readable.

  Tagged `:aws_vectors`, which `test/test_helper.exs` excludes by default; CI
  runs it with `mix test --only aws_vectors` and
  `ENCRYPTOR_REQUIRE_AWS_VECTORS=1`. Without that variable an absent corpus
  skips this module; with it, an absent corpus fails it. `Encryptor.AwsVectors`
  says where the corpus comes from.

  The counts are written here literally, so a truncated or swapped corpus
  fails rather than passing with fewer entries.
  """

  use ExUnit.Case, async: true

  alias Encryptor.AwsVectors

  @moduletag :aws_vectors

  unless AwsVectors.present?() or AwsVectors.required?() do
    @moduletag skip: AwsVectors.absent_message()
  end

  # sabotage: ran with ENCRYPTOR_REQUIRE_AWS_VECTORS=1 and the corpus
  # directory moved aside - red, the corpus is reported absent.
  test "the corpus is present" do
    assert AwsVectors.present?(), AwsVectors.absent_message()
  end

  # sabotage: set the unzipped manifest.json's version to 3 - red, the
  # header no longer reads version 2.
  test "the manifest is an awses-decrypt version 2 manifest of 9089 tests" do
    manifest = AwsVectors.manifest!()

    assert manifest["manifest"] == %{"type" => "awses-decrypt", "version" => 2}
    assert manifest["keys"] == "file://keys.json"
    assert map_size(manifest["tests"]) == 9089
  end

  # The keys are published test keys, but key-shaped all the same: the
  # assertions compare the header and a count, so a failure never prints one.
  #
  # sabotage: deleted one entry from the unzipped keys.json - red, 30 keys
  # against the literal 31.
  test "the keys file the manifest names is a version 3 keys file of 31 keys" do
    keys = AwsVectors.keys!(AwsVectors.manifest!())

    assert keys["manifest"] == %{"type" => "keys", "version" => 3}
    assert map_size(keys["keys"]) == 31
  end
end
