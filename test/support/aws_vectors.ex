defmodule Encryptor.AwsVectors do
  @moduledoc """
  Locates the AWS Encryption SDK's published decrypt vectors.

  The corpus is `vectors/awses-decrypt/python-2.3.0.zip` from
  awslabs/aws-encryption-sdk-test-vectors at commit
  b6a6c91e62cc67f891b5dc3d11b0f047d10baf76, unzipped into
  `test/fixtures/aws_vectors/python-2.3.0/`. That directory is git-ignored
  and never enters the package: CI's `aws-vectors` job fetches it at the pin,
  checks the zip's SHA-256 before unzipping, and runs
  `mix test --only aws_vectors`. Locally the tag is excluded by default.

  To fetch it by hand, from the repository root (`sha256sum -c` is
  `shasum -a 256 -c` on macOS):

      git init -q /tmp/aws-vectors
      git -C /tmp/aws-vectors fetch -q --depth 1 https://github.com/awslabs/aws-encryption-sdk-test-vectors.git b6a6c91e62cc67f891b5dc3d11b0f047d10baf76
      git -C /tmp/aws-vectors checkout -q FETCH_HEAD
      echo "99b01e3bd61dfec2fc945392a0e374f510d055229fe6bb8d14ef993527164b05  /tmp/aws-vectors/vectors/awses-decrypt/python-2.3.0.zip" | sha256sum -c -
      mkdir -p test/fixtures/aws_vectors
      unzip -q /tmp/aws-vectors/vectors/awses-decrypt/python-2.3.0.zip -d test/fixtures/aws_vectors/python-2.3.0

  The commit and the checksum are also in `.github/workflows/ci.yml`; move
  them together.

  With `ENCRYPTOR_REQUIRE_AWS_VECTORS=1` (CI sets it) an absent corpus fails
  the tagged tests instead of skipping them.
  """

  # Jason is not a direct dependency: it arrives through aws_encryption_sdk,
  # which requires it at runtime, so the test build always has it.
  @dir Path.expand("../fixtures/aws_vectors/python-2.3.0", __DIR__)

  @doc "The directory the unzipped corpus is read from."
  @spec dir() :: String.t()
  def dir, do: @dir

  @doc "Whether the corpus's manifest is on disk."
  @spec present?() :: boolean()
  def present?, do: File.regular?(Path.join(@dir, "manifest.json"))

  @doc "Whether an absent corpus must fail rather than skip."
  @spec required?() :: boolean()
  def required?, do: System.get_env("ENCRYPTOR_REQUIRE_AWS_VECTORS") == "1"

  @doc "The message an absent corpus is reported with."
  @spec absent_message() :: String.t()
  def absent_message do
    "the AWS Encryption SDK decrypt vectors are not at " <>
      Path.relative_to_cwd(@dir) <>
      "; the moduledoc of Encryptor.AwsVectors (test/support/aws_vectors.ex) says how to fetch them"
  end

  @doc "Decodes the corpus's `manifest.json`."
  @spec manifest!() :: map()
  def manifest!, do: read_json!("manifest.json")

  @doc "Decodes the keys file the manifest names (`file://keys.json`)."
  @spec keys!(map()) :: map()
  def keys!(%{"keys" => "file://" <> file}), do: read_json!(file)

  defp read_json!(file) do
    @dir
    |> Path.join(file)
    |> File.read!()
    |> Jason.decode!()
  end
end
