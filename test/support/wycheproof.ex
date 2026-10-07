defmodule Encryptor.Wycheproof do
  @moduledoc """
  Reads the Wycheproof vector files kept under `test/fixtures/wycheproof/`.

  The files are copied byte for byte from C2SP/wycheproof at the commit the
  directory's README names; this module only decodes them. It filters
  nothing: `cases/1` returns every case of every test group, so a test that
  counts what it gets back counts the file.
  """

  # Jason is not a direct dependency: it arrives through aws_encryption_sdk,
  # which requires it at runtime, so the test build always has it.
  @dir Path.expand("../fixtures/wycheproof", __DIR__)

  @doc "Decodes one vector file from the fixtures directory by its file name."
  @spec load!(String.t()) :: map()
  def load!(file) do
    @dir
    |> Path.join(file)
    |> File.read!()
    |> Jason.decode!()
  end

  @doc "Every case of every test group in a decoded vector file, in file order."
  @spec cases(map()) :: [map()]
  def cases(%{"testGroups" => groups}) do
    Enum.flat_map(groups, fn %{"tests" => tests} -> tests end)
  end

  @doc "Decodes a lowercase hex field of a vector case."
  @spec hex!(String.t()) :: binary()
  def hex!(field), do: Base.decode16!(field, case: :lower)
end
