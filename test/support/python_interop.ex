defmodule Encryptor.PythonInterop do
  @moduledoc """
  Runs the AWS Encryption SDK for Python against this package's messages.

  `Encryptor.PythonInteropTest` is the test; this module finds the Python
  interpreter, holds the run's generated test keys, and runs
  `test/interop/python/interop.py`. CI's `python-interop` job installs Python
  3.12 and `test/interop/python/requirements.txt` (every package pinned by
  version and sha256), sets the two variables below, and runs
  `mix test --only python_interop`. Locally the tag is excluded by default.

  To run it by hand, from the repository root, with any Python 3.12 (with
  mise: `mise exec python@3.12 -- python3`):

      python3 -m venv /tmp/encryptor-interop
      /tmp/encryptor-interop/bin/python -m pip install --require-hashes -r test/interop/python/requirements.txt
      ENCRYPTOR_INTEROP_PYTHON=/tmp/encryptor-interop/bin/python mix test --only python_interop

  `ENCRYPTOR_INTEROP_PYTHON` names the interpreter the requirements are
  installed into. With `ENCRYPTOR_REQUIRE_PYTHON_INTEROP=1` (CI sets it) an
  absent interpreter fails the tagged tests instead of skipping them.

  No AWS account, credential or network call is involved: both sides use a
  raw AES keyring. The Python process is started with every `AWS_` variable
  removed from its environment, and the script refuses to run if one is set.

  The keys are generated for each run (`generate_keys/0`) and never written
  anywhere but the run's temporary directory, which the test deletes.
  """

  @script Path.expand("../interop/python/interop.py", __DIR__)

  @doc "The Python script the test runs."
  @spec script() :: String.t()
  def script, do: @script

  @doc "The interpreter `ENCRYPTOR_INTEROP_PYTHON` names, if any."
  @spec python() :: String.t() | nil
  def python do
    case System.get_env("ENCRYPTOR_INTEROP_PYTHON") do
      nil -> nil
      "" -> nil
      path -> path
    end
  end

  @doc "Whether the named interpreter is on disk."
  @spec present?() :: boolean()
  def present? do
    case python() do
      nil -> false
      path -> File.regular?(path)
    end
  end

  @doc "Whether an absent interpreter must fail rather than skip."
  @spec required?() :: boolean()
  def required?, do: System.get_env("ENCRYPTOR_REQUIRE_PYTHON_INTEROP") == "1"

  @doc "The message an absent interpreter is reported with."
  @spec absent_message() :: String.t()
  def absent_message do
    "no Python interpreter for the interop test (ENCRYPTOR_INTEROP_PYTHON is unset or names no file); " <>
      "the moduledoc of Encryptor.PythonInterop (test/support/python_interop.ex) says how to set one up"
  end

  @doc """
  Generates this run's test keys and hands them to the interop vaults.

  Thirty-two random bytes each, from `:crypto.strong_rand_bytes/1`: the
  wrapping key both SDKs' raw AES keyrings use, and the reference subkey the
  `:scoped` vaults derive `scope_ref` under.
  """
  @spec generate_keys() :: :ok
  def generate_keys do
    :persistent_term.put({__MODULE__, :wrapping_key}, :crypto.strong_rand_bytes(32))
    :persistent_term.put({__MODULE__, :reference_subkey}, :crypto.strong_rand_bytes(32))
  end

  @doc "One of this run's generated keys. Never rendered by a test."
  @spec key(:wrapping_key | :reference_subkey) :: binary()
  def key(name) when name in [:wrapping_key, :reference_subkey],
    do: :persistent_term.get({__MODULE__, name})

  @doc """
  Runs the script in `mode` over `dir` and returns its decoded `results.json`.

  The script's output is returned on a non-zero exit; it carries outcome words
  and exception text, never a key or a plaintext.
  """
  @spec run(String.t(), String.t()) :: {:ok, map()} | {:error, {integer(), String.t()}}
  def run(mode, dir) when mode in ["decrypt", "encrypt"] do
    aws_unset =
      for {name, _} <- System.get_env(), String.starts_with?(name, "AWS_"), do: {name, nil}

    case System.cmd(python(), [@script, mode, dir], stderr_to_stdout: true, env: aws_unset) do
      {_output, 0} -> {:ok, dir |> Path.join("results.json") |> File.read!() |> Jason.decode!()}
      {output, status} -> {:error, {status, output}}
    end
  end
end

defmodule Encryptor.InteropVaults do
  @moduledoc """
  The four vaults `Encryptor.PythonInteropTest` drives: `:single` and
  `:scoped`, each at suite 0x0478 and 0x0578.

  Every one resolves through `Encryptor.Provider.Static` to the run's one
  generated wrapping key (`Encryptor.PythonInterop.key/1`), under the
  namespace and name the Python side's raw AES keyring is given. `Static`
  resolves every scope to that same key, so a `:scoped` vault differs from a
  `:single` one only in what it writes into the encryption context: the
  `scope_ref` it injects and requires.
  """

  @namespace "interop"
  @name "interop/v1"

  @doc "The key namespace both sides' raw AES keyrings use."
  @spec namespace() :: String.t()
  def namespace, do: @namespace

  @doc "The key name both sides' raw AES keyrings use."
  @spec name() :: String.t()
  def name, do: @name

  @doc false
  @spec init(keyword(), :single | :scoped) :: {:ok, keyword()}
  def init(config, profile) do
    provider =
      {Encryptor.Provider.Static,
       key: Encryptor.PythonInterop.key(:wrapping_key), namespace: @namespace, name: @name}

    config = Keyword.put(config, :provider, provider)

    case profile do
      :single ->
        {:ok, config}

      :scoped ->
        {:ok,
         Keyword.put(config, :reference_subkey, Encryptor.PythonInterop.key(:reference_subkey))}
    end
  end
end

for {vault, profile, suite} <- [
      {Encryptor.InteropVaults.Single0478, :single, 0x0478},
      {Encryptor.InteropVaults.Single0578, :single, 0x0578},
      {Encryptor.InteropVaults.Scoped0478, :scoped, 0x0478},
      {Encryptor.InteropVaults.Scoped0578, :scoped, 0x0578}
    ] do
  defmodule vault do
    @moduledoc false
    use Encryptor.Vault, otp_app: :encryptor, context_profile: profile, algorithm_suite_id: suite

    @profile profile
    @impl Encryptor.Vault
    def init(config), do: Encryptor.InteropVaults.init(config, @profile)
  end
end
