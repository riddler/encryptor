defmodule Encryptor.GcpKmsLive do
  @moduledoc """
  Runs `Encryptor.Provider.GcpKms` against a live Cloud KMS test key.

  `Encryptor.Provider.GcpKmsLiveTest` is the test; this module reads the two
  key names from the environment, finds the credentials, starts the token
  server and the HTTP pool, and records which Cloud KMS call answered which
  status. CI's `gcp-kms-integration` job authenticates with Workload Identity
  Federation, sets the variables below, and runs
  `mix test --only gcp_kms_integration`. Locally the tag is excluded by
  default; `guides/live-kms-suites.md` says how a maintainer runs it.

    * `GCP_KMS_KEY` - the resource name of a `CryptoKey` the credentials may
      encrypt and decrypt with, in the form
      `projects/*/locations/*/keyRings/*/cryptoKeys/*`.
    * `GCP_KMS_DENIED_KEY` - the resource name of a `CryptoKey` the
      credentials hold no grant on, in the same form.
    * `GOOGLE_APPLICATION_CREDENTIALS` - a credentials file. Unset, the
      gcloud CLI's Application Default Credentials file is read instead.

  With either key name unset or empty the tagged tests are skipped; with
  `ENCRYPTOR_REQUIRE_GCP_KMS=1` (CI sets it) they fail instead.

  Every provider state built here pins `:key_id_fun` to the test key's own
  id, so a provision's `CreateCryptoKey` names a key that already exists and
  never mints a new one: a `CryptoKey` cannot be deleted.

  ## Never in the output

  The key names arrive as CI secrets, and a CI log masks a secret only as a
  whole string. The pieces this module splits out of a name (a project, a
  location, a key ring, a key id) would print in clear, and so would the
  material a key unwraps to. Nothing here renders either: a failure message
  carries a call kind, an HTTP status or a reason term, never a URL, a name,
  a state, a row or a key.
  """

  @goth __MODULE__.Goth
  @finch __MODULE__.Finch

  @key_name ~r{\Aprojects/([^/]+)/locations/([^/]+)/keyRings/([^/]+)/cryptoKeys/([^/]+)\z}

  @doc "The token server's name, as the provider's `:goth` option takes it."
  @spec goth() :: atom()
  def goth, do: @goth

  @doc "The HTTP pool's name."
  @spec finch() :: atom()
  def finch, do: @finch

  @doc "Whether both key names are set."
  @spec present?() :: boolean()
  def present?, do: Enum.all?(["GCP_KMS_KEY", "GCP_KMS_DENIED_KEY"], &(env(&1) != nil))

  @doc "Whether absent key names must fail rather than skip."
  @spec required?() :: boolean()
  def required?, do: System.get_env("ENCRYPTOR_REQUIRE_GCP_KMS") == "1"

  @doc "The message absent key names are reported with."
  @spec absent_message() :: String.t()
  def absent_message do
    "GCP_KMS_KEY or GCP_KMS_DENIED_KEY is unset; the moduledoc of Encryptor.GcpKmsLive " <>
      "(test/support/gcp_kms_live.ex) and guides/live-kms-suites.md say how to run the suite"
  end

  @doc """
  The named variable's `CryptoKey`, split into the provider's options.

  Answers `{:error, message}` when the variable is unset or not a `CryptoKey`
  resource name; the message names the variable and never its value.
  """
  @spec key(String.t()) ::
          {:ok,
           %{project: String.t(), location: String.t(), key_ring: String.t(), key_id: String.t()}}
          | {:error, String.t()}
  def key(variable) do
    with {:set, value} <- {:set, env(variable)},
         [_whole, project, location, key_ring, key_id] <- Regex.run(@key_name, value) do
      {:ok, %{project: project, location: location, key_ring: key_ring, key_id: key_id}}
    else
      {:set, nil} ->
        {:error, "#{variable} is unset"}

      nil ->
        {:error,
         "#{variable} is not a CryptoKey resource name " <>
           "(projects/*/locations/*/keyRings/*/cryptoKeys/*)"}
    end
  end

  @doc """
  The token source the credentials file describes, in `Goth`'s terms.

  `GOOGLE_APPLICATION_CREDENTIALS` names the file; unset, the gcloud CLI's
  Application Default Credentials file is read. An `external_account` file
  (what Workload Identity Federation writes) is `Goth`'s
  `:workload_identity` source, an `authorized_user` file its
  `:refresh_token` source, a `service_account` file its `:service_account`
  source. The file's contents are never put in the message.
  """
  @spec token_source() :: {:ok, tuple()} | {:error, String.t()}
  def token_source do
    path =
      env("GOOGLE_APPLICATION_CREDENTIALS") ||
        Path.expand("~/.config/gcloud/application_default_credentials.json")

    with {:ok, contents} <- read(path),
         {:ok, %{} = credentials} <- decode(contents) do
      case credentials["type"] do
        "external_account" -> {:ok, {:workload_identity, credentials}}
        "authorized_user" -> {:ok, {:refresh_token, credentials}}
        "service_account" -> {:ok, {:service_account, credentials}}
        _other -> {:error, "the credentials file is of a type this suite does not read"}
      end
    end
  end

  @doc """
  The children the suite starts: an HTTP pool and a `Goth` server.

  The `Goth` server's retry delay is an hour, so a token it cannot fetch is
  answered as an error to the provider (which reads it as
  `{:token, :unavailable}`) and never retried into the crash `Goth` raises
  after its last retry: that crash's message carries the token endpoint's
  response body.
  """
  @spec children(tuple()) :: [Supervisor.child_spec()]
  def children(source) do
    [
      {Finch, name: @finch},
      {Goth,
       name: @goth,
       source: source,
       prefetch: :sync,
       max_retries: 1_000,
       retry_delay: fn _attempt -> :timer.hours(1) end}
    ]
  end

  @doc """
  Every call the HTTP client made since the last read, oldest first, as
  `{kind, status}`: the kind is `:create`, `:encrypt` or `:decrypt`, the
  status an HTTP status or `:transport` when the request did not complete.
  """
  @spec calls() :: [{atom(), non_neg_integer() | :transport}]
  def calls, do: drain([])

  defp drain(acc) do
    receive do
      {__MODULE__, :call, kind, status} -> drain([{kind, status} | acc])
    after
      0 -> Enum.reverse(acc)
    end
  end

  @doc false
  def record(kind, status), do: send(self(), {__MODULE__, :call, kind, status})

  defp env(name) do
    case System.get_env(name) do
      nil -> nil
      "" -> nil
      value -> value
    end
  end

  defp read(path) do
    case File.read(path) do
      {:ok, contents} ->
        {:ok, contents}

      {:error, _reason} ->
        {:error,
         "no credentials: set GOOGLE_APPLICATION_CREDENTIALS, or run " <>
           "`gcloud auth application-default login`"}
    end
  end

  defp decode(contents) do
    case JSON.decode(contents) do
      {:ok, %{} = credentials} -> {:ok, credentials}
      _other -> {:error, "the credentials file is not a JSON object"}
    end
  end
end

defmodule Encryptor.GcpKmsLive.Http do
  @moduledoc """
  The provider's HTTP client for the live suite: the five-line wrapper over
  `Finch` that `Encryptor.Provider.GcpKms`'s moduledoc asks a host for.

  It reports each call to the calling process as a call kind and a status
  (`Encryptor.GcpKmsLive.calls/0`), never the URL, which carries the key's
  resource name.
  """

  alias Encryptor.GcpKmsLive

  @doc false
  def request(method, url, headers, body, opts) do
    response =
      method
      |> Finch.build(url, headers, body)
      |> Finch.request(GcpKmsLive.finch(), receive_timeout: Keyword.fetch!(opts, :timeout))

    GcpKmsLive.record(kind(url), status(response))

    case response do
      {:ok, %Finch.Response{status: status, body: body}} -> {:ok, %{status: status, body: body}}
      {:error, _exception} -> {:error, :request_failed}
    end
  end

  defp kind(url) do
    cond do
      String.ends_with?(url, ":encrypt") -> :encrypt
      String.ends_with?(url, ":decrypt") -> :decrypt
      String.contains?(url, "cryptoKeyId=") -> :create
      true -> :other
    end
  end

  defp status({:ok, %Finch.Response{status: status}}), do: status
  defp status({:error, _exception}), do: :transport
end
