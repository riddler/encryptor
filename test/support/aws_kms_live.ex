defmodule Encryptor.AwsKmsLive do
  @moduledoc """
  Runs `Encryptor.Provider.Kms` against a live AWS KMS test key.

  `Encryptor.Provider.KmsLiveTest` is the test; this module reads the key's
  ARN and the credentials from the environment, defines the vault the test
  drives, and records which KMS call answered which status. CI's
  `aws-kms-integration` job assumes a role through GitHub's OIDC provider,
  sets the variables below, and runs `mix test --only aws_kms_integration`.
  Locally the tag is excluded by default; `guides/live-kms-suites.md` says
  how a maintainer runs it.

    * `KMS_KEY_ARN` - the ARN of a symmetric KMS key the credentials may call
      `GenerateDataKey` and `Decrypt` on, in the form
      `arn:aws:kms:<region>:<account>:key/<key id>`.
    * `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` - the credentials.
    * `AWS_SESSION_TOKEN` - the session token temporary credentials carry
      (an assumed role's always do). Sent only when set and non-empty.
    * `AWS_REGION`, else `AWS_DEFAULT_REGION` - the key's region. Unset, it
      is `us-east-1`.

  With `KMS_KEY_ARN` unset or empty the tagged tests are skipped; with
  `ENCRYPTOR_REQUIRE_AWS_KMS=1` (CI sets it) they fail instead.

  ## Why the KMS client is this module's own

  `Encryptor.Provider.Kms` takes either `:region`, which builds the engine's
  shipped `ExAws` client, or `:client`, a host's own
  `AwsEncryptionSdk.Keyring.KmsClient`. This package declares no AWS
  dependency, and its own tests pin that (`Encryptor.Provider.KmsTest`,
  "refuses the shipped client when the optional dependency is absent" and
  "it declares no AWS dependency of its own"), so the shipped client is not
  in this build. `Encryptor.AwsKmsLive.Client` is the host-supplied shape:
  the three KMS calls the engine makes, signed with Signature Version 4 and
  sent through `Finch`, which this build already carries for `Goth`.

  ## Never in the output

  The key's ARN arrives as a CI secret, and a CI log masks a secret only as
  a whole string. A piece of it (the account, the key id) would print in
  clear, and so would a credential, the material a data key unwraps to, or
  a KMS error message, which can name the key and the caller's role. Nothing
  here renders any of them: the client reads the credentials from the
  environment at each call and never holds them, a KMS error is reduced to
  its error type, and a failure message carries a call kind, an HTTP status
  or a reason tag, never a URL, an ARN, a context, a ciphertext or a key.
  """

  @finch __MODULE__.Finch

  @key_arn ~r"\Aarn:aws[a-z-]*:kms:[a-z0-9-]+:[0-9]{12}:key/[A-Za-z0-9-]+\z"

  @doc "The HTTP pool's name."
  @spec finch() :: atom()
  def finch, do: @finch

  @doc "Whether the key's ARN is set."
  @spec present?() :: boolean()
  def present?, do: env("KMS_KEY_ARN") != nil

  @doc "Whether an absent key ARN must fail rather than skip."
  @spec required?() :: boolean()
  def required?, do: System.get_env("ENCRYPTOR_REQUIRE_AWS_KMS") == "1"

  @doc "The message an absent key ARN is reported with."
  @spec absent_message() :: String.t()
  def absent_message do
    "KMS_KEY_ARN is unset; the moduledoc of Encryptor.AwsKmsLive " <>
      "(test/support/aws_kms_live.ex) and guides/live-kms-suites.md say how to run the suite"
  end

  @doc """
  The test key's ARN.

  Answers `{:error, message}` when `KMS_KEY_ARN` is unset or not a KMS key
  ARN; the message names the variable and never its value.
  """
  @spec key_arn() :: {:ok, String.t()} | {:error, String.t()}
  def key_arn do
    case env("KMS_KEY_ARN") do
      nil ->
        {:error, "KMS_KEY_ARN is unset"}

      value ->
        if Regex.match?(@key_arn, value),
          do: {:ok, value},
          else: {:error, "KMS_KEY_ARN is not the ARN of a KMS key"}
    end
  end

  @doc """
  Checks that the credentials are in the environment, naming what is
  missing and never a value.
  """
  @spec credentials() :: :ok | {:error, String.t()}
  def credentials do
    case Enum.reject(["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"], &env/1) do
      [] -> :ok
      missing -> {:error, Enum.join(missing, " and ") <> " unset; no credentials"}
    end
  end

  @doc "The region the key is in: `AWS_REGION`, else `AWS_DEFAULT_REGION`, else `us-east-1`."
  @spec region() :: String.t()
  def region, do: env("AWS_REGION") || env("AWS_DEFAULT_REGION") || "us-east-1"

  @doc "The children the suite starts: the HTTP pool."
  @spec children() :: [Supervisor.child_spec() | {module(), keyword()}]
  def children, do: [{Finch, name: @finch}]

  @doc """
  Every call the KMS client made since the last read, oldest first, as
  `{kind, status}`: the kind is `:generate_data_key`, `:encrypt` or
  `:decrypt`, the status an HTTP status or `:transport` when the request did
  not complete.
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

  @doc false
  def env(name) do
    case System.get_env(name) do
      nil -> nil
      "" -> nil
      value -> value
    end
  end
end

defmodule Encryptor.AwsKmsLive.Client do
  @moduledoc """
  An `AwsEncryptionSdk.Keyring.KmsClient` for the live suite: `GenerateDataKey`,
  `Encrypt` and `Decrypt` on the AWS KMS JSON API, signed with Signature
  Version 4 and sent through `Finch`.

  The struct holds the region and nothing else. The credentials are read
  from the environment at each call (`AWS_ACCESS_KEY_ID`,
  `AWS_SECRET_ACCESS_KEY`, and `AWS_SESSION_TOKEN` when it is set and
  non-empty), so no descriptor, state or error the vault builds around this
  client can carry one.

  Each call is reported to the calling process as a call kind and a status
  (`Encryptor.AwsKmsLive.calls/0`). A refusal comes back as the engine's
  `{:kms_error, type, message}`, with the error type KMS named and that
  type's name as the message: KMS's own message can name the key and the
  caller, so it is dropped.
  """

  @behaviour AwsEncryptionSdk.Keyring.KmsClient

  alias Encryptor.AwsKmsLive

  defstruct [:region]

  @type t :: %__MODULE__{region: String.t()}

  @service "kms"
  @content_type "application/x-amz-json-1.1"
  @timeout 15_000

  @doc "A client for one region."
  @spec new(String.t()) :: t()
  def new(region) when is_binary(region), do: %__MODULE__{region: region}

  @impl true
  def generate_data_key(%__MODULE__{} = client, key_id, bytes, context, grant_tokens) do
    body =
      %{"KeyId" => key_id, "NumberOfBytes" => bytes}
      |> with_context(context, grant_tokens)

    with {:ok, response} <- call(client, :generate_data_key, "GenerateDataKey", body) do
      {:ok,
       %{
         plaintext: Base.decode64!(response["Plaintext"]),
         ciphertext: Base.decode64!(response["CiphertextBlob"]),
         key_id: response["KeyId"]
       }}
    end
  end

  @impl true
  def encrypt(%__MODULE__{} = client, key_id, plaintext, context, grant_tokens) do
    body =
      %{"KeyId" => key_id, "Plaintext" => Base.encode64(plaintext)}
      |> with_context(context, grant_tokens)

    with {:ok, response} <- call(client, :encrypt, "Encrypt", body) do
      {:ok, %{ciphertext: Base.decode64!(response["CiphertextBlob"]), key_id: response["KeyId"]}}
    end
  end

  @impl true
  def decrypt(%__MODULE__{} = client, key_id, ciphertext, context, grant_tokens) do
    body =
      %{"KeyId" => key_id, "CiphertextBlob" => Base.encode64(ciphertext)}
      |> with_context(context, grant_tokens)

    with {:ok, response} <- call(client, :decrypt, "Decrypt", body) do
      {:ok, %{plaintext: Base.decode64!(response["Plaintext"]), key_id: response["KeyId"]}}
    end
  end

  defp with_context(body, context, grant_tokens) do
    body
    |> then(&if map_size(context) > 0, do: Map.put(&1, "EncryptionContext", context), else: &1)
    |> then(&if grant_tokens != [], do: Map.put(&1, "GrantTokens", grant_tokens), else: &1)
  end

  defp call(%__MODULE__{region: region}, kind, operation, body) do
    host = "kms.#{region}.amazonaws.com"
    payload = JSON.encode!(body)

    headers =
      signed_headers(
        "POST",
        "/",
        "",
        [
          {"content-type", @content_type},
          {"host", host},
          {"x-amz-target", "TrentService." <> operation}
        ],
        payload,
        region,
        @service,
        DateTime.utc_now()
      )

    response =
      :post
      |> Finch.build("https://" <> host <> "/", headers, payload)
      |> Finch.request(AwsKmsLive.finch(), receive_timeout: @timeout)

    AwsKmsLive.record(kind, status(response))

    case response do
      {:ok, %Finch.Response{status: 200, body: body}} ->
        {:ok, JSON.decode!(body)}

      {:ok, %Finch.Response{status: status, body: body}} ->
        {:error, refusal(status, body)}

      {:error, _exception} ->
        {:error, {:connection_error, :request_failed}}
    end
  end

  defp status({:ok, %Finch.Response{status: status}}), do: status
  defp status({:error, _exception}), do: :transport

  # KMS answers `{"__type": "...InvalidCiphertextException", "message": ...}`.
  # Only the type is kept, in the engine's `ExAws` client's spelling
  # (`:invalid_ciphertext`); the message can name the key and the caller.
  defp refusal(status, body) do
    with {:ok, %{"__type" => type}} when is_binary(type) <- JSON.decode(body),
         name = type |> String.split("#") |> List.last(),
         true <- Regex.match?(~r/\A[A-Za-z]+\z/, name) do
      atom = name |> String.replace_suffix("Exception", "") |> Macro.underscore()
      {:kms_error, String.to_atom(atom), name}
    else
      _other -> {:http_error, status, "unreadable error body"}
    end
  end

  @doc false
  # Signature Version 4 over one request: answers the request's headers with
  # `x-amz-date`, the session token when one is set, and `authorization`
  # added. Public so a check against AWS's published example can reach it;
  # the credentials are read here and returned only inside the signature
  # header.
  @spec signed_headers(
          String.t(),
          String.t(),
          String.t(),
          [{String.t(), String.t()}],
          binary(),
          String.t(),
          String.t(),
          DateTime.t()
        ) :: [{String.t(), String.t()}]
  def signed_headers(method, path, query, headers, payload, region, service, now) do
    access_key_id = AwsKmsLive.env("AWS_ACCESS_KEY_ID") || ""
    secret = AwsKmsLive.env("AWS_SECRET_ACCESS_KEY") || ""
    amz_date = Calendar.strftime(now, "%Y%m%dT%H%M%SZ")
    date = binary_part(amz_date, 0, 8)

    token =
      case AwsKmsLive.env("AWS_SESSION_TOKEN") do
        nil -> []
        value -> [{"x-amz-security-token", value}]
      end

    headers = Enum.sort([{"x-amz-date", amz_date} | token] ++ headers)
    names = Enum.map_join(headers, ";", &elem(&1, 0))
    canonical_headers = Enum.map_join(headers, "", fn {name, value} -> "#{name}:#{value}\n" end)

    canonical_request =
      Enum.join([method, path, query, canonical_headers, names, hex_sha256(payload)], "\n")

    scope = "#{date}/#{region}/#{service}/aws4_request"

    string_to_sign =
      Enum.join(["AWS4-HMAC-SHA256", amz_date, scope, hex_sha256(canonical_request)], "\n")

    signature =
      ("AWS4" <> secret)
      |> hmac(date)
      |> hmac(region)
      |> hmac(service)
      |> hmac("aws4_request")
      |> hmac(string_to_sign)
      |> Base.encode16(case: :lower)

    authorization =
      "AWS4-HMAC-SHA256 Credential=#{access_key_id}/#{scope}, " <>
        "SignedHeaders=#{names}, Signature=#{signature}"

    headers ++ [{"authorization", authorization}]
  end

  defp hmac(key, data), do: :crypto.mac(:hmac, :sha256, key, data)
  defp hex_sha256(data), do: :sha256 |> :crypto.hash(data) |> Base.encode16(case: :lower)
end

defmodule Encryptor.AwsKmsLive.Vault do
  @moduledoc """
  The vault the live suite drives: `:scoped`, its provider
  `Encryptor.Provider.Kms` on the one test key (the selector-ignoring
  `:key_id` shape) behind `Encryptor.AwsKmsLive.Client`.

  `cache: false`, so every operation reaches KMS: a cached data key is a
  call that did not happen, and the suite asserts on the calls. The
  reference subkey is fresh per start.
  """

  use Encryptor.Vault, otp_app: :encryptor, context_profile: :scoped, cache: false

  alias Encryptor.AwsKmsLive
  alias Encryptor.AwsKmsLive.Client

  @doc "Layer 5: the provider on the test key, and a fresh reference subkey."
  def init(config) do
    {:ok, key_arn} = AwsKmsLive.key_arn()

    {:ok,
     config
     |> Keyword.put(
       :provider,
       {Encryptor.Provider.Kms, client: Client.new(AwsKmsLive.region()), key_id: key_arn}
     )
     |> Keyword.put(:reference_subkey, :crypto.strong_rand_bytes(32))}
  end
end
