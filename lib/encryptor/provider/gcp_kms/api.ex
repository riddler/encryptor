defmodule Encryptor.Provider.GcpKms.Api do
  @moduledoc false

  # The three Cloud KMS v1 REST calls `Encryptor.Provider.GcpKms` makes, and
  # nothing else.
  #
  # It is deliberately thin: build a URL, ask the host's token server for a
  # bearer token, ask the host's HTTP client to make the request, and map the
  # status code onto this package's closed reason vocabulary. Every decision
  # about *what* to call and *what to bind it to* is the provider's; this
  # module only knows how to speak to the service.
  #
  # ## Why the transport is the host's
  #
  # ADR-0007 decision 9: `goth` and an HTTP client are optional dependencies,
  # and the package will not pick between `finch`, `req` and `hackney` for a
  # host that already runs one. So both arrive as modules named in `init/1`
  # and validated at start, which is also what makes every call here fakeable
  # without a network - the provider's tests substitute a module at the HTTP
  # boundary rather than an internal seam.
  #
  # ## Never in an error term
  #
  # A bearer token is credential material and a plaintext key travels through
  # `encrypt/4`. Neither is ever put in a returned term, and the failure this
  # module returns to the provider carries a status code or a shape tag, never
  # a response body.

  @base_url "https://cloudkms.googleapis.com/v1"

  @typedoc false
  @type state :: map()

  @typedoc false
  @type failure ::
          {:http_status, non_neg_integer()}
          | {:transport, :request_failed}
          | {:token, :unavailable}
          | {:malformed_response, atom()}

  @doc false
  # ADR-0007 decision 3: `CreateCryptoKey` against a `KeyRing` that already
  # exists, `ENCRYPT_DECRYPT`, no rotation schedule (decision 7), protection
  # level from configuration.
  #
  # `ALREADY_EXISTS` is `{:ok, :exists}` rather than a failure: decision 6
  # makes a repeated mint for one selector find this tenant's own key and
  # continue, which is what makes a half-succeeded provision retryable.
  @spec create_crypto_key(state(), String.t()) ::
          {:ok, :created | :exists} | {:error, failure()}
  def create_crypto_key(state, key_id) do
    body = %{
      "purpose" => "ENCRYPT_DECRYPT",
      "versionTemplate" => %{"protectionLevel" => protection_level(state)}
    }

    case post(state, ring_url(state) <> "/cryptoKeys?cryptoKeyId=" <> key_id, body) do
      {:ok, _decoded} -> {:ok, :created}
      {:error, {:http_status, 409}} -> {:ok, :exists}
      {:error, failure} -> {:error, failure}
    end
  end

  @doc false
  # ADR-0007 decision 5: the additional authenticated data is the encoded
  # binding and is never optional.
  @spec encrypt(state(), String.t(), binary(), binary()) ::
          {:ok, binary()} | {:error, failure()}
  def encrypt(state, key_id, plaintext, aad) do
    body = %{
      "plaintext" => Base.encode64(plaintext),
      "additionalAuthenticatedData" => Base.encode64(aad)
    }

    with {:ok, decoded} <- post(state, key_url(state, key_id) <> ":encrypt", body) do
      decode_field(decoded, "ciphertext")
    end
  end

  @doc false
  @spec decrypt(state(), String.t(), binary(), binary()) ::
          {:ok, binary()} | {:error, failure()}
  def decrypt(state, key_id, ciphertext, aad) do
    body = %{
      "ciphertext" => Base.encode64(ciphertext),
      "additionalAuthenticatedData" => Base.encode64(aad)
    }

    with {:ok, decoded} <- post(state, key_url(state, key_id) <> ":decrypt", body) do
      decode_field(decoded, "plaintext")
    end
  end

  @doc false
  # The resource name of a tenant's `CryptoKey`, for an operator's runbook and
  # for the provider's own moduledoc. Nothing calls GCP with it here: ADR-0007
  # decision 8 leaves `DestroyCryptoKeyVersion` to the host's runbook and open
  # question 5 leaves whether this package should ever offer it undecided.
  @spec key_name(state(), String.t()) :: String.t()
  def key_name(state, key_id) do
    "projects/#{state.project}/locations/#{state.location}" <>
      "/keyRings/#{state.key_ring}/cryptoKeys/#{key_id}"
  end

  @spec ring_url(state()) :: String.t()
  defp ring_url(state) do
    "#{@base_url}/projects/#{state.project}/locations/#{state.location}" <>
      "/keyRings/#{state.key_ring}"
  end

  @spec key_url(state(), String.t()) :: String.t()
  defp key_url(state, key_id), do: ring_url(state) <> "/cryptoKeys/" <> key_id

  @spec protection_level(state()) :: String.t()
  defp protection_level(%{protection_level: :hsm}), do: "HSM"
  defp protection_level(%{protection_level: :software}), do: "SOFTWARE"

  @spec post(state(), String.t(), map()) :: {:ok, map()} | {:error, failure()}
  defp post(state, url, body) do
    with {:ok, token} <- token(state) do
      headers = [
        {"authorization", "Bearer " <> token},
        {"content-type", "application/json"}
      ]

      state.http_client
      |> request(url, headers, JSON.encode!(body), state.timeout)
      |> handle(url)
    end
  end

  @spec request(module(), String.t(), list(), binary(), pos_integer()) :: term()
  defp request(http_client, url, headers, body, timeout) do
    http_client.request(:post, url, headers, body, timeout: timeout)
  end

  @spec handle(term(), String.t()) :: {:ok, map()} | {:error, failure()}
  defp handle({:ok, %{status: status, body: body}}, _url) when status in 200..299 do
    case JSON.decode(body) do
      {:ok, decoded} when is_map(decoded) -> {:ok, decoded}
      _other -> {:error, {:malformed_response, :not_a_json_object}}
    end
  end

  defp handle({:ok, %{status: status}}, _url), do: {:error, {:http_status, status}}
  defp handle({:error, _reason}, _url), do: {:error, {:transport, :request_failed}}
  defp handle(_other, _url), do: {:error, {:malformed_response, :not_a_response}}

  # The response field is base64 per the KMS REST encoding. A field that is
  # absent or not decodable is a malformed response and never a usable key.
  @spec decode_field(map(), String.t()) :: {:ok, binary()} | {:error, failure()}
  defp decode_field(decoded, field) do
    case Map.fetch(decoded, field) do
      {:ok, encoded} when is_binary(encoded) ->
        case Base.decode64(encoded) do
          {:ok, bytes} -> {:ok, bytes}
          :error -> {:error, {:malformed_response, :not_base64}}
        end

      _other ->
        {:error, {:malformed_response, :missing_field}}
    end
  end

  # ADR-0007 decision 9: the token server is the host's, named in `init/1`.
  # `goth: MyApp.Goth` names a running `Goth` server; `goth: {module, name}`
  # names any module exporting `fetch/1` with Goth's return shape, which is
  # what lets this call be exercised without credentials or a network.
  @spec token(state()) :: {:ok, String.t()} | {:error, failure()}
  defp token(%{goth: {module, name}}), do: fetch_token(module, name)
  defp token(%{goth: name}), do: fetch_token(Goth, name)

  @spec fetch_token(module(), term()) :: {:ok, String.t()} | {:error, failure()}
  defp fetch_token(module, name) do
    case module.fetch(name) do
      {:ok, %{token: token}} when is_binary(token) -> {:ok, token}
      _other -> {:error, {:token, :unavailable}}
    end
  end
end
