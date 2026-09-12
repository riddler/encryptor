defmodule Encryptor.GcpKms.Fake do
  @moduledoc "An in-memory Cloud KMS, spoken at the HTTP boundary."

  # An in-memory stand-in for Cloud KMS, spoken at the HTTP boundary.
  #
  # ADR-0007 decision 9 makes the HTTP client and the token server the host's
  # modules, named in `init/1`. That is what makes every GCP call in this
  # package fakeable without a network and without an internal seam: a test
  # configures a module here in the place a host configures `finch` or `req`.
  #
  # The fake is a real AEAD, not a stub that returns its input. The binding
  # ADR-0007 decision 5 encodes is only worth anything if a wrong AAD fails,
  # so the fake fails on a wrong AAD the way the service does.
  #
  # The wrapping key is derived from the `CryptoKey` id, so the fake holds no
  # state and every module below is safe in an `async: true` test.

  @iv_bytes 12
  @tag_bytes 16

  @doc false
  def request(:post, url, headers, body, _opts) do
    if authorized?(headers) do
      dispatch(url, JSON.decode!(body))
    else
      {:ok, %{status: 401, body: ~s({"error": "unauthenticated"})}}
    end
  end

  @doc false
  def ok(payload), do: {:ok, %{status: 200, body: JSON.encode!(payload)}}

  @doc false
  def key_id(url) do
    if String.contains?(url, "cryptoKeyId=") do
      url |> String.split("cryptoKeyId=") |> List.last()
    else
      url |> String.split("/cryptoKeys/") |> List.last() |> String.split(":") |> hd()
    end
  end

  @doc false
  def seal(key_id, plaintext, aad) do
    iv = :crypto.strong_rand_bytes(@iv_bytes)

    {ciphertext, tag} =
      :crypto.crypto_one_time_aead(:aes_256_gcm, kek(key_id), iv, plaintext, aad, true)

    iv <> tag <> ciphertext
  end

  @doc false
  def unseal(key_id, blob, aad) do
    case blob do
      <<iv::binary-size(@iv_bytes), tag::binary-size(@tag_bytes), ciphertext::binary>> ->
        :crypto.crypto_one_time_aead(:aes_256_gcm, kek(key_id), iv, ciphertext, aad, tag, false)

      _other ->
        :error
    end
  end

  defp dispatch(url, decoded) do
    cond do
      String.ends_with?(url, ":encrypt") -> encrypt(url, decoded)
      String.ends_with?(url, ":decrypt") -> decrypt(url, decoded)
      true -> ok(%{"name" => url, "purpose" => decoded["purpose"]})
    end
  end

  defp encrypt(url, decoded) do
    plaintext = Base.decode64!(decoded["plaintext"])
    aad = Base.decode64!(decoded["additionalAuthenticatedData"])

    ok(%{"ciphertext" => Base.encode64(seal(key_id(url), plaintext, aad))})
  end

  defp decrypt(url, decoded) do
    blob = Base.decode64!(decoded["ciphertext"])
    aad = Base.decode64!(decoded["additionalAuthenticatedData"])

    case unseal(key_id(url), blob, aad) do
      :error -> {:ok, %{status: 400, body: ~s({"error": "decryption failed"})}}
      plaintext -> ok(%{"plaintext" => Base.encode64(plaintext)})
    end
  end

  # A fixture wrapping key. Derived rather than configured so the fake holds
  # no state; it is still key-shaped, so it never reaches an assertion message.
  defp kek(key_id), do: :crypto.hash(:sha256, "fake-kek/" <> key_id)

  defp authorized?(headers) do
    Enum.any?(headers, fn {name, value} ->
      String.downcase(name) == "authorization" and String.starts_with?(value, "Bearer ")
    end)
  end
end

defmodule Encryptor.GcpKms.FakeKms do
  @moduledoc "A host HTTP client that answers like a working Cloud KMS."

  defdelegate request(method, url, headers, body, opts), to: Encryptor.GcpKms.Fake
end

defmodule Encryptor.GcpKms.ExistingKeyKms do
  @moduledoc "A client whose CreateCryptoKey answers ALREADY_EXISTS."

  # `CreateCryptoKey` on a key that is already there: ADR-0007 decision 6's
  # `ALREADY_EXISTS`, which is success for the create step.
  alias Encryptor.GcpKms.Fake

  def request(method, url, headers, body, opts) do
    if String.contains?(url, "cryptoKeyId=") do
      {:ok, %{status: 409, body: ~s({"error": "ALREADY_EXISTS"})}}
    else
      Fake.request(method, url, headers, body, opts)
    end
  end
end

defmodule Encryptor.GcpKms.UnreachableKms do
  @moduledoc "A client whose every request fails at the transport."

  def request(_method, _url, _headers, _body, _opts), do: {:error, :econnrefused}
end

defmodule Encryptor.GcpKms.ForbiddenKms do
  @moduledoc "A client whose every request is refused by IAM."

  # An IAM denial. ADR-0007's typespec section is deliberate that this is the
  # same fact to a caller as a timeout.
  def request(_method, _url, _headers, _body, _opts),
    do: {:ok, %{status: 403, body: ~s({"error": "PERMISSION_DENIED"})}}
end

defmodule Encryptor.GcpKms.GarbageKms do
  @moduledoc "A client answering 200 with a body that is not JSON."

  def request(_method, _url, _headers, _body, _opts),
    do: {:ok, %{status: 200, body: "not json at all"}}
end

defmodule Encryptor.GcpKms.EmptyBodyKms do
  @moduledoc "A client answering 200 with none of the fields the call needs."

  def request(_method, _url, _headers, _body, _opts),
    do: {:ok, %{status: 200, body: "{}"}}
end

defmodule Encryptor.GcpKms.NotBase64Kms do
  @moduledoc "A client answering 200 with fields that are not base64."

  def request(_method, _url, _headers, _body, _opts),
    do: {:ok, %{status: 200, body: ~s({"ciphertext": "!not base64!", "plaintext": "!nope!"})}}
end

defmodule Encryptor.GcpKms.NonsenseKms do
  @moduledoc "A client that does not answer with a result tuple at all."

  def request(_method, _url, _headers, _body, _opts), do: :something_else_entirely
end

defmodule Encryptor.GcpKms.ShortKeyKms do
  @moduledoc "A client whose Decrypt answers material of the wrong size."

  # Decrypts to sixteen bytes under a row that claims 256 bits.
  alias Encryptor.GcpKms.Fake

  def request(method, url, headers, body, opts) do
    if String.ends_with?(url, ":decrypt") do
      Fake.ok(%{"plaintext" => Base.encode64(:binary.copy(<<0>>, 16))})
    else
      Fake.request(method, url, headers, body, opts)
    end
  end
end

defmodule Encryptor.GcpKms.FakeToken do
  @moduledoc "A token server with Goth's return shape and no credentials."

  def fetch(_name), do: {:ok, %{token: "fake-bearer-token", type: "Bearer"}}
end

defmodule Encryptor.GcpKms.FailingToken do
  @moduledoc "A token server that cannot mint a token."

  def fetch(_name), do: {:error, :no_credentials}
end

defmodule Encryptor.GcpKmsCase do
  @moduledoc "The option list a host would configure, pointed at the fakes."

  # The option list a host would configure, with the transport pointed at the
  # fakes above.
  alias Encryptor.GcpKms.FakeKms
  alias Encryptor.GcpKms.FakeToken
  alias Encryptor.Provider.GcpKms

  @subkey :binary.copy(<<0x2B>>, 32)

  @doc false
  def subkey, do: @subkey

  @doc false
  def opts(overrides \\ []) do
    Keyword.merge(
      [
        project: "myapp-test",
        location: "us-east1",
        key_ring: "tenant-keys",
        reference_subkey: @subkey,
        http_client: FakeKms,
        goth: {FakeToken, :test_goth},
        store: fn _tenant_ref -> {:ok, []} end
      ],
      overrides
    )
  end

  @doc false
  def state(overrides \\ []) do
    {:ok, state} = GcpKms.init(opts(overrides))

    state
  end

  # Provisions a tenant and hands back the state and the row, which is what
  # every resolution test needs before it can resolve anything.
  @doc false
  def provisioned(selector, overrides \\ []) do
    state = state(overrides)
    {:ok, row} = GcpKms.provision(state, selector)

    {state, row}
  end
end

defmodule Encryptor.GcpKms.EchoKms do
  @moduledoc "A working client that reports each request to the calling process."

  alias Encryptor.GcpKms.Fake

  @doc false
  def request(method, url, headers, body, opts) do
    send(self(), {:kms_request, url, JSON.decode!(body), opts})

    Fake.request(method, url, headers, body, opts)
  end
end

defmodule Encryptor.GcpKms.EncryptFailsKms do
  @moduledoc "A client whose CreateCryptoKey succeeds and whose Encrypt does not."

  alias Encryptor.GcpKms.Fake

  @doc false
  def request(method, url, headers, body, opts) do
    if String.ends_with?(url, ":encrypt") do
      {:ok, %{status: 500, body: ~s({"error": "INTERNAL"})}}
    else
      Fake.request(method, url, headers, body, opts)
    end
  end
end

defmodule Encryptor.GcpKmsVaults do
  @moduledoc """
  Vaults for the vault-level `provision/1` of ADR-0007 decision 2.

  One tenant vault whose provider can provision, and one whose provider
  cannot, because `{:not_provisionable, module}` is the answer that has to be
  a settled term rather than an `UndefinedFunctionError`.
  """

  alias Encryptor.GcpKmsCase

  defmodule Tenant do
    @moduledoc "A tenant vault behind the GCP KMS wrap-provider."

    use Encryptor.Vault, otp_app: :encryptor, context_profile: :tenant, cache: false

    @doc "Layer 5: the provider and the reference subkey, both key material."
    def init(config) do
      {:ok,
       Keyword.merge(config,
         provider: {Encryptor.Provider.GcpKms, Encryptor.GcpKmsVaults.provider_opts()},
         reference_subkey: Encryptor.GcpKmsCase.subkey()
       )}
    end
  end

  defmodule NotProvisionable do
    @moduledoc "A single-key vault whose provider has no provision callback."

    use Encryptor.Vault, otp_app: :encryptor, context_profile: :single, cache: false

    @doc "Layer 5: the key material a config file must not hold."
    def init(config) do
      {:ok,
       Keyword.put(
         config,
         :provider,
         {Encryptor.Provider.Static, key: :binary.copy(<<0x31>>, 32), name: "v1"}
       )}
    end
  end

  @doc "The provider options both vault tests configure."
  @spec provider_opts() :: keyword()
  def provider_opts, do: GcpKmsCase.opts()
end
