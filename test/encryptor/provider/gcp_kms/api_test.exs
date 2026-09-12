defmodule Encryptor.Provider.GcpKms.ApiTest do
  @moduledoc """
  The transport's own failure mapping.

  `Encryptor.Provider.GcpKmsTest` covers what the provider does with these
  answers; this module covers the answers themselves, because a response that
  is 200 and unusable is the one a provider is most likely to trust.
  """

  use ExUnit.Case, async: true

  alias Encryptor.GcpKms.EmptyBodyKms
  alias Encryptor.GcpKms.FailingToken
  alias Encryptor.GcpKms.ForbiddenKms
  alias Encryptor.GcpKms.GarbageKms
  alias Encryptor.GcpKms.NonsenseKms
  alias Encryptor.GcpKms.NotBase64Kms
  alias Encryptor.GcpKms.UnreachableKms
  alias Encryptor.GcpKmsCase
  alias Encryptor.Provider.GcpKms.Api

  @key_id "t-abcdef"
  @aad "binding"

  # mutation: return `{:ok, decoded}` for any status - a 403 body then becomes
  # a key, and an IAM misconfiguration surfaces as corrupt key material.
  test "maps a refused status onto a status failure" do
    assert {:error, {:http_status, 403}} =
             Api.encrypt(state(ForbiddenKms), @key_id, "secret", @aad)
  end

  test "maps a transport failure onto a transport failure" do
    assert {:error, {:transport, :request_failed}} =
             Api.decrypt(state(UnreachableKms), @key_id, "blob", @aad)
  end

  # mutation: assume the body decodes - a proxy's HTML error page at 200 then
  # becomes a key.
  test "refuses a 200 whose body is not a JSON object" do
    assert {:error, {:malformed_response, :not_a_json_object}} =
             Api.encrypt(state(GarbageKms), @key_id, "secret", @aad)
  end

  test "refuses a 200 that carries none of the field the call needs" do
    assert {:error, {:malformed_response, :missing_field}} =
             Api.decrypt(state(EmptyBodyKms), @key_id, "blob", @aad)
  end

  # mutation: skip Base.decode64 and use the field as bytes - the wrapping is
  # then stored base64-encoded and never opens again.
  test "refuses a field that is not base64" do
    assert {:error, {:malformed_response, :not_base64}} =
             Api.encrypt(state(NotBase64Kms), @key_id, "secret", @aad)
  end

  test "refuses a client that does not answer with a result tuple" do
    assert {:error, {:malformed_response, :not_a_response}} =
             Api.encrypt(state(NonsenseKms), @key_id, "secret", @aad)
  end

  # mutation: proceed without a token - every call then fails as a 401 that
  # looks like an IAM problem instead of a credentials problem.
  test "makes no request at all when the token server will not mint one" do
    assert {:error, {:token, :unavailable}} =
             Api.create_crypto_key(state(UnreachableKms, goth: {FailingToken, :t}), @key_id)
  end

  # mutation: drop the ALREADY_EXISTS clause - decision 6's retry stops
  # working against a key that cannot be deleted.
  test "reads ALREADY_EXISTS as an existing key rather than a failure" do
    assert {:ok, :exists} =
             Api.create_crypto_key(state(Encryptor.GcpKms.ExistingKeyKms), @key_id)

    assert {:ok, :created} = Api.create_crypto_key(state(Encryptor.GcpKms.FakeKms), @key_id)
  end

  test "round-trips a wrapping under its binding and fails closed under another" do
    state = state(Encryptor.GcpKms.FakeKms)

    assert {:ok, wrapped} = Api.encrypt(state, @key_id, "the-material", @aad)
    assert {:ok, "the-material"} = Api.decrypt(state, @key_id, wrapped, @aad)
    assert {:error, {:http_status, 400}} = Api.decrypt(state, @key_id, wrapped, "other")
  end

  defp state(http_client, overrides \\ []) do
    GcpKmsCase.state(Keyword.put(overrides, :http_client, http_client))
  end
end
