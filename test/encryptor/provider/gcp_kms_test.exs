defmodule Encryptor.Provider.GcpKmsTest do
  @moduledoc """
  ADR-0007: the GCP KMS wrap-provider.

  The conformance suite runs first, against a tenant that was provisioned
  through `provision/2` and stored the way a host would store it, so the
  record's whole round trip - create, mint, wrap, store, unwrap - is what the
  shared properties are asserted over rather than a hand-built fixture.

  Every GCP call goes through `Encryptor.GcpKms.Fake`, a real AEAD behind the
  HTTP boundary ADR-0007 decision 9 puts in the host's hands. Nothing here
  reaches a network and nothing here needs a credential.
  """

  use Encryptor.Provider.Conformance

  alias Encryptor.Envelope
  alias Encryptor.GcpKms.EchoKms
  alias Encryptor.GcpKms.EncryptFailsKms
  alias Encryptor.GcpKms.ExistingKeyKms
  alias Encryptor.GcpKms.FailingToken
  alias Encryptor.GcpKms.FakeToken
  alias Encryptor.GcpKms.ForbiddenKms
  alias Encryptor.GcpKms.ShortKeyKms
  alias Encryptor.GcpKms.UnreachableKms
  alias Encryptor.GcpKmsCase
  alias Encryptor.Key.Aes
  alias Encryptor.Provider.GcpKms
  alias Encryptor.Provider.GcpKms.Aad
  alias Encryptor.Provider.GcpKms.Api
  alias Encryptor.Vault.Reference

  @selector "tenant-42"
  @unknown "tenant-99"

  @impl true
  def provider_case do
    {_state, row} = GcpKmsCase.provisioned(@selector)

    %{
      provider: GcpKms,
      opts: GcpKmsCase.opts(store: store([row])),
      selectors: [@selector],
      unknown: [@unknown]
    }
  end

  describe "init/1" do
    # mutation: drop the `required/1` clause from init/1 - a vault starts with
    # no project and fails at the first call instead.
    test "refuses an option list missing a required key" do
      assert {:error, {:missing_config, [:provider, :project]}} =
               GcpKms.init(Keyword.delete(GcpKmsCase.opts(), :project))

      assert {:error, {:missing_config, [:provider, :store]}} =
               GcpKms.init(Keyword.delete(GcpKmsCase.opts(), :store))
    end

    # mutation: accept any binary as the reference subkey - a 16-byte subkey
    # derives a tenant_ref no other deployment can reproduce.
    test "refuses a reference subkey that is not 32 bytes" do
      assert {:error, {:invalid_config, :reference_subkey, :invalid_length}} =
               GcpKms.init(GcpKmsCase.opts(reference_subkey: :binary.copy(<<1>>, 16)))
    end

    # mutation: skip the arity check on :store - a non-closure raises on the
    # first encrypt rather than failing the vault's start.
    test "refuses a store that is not a one-argument closure" do
      assert {:error, {:invalid_config, :provider, {:not_a_closure, :store}}} =
               GcpKms.init(GcpKmsCase.opts(store: :not_a_closure))
    end

    # mutation: drop the `loaded/3` check - a missing HTTP client becomes an
    # UndefinedFunctionError on a customer's first write, which is exactly the
    # at-start principle ADR-0002 decision 5 bought.
    test "refuses an HTTP client that is absent or does not export request/5" do
      assert {:error, {:missing_optional_dependency, Encryptor.NoSuchHttpClient}} =
               GcpKms.init(GcpKmsCase.opts(http_client: Encryptor.NoSuchHttpClient))

      assert {:error, {:missing_optional_dependency, FakeToken}} =
               GcpKms.init(GcpKmsCase.opts(http_client: FakeToken))
    end

    test "refuses an HTTP client that is not a module at all" do
      assert {:error, {:invalid_config, :provider, :http_client}} =
               GcpKms.init(GcpKmsCase.opts(http_client: "MyApp.Finch"))
    end

    # mutation: accept any term as :goth - the token server is resolved at the
    # first call instead, against a name that can never answer.
    test "refuses a token server that is neither a name nor a loaded module" do
      assert {:error, {:invalid_config, :provider, :goth}} =
               GcpKms.init(GcpKmsCase.opts(goth: "MyApp.Goth"))

      assert {:error, {:missing_optional_dependency, Encryptor.NoSuchTokenServer}} =
               GcpKms.init(GcpKmsCase.opts(goth: {Encryptor.NoSuchTokenServer, :name}))
    end

    test "accepts a bare Goth server name when goth is available" do
      assert {:ok, %{goth: MyApp.Goth}} = GcpKms.init(GcpKmsCase.opts(goth: MyApp.Goth))
    end

    # mutation: default an unknown protection level to :software - a host
    # asking for HSM silently gets software keys.
    test "refuses a protection level outside the two GCP offers" do
      assert {:error, {:invalid_config, :provider, :protection_level}} =
               GcpKms.init(GcpKmsCase.opts(protection_level: :hardware))
    end

    test "refuses a key_id_fun that is not a one-argument closure" do
      assert {:error, {:invalid_config, :provider, {:not_a_closure, :key_id_fun}}} =
               GcpKms.init(GcpKmsCase.opts(key_id_fun: fn -> "t-x" end))
    end

    # mutation: change a default - the namespace default is ADR-0003 decision
    # 5's and the prefix and timeout are ADR-0007 decision 4's and 10's.
    test "defaults the namespace, the id prefix, the protection level and the timeout" do
      assert {:ok, state} = GcpKms.init(GcpKmsCase.opts())

      assert state.namespace == "encryptor-tenant"
      assert state.key_id_prefix == "t-"
      assert state.protection_level == :software
      assert state.timeout == 5_000
      assert state.key_id_fun == nil
    end
  end

  describe "the CryptoKey id (ADR-0007 decision 4)" do
    # mutation: truncate the digest, or drop the zero separator - an
    # undeletable resource that collides is unrecoverable, and an unseparated
    # pre-image lets two (namespace, selector) pairs produce one id.
    test "is the prefixed, untruncated base32 digest of the namespace and the selector" do
      state = GcpKmsCase.state()

      expected =
        "t-" <>
          Base.encode32(:crypto.hash(:sha256, ["encryptor-tenant", 0, @selector]),
            case: :lower,
            padding: false
          )

      assert GcpKms.crypto_key_name(state, @selector) ==
               "projects/myapp-test/locations/us-east1/keyRings/tenant-keys/cryptoKeys/" <>
                 expected
    end

    # mutation: encode base64 instead - `=` and `+` are outside GCP's
    # [a-zA-Z0-9_-] id charset and the case folding differs.
    test "is inside GCP's id charset and length limit" do
      state = GcpKmsCase.state()
      id = state |> GcpKms.crypto_key_name(@selector) |> String.split("/") |> List.last()

      assert String.match?(id, ~r/\A[a-z2-7-]{1,63}\z/)
      assert String.length(id) == 54
    end

    test "is stable for one selector and distinct across selectors" do
      state = GcpKmsCase.state()

      assert GcpKms.crypto_key_name(state, @selector) ==
               GcpKms.crypto_key_name(state, @selector)

      refute GcpKms.crypto_key_name(state, @selector) ==
               GcpKms.crypto_key_name(state, @unknown)
    end

    # mutation: ignore :key_id_fun - the documented escape hatch silently
    # stops being one.
    test "is the host's when key_id_fun is configured" do
      state = GcpKmsCase.state(key_id_fun: fn selector -> "host-" <> selector end)

      assert String.ends_with?(GcpKms.crypto_key_name(state, @selector), "/host-tenant-42")
    end
  end

  describe "the additional authenticated data (ADR-0007 decision 5)" do
    # mutation: change a length width, drop the keys from the pre-image, or
    # sort differently - each one is a format change that makes every stored
    # wrapping permanently undecryptable, against a key GCP will not delete.
    test "encodes the record's worked vector to the byte" do
      aad = Aad.encode(Envelope.binding("abc", 1, "encryptor-tenant"))

      assert byte_size(aad) == 140

      assert binary_part(aad, 0, 45) ==
               <<0, 23>> <>
                 "encryptor-key-namespace" <> <<0, 0, 0, 16>> <> "encryptor-tenant"
    end

    test "sorts bytewise by key and length-delimits both halves of every pair" do
      aad = Aad.encode(%{"b" => "22", "a" => "1"})

      assert aad ==
               <<0, 1>> <>
                 "a" <> <<0, 0, 0, 1>> <> "1" <> <<0, 1>> <> "b" <> <<0, 0, 0, 2>> <> "22"
    end
  end

  describe "provision/2 (ADR-0007 decisions 3 and 6)" do
    # mutation: return the selector instead of the tenant_ref - the raw tenant
    # identifier lands in the wrapped-key store, reversing the property
    # ADR-0004 decision 4's amendment established.
    test "returns a row keyed by tenant_ref, with neither the selector nor the plaintext" do
      {state, row} = GcpKmsCase.provisioned(@selector)

      assert row.tenant_ref == Reference.derive(GcpKmsCase.subkey(), @selector)
      assert row.version == 1
      assert row.namespace == "encryptor-tenant"
      assert row.name == "t/" <> row.tenant_ref <> "/v1"
      assert row.bits == 256
      assert is_binary(row.wrapped)
      assert row.key_id == key_id(state, @selector)

      refute Enum.any?(Map.values(row), &(&1 == @selector))
      refute Map.has_key?(row, :material)
      refute Map.has_key?(row, :key)
    end

    # mutation: send a rotation schedule, or a purpose other than
    # ENCRYPT_DECRYPT - decision 3 and decision 7 both forbid it.
    test "creates the key with ENCRYPT_DECRYPT, the configured protection level and no rotation" do
      state = GcpKmsCase.state(http_client: EchoKms, protection_level: :hsm)

      assert {:ok, _row} = GcpKms.provision(state, @selector)

      assert_received {:kms_request, url, body, opts}
      assert url =~ "/keyRings/tenant-keys/cryptoKeys?cryptoKeyId=t-"
      assert body["purpose"] == "ENCRYPT_DECRYPT"
      assert body["versionTemplate"] == %{"protectionLevel" => "HSM"}
      refute Map.has_key?(body, "rotationPeriod")
      assert opts[:timeout] == 5_000
    end

    # mutation: treat ALREADY_EXISTS as a failure - a provision that
    # half-succeeded can then never be retried, and the key cannot be deleted.
    test "treats an already-created key as success for the create step" do
      state = GcpKmsCase.state(http_client: ExistingKeyKms)

      assert {:ok, row} = GcpKms.provision(state, @selector)
      assert row.version == 1
    end

    test "reports a refused create as key_unavailable" do
      state = GcpKmsCase.state(http_client: ForbiddenKms)

      assert {:error, {:key_unavailable, @selector}} = GcpKms.provision(state, @selector)
    end

    test "reports a failed wrap as key_unavailable" do
      state = GcpKmsCase.state(http_client: EncryptFailsKms)

      assert {:error, {:key_unavailable, @selector}} = GcpKms.provision(state, @selector)
    end

    # mutation: accept :default - a tenant reference has no meaning for it and
    # the derivation would raise.
    test "refuses a selector that is not a non-empty string" do
      state = GcpKmsCase.state()

      assert {:error, {:unknown_key, :default}} = GcpKms.provision(state, :default)
      assert {:error, {:unknown_key, ""}} = GcpKms.provision(state, "")
    end

    # mutation: derive the master key from anything - decision 1 keeps
    # ADR-0003 decision 1's independent 32 CSPRNG bytes per tenant.
    test "mints independent material on every call" do
      {state, first} = GcpKmsCase.provisioned(@selector)
      {:ok, second} = GcpKms.provision(state, @selector)

      refute first.wrapped == second.wrapped
    end
  end

  describe "resolution" do
    # mutation: resolve from the selector rather than the derived tenant_ref -
    # the store is keyed by reference, never by a raw tenant identifier.
    test "unwraps the stored row into an AES descriptor the vault can build" do
      {_state, row} = GcpKmsCase.provisioned(@selector)
      state = GcpKmsCase.state(store: store([row]))

      assert {:ok, %Aes{} = descriptor} = GcpKms.encryption_key(state, @selector)
      assert descriptor.namespace == row.namespace
      assert descriptor.name == row.name
      assert descriptor.bits == 256
      assert byte_size(descriptor.material) == 32
    end

    # mutation: rebuild the AAD from anything but the row's own fields - a
    # wrapping moved between tenants or versions then unwraps silently, which
    # is the property the binding exists to buy.
    test "fails closed on a row whose claimed version does not match its blob" do
      {_state, row} = GcpKmsCase.provisioned(@selector)
      state = GcpKmsCase.state(store: store([%{row | version: 2}]))

      assert {:error, {:key_unavailable, @selector}} = GcpKms.encryption_key(state, @selector)
    end

    test "fails closed on a wrapping moved to another tenant's row" do
      {_state, row} = GcpKmsCase.provisioned(@selector)
      {_other_state, other} = GcpKmsCase.provisioned(@unknown)
      state = GcpKmsCase.state(store: store([%{row | wrapped: other.wrapped}]))

      assert {:error, {:key_unavailable, @selector}} = GcpKms.encryption_key(state, @selector)
    end

    # mutation: answer {:key_unavailable, _} for a selector with no rows - an
    # operator then retries forever against a settled negative answer, and
    # ADR-0003 decision 8 forbids resolving into a create.
    test "answers a selector with no rows with a settled unknown_key" do
      state = GcpKmsCase.state()

      assert {:error, {:unknown_key, @selector}} = GcpKms.encryption_key(state, @selector)
      assert {:error, {:unknown_key, @selector}} = GcpKms.decryption_keys(state, @selector)
      assert {:error, {:unknown_key, :default}} = GcpKms.encryption_key(state, :default)
      assert {:error, {:unknown_key, :default}} = GcpKms.decryption_keys(state, :default)
    end

    # mutation: return the store's own term unchanged - a host's store failure
    # would leak a term outside this package's closed vocabulary.
    test "maps a store failure onto the closed vocabulary" do
      timing_out = GcpKmsCase.state(store: fn _ref -> {:error, :timeout} end)
      settled = GcpKmsCase.state(store: fn _ref -> {:error, {:unknown_key, @selector}} end)
      off_contract = GcpKmsCase.state(store: fn _ref -> [%{}] end)

      assert {:error, {:key_unavailable, @selector}} =
               GcpKms.encryption_key(timing_out, @selector)

      assert {:error, {:unknown_key, @selector}} = GcpKms.encryption_key(settled, @selector)

      assert {:error, {:invalid_key_descriptor, {:store_off_contract, :unnameable}}} =
               GcpKms.encryption_key(off_contract, @selector)
    end

    # mutation: skip validate_row/1 - a hand-edited row reaches the AAD and
    # the descriptor, and the failure surfaces as a decrypt of application
    # data rather than as a refused row.
    test "refuses a row that cannot rebuild a binding and a descriptor" do
      {_state, row} = GcpKmsCase.provisioned(@selector)
      broken = GcpKmsCase.state(store: store([Map.delete(row, :key_id)]))
      not_a_row = GcpKmsCase.state(store: fn _ref -> {:ok, [:nonsense]} end)

      assert {:error, {:invalid_key_descriptor, :invalid_row}} =
               GcpKms.encryption_key(broken, @selector)

      assert {:error, {:invalid_key_descriptor, {:not_a_row, :nonsense}}} =
               GcpKms.encryption_key(not_a_row, @selector)
    end

    # mutation: trust the size the row claims - a descriptor whose material is
    # shorter than its declared bits is a keyring the engine cannot build.
    test "refuses material whose size does not match the row's declared bits" do
      {_state, row} = GcpKmsCase.provisioned(@selector)
      state = GcpKmsCase.state(store: store([row]), http_client: ShortKeyKms)

      assert {:error, {:invalid_key_descriptor, :material_size}} =
               GcpKms.encryption_key(state, @selector)
    end

    test "reports an unreachable service as key_unavailable" do
      {_state, row} = GcpKmsCase.provisioned(@selector)
      state = GcpKmsCase.state(store: store([row]), http_client: UnreachableKms)

      assert {:error, {:key_unavailable, @selector}} = GcpKms.encryption_key(state, @selector)
      assert {:error, {:key_unavailable, @selector}} = GcpKms.decryption_keys(state, @selector)
    end

    test "reports a token the server will not mint as key_unavailable" do
      {_state, row} = GcpKmsCase.provisioned(@selector)
      state = GcpKmsCase.state(store: store([row]), goth: {FailingToken, :test_goth})

      assert {:error, {:key_unavailable, @selector}} = GcpKms.encryption_key(state, @selector)
    end

    # mutation: return the candidates oldest first - writes then go under a
    # key that is not the newest the provider admits to.
    test "answers every live version newest first, with the newest as the encryption key" do
      {provisioning, first} = GcpKmsCase.provisioned(@selector)
      second = next_version(provisioning, first)
      state = GcpKmsCase.state(store: store([second, first]))

      assert {:ok, [newest, previous]} = GcpKms.decryption_keys(state, @selector)
      assert {:ok, ^newest} = GcpKms.encryption_key(state, @selector)
      assert newest.name == second.name
      assert previous.name == first.name
      refute newest.material == previous.material
    end

    test "refuses the whole candidate list when one row will not unwrap" do
      {provisioning, first} = GcpKmsCase.provisioned(@selector)
      second = next_version(provisioning, first)
      state = GcpKmsCase.state(store: store([%{second | version: 7}, first]))

      assert {:error, {:key_unavailable, @selector}} = GcpKms.decryption_keys(state, @selector)
    end
  end

  defp store(rows) do
    tenant_ref = Reference.derive(GcpKmsCase.subkey(), @selector)

    fn ref -> if ref == tenant_ref, do: {:ok, rows}, else: {:ok, []} end
  end

  # A second live version for one tenant: ADR-0007 decision 7's level-2
  # rotation, which is a procedure over the store rather than a second
  # `provision/2`.
  defp next_version(state, row) do
    version = row.version + 1
    aad = Aad.encode(Envelope.binding(row.tenant_ref, version, row.namespace))
    {:ok, wrapped} = Api.encrypt(state, row.key_id, :crypto.strong_rand_bytes(32), aad)

    %{
      row
      | version: version,
        name: Envelope.key_name(row.tenant_ref, version),
        wrapped: wrapped
    }
  end

  defp key_id(state, selector) do
    state |> GcpKms.crypto_key_name(selector) |> String.split("/") |> List.last()
  end
end
