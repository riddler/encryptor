defmodule Encryptor.Provider.GcpKmsLiveTest do
  @moduledoc """
  `Encryptor.Provider.GcpKms` against a live Cloud KMS test key.

  Tagged `:gcp_kms_integration`, which `test/test_helper.exs` excludes by
  default; CI's `gcp-kms-integration` job runs it with
  `mix test --only gcp_kms_integration`. `Encryptor.GcpKmsLive` reads the two
  key names and the credentials, and with `ENCRYPTOR_REQUIRE_GCP_KMS=1` (CI
  sets it) absent key names fail this module rather than skipping it.
  `guides/live-kms-suites.md` says how a maintainer runs it.

  Everything else in the provider's tests runs against `Encryptor.GcpKms.Fake`;
  this module is the one place the provider's three calls meet the service:

    1. a provision against the test key: `CreateCryptoKey` finds the key
       already there and `Encrypt` wraps fresh material, and the row unwraps;
    2. `Decrypt` hands back exactly the bytes `Encrypt` wrapped;
    3. a wrapping read under another scope's binding is refused, as ADR-0007
       Amendment B classifies a 400;
    4. a key the credentials hold no grant on answers `key_unavailable`, as
       Amendment B classifies a 403.

  Every state here pins `:key_id_fun` to the test key's id, so no run mints
  a `CryptoKey`. The selector and the reference subkey are fresh per run.

  A disabled `CryptoKeyVersion` is not exercised: the provider names a
  `CryptoKey` in every call, `Decrypt` picks the version the ciphertext
  names, and a disabled version can wrap nothing new, so no surface of the
  provider can address one.

  No assertion here renders a row, a state, a key name or key material: each
  compares inside the test and fails with a call kind, a status or a reason
  (`Encryptor.GcpKmsLive`, "Never in the output").
  """

  use ExUnit.Case, async: false

  alias Encryptor.Envelope
  alias Encryptor.GcpKmsLive
  alias Encryptor.GcpKmsLive.Http
  alias Encryptor.Key.Aes
  alias Encryptor.Provider.GcpKms
  alias Encryptor.Provider.GcpKms.Aad
  alias Encryptor.Provider.GcpKms.Api
  alias Encryptor.Vault.Reference

  @moduletag :gcp_kms_integration

  unless GcpKmsLive.present?() or GcpKmsLive.required?() do
    @moduletag skip: GcpKmsLive.absent_message()
  end

  @namespace "encryptor-scope"

  setup_all do
    # Reached without the key names only when they are required (CI): fail.
    key = fetch!(GcpKmsLive.key("GCP_KMS_KEY"))
    denied = fetch!(GcpKmsLive.key("GCP_KMS_DENIED_KEY"))
    source = fetch!(GcpKmsLive.token_source())

    {:ok, _apps} = Application.ensure_all_started(:goth)

    for child <- GcpKmsLive.children(source), do: start_supervised!(child)

    %{key: key, denied: denied, subkey: :crypto.strong_rand_bytes(32)}
  end

  setup do
    # Calls a previous test left unread are not this test's.
    GcpKmsLive.calls()
    :ok
  end

  # sabotage (on a copy driven by a fake answering the statuses this file
  # asserts; the live key was not used): stopped Api.create_crypto_key/2
  # reading 409 as an existing key - red, the provision answered
  # key_unavailable.
  test "provisions a scope on the test key and unwraps the row it returns", ctx do
    selector = selector()
    provisioning = state(ctx, ctx.key, fn _ref -> {:ok, []} end)

    row =
      case GcpKms.provision(provisioning, selector) do
        {:ok, row} -> row
        {:error, reason} -> flunk("provision answered #{inspect(reason)}; #{calls()}")
      end

    assert [{:create, 409}, {:encrypt, 200}] == GcpKmsLive.calls()
    assert row.scope_ref == Reference.derive(ctx.subkey, selector)
    assert row.version == 1
    assert row.bits == 256

    reading = state(ctx, ctx.key, store([row]))

    current = material!(GcpKms.encryption_key(reading, selector), "encryption_key")

    live =
      case GcpKms.decryption_keys(reading, selector) do
        {:ok, [%Aes{material: material}]} -> material
        {:ok, keys} -> flunk("decryption_keys answered #{length(keys)} keys for one row")
        {:error, reason} -> flunk("decryption_keys answered #{inspect(reason)}; #{calls()}")
      end

    same = byte_size(current) == 32 and current == live
    assert same, "encryption_key and decryption_keys unwrapped different material"
  end

  # sabotage (the same fake): returned Decrypt's "plaintext" field without
  # Base.decode64 in Api.decrypt/4 - red.
  test "decrypts exactly the material Encrypt wrapped", ctx do
    selector = selector()
    scope_ref = Reference.derive(ctx.subkey, selector)
    material = :crypto.strong_rand_bytes(32)
    wrapping = state(ctx, ctx.key, fn _ref -> {:ok, []} end)

    row = wrap!(wrapping, ctx.key, scope_ref, material)
    reading = state(ctx, ctx.key, store([row]))

    unwrapped = material!(GcpKms.encryption_key(reading, selector), "encryption_key")

    same = unwrapped == material
    assert same, "Decrypt answered other bytes than Encrypt wrapped"
  end

  # sabotage (the same fake): dropped 400 from @refused_statuses in
  # Encryptor.Provider.GcpKms - red.
  test "refuses a wrapping read under another scope's binding", ctx do
    owner = selector()
    other = selector()
    wrapping = state(ctx, ctx.key, fn _ref -> {:ok, []} end)

    owners_row =
      wrap!(
        wrapping,
        ctx.key,
        Reference.derive(ctx.subkey, owner),
        :crypto.strong_rand_bytes(32)
      )

    # The owner's wrapping, filed under the other scope: the row is well
    # formed and names the other scope, so only Cloud KMS's AAD check stands
    # between the other scope and the owner's key.
    moved = %{
      owners_row
      | scope_ref: Reference.derive(ctx.subkey, other),
        name: Envelope.key_name(Reference.derive(ctx.subkey, other), 1)
    }

    reading = state(ctx, ctx.key, store([moved]))

    case GcpKms.encryption_key(reading, other) do
      {:ok, _key} ->
        flunk("a wrapping bound to another scope unwrapped")

      {:error, reason} ->
        assert reason == {:invalid_key_descriptor, {:kms_refused, 400}}
        assert [{:decrypt, 400}] == GcpKmsLive.calls()
    end
  end

  # sabotage (the same fake): added 403 to @refused_statuses in
  # Encryptor.Provider.GcpKms - red.
  test "answers key_unavailable for a key the credentials hold no grant on", ctx do
    selector = selector()
    scope_ref = Reference.derive(ctx.subkey, selector)
    wrapping = state(ctx, ctx.key, fn _ref -> {:ok, []} end)

    # A real wrapping, so the only thing wrong with the call is the key it
    # names.
    row = wrap!(wrapping, ctx.key, scope_ref, :crypto.strong_rand_bytes(32))
    denied_row = %{row | key_id: ctx.denied.key_id}
    reading = state(ctx, ctx.denied, store([denied_row]))

    case GcpKms.encryption_key(reading, selector) do
      {:ok, _key} ->
        flunk("a key with no grant unwrapped")

      {:error, reason} ->
        assert reason == {:key_unavailable, selector}
        assert [{:decrypt, 403}] == GcpKmsLive.calls()
    end
  end

  defp fetch!({:ok, value}), do: value
  defp fetch!({:error, message}), do: flunk(message)

  defp selector, do: "live-" <> Base.encode16(:crypto.strong_rand_bytes(8), case: :lower)

  defp store(rows) do
    fn scope_ref -> {:ok, Enum.filter(rows, &(&1.scope_ref == scope_ref))} end
  end

  # The provider's state for one key, its `CryptoKey` id pinned to that key.
  defp state(ctx, key, store) do
    opts = [
      project: key.project,
      location: key.location,
      key_ring: key.key_ring,
      reference_subkey: ctx.subkey,
      http_client: Http,
      goth: GcpKmsLive.goth(),
      store: store,
      key_id_fun: fn _selector -> key.key_id end
    ]

    case GcpKms.init(opts) do
      {:ok, state} -> state
      {:error, reason} -> flunk("init answered #{inspect(reason)}")
    end
  end

  # A row as `provision/2` writes one, around material this test chose, so the
  # read path can be checked against known bytes. The AAD is the provider's
  # own encoding of the binding (ADR-0007 decision 5).
  defp wrap!(state, key, scope_ref, material) do
    aad = scope_ref |> Envelope.binding(1, @namespace) |> Aad.encode()

    case Api.encrypt(state, key.key_id, material, aad) do
      {:ok, wrapped} ->
        GcpKmsLive.calls()

        %{
          scope_ref: scope_ref,
          version: 1,
          namespace: @namespace,
          name: Envelope.key_name(scope_ref, 1),
          bits: 256,
          wrapped: wrapped,
          key_id: key.key_id
        }

      {:error, failure} ->
        flunk("Encrypt answered #{inspect(failure)}; #{calls()}")
    end
  end

  defp material!({:ok, %Aes{material: material}}, _call), do: material

  defp material!({:error, reason}, call),
    do: flunk("#{call} answered #{inspect(reason)}; #{calls()}")

  defp calls do
    rendered =
      Enum.map_join(GcpKmsLive.calls(), ", ", fn {kind, status} -> "#{kind} #{status}" end)

    "Cloud KMS calls: [" <> rendered <> "]"
  end
end
