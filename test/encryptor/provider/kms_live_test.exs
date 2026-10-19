defmodule Encryptor.Provider.KmsLiveTest do
  @moduledoc """
  `Encryptor.Provider.Kms` against a live AWS KMS test key.

  Tagged `:aws_kms_integration`, which `test/test_helper.exs` excludes by
  default; CI's `aws-kms-integration` job runs it with
  `mix test --only aws_kms_integration`. `Encryptor.AwsKmsLive` reads the
  key's ARN and the credentials, and with `ENCRYPTOR_REQUIRE_AWS_KMS=1` (CI
  sets it) an absent ARN fails this module rather than skipping it.
  `guides/live-kms-suites.md` says how a maintainer runs it.

  Everything else in the provider's tests runs against `Encryptor.AwsKms.Fake`
  at the engine's client boundary; this module is the one place a vault on
  the provider meets the service. It drives `Encryptor.AwsKmsLive.Vault`, a
  `:scoped` vault whose provider names the one test key:

    1. a provision answers `{:not_provisionable, Encryptor.Provider.Kms}`,
       as the provider's moduledoc says, and reaches no KMS call;
    2. a write calls `GenerateDataKey` on the test key, and a read of that
       message calls `Decrypt` and hands back exactly the plaintext written;
    3. the same message read under another scope is refused by KMS: the
       vault requires `scope_ref` and the engine leaves a required pair out
       of the header, so the reader's own `scope_ref` reaches `Decrypt` in
       the encryption context and KMS answers `InvalidCiphertextException`
       (400). The engine then retries once under the header's stored context
       alone, which lacks the writer's `scope_ref`, and KMS refuses that
       too; the vault answers `:decrypt_failed`.

  The wrong-key case is therefore a wrong binding on the one usable key: the
  read names the right key under a scope the data key was not generated
  for. A second key, one the credentials hold no grant on, is not part of
  this suite.

  No assertion here renders a message, an error struct, a key ARN or a
  plaintext: each compares inside the test and fails with a call kind, a
  status or a reason tag (`Encryptor.AwsKmsLive`, "Never in the output").
  """

  use ExUnit.Case, async: false

  alias Encryptor.AwsKmsLive
  alias Encryptor.AwsKmsLive.Vault, as: LiveVault
  alias Encryptor.Error
  alias Encryptor.Vault

  @moduletag :aws_kms_integration

  unless AwsKmsLive.present?() or AwsKmsLive.required?() do
    @moduletag skip: AwsKmsLive.absent_message()
  end

  setup_all do
    # Reached without the ARN only when it is required (CI): fail.
    fetch!(AwsKmsLive.key_arn())
    fetch!(AwsKmsLive.credentials())

    {:ok, _apps} = Application.ensure_all_started(:finch)

    for child <- AwsKmsLive.children(), do: start_supervised!(child)

    :ok
  end

  setup do
    case start_supervised(Supervisor.child_spec({LiveVault, []}, restart: :temporary)) do
      {:ok, _pid} -> :ok
      {:error, _reason} -> flunk("the live vault did not start")
    end

    # Calls a previous test left unread are not this test's.
    AwsKmsLive.calls()
    :ok
  end

  # sabotage (on a copy of this file whose vault ran Encryptor.AwsKms.Fake
  # behind a client recording 200 or 400 per call; the live key was not
  # used): made Encryptor.Vault.Resolve.provision/3 answer unknown_key for a
  # provider without provision/2 - red.
  test "answers not_provisionable to a provision, and calls KMS for nothing" do
    case Vault.provision(LiveVault, selector()) do
      {:error, %Error{reason: reason}} ->
        refused = reason == {:not_provisionable, Encryptor.Provider.Kms}
        assert refused, "provision answered #{inspect(tag(reason))}"

      {:ok, _provisioned} ->
        flunk("provision answered :ok")
    end

    assert [] == AwsKmsLive.calls()
  end

  # sabotage (the same copy): made the recording client hand back other
  # bytes than the data key Decrypt unwrapped - red, the read answered
  # decrypt_failed.
  test "decrypts exactly the plaintext a write under the test key encrypted" do
    selector = selector()
    plaintext = :crypto.strong_rand_bytes(48)

    ciphertext = encrypt!(plaintext, selector)
    assert [{:generate_data_key, 200}] == AwsKmsLive.calls()

    case LiveVault.decrypt(ciphertext, key: selector) do
      {:ok, read} ->
        same = read == plaintext
        assert same, "Decrypt answered other bytes than the write encrypted"

      {:error, %Error{reason: reason}} ->
        flunk("decrypt answered #{inspect(tag(reason))}; #{calls()}")
    end

    assert [{:decrypt, 200}] == AwsKmsLive.calls()
  end

  # sabotage (the same copy): made Encryptor.AwsKms.Fake bind no encryption
  # context - red, Decrypt answered 200 under the other scope's binding.
  test "refuses a read under another scope's binding" do
    owner = selector()
    other = selector()

    ciphertext = encrypt!(:crypto.strong_rand_bytes(48), owner)
    AwsKmsLive.calls()

    case LiveVault.decrypt(ciphertext, key: other) do
      {:ok, _plaintext} ->
        flunk("a message written under another scope decrypted")

      {:error, %Error{reason: reason, engine: engine}} ->
        made = AwsKmsLive.calls()
        assert tag(reason) == :decrypt_failed
        assert [{:decrypt, 400}, {:decrypt, 400}] == made
        refused = kms_refused?(engine, :invalid_ciphertext)
        assert refused, "the refusal was not KMS's InvalidCiphertextException"
    end
  end

  defp fetch!(:ok), do: :ok
  defp fetch!({:ok, value}), do: value
  defp fetch!({:error, message}), do: flunk(message)

  defp selector, do: "live-" <> Base.encode16(:crypto.strong_rand_bytes(8), case: :lower)

  defp encrypt!(plaintext, selector) do
    case LiveVault.encrypt(plaintext, key: selector) do
      {:ok, ciphertext} ->
        ciphertext

      {:error, %Error{reason: reason}} ->
        flunk("encrypt answered #{inspect(tag(reason))}; #{calls()}")
    end
  end

  # The engine's detail for a decrypt every candidate refused: one
  # `{:kms_error, type, _}` per wrapped data key the keyring tried.
  defp kms_refused?({:unable_to_decrypt_any_data_key, errors}, type) when is_list(errors),
    do: errors != [] and Enum.all?(errors, &match?({:kms_error, ^type, _message}, &1))

  defp kms_refused?(_engine, _type), do: false

  # A reason's leading tag, never its whole term: a reason can carry a selector
  # or an engine detail that names the key.
  defp tag(reason) when is_tuple(reason), do: elem(reason, 0)
  defp tag(reason) when is_atom(reason), do: reason
  defp tag(_reason), do: :unnameable

  defp calls do
    rendered =
      Enum.map_join(AwsKmsLive.calls(), ", ", fn {kind, status} -> "#{kind} #{status}" end)

    "KMS calls: [" <> rendered <> "]"
  end
end
