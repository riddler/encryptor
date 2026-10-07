defmodule Encryptor.Vectors.AwsVectorsVaultDecryptTest do
  @moduledoc """
  Every raw-AES AWS Encryption SDK decrypt vector, positive and negative,
  through `Encryptor.Vault.decrypt/3`.

  The engine runs these vectors through its own API. This module runs them
  through encryptor's: each vector is read by a vault started with an
  `Encryptor.Provider.Static` provider built from the vector's key and the
  provider id its master key names, so the read goes through the vault's
  selector check, candidate list, context composition and value comparison
  before it reaches the engine.

  ## What is selected, and what is excluded

  The corpus's manifest holds 9089 tests, and every one of them falls in
  exactly one of these sets. The counts are literal, so a truncated or swapped
  corpus fails rather than passing with fewer cases.

    * **Run here**: every test whose master keys are all raw AES -
      661 expected to decrypt and 4240 expected to fail.
    * **Excluded, raw RSA: 2200.** encryptor has no RSA key descriptor, so no
      vault can be built from these keys.
    * **Excluded, KMS: 1988.** Every test naming an `aws-kms`,
      `aws-kms-mrk-aware` or `aws-kms-mrk-aware-discovery` master key needs
      cloud credentials to unwrap its data key.

  ## What is asserted

    * The 120 positives written under a suite with key commitment (`0x0478`
      and `0x0578`, 60 each) decrypt to the expected plaintext under the
      default commitment policy.
    * The 541 positives written under the eleven suites without it are
      refused under the default policy, and decrypt to the expected plaintext
      under a vault configured `commitment_policy:
      :require_encrypt_allow_decrypt`.
    * Every one of the 4240 negatives is refused under the default policy
      with encryptor's own error: `reason: :decrypt_failed`, `operation:
      :decrypt` and the reading vault. The engine's term is never asserted;
      it rides in `:engine` and is not this package's contract.
    * One `:scoped` vault refuses a committed positive: the vault requires the
      `"scope_ref"` it injects, and no vector's message carries one.

  One negative names a decryption method rather than a defect in its bytes:
  `fe0a0327-a701-47f9-a42e-8ec7744161ab` is a well-formed signed message
  under suite `0x0378` that the manifest expects to fail only through a
  streaming, unsigned-only decryption method. encryptor offers no such
  method. The case is run with the other negatives and refused under the
  default policy, because its suite has no key commitment; its manifest
  entry says why it is a negative, and this paragraph says why the refusal
  here is the commitment policy's.

  ## Running it

  Tagged `:aws_vectors`, which `test/test_helper.exs` excludes by default; CI
  runs it with `mix test --only aws_vectors` and
  `ENCRYPTOR_REQUIRE_AWS_VECTORS=1`. `Encryptor.AwsVectors` says where the
  corpus comes from. A failure names case ids only: the keys are published
  test keys, but key-shaped all the same, and no assertion renders a key or a
  plaintext.
  """

  use ExUnit.Case, async: false

  alias Encryptor.AwsVectors
  alias Encryptor.AwsVectorVaults.Committed
  alias Encryptor.AwsVectorVaults.Legacy
  alias Encryptor.AwsVectorVaults.Scoped
  alias Encryptor.Error
  alias Encryptor.Message
  alias Encryptor.Provider.Static

  @moduletag :aws_vectors
  @moduletag timeout: :infinity

  unless AwsVectors.present?() or AwsVectors.required?() do
    @moduletag skip: AwsVectors.absent_message()
  end

  @kms_types ["aws-kms", "aws-kms-mrk-aware", "aws-kms-mrk-aware-discovery"]

  setup_all do
    if AwsVectors.present?() do
      manifest = AwsVectors.manifest!()
      %{"keys" => keys} = AwsVectors.keys!(manifest)
      {:ok, corpus: classify(manifest["tests"]), keys: keys}
    else
      {:ok, corpus: nil, keys: nil}
    end
  end

  # sabotage: dropped `"aws-kms-mrk-aware-discovery"` from @kms_types - red,
  # its tests then fall in no set.
  test "the corpus splits into the raw AES set run here and the two excluded sets",
       %{corpus: corpus} do
    assert corpus.unclassified == []

    assert length(corpus.positives) == 661
    assert length(corpus.negatives) == 4240
    assert corpus.rsa == 2200
    assert corpus.kms == 1988
    assert 661 + 4240 + 2200 + 1988 == 9089
  end

  # sabotage: made Encryptor.Message.describe/1 report `committed?: true` for
  # every suite - red, 661 committed against the literal 120.
  test "the raw AES positives span every suite, 120 of them committed",
       %{corpus: corpus} do
    assert tally_suites(corpus.positives) == %{
             0x0014 => 60,
             0x0046 => 60,
             0x0078 => 60,
             0x0114 => 60,
             0x0146 => 60,
             0x0178 => 61,
             0x0214 => 60,
             0x0346 => 60,
             0x0378 => 60,
             0x0478 => 60,
             0x0578 => 60
           }

    assert length(committed(corpus.positives)) == 120
    assert length(uncommitted(corpus.positives)) == 541
  end

  # sabotage: made the value comparison behind Decrypt.agree/4 refuse every
  # message - red, every committed id is reported as not decrypting.
  test "every committed positive decrypts to its plaintext under the default policy",
       %{corpus: corpus, keys: keys} do
    cases = committed(corpus.positives)
    assert length(cases) == 120

    assert decrypt_failures(Committed, cases, keys) == []
  end

  # sabotage: relaxed Config's default commitment policy to
  # :require_encrypt_allow_decrypt - red, the older-suite ids decrypt.
  test "every positive without key commitment is refused under the default policy",
       %{corpus: corpus, keys: keys} do
    cases = uncommitted(corpus.positives)
    assert length(cases) == 541

    assert refusal_failures(Committed, cases, keys) == []
  end

  # sabotage: built every client in Vault.Encrypt with
  # :require_encrypt_require_decrypt instead of the vault's own policy - red,
  # the older-suite ids are refused on the relaxed vault.
  test "every positive without key commitment decrypts under :require_encrypt_allow_decrypt",
       %{corpus: corpus, keys: keys} do
    cases = uncommitted(corpus.positives)
    assert length(cases) == 541

    assert decrypt_failures(Legacy, cases, keys) == []
  end

  # sabotage: made Decrypt.engine_result/3 answer `{:ok, <<>>}` for every
  # engine error - red, the negative ids decrypt. And in the engine
  # (deps/aws_encryption_sdk, recompiled for the test env) ignored the footer
  # signature check - red, the ids whose flipped bit lands in a signature
  # decrypt.
  test "every negative is refused with encryptor's own error under the default policy",
       %{corpus: corpus, keys: keys} do
    assert length(corpus.negatives) == 4240

    assert refusal_failures(Committed, corpus.negatives, keys) == []
  end

  # sabotage: dropped `"scope_ref"` from a :scoped vault's required keys in
  # Config - red, the positive decrypts on the scoped vault.
  test "a :scoped vault refuses a positive vector, which carries no scope reference",
       %{corpus: corpus, keys: keys} do
    [vector | _rest] = committed(corpus.positives)
    {:ok, %{encryption_context: stored}} = Message.describe(vector.ciphertext)
    refute Map.has_key?(stored, "scope_ref")

    start_vault(Scoped, vector, keys, reference_subkey: :crypto.strong_rand_bytes(32))

    # A boolean, so a failure renders the case id and never a plaintext.
    refused? =
      match?(
        {:error, %Error{reason: :decrypt_failed, operation: :decrypt, vault: Scoped}},
        Scoped.decrypt(vector.ciphertext, key: "any-scope")
      )

    assert refused?, "the :scoped vault did not refuse #{vector.id}"
  end

  # -- running ----------------------------------------------------------------

  # One vault start per key the cases name, reused for every case under it:
  # the vault is a singleton per module, so the groups run one after another.
  defp decrypt_failures(vault, cases, keys) do
    each_key_group(vault, cases, keys, fn vector ->
      case vault.decrypt(vector.ciphertext) do
        {:ok, plaintext} -> plaintext == vector.plaintext
        {:error, %Error{}} -> false
      end
    end)
  end

  defp refusal_failures(vault, cases, keys) do
    each_key_group(vault, cases, keys, fn vector ->
      match?(
        {:error, %Error{reason: :decrypt_failed, operation: :decrypt, vault: ^vault}},
        vault.decrypt(vector.ciphertext)
      )
    end)
  end

  # Returns the sorted `{id, outcome}` of every case `ok?` did not accept,
  # never its bytes.
  defp each_key_group(vault, cases, keys, ok?) do
    cases
    |> Enum.group_by(&{&1.key, &1.provider_id})
    |> Enum.flat_map(fn {_group, [first | _rest] = group} ->
      start_vault(vault, first, keys, [])
      outcomes = for vector <- group, do: {vector.id, outcome(ok?, vector)}
      :ok = stop_supervised(vault)
      Enum.reject(outcomes, &match?({_id, :ok}, &1))
    end)
    |> Enum.sort()
  end

  # A raise is a failing case too, reported by the exception's module alone:
  # its message can carry the engine's term, and that term carries key-shaped
  # bytes.
  defp outcome(ok?, vector) do
    if ok?.(vector), do: :ok, else: :wrong_result
  rescue
    exception -> {:raised, exception.__struct__}
  end

  defp start_vault(vault, vector, keys, extra) do
    %{"material" => material, "encoding" => "base64", "key-id" => key_id} = keys[vector.key]

    provider =
      {Static, key: Base.decode64!(material), namespace: vector.provider_id, name: key_id}

    start_supervised!(
      Supervisor.child_spec({vault, [provider: provider] ++ extra}, restart: :temporary)
    )
  end

  # -- the corpus -------------------------------------------------------------

  defp classify(tests) do
    acc = %{positives: [], negatives: [], rsa: 0, kms: 0, unclassified: []}

    Enum.reduce(tests, acc, fn {id, test}, acc ->
      master_keys = test["master-keys"]

      cond do
        Enum.any?(master_keys, &(&1["type"] in @kms_types)) ->
          Map.update!(acc, :kms, &(&1 + 1))

        Enum.all?(master_keys, &raw?(&1, "rsa")) ->
          Map.update!(acc, :rsa, &(&1 + 1))

        Enum.all?(master_keys, &raw?(&1, "aes")) and length(master_keys) == 1 ->
          add_aes(acc, id, test)

        true ->
          Map.update!(acc, :unclassified, &[id | &1])
      end
    end)
  end

  defp raw?(master_key, algorithm),
    do: master_key["type"] == "raw" and master_key["encryption-algorithm"] == algorithm

  defp add_aes(acc, id, %{"master-keys" => [master_key], "result" => result} = test) do
    vector = %{
      id: id,
      key: master_key["key"],
      provider_id: master_key["provider-id"],
      ciphertext: read_file(test["ciphertext"])
    }

    case result do
      %{"output" => %{"plaintext" => plaintext}} ->
        Map.update!(acc, :positives, &[Map.put(vector, :plaintext, read_file(plaintext)) | &1])

      %{"error" => _error} ->
        Map.update!(acc, :negatives, &[vector | &1])
    end
  end

  defp read_file("file://" <> path), do: File.read!(Path.join(AwsVectors.dir(), path))

  defp tally_suites(vectors) do
    Enum.frequencies_by(vectors, fn vector ->
      {:ok, info} = Message.describe(vector.ciphertext)
      info.algorithm_suite_id
    end)
  end

  defp committed(vectors), do: Enum.filter(vectors, &committed?/1)
  defp uncommitted(vectors), do: Enum.reject(vectors, &committed?/1)

  defp committed?(vector) do
    {:ok, info} = Message.describe(vector.ciphertext)
    info.committed?
  end
end
