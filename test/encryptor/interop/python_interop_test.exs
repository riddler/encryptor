defmodule Encryptor.PythonInteropTest do
  @moduledoc """
  Messages cross between this package and the AWS Encryption SDK for Python.

  Tagged `:python_interop`, which `test/test_helper.exs` excludes by default;
  CI's `python-interop` job runs it with `mix test --only python_interop`.
  `Encryptor.PythonInterop` says how to run it locally, and with
  `ENCRYPTOR_REQUIRE_PYTHON_INTEROP=1` (CI sets it) a missing interpreter
  fails this module rather than skipping it.

  The other side is the Python SDK 4.0.7 with the Material Providers Library,
  pinned by version and sha256 in `test/interop/python/requirements.txt`,
  under `REQUIRE_ENCRYPT_REQUIRE_DECRYPT`, with a raw AES keyring given the
  same namespace, name and key as the vaults' `Encryptor.Provider.Static`
  (`Encryptor.InteropVaults`). The key is generated for the run and never
  committed. For a `:scoped` vault Python wraps that keyring's default CMM in
  the required-encryption-context CMM with `scope_ref` required, and supplies
  the reference the vault would derive (`Encryptor.Envelope.scope_ref/2`) as
  the reproduced context.

  Four directions per suite, every case at 0x0478 and again at 0x0578:

    1. a `:single` vault encrypts and Python decrypts;
    2. Python encrypts and a `:single` vault decrypts;
    3. a `:scoped` vault encrypts and Python decrypts;
    4. Python encrypts and a `:scoped` vault decrypts.

  Each over five plaintexts: empty, one byte, exactly one frame (the engine's
  default frame of 4096 bytes), several frames, and a short plaintext under a
  caller context with non-ASCII keys and values. Python compares the plaintext
  and the context it reads back; this side compares the plaintext.

  ## What passes today, and the two known failures

  `:single` at 0x0478 passes both ways, and Python to a `:single` vault passes
  at 0x0578. Every other direction fails today because of one of two defects
  in the engine this package runs on (aws_encryption_sdk 1.0.x). Each is
  asserted here as a KNOWN failure with its exact error - not skipped, not
  deleted - so the day the engine is fixed these tests go red and are turned
  into passes, rather than the fix going unnoticed.

  **The stored required context.** The AWS Encryption SDK specification, at
  commit f95ae385f2e5388d0c5e1dca9d7b592e7329dc2a
  (awslabs/aws-encryption-sdk-specification), `client-apis/encrypt.md`,
  "Construct the header", the V2 header's AAD:

  > The value MUST be the serialization of the encryption context in the
  > encryption materials, and this serialization MUST NOT contain any key
  > value pairs listed in the encryption material's required encryption
  > context keys.

  A required key is authenticated but not stored. The engine stores it and
  also authenticates it, so a `:scoped` message (where `scope_ref` is always
  required) fails Python's header authentication. The other way, Python
  stores no `scope_ref` and wraps the data key under the full context, while
  the engine unwraps under the stored context alone, so a `:scoped` vault
  cannot open the data key. Directions 3 and 4.

  **The signature verification key's encoding.** On a signing suite (0x0578,
  this package's default) the engine writes the ECDSA P-384 verification key
  as an uncompressed point, where the specification
  (`framework/transitive-requirements.md`) requires the SEC 1 compressed
  form. The Python SDK decodes only the compressed form, so it cannot read any
  message the engine writes at 0x0578, `:single` or `:scoped`; this is the
  failure a 0x0578 `:scoped` message reaches first. The engine reads both
  forms, so Python to a `:single` vault at 0x0578 passes.
  """

  use ExUnit.Case, async: false

  alias Encryptor.InteropVaults
  alias Encryptor.PythonInterop

  @moduletag :python_interop

  unless PythonInterop.present?() or PythonInterop.required?() do
    @moduletag skip: PythonInterop.absent_message()
  end

  @frame 4096

  @plaintexts [
    empty: {"", %{}},
    one_byte: {"x", %{}},
    one_frame: {:binary.copy("0123456789abcdef", div(@frame, 16)), %{}},
    several_frames:
      {:binary.copy("0123456789abcdef", div(3 * @frame, 16)) <> "seventeen bytes!!", %{}},
    non_ascii_context: {"naïve plaintext ✓", %{"clé" => "valeur ✓", "名前" => "値 ünïcödé"}}
  ]

  @vaults %{
    {:single, 0x0478} => InteropVaults.Single0478,
    {:single, 0x0578} => InteropVaults.Single0578,
    {:scoped, 0x0478} => InteropVaults.Scoped0478,
    {:scoped, 0x0578} => InteropVaults.Scoped0578
  }

  # The selector every `:scoped` call uses. `Static` resolves it to the run's
  # one key; what it changes is the `scope_ref` in the context.
  @selector "interop-scope"

  # The exact errors the known failures are asserted with.
  @python_header_auth "aws_encryption_sdk.exceptions.SerializationError: Header authorization failed"
  @python_point_decode "builtins.KeyError: b'\\x04'"

  # direction, profile, suite => the expected outcome, for every plaintext.
  @expected %{
    {:to_python, :single, 0x0478} => :pass,
    {:to_python, :single, 0x0578} => {:python_error, @python_point_decode},
    {:to_python, :scoped, 0x0478} => {:python_error, @python_header_auth},
    {:to_python, :scoped, 0x0578} => {:python_error, @python_point_decode},
    {:from_python, :single, 0x0478} => :pass,
    {:from_python, :single, 0x0578} => :pass,
    {:from_python, :scoped, 0x0478} => {:vault_error, :unable_to_decrypt_data_key},
    {:from_python, :scoped, 0x0578} => {:vault_error, :unable_to_decrypt_data_key}
  }

  setup_all do
    # Reached without an interpreter only when one is required (CI): fail.
    unless PythonInterop.present?(), do: flunk(PythonInterop.absent_message())

    dir = Path.join(System.tmp_dir!(), "encryptor-interop-#{System.unique_integer([:positive])}")
    File.mkdir_p!(dir)
    on_exit(fn -> File.rm_rf!(dir) end)

    :ok = PythonInterop.generate_keys()
    for vault <- Map.values(@vaults), do: start_supervised!(vault)

    {:ok, scope_ref} =
      Encryptor.Envelope.scope_ref(PythonInterop.key(:reference_subkey), @selector)

    to_python = Path.join(dir, "to_python")
    from_python = Path.join(dir, "from_python")

    for side <- [to_python, from_python] do
      File.mkdir_p!(side)
      File.write!(Path.join(side, "key.bin"), PythonInterop.key(:wrapping_key))
    end

    cases = cases(scope_ref)

    for %{id: id, profile: profile, suite: suite, plaintext: plaintext, context: context} <- cases do
      vault = Map.fetch!(@vaults, {profile, suite})
      {:ok, ciphertext} = vault.encrypt(plaintext, call_opts(profile, context))
      File.write!(Path.join(to_python, id <> ".ct"), ciphertext)
      File.write!(Path.join(to_python, id <> ".pt"), plaintext)
      File.write!(Path.join(from_python, id <> ".pt"), plaintext)
    end

    write_cases(to_python, cases)
    write_cases(from_python, cases)

    {:ok, python_read} = PythonInterop.run("decrypt", to_python)
    {:ok, python_wrote} = PythonInterop.run("encrypt", from_python)

    %{
      cases: cases,
      python_read: python_read,
      python_wrote: python_wrote,
      from_python: from_python
    }
  end

  # The literal count: 2 profiles x 2 suites x 5 plaintexts, each way. A case
  # the script dropped, or one it invented, fails here.
  #
  # sabotage: made interop.py skip its last case - red, 19 results against 20.
  test "Python read and wrote all twenty cases", %{python_read: read, python_wrote: wrote} do
    assert map_size(read) == 20
    assert map_size(wrote) == 20
  end

  # One test per direction, profile, suite and plaintext, each asserting the
  # outcome @expected names for its row.
  #
  # sabotage: made the 0x0478 vault write suite 0x0578 (Vault.Encrypt.suite/1) -
  # red, the ten to_python 0x0478 tests get the point-decode error instead.
  # sabotage: made the vault's decrypt append a byte to the plaintext
  # (Vault.Decrypt.engine_decrypt/5) - red, the ten passing from_python tests.
  # sabotage: made the engine write the verification key compressed
  # (ECDSA.encode_public_key/1) - red, the ten to_python 0x0578 known failures.
  # sabotage: made the engine leave required keys out of the stored header
  # (HeaderAuth.build_header/4) - red, the five to_python scoped 0x0478 known
  # failures.
  # sabotage: made the engine's default CMM unwrap under the reproduced context
  # too (Cmm.Default.get_decryption_materials/2) - red, the ten from_python
  # scoped known failures.
  for {direction, profile, suite} = row <- Enum.sort(Map.keys(@expected)),
      {label, _} <- @plaintexts do
    expected = Map.fetch!(@expected, row)
    id = "#{profile}_#{Integer.to_string(suite, 16) |> String.pad_leading(4, "0")}_#{label}"
    known = if expected == :pass, do: "passes", else: "KNOWN FAILURE"
    suite_hex = "0x" <> String.pad_leading(Integer.to_string(suite, 16), 4, "0")

    @tag case_id: id, direction: direction, expected: expected, profile: profile
    test "#{direction} #{profile} #{suite_hex} #{label}: #{known}", ctx do
      assert_case(ctx)
    end
  end

  defp assert_case(%{direction: :to_python, case_id: id, expected: expected, python_read: read}) do
    result = Map.fetch!(read, id)

    case expected do
      :pass -> assert %{"outcome" => "pass"} = result
      {:python_error, error} -> assert %{"outcome" => "error", "error" => ^error} = result
    end
  end

  defp assert_case(%{direction: :from_python} = ctx) do
    %{case_id: id, expected: expected, profile: profile, python_wrote: wrote, from_python: dir} =
      ctx

    %{suite: suite, plaintext: plaintext, context: context} = Enum.find(ctx.cases, &(&1.id == id))

    assert %{"outcome" => "pass"} = Map.fetch!(wrote, id)

    ciphertext = File.read!(Path.join(dir, id <> ".ct"))
    vault = Map.fetch!(@vaults, {profile, suite})
    result = vault.decrypt(ciphertext, call_opts(profile, context))

    case expected do
      :pass ->
        assert {:ok, read_back} = result
        assert read_back == plaintext

      {:vault_error, engine} ->
        assert {:error,
                %Encryptor.Error{reason: :decrypt_failed, operation: :decrypt, engine: ^engine}} =
                 result
    end
  end

  defp cases(scope_ref) do
    for {profile, suite} <- Enum.sort(Map.keys(@vaults)),
        {label, {plaintext, context}} <- @plaintexts do
      suite_hex = String.pad_leading(Integer.to_string(suite, 16), 4, "0")

      %{
        id: "#{profile}_#{suite_hex}_#{label}",
        profile: profile,
        suite: suite,
        plaintext: plaintext,
        context: context,
        python_context:
          if(profile == :scoped, do: Map.put(context, "scope_ref", scope_ref), else: context),
        required_keys: if(profile == :scoped, do: ["scope_ref"], else: [])
      }
    end
  end

  defp write_cases(dir, cases) do
    spec = %{
      key_namespace: InteropVaults.namespace(),
      key_name: InteropVaults.name(),
      cases:
        Enum.map(cases, fn c ->
          %{
            id: c.id,
            suite: c.suite,
            encryption_context: c.python_context,
            required_keys: c.required_keys
          }
        end)
    }

    File.write!(Path.join(dir, "cases.json"), Jason.encode!(spec))
  end

  defp call_opts(:single, context), do: [encryption_context: context]
  defp call_opts(:scoped, context), do: [key: @selector, encryption_context: context]
end
