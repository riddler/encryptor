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

  ## Every direction passes

  Every direction, profile and suite passes, both ways. On the 1.0.x engine
  two defects failed every direction but `:single` at 0x0478 both ways and
  Python to a `:single` vault at 0x0578; they were asserted here as known
  failures with their exact errors, and `aws_encryption_sdk` 1.1, which this
  package requires, fixes both. What the two were, for the record:

  **The stored required context.** The AWS Encryption SDK specification, at
  commit f95ae385f2e5388d0c5e1dca9d7b592e7329dc2a
  (awslabs/aws-encryption-sdk-specification), `client-apis/encrypt.md`,
  "Construct the header", the V2 header's AAD:

  > The value MUST be the serialization of the encryption context in the
  > encryption materials, and this serialization MUST NOT contain any key
  > value pairs listed in the encryption material's required encryption
  > context keys.

  A required key is authenticated but not stored. The 1.0.x engine stored it
  and also authenticated it, so a `:scoped` message (where `scope_ref` is
  always required) failed Python's header authentication. The other way,
  Python stores no `scope_ref` and wraps the data key under the full context,
  while the 1.0.x engine unwrapped under the stored context alone, so a
  `:scoped` vault could not open the data key. The 1.1 engine stores no
  required pair and appends the reproduced ones before it unwraps. Python's
  comparison of the context it reads back therefore covers the pairs the
  header stores; a required pair is checked by the decrypt itself, and this
  side asserts that the header Python reads stores no `scope_ref`.

  **The signature verification key's encoding.** On a signing suite (0x0578,
  this package's default) the 1.0.x engine wrote the ECDSA P-384
  verification key as an uncompressed point, where the specification
  (`framework/transitive-requirements.md`) requires the SEC 1 compressed
  form, and the Python SDK decodes only the compressed form. The 1.1 engine
  writes it compressed and still reads both forms.
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

  # direction, profile, suite => the expected outcome, for every plaintext.
  @expected %{
    {:to_python, :single, 0x0478} => :pass,
    {:to_python, :single, 0x0578} => :pass,
    {:to_python, :scoped, 0x0478} => :pass,
    {:to_python, :scoped, 0x0578} => :pass,
    {:from_python, :single, 0x0478} => :pass,
    {:from_python, :single, 0x0578} => :pass,
    {:from_python, :scoped, 0x0478} => :pass,
    {:from_python, :scoped, 0x0578} => :pass
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
  # sabotage: made the vault's decrypt append a byte to the plaintext
  # (Vault.Decrypt.engine_decrypt/5) - red, the twenty from_python tests.
  # sabotage: made interop.py compare every pair of the context against the
  # header it reads back, required ones included - red, the ten to_python
  # scoped tests, Python reporting context_mismatch: the header stores no
  # `scope_ref`.
  # sabotage: made the vault hand the engine only the stored pairs on decrypt
  # (Vault.Decrypt's engine_context/3 dropping its required-key clause) - red,
  # the ten from_python scoped tests, the reproduced `scope_ref` never reaching
  # the unwrap.
  for {direction, profile, suite} = row <- Enum.sort(Map.keys(@expected)),
      {label, _} <- @plaintexts do
    expected = Map.fetch!(@expected, row)
    id = "#{profile}_#{Integer.to_string(suite, 16) |> String.pad_leading(4, "0")}_#{label}"
    suite_hex = "0x" <> String.pad_leading(Integer.to_string(suite, 16), 4, "0")

    @tag case_id: id, direction: direction, expected: expected, profile: profile
    test "#{direction} #{profile} #{suite_hex} #{label}: passes", ctx do
      assert_case(ctx)
    end
  end

  # A `:scoped` message's header, as Python parses it, stores no `scope_ref`:
  # the required pair is authenticated and bound, not stored, both in what a
  # vault writes and in what Python writes.
  defp assert_case(
         %{direction: :to_python, case_id: id, expected: :pass, python_read: read} = ctx
       ) do
    result = Map.fetch!(read, id)

    assert %{"outcome" => "pass", "stored_context_keys" => stored} = result
    if ctx.profile == :scoped, do: refute("scope_ref" in stored)
  end

  defp assert_case(%{direction: :from_python} = ctx) do
    %{case_id: id, expected: expected, profile: profile, python_wrote: wrote, from_python: dir} =
      ctx

    %{suite: suite, plaintext: plaintext, context: context} = Enum.find(ctx.cases, &(&1.id == id))

    assert :pass = expected
    assert %{"outcome" => "pass", "stored_context_keys" => stored} = Map.fetch!(wrote, id)
    if profile == :scoped, do: refute("scope_ref" in stored)

    ciphertext = File.read!(Path.join(dir, id <> ".ct"))
    vault = Map.fetch!(@vaults, {profile, suite})

    assert {:ok, read_back} = vault.decrypt(ciphertext, call_opts(profile, context))
    assert read_back == plaintext
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
