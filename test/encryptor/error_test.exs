defmodule Encryptor.ErrorTest do
  use ExUnit.Case, async: true

  alias Encryptor.Error

  doctest Encryptor.Error

  # The engine terms an ESDK decrypt can fail with, plus the vault's own
  # context-mismatch term (ADR-0004 decision 8 moves that check above the
  # engine and shapes the term the same way).
  @message_dependent_failures [
    {:encryption_context_mismatch, "tenant_ref"},
    {:encryption_context_mismatch, "column"},
    {:required_keys_not_in_decryption_context, ["table", "column"]},
    :authentication_failed,
    :commitment_policy_violated,
    {:no_matching_encrypted_data_key, :any},
    :header_parse_failed
  ]

  describe "the struct" do
    # sabotage: dropped :engine from the defexception field list - red, at
    # compile time, because the struct literal below names the field.
    test "carries reason, vault, operation and engine" do
      error = %Error{
        reason: {:unknown_key, "tenant_a"},
        vault: MyApp.Vault,
        operation: :encrypt,
        engine: nil
      }

      assert %Error{
               reason: {:unknown_key, "tenant_a"},
               vault: MyApp.Vault,
               operation: :encrypt,
               engine: nil
             } = error
    end

    # sabotage: changed defexception to defstruct - red on both asserts.
    test "is an exception a bang variant can raise" do
      assert Exception.exception?(%Error{reason: :decrypt_failed})

      assert_raise Error, "decryption failed", fn ->
        raise %Error{reason: :decrypt_failed}
      end
    end
  end

  describe "the oracle rule" do
    # sabotage: made decrypt_failed/3 pass the engine term through as the
    # reason - red for every entry in the table.
    test "every message-dependent decrypt failure collapses to :decrypt_failed" do
      for engine_term <- @message_dependent_failures do
        error = Error.decrypt_failed(MyApp.Vault, :decrypt, engine_term)

        assert %Error{reason: :decrypt_failed, operation: :decrypt} = error
      end
    end

    # sabotage: had decrypt_failed/3 store `inspect(engine)` in :engine - red.
    test "carries the engine term in :engine unchanged" do
      for engine_term <- @message_dependent_failures do
        assert %Error{engine: ^engine_term} =
                 Error.decrypt_failed(MyApp.Vault, :decrypt, engine_term)
      end
    end

    # sabotage: appended `<> inspect(error.engine)` to message/1 - red.
    test "never leaks the engine term into the rendered message" do
      for engine_term <- @message_dependent_failures do
        message = Error.message(Error.decrypt_failed(MyApp.Vault, :decrypt, engine_term))

        assert message == "decryption failed (MyApp.Vault, decrypt)"
      end
    end

    # sabotage: widened the guard to `is_atom(operation)` - red.
    test "refuses an operation that has no decrypt half" do
      assert_raise FunctionClauseError, fn ->
        Error.decrypt_failed(MyApp.Vault, :encrypt, :whatever)
      end
    end

    # sabotage: gave rekey the :decrypt operation - red.
    test "a rekey failure is reported as :rekey" do
      assert %Error{reason: :decrypt_failed, operation: :rekey} =
               Error.decrypt_failed(MyApp.Vault, :rekey, :authentication_failed)
    end
  end

  describe "message/1" do
    # sabotage: dropped the {:invalid_config, _, _} clause - red (and every
    # other row in the table with its own clause removed).
    test "renders every term in the vocabulary" do
      cases = [
        {:decrypt_failed, "decryption failed"},
        {{:vault_not_started, MyApp.Vault}, "vault MyApp.Vault is not started"},
        {{:missing_config, [:my_app, MyApp.Vault]},
         "missing configuration at [:my_app, MyApp.Vault]"},
        {{:invalid_config, :commitment_policy, :bogus},
         "invalid configuration for :commitment_policy"},
        {{:unknown_key, "tenant_a"}, ~s(no key for selector "tenant_a")},
        {{:encryption_context_conflict, "table"},
         ~s(caller-supplied encryption context conflicts on key "table")},
        {{:reserved_context_key, "aws-crypto-public-key"},
         ~s(encryption context key "aws-crypto-public-key" is reserved)},
        {{:key_unavailable, "tenant_a"}, ~s(key for selector "tenant_a" is unavailable)},
        {{:invalid_key_descriptor, :anything},
         "the provider returned a key descriptor this vault cannot use"},
        {{:provider_not_started, MyApp.Provider}, "provider MyApp.Provider is not started"},
        {{:missing_optional_dependency, :ecto}, "missing optional dependency :ecto"},
        {{:missing_required_context_keys, ["tenant_ref"]},
         ~s(missing required encryption context keys ["tenant_ref"])},
        {{:invalid_context_value, :count}, "the encryption context has too many entries"},
        {{:invalid_context_value, :too_large}, "the encryption context is too large"},
        {{:invalid_context_value, "column"}, ~s(invalid encryption context value for "column")},
        {{:invalid_selector, :default},
         "invalid selector :default for this vault's context profile"}
      ]

      for {reason, expected} <- cases do
        assert Error.message(%Error{reason: reason}) == expected
      end
    end

    # sabotage: rendered the detail of {:invalid_config, key, detail} and of
    # {:invalid_key_descriptor, detail} - red.
    test "never renders a detail that could hold key material" do
      key_shaped = :binary.copy(<<0xAB>>, 32)

      for reason <- [
            {:invalid_config, :static_key, key_shaped},
            {:invalid_key_descriptor, %{material: key_shaped}}
          ] do
        message = Error.message(%Error{reason: reason})

        refute message =~ "171"
        refute message =~ "0xAB"
        refute message =~ inspect(key_shaped)
      end
    end

    # sabotage: made where/1 return "" for every clause - red on three rows.
    test "names the vault and the operation when they are known" do
      assert Error.message(%Error{reason: :decrypt_failed}) == "decryption failed"

      assert Error.message(%Error{reason: :decrypt_failed, operation: :decrypt}) ==
               "decryption failed (decrypt)"

      assert Error.message(%Error{reason: :decrypt_failed, vault: MyApp.Vault}) ==
               "decryption failed (MyApp.Vault)"

      assert Error.message(%Error{
               reason: :decrypt_failed,
               vault: MyApp.Vault,
               operation: :start
             }) == "decryption failed (MyApp.Vault, start)"
    end
  end

  describe "the vocabulary is closed" do
    # sabotage: added a fifteenth term to reason/0 - red. This test exists so
    # that a later bead extending the vocabulary without an ADR trips over it.
    test "reason/0 is exactly the fourteen terms the accepted records fix" do
      assert union_size(:reason) == 14
    end

    # sabotage: added :describe to operation/0 - red. ADR-0001 decision 10
    # fixes four operations; enc-o1x may need a fifth, via a record.
    test "operation/0 is exactly the four ADR-0001 fixes" do
      assert union_size(:operation) == 4
    end
  end

  defp union_size(name) do
    {:ok, types} = Code.Typespec.fetch_types(Error)

    {_kind, {^name, {:type, _line, :union, members}, []}} =
      Enum.find(types, fn {_kind, {type_name, _def, _args}} -> type_name == name end)

    length(members)
  end
end
