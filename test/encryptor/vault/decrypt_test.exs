defmodule Encryptor.Vault.DecryptTest do
  use ExUnit.Case, async: false

  alias Encryptor.DecryptVaults
  alias Encryptor.EncryptVaults
  alias Encryptor.Error
  alias Encryptor.Message
  alias Encryptor.Vault
  alias Encryptor.Vault.Reference

  @pan "4111111111111111"
  @columns %{"table" => "payment_methods", "column" => "pan"}

  defp start_vault(vault) do
    start_supervised!(Supervisor.child_spec({vault, []}, restart: :temporary))
    vault
  end

  defp merchant_context(selector) do
    Map.put(
      @columns,
      "tenant_ref",
      Reference.derive(EncryptVaults.reference_subkey(), selector)
    )
  end

  defp reason({:error, %Error{reason: reason}}), do: reason
  defp engine({:error, %Error{engine: engine}}), do: engine

  describe "the round trip against the landed encrypt path" do
    # sabotage: returned the engine's whole `decrypt_result` instead of its
    # `plaintext` from engine_decrypt/4 - red, because a caller then holds the
    # header and the verified context beside the one value it asked for.
    test "returns the plaintext and nothing else" do
      vault = start_vault(EncryptVaults.App)

      {:ok, ciphertext} = vault.encrypt(@pan)

      assert {:ok, @pan} = vault.decrypt(ciphertext)
    end

    # sabotage: inverted the value comparison in compare/4 so agreement is what
    # fails - red, and red on the second read too, which is the read the engine's
    # own comparison would not have seen.
    test "round trips through a vault that caches materials" do
      vault = start_vault(EncryptVaults.Cached)

      {:ok, ciphertext} = vault.encrypt(@pan, encryption_context: @columns)

      assert {:ok, @pan} = vault.decrypt(ciphertext, encryption_context: @columns)
      assert {:ok, @pan} = vault.decrypt(ciphertext, encryption_context: @columns)
    end

    # sabotage: read with a bare Default CMM instead of Encrypt.client/3's stack -
    # red, because this engine mixes the required subset of the context into the
    # header AAD and a reader that does not know it fails authentication.
    test "round trips on a tenant vault, with the pair the vault supplied itself" do
      vault = start_vault(EncryptVaults.Merchant)

      {:ok, ciphertext} =
        vault.encrypt(@pan, key: "merchant_a", encryption_context: @columns)

      assert {:ok, @pan} =
               vault.decrypt(ciphertext, key: "merchant_a", encryption_context: @columns)
    end

    # sabotage: passed `supplied: %{}` from Resolve.context/4 - red, because the
    # tenant pair is then in neither the message nor the claim, and the binding
    # the whole tenant profile exists for is gone.
    test "the message the vault wrote carries the context the reader reproduces" do
      vault = start_vault(EncryptVaults.Merchant)

      {:ok, ciphertext} =
        vault.encrypt(@pan, key: "merchant_a", encryption_context: @columns)

      {:ok, info} = Message.describe(ciphertext)

      assert info.encryption_context == merchant_context("merchant_a")
    end

    # sabotage: returned the engine's whole result map from engine_decrypt/4 -
    # red, since the bang variant unwraps whatever the non-bang one returns.
    test "decrypt! returns the plaintext" do
      vault = start_vault(EncryptVaults.App)

      assert @pan == vault.decrypt!(vault.encrypt!(@pan))
    end

    # sabotage: made the generated decrypt!/2 match `{:ok, plaintext}` instead of
    # raising - red with a MatchError rather than the Encryptor.Error a rescue
    # clause is written against.
    test "decrypt! raises the struct decrypt/2 would have returned" do
      vault = start_vault(EncryptVaults.Bound)

      ciphertext = vault.encrypt!(@pan, encryption_context: @columns)

      error = assert_raise Error, fn -> vault.decrypt!(ciphertext) end

      assert error.reason == {:missing_required_context_keys, ["table", "column"]}
      assert error.operation == :decrypt
    end
  end

  describe "the candidate list" do
    # sabotage: built one keyring from `hd(candidates)` instead of
    # Keyring.build_all/3 - red, because the Multi walk is the whole rotation
    # mechanism and the outgoing key is never the newest.
    test "reads a message written under a retired key" do
      writer = start_vault(DecryptVaults.Retired)
      reader = start_vault(EncryptVaults.Bound)

      ciphertext = writer.encrypt!(@pan, encryption_context: @columns)

      assert {:ok, @pan} = reader.decrypt(ciphertext, encryption_context: @columns)
    end

    # sabotage: returned `{:ok, ""}` from engine_decrypt/4's catch-all - red,
    # which is the rescue-to-default this package is not allowed to have.
    test "a message whose key is not in the candidate list is decrypt_failed" do
      writer = start_vault(EncryptVaults.Bound)
      reader = start_vault(DecryptVaults.Retired)

      ciphertext = writer.encrypt!(@pan, encryption_context: @columns)
      result = reader.decrypt(ciphertext, encryption_context: @columns)

      assert reason(result) == :decrypt_failed
      refute engine(result) == nil
    end

    # sabotage: moved agree/4 above the provider in call/3 - red, because the
    # unresolvable selector then collapses to :decrypt_failed and an operator is
    # sent looking for corruption instead of a key store.
    test "a provider that cannot resolve the selector stays distinct from a bad message" do
      vault = start_vault(EncryptVaults.Merchant)

      result = vault.decrypt("not a message", key: "merchant_z", encryption_context: @columns)

      assert reason(result) == {:unknown_key, "merchant_z"}
    end

    # sabotage: made provider_reason?/1 answer true for anything - red, because
    # the provider's own term is then promoted into the closed reason vocabulary.
    test "a provider answering outside its contract is named as a provider defect" do
      vault = start_vault(EncryptVaults.OffContract)

      result = vault.decrypt("not a message")

      assert reason(result) == {:invalid_key_descriptor, :provider_off_contract}
      assert engine(result) == :weird_and_unenumerated
    end

    # sabotage: moved agree/4 above the provider in call/3 - red, because the
    # provider is then never asked and its defect never surfaces.
    test "a provider answering with something that is not a result is the same defect" do
      vault = start_vault(EncryptVaults.Silent)

      result = vault.decrypt("not a message")

      assert reason(result) == {:invalid_key_descriptor, :provider_off_contract}
      assert engine(result) == :i_have_no_idea
    end
  end

  describe "the vault-side reproduced-context value check" do
    # sabotage: inverted the comparison in compare/4 - red. Note this one is red
    # for the cold read only; the warm-cache test below is the one that fails
    # when the check is removed outright.
    test "a column swap inside one tenant fails, and the engine's term shape is ours" do
      vault = start_vault(EncryptVaults.Bound)

      ciphertext = vault.encrypt!(@pan, encryption_context: @columns)

      result =
        vault.decrypt(ciphertext,
          encryption_context: %{"table" => "payment_methods", "column" => "notes"}
        )

      assert reason(result) == :decrypt_failed
      assert engine(result) == {:encryption_context_mismatch, "column"}
    end

    # sabotage: dropped the agree/4 step from call/3's with-chain - red, and red
    # here ALONE of the whole project suite (301 tests, 42 doctests, checked):
    # with the check gone the engine still catches the cold read one layer down,
    # so every other test stays green and this one returns `{:ok, @pan}` to a
    # reader claiming a column the message was never bound to. That is upstream
    # issue #96 reproduced, and it is the reason the step exists. Deleting it
    # would look free from the suite; it is not.
    test "the same swap fails on a warm decryption cache, which is the whole point" do
      vault = start_vault(EncryptVaults.Merchant)

      ciphertext =
        vault.encrypt!(@pan, key: "merchant_a", encryption_context: @columns)

      # The legitimate read that populates the decryption cache. The cache id
      # is derived from the message's own stored context, so the read below
      # hits this entry and never reaches the CMM the engine's own comparison
      # lives in.
      assert {:ok, @pan} =
               vault.decrypt(ciphertext, key: "merchant_a", encryption_context: @columns)

      result =
        vault.decrypt(ciphertext,
          key: "merchant_a",
          encryption_context: %{"table" => "payment_methods", "column" => "notes"}
        )

      assert reason(result) == :decrypt_failed
      assert engine(result) == {:encryption_context_mismatch, "column"}
    end

    # sabotage: replaced `Map.get(stored, key, value)` with `Map.get(stored, key)`
    # in compare/4 - red, because a reader's extra key then reads as a mismatch
    # and the comparison stops matching the engine's semantics.
    test "a claim the message does not carry is ignored" do
      vault = start_vault(DecryptVaults.Loose)

      ciphertext = vault.encrypt!(@pan)

      assert {:ok, @pan} = vault.decrypt(ciphertext, encryption_context: @columns)
    end

    # sabotage: walked `stored` instead of `reproduced` in compare/4, requiring
    # the claim to cover the message - red, and it would make every stored row
    # unreadable the moment a host added an advisory static key.
    test "a key the message carries that the reader omits is ignored" do
      vault = start_vault(DecryptVaults.Loose)

      ciphertext = vault.encrypt!(@pan, encryption_context: %{"blob" => "settlement_export"})

      assert {:ok, @pan} = vault.decrypt(ciphertext)
    end

    # sabotage: sorted the reproduced context `:desc` in compare/4 - red, because
    # the reported key then depends on ordering rather than on the context.
    test "two disagreeing keys name the same one on every run" do
      vault = start_vault(DecryptVaults.Loose)

      ciphertext = vault.encrypt!(@pan, encryption_context: @columns)

      result =
        vault.decrypt(ciphertext,
          encryption_context: %{"table" => "receipts", "column" => "notes"}
        )

      assert engine(result) == {:encryption_context_mismatch, "column"}
    end

    # sabotage: dropped the engine's parse term from agree/4's unreadable-header
    # branch - red, because an operator then has a failure with no detail at all.
    test "a message this package cannot parse is decrypt_failed, carrying the parse term" do
      vault = start_vault(DecryptVaults.Loose)

      result = vault.decrypt("not an ESDK message")

      assert reason(result) == :decrypt_failed
      assert engine(result) == {:unsupported_version, 110}
      assert %Error{vault: DecryptVaults.Loose, operation: :decrypt} = elem(result, 1)
    end

    # sabotage: returned `{:ok, ""}` from engine_decrypt/4's catch-all - red,
    # because a header-authentication failure is exactly the failure that must
    # never come back as a plausible-looking value.
    test "a reader whose required set differs from the writer's fails authentication" do
      writer = start_vault(EncryptVaults.Bound)
      reader = start_vault(DecryptVaults.Unbound)

      ciphertext = writer.encrypt!(@pan, encryption_context: @columns)
      result = reader.decrypt(ciphertext, encryption_context: @columns)

      assert reason(result) == :decrypt_failed
    end
  end

  describe "the failure mapping of ADR-0004 decision 8" do
    # sabotage: collapsed the missing-required-keys clause into engine_decrypt/4's
    # catch-all - red, because the one context failure a caller can act on then
    # arrives as the same opaque :decrypt_failed as everything else.
    test "a reader that supplies no context at all is a loud, fixable error" do
      vault = start_vault(EncryptVaults.Bound)

      ciphertext = vault.encrypt!(@pan, encryption_context: @columns)
      result = vault.decrypt(ciphertext)

      assert reason(result) == {:missing_required_context_keys, ["table", "column"]}
    end

    # sabotage: passed `supplied: %{}` from Resolve.context/4 - red, because the
    # caller's `tenant_ref` is then no longer colliding with the vault's and a
    # second way to claim a tenant reopens.
    test "a caller cannot claim a tenant through the context" do
      vault = start_vault(EncryptVaults.Merchant)

      ciphertext =
        vault.encrypt!(@pan, key: "merchant_a", encryption_context: @columns)

      result =
        vault.decrypt(ciphertext,
          key: "merchant_a",
          encryption_context: merchant_context("merchant_b")
        )

      assert reason(result) == {:reserved_context_key, "tenant_ref"}
    end

    # sabotage: gave Resolve.selector/3's :tenant clause a `:default` arm - red,
    # because a tenant vault would then read under a selector no write could use.
    test "a tenant vault refuses a read that names no tenant, before the provider" do
      vault = start_vault(EncryptVaults.Merchant)

      assert reason(vault.decrypt("not a message")) == {:invalid_selector, :default}
    end

    # sabotage: gave Resolve.selector/3's :single clause a binary arm - red,
    # because a per-tenant selector would then silently resolve the one key.
    test "a single-key vault refuses a read that names one" do
      vault = start_vault(DecryptVaults.Loose)

      assert reason(vault.decrypt("not a message", key: "merchant_a")) ==
               {:invalid_selector, "merchant_a"}
    end

    # sabotage: called `Vault.ready(vault, :encrypt)` from call/3 - red, because
    # an operator reading the log line is then told the wrong call failed.
    test "a vault that is not running is a typed error stamped with the operation" do
      result = EncryptVaults.Unstarted.decrypt("not a message")

      assert reason(result) == {:vault_not_started, EncryptVaults.Unstarted}
      assert %Error{operation: :decrypt} = elem(result, 1)
    end

    # sabotage: hardcoded `operation: :encrypt` in Resolve.context/4 - red, for
    # the same reason: the stamp is what says which call failed.
    test "a non-string context value is refused before any message is read" do
      vault = start_vault(DecryptVaults.Loose)

      result = vault.decrypt("not a message", encryption_context: %{"table" => :customers})

      assert reason(result) == {:invalid_context_value, "table"}
      assert %Error{operation: :decrypt} = elem(result, 1)
    end

    # sabotage: hardcoded `operation: :encrypt` in Resolve.context/4 - red.
    test "a per-call key conflicting with the static context is refused" do
      vault = start_vault(EncryptVaults.Cached)

      result = vault.decrypt("not a message", encryption_context: %{"app" => "someone_else"})

      assert reason(result) == {:encryption_context_conflict, "app"}
      assert %Error{operation: :decrypt} = elem(result, 1)
    end
  end

  describe "the door" do
    # sabotage: made the generated decrypt/2 pass `[]` instead of `opts` - red,
    # because the reproduced context and the selector both arrive that way and a
    # read that dropped them would return plaintext for a claim nobody made.
    test "the generated function carries the caller's options through unchanged" do
      vault = start_vault(EncryptVaults.App)

      ciphertext = vault.encrypt!(@pan, encryption_context: @columns)
      opts = [encryption_context: %{"table" => "payment_methods", "column" => "notes"}]

      # The same call spelled both ways, with an option that decides the
      # answer: a generated function that dropped `opts` would return the
      # plaintext here rather than the refusal.
      assert vault.decrypt(ciphertext, opts) ==
               Vault.decrypt(EncryptVaults.App, ciphertext, opts)

      assert reason(vault.decrypt(ciphertext, opts)) == :decrypt_failed
    end

    # sabotage: dropped the `is_binary/1` guard from Vault.decrypt/3 and coerced
    # with `to_string/1` - red, because a source-level mistake then becomes a
    # runtime error term the closed vocabulary was never meant to describe.
    test "a ciphertext that is not a binary is wrong in the source, not at runtime" do
      start_vault(EncryptVaults.App)

      assert_raise FunctionClauseError, fn -> EncryptVaults.App.decrypt(:not_a_binary) end
    end
  end
end
