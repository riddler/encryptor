defmodule Encryptor.Vault.DecryptTest do
  use ExUnit.Case, async: false

  alias Encryptor.DecryptVaults
  alias Encryptor.EncryptVaults
  alias Encryptor.EngineReader
  alias Encryptor.Error
  alias Encryptor.Message
  alias Encryptor.Vault
  alias Encryptor.Vault.Config
  alias Encryptor.Vault.Decrypt
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
      "scope_ref",
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
    test "round trips on a scoped vault, with the pair the vault supplied itself" do
      vault = start_vault(EncryptVaults.Merchant)

      {:ok, ciphertext} =
        vault.encrypt(@pan, key: "merchant_a", encryption_context: @columns)

      assert {:ok, @pan} =
               vault.decrypt(ciphertext, key: "merchant_a", encryption_context: @columns)
    end

    # On the 1.1 engine the required pairs are bound to the message and not
    # stored in its header (ADR-0004 Amendment B); the engine reader opens it
    # under exactly the context the vault reproduces, and not under another
    # scope's reference.
    #
    # sabotage: passed `supplied: %{}` from Resolve.context/5 - red, because
    # the scope pair is then in neither the message nor the claim, and the
    # write the binding exists for is refused.
    test "the message the vault wrote is bound to the context the reader reproduces" do
      vault = start_vault(EncryptVaults.Merchant)

      {:ok, ciphertext} =
        vault.encrypt(@pan, key: "merchant_a", encryption_context: @columns)

      {:ok, info} = Message.describe(ciphertext)
      descriptor = EncryptVaults.merchant_descriptor("merchant_a")

      assert info.encryption_context == %{}

      assert {:ok, %{plaintext: @pan}} =
               EngineReader.read(ciphertext, descriptor, merchant_context("merchant_a"))

      assert {:error, _} =
               EngineReader.read(ciphertext, descriptor, merchant_context("merchant_b"))
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
    # The comparison covers every key the header stores (ADR-0004 decision 6,
    # kept unchanged by Amendment B's B2). On the 1.1 engine a stored key is an
    # advisory one; the `Cached` vault requires nothing, so its column is
    # stored.
    #
    # sabotage: inverted the comparison in compare/4 - red, the agreeing
    # `table` is then the key reported.
    test "a column swap inside one scope fails, and the engine's term shape is ours" do
      vault = start_vault(EncryptVaults.Cached)

      ciphertext = vault.encrypt!(@pan, encryption_context: @columns)

      result =
        vault.decrypt(ciphertext,
          encryption_context: %{"table" => "payment_methods", "column" => "notes"}
        )

      assert reason(result) == :decrypt_failed
      assert engine(result) == {:encryption_context_mismatch, "column"}
    end

    # The same swap after a legitimate read has populated the decryption
    # cache. The 1.1 engine's cache hit check refuses it too, so this pins the
    # outcome on a warm cache rather than which layer refuses; the direct test
    # of agree/4 below is the one that fails when the vault's comparison is
    # removed. sabotage: inverted the comparison in compare/4 - red, as above.
    test "the same swap fails on a warm decryption cache, which is the whole point" do
      vault = start_vault(EncryptVaults.Cached)

      ciphertext = vault.encrypt!(@pan, encryption_context: @columns)

      assert {:ok, @pan} = vault.decrypt(ciphertext, encryption_context: @columns)

      result =
        vault.decrypt(ciphertext,
          encryption_context: %{"table" => "payment_methods", "column" => "notes"}
        )

      assert reason(result) == :decrypt_failed
      assert engine(result) == {:encryption_context_mismatch, "column"}
    end

    # sabotage: made compare/4 answer :ok for every pair - red: the vault's own
    # comparison is then gone, which no read through the 1.1 engine shows,
    # since its cold read and its cache hit check both refuse the swap too.
    test "agree/4 refuses a stored pair the reader disagrees with, before the engine" do
      vault = start_vault(EncryptVaults.Cached)
      {:ok, config} = Config.fetch(vault)

      ciphertext = vault.encrypt!(@pan, encryption_context: @columns)
      swapped = %{"table" => "payment_methods", "column" => "notes"}

      assert Decrypt.agree(config, ciphertext, @columns) == :ok

      assert {:error, %Error{reason: :decrypt_failed} = error} =
               Decrypt.agree(config, ciphertext, swapped)

      assert error.engine == {:encryption_context_mismatch, "column"}
    end

    # A required pair is bound, not stored, so a swap of it is refused by the
    # engine's unwrap on a cold read (ADR-0004 Amendment B, B2's first bullet).
    # sabotage: handed the engine only the stored pairs (engine_context/3
    # dropping the `key in required` clause) - red, the read then reports the
    # missing pairs instead of a refused value.
    test "a column swap on a required column fails on a cold read" do
      vault = start_vault(EncryptVaults.Bound)

      ciphertext = vault.encrypt!(@pan, encryption_context: @columns)

      result =
        vault.decrypt(ciphertext,
          encryption_context: %{"table" => "payment_methods", "column" => "notes"}
        )

      assert reason(result) == :decrypt_failed
    end

    # The same swap of a required pair after a legitimate read has populated
    # the decryption cache: the cache id hashes the stored context, which no
    # longer carries the column, so it is the engine's hit check that refuses
    # (ADR-0004 Amendment B, B2's second bullet; engine issue #96). sabotage:
    # the same engine_context/3 change - red, as above.
    test "a column swap on a required column fails on a warm decryption cache" do
      vault = start_vault(EncryptVaults.Merchant)

      ciphertext =
        vault.encrypt!(@pan, key: "merchant_a", encryption_context: @columns)

      assert {:ok, @pan} =
               vault.decrypt(ciphertext, key: "merchant_a", encryption_context: @columns)

      result =
        vault.decrypt(ciphertext,
          key: "merchant_a",
          encryption_context: %{"table" => "payment_methods", "column" => "notes"}
        )

      assert reason(result) == :decrypt_failed

      assert {:ok, @pan} =
               vault.decrypt(ciphertext, key: "merchant_a", encryption_context: @columns)
    end

    # ADR-0004 Amendment B, B3: decision 6's "a claim the message does not
    # carry is ignored", on a message whose required pairs are not stored.
    # sabotage: made engine_context/3 return the whole reproduced context -
    # red, the engine appends the extra key, the unwrap under it fails, its
    # retry under the stored context alone fails too, and the read is refused.
    test "an extra claim beside the required pairs is ignored" do
      vault = start_vault(EncryptVaults.Bound)

      ciphertext = vault.encrypt!(@pan, encryption_context: @columns)
      claim = Map.put(@columns, "purpose", "pii")

      assert {:ok, @pan} = vault.decrypt(ciphertext, encryption_context: claim)
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

    # The two tests below pin where the binding stops, as the threat model
    # states it: a key binds a message only when the writer passed it, which
    # `:required_context` is the way to guarantee.
    #
    # sabotage: replaced `Map.get(stored, key, value)` with `Map.get(stored, key)`
    # in compare/4 - red on the first read, which then fails as a mismatch.
    test "a message written without a column reads under any column claim" do
      vault = start_vault(DecryptVaults.Loose)

      unbound = vault.encrypt!(@pan, encryption_context: %{"table" => "payment_methods"})
      bound = vault.encrypt!(@pan, encryption_context: @columns)
      moved = %{"table" => "payment_methods", "column" => "notes"}

      assert {:ok, @pan} = vault.decrypt(unbound, encryption_context: @columns)
      assert {:ok, @pan} = vault.decrypt(unbound, encryption_context: moved)

      assert engine(vault.decrypt(bound, encryption_context: moved)) ==
               {:encryption_context_mismatch, "column"}
    end

    # sabotage: made maybe_required/2 in encrypt.ex return the CMM unwrapped for
    # every config - red, because the requiring reader then opens the message.
    test "a vault requiring the column refuses a message written without it" do
      writer = start_vault(DecryptVaults.Loose)
      reader = start_vault(DecryptVaults.Retired)

      unbound = writer.encrypt!(@pan, encryption_context: %{"table" => "payment_methods"})
      result = reader.decrypt(unbound, encryption_context: @columns)

      assert {:error, %Error{reason: :decrypt_failed}} = result
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

    # On the 1.1 engine the writer's required pairs are not stored, and the
    # reader hands the engine only the pairs its own required set names
    # (Amendment B's B3), so a reader that does not require them cannot open
    # the message even when it claims them. sabotage: returned `{:ok, ""}`
    # from engine_result/3's error clause - red, because a failed read is
    # exactly the failure that must never come back as a plausible-looking
    # value.
    test "a reader whose required set differs from the writer's fails authentication" do
      writer = start_vault(EncryptVaults.Bound)
      reader = start_vault(DecryptVaults.Unbound)

      ciphertext = writer.encrypt!(@pan, encryption_context: @columns)
      result = reader.decrypt(ciphertext, encryption_context: @columns)

      assert reason(result) == :decrypt_failed
    end
  end

  describe "the suite a message was written under" do
    # Pins where signing stops, as the threat model states it: the configured
    # `:algorithm_suite_id` is the suite a vault writes, and decrypt reads a
    # message under whichever of the two accepted suites it names.
    #
    # sabotage: made agree/4 in decrypt.ex refuse a message whose suite differs
    # from the configured one - red, on the signing vault's read.
    test "a signing-suite vault reads an unsigned message under the same key" do
      writer = start_vault(DecryptVaults.Loose)
      reader = start_vault(EncryptVaults.App)

      ciphertext = writer.encrypt!(@pan, encryption_context: @columns)

      assert {:ok, %Message.Info{algorithm_suite_id: 0x0478}} = Message.describe(ciphertext)
      assert {:ok, %Config{algorithm_suite_id: 0x0578}} = Config.fetch(reader)
      assert {:ok, @pan} = reader.decrypt(ciphertext, encryption_context: @columns)
    end
  end

  describe "an engine return outside its contract" do
    # The 1.1 engine answers a message followed by trailing bytes inside its
    # contract, with `{:error, :trailing_bytes}`. sabotage: carried `:other`
    # in `:engine` from engine_result/3's error clause - red.
    test "a message followed by one trailing byte is decrypt_failed" do
      vault = start_vault(EncryptVaults.App)

      {:ok, ciphertext} = vault.encrypt(@pan)
      result = vault.decrypt(ciphertext <> <<0>>)

      assert {:error,
              %Error{
                reason: :decrypt_failed,
                vault: EncryptVaults.App,
                operation: :decrypt,
                engine: :trailing_bytes
              }} = result
    end

    # The 1.0.x engine's answer to the same message, a three-element tuple
    # holding the parsed message, handed to the mapping directly since no
    # engine this package accepts returns it now. sabotage: carried the
    # engine's own return in `:engine` from engine_result/3's catch-all
    # instead of `:unexpected_engine_result` - red, because the parsed message
    # then rides into every log line that inspects the error. Deleting the
    # clause is red too, with a CaseClauseError.
    test "a return outside the pair is decrypt_failed, carrying no engine term" do
      vault = start_vault(EncryptVaults.App)
      {:ok, config} = Config.fetch(vault)

      result = Decrypt.engine_result({:ok, %{parsed: :message}, <<0>>}, config, :decrypt)

      assert {:error,
              %Error{
                reason: :decrypt_failed,
                vault: EncryptVaults.App,
                operation: :decrypt,
                engine: :unexpected_engine_result
              }} = result
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
    # caller's `scope_ref` is then no longer colliding with the vault's and a
    # second way to claim a scope reopens.
    test "a caller cannot claim a scope through the context" do
      vault = start_vault(EncryptVaults.Merchant)

      ciphertext =
        vault.encrypt!(@pan, key: "merchant_a", encryption_context: @columns)

      result =
        vault.decrypt(ciphertext,
          key: "merchant_a",
          encryption_context: merchant_context("merchant_b")
        )

      assert reason(result) == {:reserved_context_key, "scope_ref"}
    end

    # sabotage: gave Resolve.selector/3's :scoped clause a `:default` arm - red,
    # because a scoped vault would then read under a selector no write could use.
    test "a scoped vault refuses a read that names no scope, before the provider" do
      vault = start_vault(EncryptVaults.Merchant)

      assert reason(vault.decrypt("not a message")) == {:invalid_selector, :default}
    end

    # sabotage: gave Resolve.selector/3's :single clause a binary arm - red,
    # because a per-scope selector would then silently resolve the one key.
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
