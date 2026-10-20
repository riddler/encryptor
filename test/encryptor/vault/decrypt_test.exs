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

  # A plaintext with no meaning, for the tests that need one.
  @value "a value to keep"

  defp start_vault(vault, opts \\ []) do
    start_supervised!(Supervisor.child_spec({vault, opts}, restart: :temporary))
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
    # `plaintext` from engine_result/3 - red, because a caller then holds the
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

    # sabotage: returned the engine's whole result map from engine_result/3 -
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

    # sabotage: returned `{:ok, ""}` from engine_result/3's catch-all - red,
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

    # sabotage: dropped the `:provision` guard from the `{:key_name_in_use, _}`
    # clause of Resolve.in_contract/3 - red, because a provider's re-mint
    # refusal from `decryption_keys/2` is then reported as a settled answer
    # when the term is in contract on the provision path only.
    test "a re-mint refusal from decryption_keys is a provider defect" do
      vault = start_vault(EncryptVaults.RemintingVault)

      result = vault.decrypt("not a message")

      assert reason(result) == {:invalid_key_descriptor, :provider_off_contract}
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
    # cache. On the 1.1 engine a disagreeing hit goes cold and the cold unwrap
    # refuses it (ADR-0004, Note "on the 1.1.0 engine a disagreeing warm read
    # goes cold, and the cold unwrap refuses it"), so this pins the outcome on
    # a warm cache rather than which layer refuses; the direct test
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
    # since a disagreeing hit goes cold there and the cold unwrap refuses the
    # swap too (the same ADR-0004 Note).
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
    # longer carries the column, so the engine's hit check does not serve the
    # hit: it goes cold and the cold unwrap refuses (ADR-0004, Note "on the
    # 1.1.0 engine a disagreeing warm read goes cold, and the cold unwrap
    # refuses it"; engine issue #96). sabotage:
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
    # This test pinned that read under the default until ADR-0004 Amendment C
    # made it the `legacy_context: :accept` arm; it keeps the read, scoped to
    # that arm, which is the one where B3's filter still decides it.
    #
    # sabotage: made engine_context/3 return the whole reproduced context -
    # red, the engine appends the extra key, the unwrap under it fails, its
    # retry under the stored context alone fails too, and the read is refused.
    test "an extra claim beside the required pairs is ignored under legacy_context: :accept" do
      vault = start_vault(EncryptVaults.Bound, legacy_context: :accept)

      ciphertext = vault.encrypt!(@pan, encryption_context: @columns)
      claim = Map.put(@columns, "purpose", "pii")

      assert {:ok, @pan} = vault.decrypt(ciphertext, encryption_context: claim)
    end

    # This test pinned that read under the default until ADR-0004 Amendment C
    # made it the `legacy_context: :accept` arm; it keeps the read, scoped to
    # that arm.
    #
    # sabotage: replaced `Map.get(stored, key, value)` with `Map.get(stored, key)`
    # in compare/5 - red, because a reader's extra key then reads as a mismatch
    # and the comparison stops matching the engine's semantics.
    test "a claim the message does not carry is ignored under legacy_context: :accept" do
      vault = start_vault(DecryptVaults.Loose, legacy_context: :accept)

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

    # The two tests below pinned where the binding stopped before ADR-0004
    # Amendment C: a key bound a message only when the writer passed it. The
    # first is now the `legacy_context: :accept` arm, kept and scoped to it
    # (it was "a message written without a column reads under any column
    # claim"); the default's refusal is pinned in "a per-call key the
    # message does not carry", below. The second is unchanged: a key the
    # vault requires is checked as before.
    #
    # sabotage: replaced `Map.get(stored, key, value)` with `Map.get(stored, key)`
    # in compare/5 - red on the first read, which then fails as a mismatch.
    test "a message written without a column reads under any column claim under :accept" do
      vault = start_vault(DecryptVaults.Loose, legacy_context: :accept)

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

  describe "a per-call key the message does not carry" do
    # ADR-0004 Amendment C, as ruled by the operator, 2026-10-19: decrypt
    # refuses a key the caller passes in this call's `:encryption_context`
    # when the message's stored context lacks it, unless the vault's
    # `:legacy_context` is `:accept`. A key the vault requires is checked as
    # before, and a key from the static layer is still ignored.

    # sabotage: made unstored_per_call_key/3 answer nil for every config -
    # red, the claim the writer never passed is read.
    test "is refused by default, as a disagreeing value is" do
      vault = start_vault(DecryptVaults.Loose)
      assert {:ok, %Config{legacy_context: :refuse}} = Config.fetch(vault)

      unbound = vault.encrypt!(@pan, encryption_context: %{"table" => "payment_methods"})

      assert {:error,
              %Error{
                reason: :decrypt_failed,
                vault: DecryptVaults.Loose,
                operation: :decrypt,
                engine: {:encryption_context_mismatch, "column"}
              }} = vault.decrypt(unbound, encryption_context: @columns)
    end

    # A message written with no per-call context at all, read under two
    # claims it never carried: the key reported is the first in sorted
    # order, on every run.
    #
    # sabotage: sorted the per-call keys `:desc` in unstored_per_call_key/3 -
    # red, the refusal names "table".
    test "a message written with no context is refused when the reader passes one" do
      vault = start_vault(DecryptVaults.Loose)

      bare = vault.encrypt!(@pan)

      assert engine(vault.decrypt(bare, encryption_context: @columns)) ==
               {:encryption_context_mismatch, "column"}
    end

    # The check is the vault's, above the engine and its cache, so a warm
    # decryption cache answers as a cold one does.
    #
    # sabotage: passed no per-call keys from decrypt/7 to agreed_stored/5 -
    # red, both reads succeed.
    test "is refused on a warm decryption cache too" do
      vault = start_vault(EncryptVaults.Cached)

      unbound = vault.encrypt!(@pan, encryption_context: %{"table" => "payment_methods"})

      assert {:ok, @pan} =
               vault.decrypt(unbound, encryption_context: %{"table" => "payment_methods"})

      assert engine(vault.decrypt(unbound, encryption_context: @columns)) ==
               {:encryption_context_mismatch, "column"}
    end

    # sabotage: made unstored_per_call_key/3 refuse every per-call key,
    # stored or not - red, the reader that passes what the writer passed is
    # refused.
    test "a message written with the key reads under the same value" do
      vault = start_vault(DecryptVaults.Loose)

      bound = vault.encrypt!(@pan, encryption_context: @columns)

      assert {:ok, @pan} = vault.decrypt(bound, encryption_context: @columns)
    end

    # sabotage: dropped `&1 not in required` from unstored_per_call_key/3 -
    # red, the 1.1 engine stores no required pair, so every read of a
    # message written under a required set is refused.
    test "a key :required_context names is checked as before" do
      vault = start_vault(EncryptVaults.Bound)

      ciphertext = vault.encrypt!(@pan, encryption_context: @columns)

      assert {:ok, %Message.Info{encryption_context: stored}} = Message.describe(ciphertext)
      refute Map.has_key?(stored, "column")
      assert {:ok, @pan} = vault.decrypt(ciphertext, encryption_context: @columns)

      swapped = %{"table" => "payment_methods", "column" => "notes"}
      assert reason(vault.decrypt(ciphertext, encryption_context: swapped)) == :decrypt_failed
    end

    # Decision 6's advisory-key reason stands for the static layer: a vault
    # that gains a static key still reads the messages written before it.
    #
    # sabotage: passed the keys of the whole composed context from decrypt/7
    # instead of the per-call layer's - red, the static key is refused.
    test "a static key the message does not carry is still ignored" do
      start_vault(DecryptVaults.Loose)
      before = DecryptVaults.Loose.encrypt!(@pan, encryption_context: @columns)
      :ok = stop_supervised(DecryptVaults.Loose)

      start_vault(DecryptVaults.Loose, static_encryption_context: %{"app" => "a_host"})

      assert {:ok, @pan} = DecryptVaults.Loose.decrypt(before, encryption_context: @columns)
    end

    # sabotage: made unstored_per_call_key/3 ignore `:legacy_context` (refuse
    # under `:accept` too) - red, the migration read is refused.
    test "is read under legacy_context: :accept, the migration switch" do
      vault = start_vault(DecryptVaults.Loose, legacy_context: :accept)

      unbound = vault.encrypt!(@pan, encryption_context: %{"table" => "payment_methods"})

      assert {:ok, @pan} = vault.decrypt(unbound, encryption_context: @columns)

      moved = %{"table" => "receipts"}

      assert engine(vault.decrypt(unbound, encryption_context: moved)) ==
               {:encryption_context_mismatch, "table"}
    end

    # The same vault reads the message under either setting when its reader
    # does not claim the missing key, so no message becomes unreadable.
    # sabotage: made unstored_per_call_key/3 refuse every per-call key,
    # stored or not - red, the read under the claim the writer passed fails.
    test "a reader that does not claim the missing key reads under the default" do
      vault = start_vault(DecryptVaults.Loose)

      unbound = vault.encrypt!(@pan, encryption_context: %{"table" => "payment_methods"})

      assert {:ok, @pan} =
               vault.decrypt(unbound, encryption_context: %{"table" => "payment_methods"})

      assert {:ok, @pan} = vault.decrypt(unbound)
    end

    # agree/5 directly: the per-call keys are the argument that decides it.
    # sabotage: made unstored_per_call_key/3 answer nil for every config -
    # red, the call naming "table" is :ok.
    test "agree/5 refuses a per-call key the message does not store, and only that" do
      vault = start_vault(DecryptVaults.Loose)
      {:ok, config} = Config.fetch(vault)

      bare = vault.encrypt!(@pan)

      assert Decrypt.agree(config, bare, @columns) == :ok

      assert {:error,
              %Error{reason: :decrypt_failed, engine: {:encryption_context_mismatch, "table"}}} =
               Decrypt.agree(config, bare, @columns, :decrypt, ["table"])
    end
  end

  describe "the suite a message was written under" do
    # ADR-0001 Amendment D: a vault reads the suite it writes and the suites
    # `:accept_suites` lists, and refuses any other. `DecryptVaults.Loose`
    # writes `0x0478` and `EncryptVaults.App` writes `0x0578`, under the same
    # key, so the suite is the only thing that differs between them.

    # sabotage: made accepted_suite/3 in decrypt.ex answer :ok for every
    # suite - red, the signing vault reads the unsigned message.
    test "a signing-suite vault refuses an unsigned message under the same key" do
      writer = start_vault(DecryptVaults.Loose)
      reader = start_vault(EncryptVaults.App)

      ciphertext = writer.encrypt!(@value)

      assert {:ok, %Message.Info{algorithm_suite_id: 0x0478}} = Message.describe(ciphertext)
      assert {:ok, %Config{algorithm_suite_id: 0x0578, accept_suites: []}} = Config.fetch(reader)

      assert {:error,
              %Error{
                reason: :decrypt_failed,
                vault: EncryptVaults.App,
                operation: :decrypt,
                engine: {:algorithm_suite_not_accepted, 0x0478}
              }} = reader.decrypt(ciphertext)
    end

    # This test pinned the old answer, under the name "a signing-suite vault
    # reads an unsigned message under the same key", until Amendment D made
    # that read the `:accept_suites` arm. It keeps the read, scoped to it.
    #
    # sabotage: made accepted_suite/3 in decrypt.ex ignore `:accept_suites`
    # (refuse every suite but the configured one) - red, the listed suite is
    # refused.
    test "a signing-suite vault reads an unsigned message when :accept_suites lists its suite" do
      writer = start_vault(DecryptVaults.Loose)
      reader = start_vault(EncryptVaults.App, accept_suites: [0x0478])

      ciphertext = writer.encrypt!(@value)

      assert {:ok, %Message.Info{algorithm_suite_id: 0x0478}} = Message.describe(ciphertext)
      assert {:ok, @value} = reader.decrypt(ciphertext)
    end

    # The other direction: the refusal is not about signing, it is about the
    # suite. sabotage: made accepted_suite/3 refuse only 0x0478 - red, the
    # unsigned vault reads the signed message.
    test "an unsigned-suite vault refuses a signed message unless :accept_suites lists it" do
      writer = start_vault(EncryptVaults.App)
      ciphertext = writer.encrypt!(@value)
      assert {:ok, %Message.Info{algorithm_suite_id: 0x0578}} = Message.describe(ciphertext)

      start_vault(DecryptVaults.Loose)

      assert {:error,
              %Error{
                reason: :decrypt_failed,
                engine: {:algorithm_suite_not_accepted, 0x0578}
              }} = DecryptVaults.Loose.decrypt(ciphertext)

      :ok = stop_supervised(DecryptVaults.Loose)
      start_vault(DecryptVaults.Loose, accept_suites: [0x0578])

      assert {:ok, @value} = DecryptVaults.Loose.decrypt(ciphertext)
    end

    # sabotage: made accepted_suite/3 consult `:accept_suites` alone, dropping
    # its configured-suite clause - red, a vault whose list names only the
    # other suite refuses its own message.
    test "the configured suite is read whatever :accept_suites lists" do
      vault = start_vault(DecryptVaults.Loose, accept_suites: [0x0578])

      ciphertext = vault.encrypt!(@value)

      assert {:ok, %Message.Info{algorithm_suite_id: 0x0478}} = Message.describe(ciphertext)
      assert {:ok, @value} = vault.decrypt(ciphertext)
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
    # sabotage: collapsed the missing-required-keys clause into engine_result/3's
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
