defmodule Encryptor.Vault.RekeyTest do
  use ExUnit.Case, async: false

  alias Encryptor.DecryptVaults
  alias Encryptor.EncryptVaults
  alias Encryptor.EngineReader
  alias Encryptor.Error
  alias Encryptor.Message
  alias Encryptor.RekeyVaults
  alias Encryptor.Vault
  alias Encryptor.Vault.Reference
  alias Encryptor.WireFixtureV2Vaults, as: Fixture

  @pan "4111111111111111"
  @columns %{"table" => "payment_methods", "column" => "pan"}

  defp start_vault(vault) do
    start_supervised!(Supervisor.child_spec({vault, []}, restart: :temporary))
    vault
  end

  # An `{:ok, _}` renders as `:opened`, never as its value, so a sabotage that
  # lets a refused rekey through fails on the assertion and prints no message.
  defp reason({:ok, _ciphertext}), do: :opened
  defp reason({:error, %Error{reason: reason}}), do: reason
  defp engine({:error, %Error{engine: engine}}), do: engine

  defp context(ciphertext) do
    {:ok, info} = Message.describe(ciphertext)
    info.encryption_context
  end

  defp key_names(ciphertext) do
    {:ok, info} = Message.describe(ciphertext)
    Enum.map(info.encrypted_data_keys, & &1.key_name)
  end

  defp merchant_context(selector) do
    Map.put(
      @columns,
      "scope_ref",
      Reference.derive(EncryptVaults.reference_subkey(), selector)
    )
  end

  describe "the rotation it exists for" do
    # sabotage: resolved the write half with Resolve.decryption_keys/3 and
    # Keyring.build_all/3 instead of encryption_key/3 and build/3 - red, because
    # a Multi keyring wraps the data key under every candidate and the message
    # comes back still readable by the key the rotation was meant to leave.
    test "moves a message off a retired key and onto the current one" do
      writer = start_vault(DecryptVaults.Retired)
      rotator = start_vault(EncryptVaults.Bound)

      old = writer.encrypt!(@pan, encryption_context: @columns)
      {:ok, new} = rotator.rekey(old, encryption_context: @columns)

      assert key_names(old) == ["app/v1"]
      assert key_names(new) == ["app/v2"]
    end

    # sabotage: passed `plaintext` straight back from call/3 instead of the
    # re-encrypt's result - red, and it is the failure that matters most here:
    # a rotation that returns the plaintext it decrypted writes a cleartext PAN
    # into the column it was rotating.
    test "the rekeyed message opens under a vault that holds only the new key" do
      writer = start_vault(DecryptVaults.Retired)
      rotator = start_vault(EncryptVaults.Bound)
      shredded = start_vault(RekeyVaults.Shredded)

      old = writer.encrypt!(@pan, encryption_context: @columns)

      # Before: the shredded vault cannot read the outgoing version at all,
      # which is what makes the read after the rekey evidence of anything.
      assert reason(shredded.decrypt(old, encryption_context: @columns)) == :decrypt_failed

      {:ok, new} = rotator.rekey(old, encryption_context: @columns)

      assert {:ok, @pan} = shredded.decrypt(new, encryption_context: @columns)
    end

    # ADR-0004 Amendment B reads ADR-0001 decision 4's "byte for byte" as the
    # authenticated context: the same pairs are bound to the rekeyed message.
    # The header of either stores none of the required pairs.
    #
    # sabotage: re-encrypted under `writable(stored)` instead of
    # `writable(reproduced)` - red, because the required pairs the header does
    # not store are then missing from the write, and the engine refuses it.
    test "binds the same context to the new message, which stores what the old one did" do
      writer = start_vault(DecryptVaults.Retired)
      rotator = start_vault(EncryptVaults.Bound)

      old = writer.encrypt!(@pan, encryption_context: @columns)
      {:ok, new} = rotator.rekey(old, encryption_context: @columns)

      assert context(old) == %{}
      assert context(new) == context(old)
      assert {:ok, @pan} = rotator.decrypt(new, encryption_context: @columns)

      assert reason(rotator.decrypt(new, encryption_context: %{@columns | "column" => "notes"})) ==
               :decrypt_failed
    end

    # sabotage: returned the input `{:ok, ciphertext}` from call/3 - red,
    # because a rotation that answers with its own argument reports success
    # while leaving every row it walked on the outgoing key.
    test "a rekey under the key already in use is a fresh message, not a no-op" do
      vault = start_vault(EncryptVaults.Bound)

      old = vault.encrypt!(@pan, encryption_context: @columns)
      {:ok, new} = vault.rekey(old, encryption_context: @columns)

      refute new == old
      assert context(new) == context(old)
      assert {:ok, @pan} = vault.decrypt(new, encryption_context: @columns)
    end

    # sabotage: composed the read half's client from a bare Default CMM instead
    # of Encrypt.client/3's stack - red, because this engine mixes the required
    # subset of the context into the header AAD, so the decrypt half of a rekey
    # has to be spelled exactly as a read is.
    test "round trips on a scoped vault, with the pair the vault supplied itself" do
      vault = start_vault(EncryptVaults.Merchant)

      old = vault.encrypt!(@pan, key: "merchant_a", encryption_context: @columns)
      {:ok, new} = vault.rekey(old, key: "merchant_a", encryption_context: @columns)

      assert context(new) == %{}
      assert {:ok, @pan} = vault.decrypt(new, key: "merchant_a", encryption_context: @columns)

      assert {:ok, %{plaintext: @pan}} =
               EngineReader.read(
                 new,
                 EncryptVaults.merchant_descriptor("merchant_a"),
                 merchant_context("merchant_a")
               )
    end

    # sabotage: made the generated rekey!/2 match `{:ok, ciphertext}` instead of
    # raising - red with a MatchError rather than the Encryptor.Error a rescue
    # clause is written against.
    test "rekey! returns the ciphertext, and raises the struct rekey/2 would return" do
      vault = start_vault(EncryptVaults.Bound)

      old = vault.encrypt!(@pan, encryption_context: @columns)

      assert {:ok, @pan} =
               vault.decrypt(vault.rekey!(old, encryption_context: @columns),
                 encryption_context: @columns
               )

      error = assert_raise Error, fn -> vault.rekey!("not an ESDK message") end

      assert error.reason == :decrypt_failed
      assert error.operation == :rekey
    end
  end

  describe "the context comes from the message, the vault, and then the row" do
    # ADR-0004 Amendment B, B1's table, one test per row, then its worked
    # example's outcomes.

    # Row 1. sabotage: made acceptable?/4 answer false for every key - red,
    # because the one way a required pair the header does not store reaches
    # the decrypt is then closed, and the rekey is refused.
    test "a required pair the header does not store is accepted, and rebinds nothing" do
      vault = start_vault(EncryptVaults.Bound)

      old = vault.encrypt!(@pan, encryption_context: @columns)
      assert context(old) == %{}

      assert {:ok, new} = vault.rekey(old, encryption_context: @columns)
      assert {:ok, @pan} = vault.decrypt(new, encryption_context: @columns)
    end

    # Row 2, on a message the 1.0.x engine wrote, whose header stores its
    # required pairs. sabotage: dropped the `not Map.has_key?(stored, key)`
    # clause from acceptable?/4 - red, the stored pair is then accepted.
    test "a required pair the header stores is refused" do
      start_supervised!(Supervisor.child_spec({Fixture.RootVault, []}, restart: :temporary))
      start_supervised!(Supervisor.child_spec({Fixture.ScopedVault, []}, restart: :temporary))

      result =
        Fixture.ScopedVault.rekey(Fixture.ciphertext(),
          key: Fixture.selector(),
          encryption_context: %{"column" => "secret"}
        )

      assert reason(result) == {:reserved_context_key, "column"}
      assert %Error{operation: :rekey, engine: nil} = elem(result, 1)
    end

    # Row 3, a key of the static layer the vault requires. sabotage: dropped
    # the `not Map.has_key?(composed, key)` clause from acceptable?/4 - red,
    # the caller's copy of the vault's own pair is then accepted.
    test "a required pair the vault composes is refused, and supplied by the vault" do
      vault = start_vault(RekeyVaults.StaticBound)

      old = vault.encrypt!(@pan, encryption_context: @columns)
      refute Map.has_key?(context(old), "app")

      result = vault.rekey(old, encryption_context: Map.put(@columns, "app", "acme_checkout"))
      assert reason(result) == {:reserved_context_key, "app"}

      assert {:ok, new} = vault.rekey(old, encryption_context: @columns)
      assert {:ok, @pan} = vault.decrypt(new, encryption_context: @columns)
    end

    # Row 3 on a scoped vault: `scope_ref` comes from `:key`, never from a
    # caller. `scope_ref` is composed and reserved both, and
    # `Encryptor.Context.compose/3` refuses it as well, so no single clause
    # dropped is red; this pins the outcome.
    test "the scope pair is refused from a caller on a scoped vault" do
      vault = start_vault(EncryptVaults.Merchant)
      ref = Reference.derive(EncryptVaults.reference_subkey(), "merchant_a")

      old = vault.encrypt!(@pan, key: "merchant_a", encryption_context: @columns)
      result = vault.rekey(old, key: "merchant_a", encryption_context: %{"scope_ref" => ref})

      assert reason(result) == {:reserved_context_key, "scope_ref"}
    end

    # Row 5. sabotage: dropped the `key in required` clause from acceptable?/4 -
    # red, a key the vault does not require is then accepted and written into
    # what the rekeyed message is bound to.
    test "a key the vault does not require is refused" do
      vault = start_vault(EncryptVaults.Bound)

      old = vault.encrypt!(@pan, encryption_context: @columns)
      result = vault.rekey(old, encryption_context: Map.put(@columns, "purpose", "pii"))

      assert reason(result) == {:reserved_context_key, "purpose"}
      assert %Error{operation: :rekey, engine: nil} = elem(result, 1)
    end

    # sabotage: sorted the caller's keys `:desc` in accept_pairs/4 - red,
    # because the key a caller is told about then depends on term ordering
    # inside the runtime rather than on what they passed.
    test "two refused keys name the same one on every run" do
      vault = start_vault(EncryptVaults.Bound)

      old = vault.encrypt!(@pan, encryption_context: @columns)

      assert reason(vault.rekey(old, encryption_context: %{"zeta" => "z", "alpha" => "a"})) ==
               {:reserved_context_key, "alpha"}
    end

    # Worked example, step 2. The term is the required-context CMM's, so
    # this pins the outcome rather than a line of this package's.
    test "a required pair nobody supplies is the caller-fixable error" do
      vault = start_vault(EncryptVaults.Merchant)

      old = vault.encrypt!(@pan, key: "merchant_a", encryption_context: @columns)
      result = vault.rekey(old, key: "merchant_a")

      assert {:missing_required_context_keys, keys} = reason(result)
      assert Enum.sort(keys) == ["column", "table"]
      assert %Error{operation: :rekey} = elem(result, 1)
    end

    # Worked example, step 4. sabotage: re-encrypted under the caller's map
    # without decrypting under it first (passed `stored` to open/5) - red,
    # because the decrypt then refuses the missing pairs instead of the wrong
    # value, and the reason changes.
    test "a supplied value that disagrees with the message is decrypt_failed" do
      vault = start_vault(EncryptVaults.Merchant)

      old = vault.encrypt!(@pan, key: "merchant_a", encryption_context: @columns)

      result =
        vault.rekey(old,
          key: "merchant_a",
          encryption_context: %{@columns | "column" => "notes"}
        )

      assert reason(result) == :decrypt_failed
      assert %Error{operation: :rekey} = elem(result, 1)
    end

    # sabotage: matched any `{:ok, _}` in accept_context/4 as a map - red with
    # a FunctionClauseError, since a non-map has no keys to check.
    test "an :encryption_context that is not a map is refused under the option's own name" do
      vault = start_vault(EncryptVaults.Bound)

      result = vault.rekey("not an ESDK message", encryption_context: [table: "receipts"])

      assert reason(result) == {:invalid_context_value, "encryption_context"}
    end

    # The empty map supplies nothing and there is no key in it to name, so it
    # is accepted on a message with nothing to supply.
    #
    # sabotage: removed accept_context/4's empty-map clause - not red alone
    # (the map clause finds no key to refuse); made that clause return a
    # refusal instead - red.
    test "an empty :encryption_context supplies nothing and is accepted" do
      vault = start_vault(EncryptVaults.App)

      old = vault.encrypt!(@pan, encryption_context: %{"table" => "receipts"})

      assert {:ok, new} = vault.rekey(old, encryption_context: %{})
      assert Map.delete(context(new), "aws-crypto-public-key") == %{"table" => "receipts"}
    end

    # On a message whose header stores `scope_ref` (the 1.0.x engine wrote
    # it), the vault's comparison is what refuses another scope, even where
    # the two scopes' key material is the same: the fixture's provider answers
    # every selector with the one fixture key.
    #
    # sabotage: dropped the agreed_stored/4 step from rekey/7's with-chain
    # (reproduced from the header alone) - red, the rekey under the other
    # scope's selector opens the message and rewrites it under that scope.
    test "a rekey cannot move a message between scopes" do
      start_supervised!(Supervisor.child_spec({Fixture.RootVault, []}, restart: :temporary))
      start_supervised!(Supervisor.child_spec({Fixture.ScopedVault, []}, restart: :temporary))

      result = Fixture.ScopedVault.rekey(Fixture.ciphertext(), key: "workspace-8")

      assert reason(result) == :decrypt_failed
      assert engine(result) == {:encryption_context_mismatch, "scope_ref"}
    end

    # On a message whose header does not store `scope_ref`, the composed pair
    # is reproduced into the decrypt and the engine refuses a scope the
    # message was not bound to, with the same key material on both sides.
    #
    # sabotage: made reproduce/3 return `stored` alone - red, because the
    # decrypt then reports the missing pairs rather than a refused scope.
    test "a rekey cannot move a message the 1.1 engine wrote between scopes either" do
      start_supervised!(Supervisor.child_spec({Fixture.RootVault, []}, restart: :temporary))
      start_supervised!(Supervisor.child_spec({Fixture.ScopedVault, []}, restart: :temporary))

      {:ok, new} =
        Fixture.ScopedVault.rekey(Fixture.ciphertext(),
          key: Fixture.selector(),
          encryption_context: %{}
        )

      assert context(new) == %{}

      result =
        Fixture.ScopedVault.rekey(new, key: "workspace-8", encryption_context: Fixture.context())

      assert reason(result) == :decrypt_failed

      assert {:ok, _} =
               Fixture.ScopedVault.rekey(new,
                 key: Fixture.selector(),
                 encryption_context: Fixture.context()
               )
    end
  end

  describe "the failure mapping, stamped with the operation the caller asked for" do
    # sabotage: passed `:decrypt` rather than `operation` to Error.decrypt_failed/3
    # in Decrypt.engine_decrypt/5 - red, because an operator reading the log line
    # is then told a read failed when nobody performed one.
    test "a message this vault's candidate list cannot open is decrypt_failed" do
      writer = start_vault(EncryptVaults.Bound)
      rotator = start_vault(DecryptVaults.Retired)

      old = writer.encrypt!(@pan, encryption_context: @columns)
      result = rotator.rekey(old, encryption_context: @columns)

      assert reason(result) == :decrypt_failed
      assert %Error{operation: :rekey} = elem(result, 1)
      refute engine(result) == nil
    end

    # sabotage: dropped the engine's parse term from stored_context/2's
    # unreadable-header branch - red, because an operator then has a failure with
    # no detail at all.
    test "a message this package cannot parse is decrypt_failed, carrying the parse term" do
      vault = start_vault(DecryptVaults.Loose)

      result = vault.rekey("not an ESDK message")

      assert reason(result) == :decrypt_failed
      assert engine(result) == {:unsupported_version, 110}
      assert %Error{vault: DecryptVaults.Loose, operation: :rekey} = elem(result, 1)
    end

    # sabotage: hardcoded `operation: :decrypt` in Decrypt.engine_decrypt/5's
    # missing-required-keys clause - red. This is the one failure a rekey caller
    # cannot fix from their own arguments: the context came from the message, so
    # what it says is that the vault now requires a key the message was never
    # written with, which is a re-encrypt and not a rotation.
    test "a vault requiring a key the message was never written with says so, loudly" do
      writer = start_vault(DecryptVaults.Loose)
      rotator = start_vault(DecryptVaults.Retired)

      old = writer.encrypt!(@pan, encryption_context: %{"table" => "payment_methods"})
      result = rotator.rekey(old)

      assert reason(result) == {:missing_required_context_keys, ["column"]}
      assert %Error{operation: :rekey} = elem(result, 1)
    end

    # The 1.1 engine answers a message followed by trailing bytes with
    # `{:error, :trailing_bytes}`. sabotage: passed `:decrypt` rather than
    # `operation` to Error.decrypt_failed/3 in Decrypt.engine_result/3's error
    # clause - red, because the rekey's decrypt half is the same call and must
    # report the operation the caller asked for.
    test "a message followed by one trailing byte is decrypt_failed, stamped :rekey" do
      vault = start_vault(EncryptVaults.App)

      old = vault.encrypt!(@pan)
      result = vault.rekey(old <> <<0>>)

      assert {:error,
              %Error{
                reason: :decrypt_failed,
                vault: EncryptVaults.App,
                operation: :rekey,
                engine: :trailing_bytes
              }} = result
    end

    # sabotage: parsed the header in accept_context/4 whether or not the option
    # was given - red, because an unresolvable selector then collapses to
    # :decrypt_failed and an
    # operator is sent looking for corruption instead of a key store.
    test "a provider that cannot resolve the selector stays distinct from a bad message" do
      vault = start_vault(EncryptVaults.Merchant)

      assert reason(vault.rekey("not a message", key: "merchant_z")) ==
               {:unknown_key, "merchant_z"}
    end

    # sabotage: gave Resolve.selector/3's :scoped clause a `:default` arm - red,
    # because a scoped vault would then rotate under a selector no write could use.
    test "a scoped vault refuses a rekey that names no scope, before the provider" do
      vault = start_vault(EncryptVaults.Merchant)

      assert reason(vault.rekey("not a message")) == {:invalid_selector, :default}
    end

    # sabotage: called `Vault.ready(vault, :decrypt)` from call/3 - red, because
    # the stamp is what says which call failed.
    test "a vault that is not running is a typed error stamped with the operation" do
      result = EncryptVaults.Unstarted.rekey("not a message")

      assert reason(result) == {:vault_not_started, EncryptVaults.Unstarted}
      assert %Error{operation: :rekey} = elem(result, 1)
    end
  end

  describe "on the signing suite, 0x0578" do
    # The engine's own pair, written out here rather than read from the engine
    # or the module under test, so a test agrees with neither by construction.
    @verification_key "aws-crypto-public-key"

    # sabotage: passed `reproduced` to the re-encrypt instead of
    # `writable(reproduced)` - red, because the engine refuses a context that
    # carries its own verification-key pair and every rekey on the default
    # suite fails with :reserved_encryption_context_key.
    test "moves a message off a retired key, and it opens under the new one" do
      writer = start_vault(RekeyVaults.SignedRetired)
      rotator = start_vault(RekeyVaults.SignedBound)

      old = writer.encrypt!(@pan, encryption_context: @columns)
      assert Map.has_key?(context(old), @verification_key)

      assert {:ok, new} = rotator.rekey(old, encryption_context: @columns)

      assert key_names(old) == ["app/v1"]
      assert key_names(new) == ["app/v2"]
      assert {:ok, @pan} = rotator.decrypt(new, encryption_context: @columns)
    end

    # sabotage: passed `reproduced` to the re-encrypt instead of
    # `writable(reproduced)` - red on the rekey itself, as above; the
    # assertions below then pin what a fixed rekey writes: the host's pairs
    # bound, none of them stored, and a verification key the engine generated
    # for this write, not the old one.
    test "carries the host's pairs across, and the engine writes a fresh verification key" do
      writer = start_vault(RekeyVaults.SignedRetired)
      rotator = start_vault(RekeyVaults.SignedBound)

      old = writer.encrypt!(@pan, encryption_context: @columns)
      assert {:ok, new} = rotator.rekey(old, encryption_context: @columns)

      assert Map.keys(context(new)) == [@verification_key]
      assert Map.keys(context(new)) == Map.keys(context(old))
      refute context(new)[@verification_key] == context(old)[@verification_key]
      assert {:ok, @pan} = rotator.decrypt(new, encryption_context: @columns)
    end

    # sabotage: passed `reproduced` to the re-encrypt instead of
    # `writable(reproduced)` - red on a scoped vault too, where the reproduced
    # context also carries the `scope_ref` the vault supplied.
    test "round trips on a scoped vault, with the pair the vault supplied itself" do
      vault = start_vault(RekeyVaults.SignedMerchant)

      old = vault.encrypt!(@pan, key: "merchant_a", encryption_context: @columns)
      assert {:ok, new} = vault.rekey(old, key: "merchant_a", encryption_context: @columns)

      assert Map.keys(context(new)) == [@verification_key]
      assert {:ok, @pan} = vault.decrypt(new, key: "merchant_a", encryption_context: @columns)
    end
  end

  describe "the door" do
    # sabotage: made the generated rekey/2 pass `[]` instead of `opts` - red,
    # because the selector arrives that way and a scope rekey that dropped it
    # would be refused as naming no scope.
    test "the generated function carries the caller's options through unchanged" do
      vault = start_vault(EncryptVaults.Merchant)

      old = vault.encrypt!(@pan, key: "merchant_a", encryption_context: @columns)
      opts = [key: "merchant_a", encryption_context: @columns]

      assert {:ok, _new} = vault.rekey(old, opts)

      assert context(elem(vault.rekey(old, opts), 1)) ==
               context(elem(Vault.rekey(EncryptVaults.Merchant, old, opts), 1))
    end

    # sabotage: dropped the `is_binary/1` guard from Vault.rekey/3 and coerced
    # with `to_string/1` - red, because a source-level mistake then becomes a
    # runtime error term the closed vocabulary was never meant to describe.
    test "a ciphertext that is not a binary is wrong in the source, not at runtime" do
      start_vault(EncryptVaults.App)

      assert_raise FunctionClauseError, fn -> EncryptVaults.App.rekey(:not_a_binary) end
    end
  end
end
