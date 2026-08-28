defmodule Encryptor.Vault.RekeyTest do
  use ExUnit.Case, async: false

  alias Encryptor.DecryptVaults
  alias Encryptor.EncryptVaults
  alias Encryptor.Error
  alias Encryptor.Message
  alias Encryptor.RekeyVaults
  alias Encryptor.Vault
  alias Encryptor.Vault.Reference

  @pan "4111111111111111"
  @columns %{"table" => "payment_methods", "column" => "pan"}

  defp start_vault(vault) do
    start_supervised!(Supervisor.child_spec({vault, []}, restart: :temporary))
    vault
  end

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
      "tenant_ref",
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
      {:ok, new} = rotator.rekey(old)

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

      {:ok, new} = rotator.rekey(old)

      assert {:ok, @pan} = shredded.decrypt(new, encryption_context: @columns)
    end

    # sabotage: re-encrypted under `composed` - the vault-composed context -
    # instead of `stored` - red, because a message written with a per-call
    # context comes back bound to the vault's static layer alone, which is a
    # rotation job silently unbinding every row it touches.
    test "preserves the encryption context byte for byte" do
      writer = start_vault(DecryptVaults.Retired)
      rotator = start_vault(EncryptVaults.Bound)

      old = writer.encrypt!(@pan, encryption_context: @columns)
      {:ok, new} = rotator.rekey(old)

      assert context(new) == context(old)
      assert context(new) == @columns
    end

    # sabotage: returned the input `{:ok, ciphertext}` from call/3 - red,
    # because a rotation that answers with its own argument reports success
    # while leaving every row it walked on the outgoing key.
    test "a rekey under the key already in use is a fresh message, not a no-op" do
      vault = start_vault(EncryptVaults.Bound)

      old = vault.encrypt!(@pan, encryption_context: @columns)
      {:ok, new} = vault.rekey(old)

      refute new == old
      assert context(new) == context(old)
      assert {:ok, @pan} = vault.decrypt(new, encryption_context: @columns)
    end

    # sabotage: composed the read half's client from a bare Default CMM instead
    # of Encrypt.client/3's stack - red, because this engine mixes the required
    # subset of the context into the header AAD, so the decrypt half of a rekey
    # has to be spelled exactly as a read is.
    test "round trips on a tenant vault, with the pair the vault supplied itself" do
      vault = start_vault(EncryptVaults.Merchant)

      old = vault.encrypt!(@pan, key: "merchant_a", encryption_context: @columns)
      {:ok, new} = vault.rekey(old, key: "merchant_a")

      assert context(new) == merchant_context("merchant_a")
      assert {:ok, @pan} = vault.decrypt(new, key: "merchant_a", encryption_context: @columns)
    end

    # sabotage: made the generated rekey!/2 match `{:ok, ciphertext}` instead of
    # raising - red with a MatchError rather than the Encryptor.Error a rescue
    # clause is written against.
    test "rekey! returns the ciphertext, and raises the struct rekey/2 would return" do
      vault = start_vault(EncryptVaults.Bound)

      old = vault.encrypt!(@pan, encryption_context: @columns)

      assert {:ok, @pan} = vault.decrypt(vault.rekey!(old), encryption_context: @columns)

      error = assert_raise Error, fn -> vault.rekey!("not an ESDK message") end

      assert error.reason == :decrypt_failed
      assert error.operation == :rekey
    end
  end

  describe "the context comes from the message and nowhere else" do
    # sabotage: dropped the refuse_context/2 step from call/3's with-chain - red,
    # because the caller's map is then simply ignored, which is the same silence
    # a caller would read as "my context was applied".
    test "an :encryption_context option is refused, naming the caller's own key" do
      vault = start_vault(EncryptVaults.Bound)

      old = vault.encrypt!(@pan, encryption_context: @columns)
      result = vault.rekey(old, encryption_context: %{"table" => "receipts"})

      assert reason(result) == {:reserved_context_key, "table"}
      assert %Error{operation: :rekey, engine: nil} = elem(result, 1)
    end

    # sabotage: sorted the caller's keys `:desc` in refuse_pairs/2 - red, because
    # the key a caller is told about then depends on term ordering inside the
    # runtime rather than on what they passed.
    test "two supplied keys name the same one on every run" do
      vault = start_vault(EncryptVaults.Bound)

      old = vault.encrypt!(@pan, encryption_context: @columns)

      assert reason(vault.rekey(old, encryption_context: @columns)) ==
               {:reserved_context_key, "column"}
    end

    # sabotage: matched any `{:ok, _}` in refuse_context/2 and refused it as a
    # reserved key - red with a FunctionClauseError out of refuse_pairs/2, since
    # a non-map has no keys to name.
    test "an :encryption_context that is not a map is refused under the option's own name" do
      vault = start_vault(EncryptVaults.Bound)

      result = vault.rekey("not an ESDK message", encryption_context: [table: "receipts"])

      assert reason(result) == {:invalid_context_value, "encryption_context"}
    end

    # The empty map is the one shape of the option that is accepted, because the
    # refusal exists to stop a caller rewriting a binding and an empty map
    # rewrites nothing. See this bead's note: the record names the refusal for
    # the ordinary case and does not reach this one.
    #
    # sabotage: made refuse_pairs/2's empty clause fall through to the naming
    # clause - red with a FunctionClauseError from `hd([])`, which is the shape
    # of the problem: there is no key to put in the reason.
    test "an empty :encryption_context supplies nothing and is accepted" do
      vault = start_vault(EncryptVaults.Bound)

      old = vault.encrypt!(@pan, encryption_context: @columns)

      assert {:ok, new} = vault.rekey(old, encryption_context: %{})
      assert context(new) == @columns
    end

    # sabotage: dropped the agree/4 step from call/3's with-chain - red, and this
    # is the test that says why the step is not redundant when the reproduced
    # context is the stored one: what it compares is the context the *vault*
    # composed from the caller's selector, so removing it lets a rekey move a
    # message between tenants wherever their key material overlaps.
    test "a rekey cannot move a message between tenants" do
      vault = start_vault(EncryptVaults.Merchant)

      old = vault.encrypt!(@pan, key: "merchant_a", encryption_context: @columns)
      result = vault.rekey(old, key: "merchant_b")

      assert reason(result) == :decrypt_failed
      assert engine(result) == {:encryption_context_mismatch, "tenant_ref"}
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
      result = rotator.rekey(old)

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

    # sabotage: moved stored_context/2 above the provider in call/3 - red,
    # because an unresolvable selector then collapses to :decrypt_failed and an
    # operator is sent looking for corruption instead of a key store.
    test "a provider that cannot resolve the selector stays distinct from a bad message" do
      vault = start_vault(EncryptVaults.Merchant)

      assert reason(vault.rekey("not a message", key: "merchant_z")) ==
               {:unknown_key, "merchant_z"}
    end

    # sabotage: gave Resolve.selector/3's :tenant clause a `:default` arm - red,
    # because a tenant vault would then rotate under a selector no write could use.
    test "a tenant vault refuses a rekey that names no tenant, before the provider" do
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

  describe "the door" do
    # sabotage: made the generated rekey/2 pass `[]` instead of `opts` - red,
    # because the selector arrives that way and a tenant rekey that dropped it
    # would be refused as naming no tenant.
    test "the generated function carries the caller's options through unchanged" do
      vault = start_vault(EncryptVaults.Merchant)

      old = vault.encrypt!(@pan, key: "merchant_a", encryption_context: @columns)
      opts = [key: "merchant_a"]

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
