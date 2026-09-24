defmodule Encryptor.Vault.SpansTest do
  @moduledoc """
  ADR-0006's four span pairs, around the three entry points and the provider
  round trip nested inside them, and its amendment A's opt-in scope
  dimension.

  The record's own worked example is the shape most of this file asserts: a
  provider span reporting `key_unavailable` with the store's latency, an
  operation span reporting the collapsed `:decrypt_failed`, and nothing in
  either that names a merchant.
  """

  use ExUnit.Case, async: false

  alias Encryptor.EncryptVaults
  alias Encryptor.Error
  alias Encryptor.Telemetry
  alias Encryptor.TelemetryVaults
  alias Encryptor.Vault.Partition
  alias Encryptor.Vault.Reference
  alias Encryptor.Vault.Resolve

  @merchant "merchant_a"
  @plaintext "4111111111111111"

  @span_names [:encrypt, :decrypt, :rekey, :provider]

  defp capture(events \\ Telemetry.events()) do
    parent = self()
    id = "enc-iet-#{System.unique_integer([:positive])}"

    Enum.each(events, fn event ->
      handler_id = {id, event}
      :telemetry.attach(handler_id, event, &__MODULE__.forward/4, parent)
      on_exit(fn -> :telemetry.detach(handler_id) end)
    end)

    :ok
  end

  @doc false
  @spec forward([atom()], map(), map(), pid()) :: :ok
  def forward(name, measurements, metadata, parent) do
    send(parent, {:telemetry, name, measurements, metadata})

    :ok
  end

  defp start_vault(vault, opts \\ []) do
    start_supervised!(Supervisor.child_spec({vault, opts}, restart: :temporary))
  end

  defp drain(acc \\ []) do
    receive do
      {:telemetry, name, measurements, metadata} -> drain([{name, measurements, metadata} | acc])
    after
      0 -> Enum.reverse(acc)
    end
  end

  defp names(events), do: Enum.map(events, fn {name, _m, _md} -> name end)

  defp event(events, name) do
    Enum.find(events, fn {candidate, _m, _md} -> candidate == name end)
  end

  describe "the three operation spans" do
    # sabotage: paired the stop half with a fresh make_ref/0 instead of the
    # start's - red, because span_ref is the only correct way to pair a stop
    # with its start (decision 4) and a consumer can then pair nothing.
    test "encrypt pairs a start and a stop on one span_ref" do
      start_vault(TelemetryVaults.Quiet)
      capture()

      assert {:ok, _ciphertext} = TelemetryVaults.Quiet.encrypt(@plaintext, key: @merchant)

      events = drain()

      assert names(events) == [
               [:encryptor, :encrypt, :start],
               [:encryptor, :provider, :start],
               [:encryptor, :provider, :stop],
               [:encryptor, :encrypt, :stop]
             ]

      {_name, start_measurements, start_metadata} = event(events, [:encryptor, :encrypt, :start])
      {_name, stop_measurements, stop_metadata} = event(events, [:encryptor, :encrypt, :stop])

      assert start_metadata.span_ref == stop_metadata.span_ref
      assert is_reference(start_metadata.span_ref)
      assert start_metadata.vault == TelemetryVaults.Quiet
      assert start_metadata.operation == :encrypt
      refute Map.has_key?(start_metadata, :outcome)

      assert start_measurements.size == byte_size(@plaintext)
      assert is_integer(start_measurements.system_time)
      assert stop_metadata.outcome == :ok
      refute Map.has_key?(stop_metadata, :reason_tag)
      assert Map.keys(stop_measurements) == [:duration]
      assert stop_measurements.duration > 0
    end

    # sabotage: measured `size` from the ciphertext on the decrypt stop - red,
    # because the measurement ADR-0006 decision 4 permits is the plaintext's
    # length, which the stored row already discloses, and the ciphertext's is
    # a different number reported under the same name.
    test "decrypt reports the plaintext it produced, and zero when it produced none" do
      start_vault(TelemetryVaults.Quiet)
      {:ok, ciphertext} = TelemetryVaults.Quiet.encrypt(@plaintext, key: @merchant)
      capture()

      assert {:ok, @plaintext} = TelemetryVaults.Quiet.decrypt(ciphertext, key: @merchant)

      {_name, measurements, metadata} = event(drain(), [:encryptor, :decrypt, :stop])
      assert measurements.size == byte_size(@plaintext)
      assert metadata.outcome == :ok

      capture()
      assert {:error, _error} = TelemetryVaults.Quiet.decrypt("not a message", key: @merchant)

      {_name, failed, failed_metadata} = event(drain(), [:encryptor, :decrypt, :stop])
      assert failed.size == 0
      assert failed_metadata.outcome == :error
    end

    # sabotage: named the rekey span [:encryptor, :encrypt, :start] by
    # threading the wrong operation - red, because a rotation then counts as a
    # write in every dashboard and the rekey stream is empty.
    test "rekey opens its own span, under its own name" do
      start_vault(TelemetryVaults.Quiet)
      {:ok, ciphertext} = TelemetryVaults.Quiet.encrypt(@plaintext, key: @merchant)
      capture()

      assert {:ok, _rotated} = TelemetryVaults.Quiet.rekey(ciphertext, key: @merchant)

      events = drain()

      assert names(events) == [
               [:encryptor, :rekey, :start],
               [:encryptor, :provider, :start],
               [:encryptor, :provider, :stop],
               [:encryptor, :provider, :start],
               [:encryptor, :provider, :stop],
               [:encryptor, :rekey, :stop]
             ]

      {_name, _m, metadata} = event(events, [:encryptor, :rekey, :stop])
      assert metadata.operation == :rekey
      assert metadata.outcome == :ok
    end

    # sabotage: replaced the hand-written halves with :telemetry.span/3 - red,
    # because that helper wraps the work in a rescue and ADR-0001 decision 10
    # says this package does not rescue exceptions into anything.
    test "no lib/ module calls :telemetry.span/3 (decision 2)" do
      callers =
        "lib/**/*.ex"
        |> Path.wildcard()
        |> Enum.filter(&String.contains?(File.read!(&1), ":telemetry.span("))

      assert callers == []
    end

    # sabotage: emitted the :stop half only when the operation succeeded -
    # red, because a refusal is exactly what an operator wants the counter
    # on, and a start with no stop is decision 2's raise case rather than a
    # refused call. The start half fires after selector resolution and before
    # the refusal is returned, which is what amendment A decision 3 requires
    # so that it can carry the reference at all.
    test "a refused selector still opens and closes its span" do
      start_vault(TelemetryVaults.Merchant)
      capture()

      assert {:error, _error} = TelemetryVaults.Merchant.encrypt(@plaintext, key: 42)

      events = drain()
      assert names(events) == [[:encryptor, :encrypt, :start], [:encryptor, :encrypt, :stop]]

      {_name, _m, metadata} = event(events, [:encryptor, :encrypt, :stop])
      assert metadata.outcome == :error
      assert metadata.reason_tag == :invalid_selector
      refute Map.has_key?(metadata, :scope_ref)
    end

    # sabotage: emitted the :stop half only when the operation succeeded -
    # red, because a vault that is down then reports a start and nothing
    # else, and the one failure an operator most needs a counter on is
    # invisible.
    test "a vault that is not running reports the refusal on its stop half" do
      capture()

      assert {:error, _error} = TelemetryVaults.Merchant.encrypt(@plaintext, key: @merchant)

      events = drain()
      assert names(events) == [[:encryptor, :encrypt, :start], [:encryptor, :encrypt, :stop]]

      {_name, _m, metadata} = event(events, [:encryptor, :encrypt, :stop])
      assert metadata.reason_tag == :vault_not_started
    end
  end

  describe "decision 7: the oracle rule in telemetry" do
    # sabotage: carried the Encryptor.Error's :engine term beside the tag -
    # red, and on the decrypt path that term is precisely the distinction
    # ADR-0001 decision 10 collapsed to avoid a decryption oracle. It is a
    # worse oracle here than in a return value, because an error return goes
    # to the caller who made the call while an event goes to every attached
    # handler whether or not anyone asked.
    test "a decrypt failure's stop carries reason_tag and nothing finer" do
      start_vault(TelemetryVaults.Quiet)
      {:ok, ciphertext} = TelemetryVaults.Quiet.encrypt(@plaintext, key: @merchant)
      capture()

      # A wrong key, a corrupted body and an unparseable header are three
      # different failures to the engine and one reason here.
      assert {:error, _wrong_key} = TelemetryVaults.Quiet.decrypt(ciphertext, key: "merchant_b")
      assert {:error, _garbage} = TelemetryVaults.Quiet.decrypt("garbage", key: @merchant)

      corrupted = :binary.part(ciphertext, 0, byte_size(ciphertext) - 1) <> <<0>>
      assert {:error, _corrupt} = TelemetryVaults.Quiet.decrypt(corrupted, key: @merchant)

      stops =
        drain()
        |> Enum.filter(fn {name, _m, _md} -> name == [:encryptor, :decrypt, :stop] end)
        |> Enum.map(fn {_name, _m, metadata} -> metadata end)

      assert length(stops) == 3

      Enum.each(stops, fn metadata ->
        assert metadata.outcome == :error
        assert metadata.reason_tag == :decrypt_failed

        assert Map.keys(metadata) -- [:vault, :operation, :span_ref, :outcome, :reason_tag] == []
      end)
    end
  end

  describe "decision 8: the nested provider span" do
    # sabotage: put the provider's whole `{module, opts}` pair in metadata
    # instead of the module - red, because a provider's options are where a
    # static key lives and decision 4 lets no term ride that its table does
    # not name.
    test "names the adapter module, the callback and the operation" do
      start_vault(TelemetryVaults.Quiet)
      capture()

      {:ok, _ciphertext} = TelemetryVaults.Quiet.encrypt(@plaintext, key: @merchant)

      events = drain()
      {_name, start_measurements, start_metadata} = event(events, [:encryptor, :provider, :start])
      {_name, stop_measurements, stop_metadata} = event(events, [:encryptor, :provider, :stop])

      assert start_metadata.provider == Encryptor.Provider.Function
      assert start_metadata.callback == :encryption_key
      assert start_metadata.operation == :encrypt
      assert start_metadata.span_ref == stop_metadata.span_ref
      assert Map.keys(start_measurements) == [:system_time]

      assert stop_metadata.outcome == :ok
      # No candidate list on the write side, so no `candidates`.
      assert Map.keys(stop_measurements) == [:duration]
    end

    # sabotage: dropped the `candidates` measurement - red, because
    # ADR-0002's consequence that a long-lived key owner accumulates candidates says
    # the list grows without bound and this is the only measurement that would
    # tell an operator it had.
    test "counts the candidate list a decryption_keys round trip answered with" do
      start_vault(TelemetryVaults.Quiet)
      {:ok, ciphertext} = TelemetryVaults.Quiet.encrypt(@plaintext, key: @merchant)
      capture()

      {:ok, _plaintext} = TelemetryVaults.Quiet.decrypt(ciphertext, key: @merchant)

      {_name, measurements, metadata} = event(drain(), [:encryptor, :provider, :stop])
      assert metadata.callback == :decryption_keys
      assert measurements.candidates == 1
    end

    # sabotage: swallowed the provider's failure and emitted outcome: :ok -
    # red, and it is the record's motivating case: the key_unavailable counter
    # is what tells an operator the store is down rather than that the data is
    # corrupt.
    test "a store that has gone away reports key_unavailable on both spans" do
      start_vault(TelemetryVaults.Downed)
      capture()

      assert {:error, _error} = TelemetryVaults.Downed.encrypt(@plaintext, key: @merchant)

      events = drain()
      {_name, _m, provider} = event(events, [:encryptor, :provider, :stop])
      {_name, _m2, operation} = event(events, [:encryptor, :encrypt, :stop])

      assert provider.outcome == :error
      assert provider.reason_tag == :key_unavailable
      assert operation.reason_tag == :key_unavailable
    end

    # sabotage: dropped the write half's provider span - red, because a rekey
    # that cannot reach the store to write then reports nothing on the span an
    # operator pages on, and a rotation's two round trips are two spans.
    test "a rekey's two round trips are two spans" do
      start_vault(TelemetryVaults.Quiet)
      {:ok, ciphertext} = TelemetryVaults.Quiet.encrypt(@plaintext, key: @merchant)
      capture()

      {:ok, _rotated} = TelemetryVaults.Quiet.rekey(ciphertext, key: @merchant)

      provider =
        drain()
        |> Enum.filter(fn {name, _m, _md} -> name == [:encryptor, :provider, :stop] end)
        |> Enum.map(fn {_name, _m, metadata} -> metadata end)

      assert [read, write] = provider
      assert read.callback == :decryption_keys
      assert write.callback == :encryption_key
      assert read.span_ref != write.span_ref
      assert read.operation == :rekey
      assert write.operation == :rekey
    end

    # sabotage: instrumented Resolve.encryption_key/3 itself - red, because
    # derive/3 and provision/2 reach the same callback with operation
    # :derive and :provision, neither of which decision 4's allow-list admits.
    test "a derivation emits no provider span" do
      start_vault(TelemetryVaults.Quiet)
      capture()

      Encryptor.Vault.derive(TelemetryVaults.Quiet, "index", key: @merchant)

      refute Enum.any?(drain(), fn {name, _m, _md} -> name == [:encryptor, :provider, :start] end)
    end
  end

  describe "amendment A: the opt-in scope dimension" do
    # sabotage: emitted a shorter prefix of the reference "to make the
    # dimension less identifying" - red, and it is the alternative amendment A
    # decision 2 refuses outright: a prefix buys no disclosure property, and
    # two scopes sharing one silently become a single dimension value during
    # the incident this option exists for.
    test "an opted-in vault carries the keyed reference on all four span names" do
      start_vault(TelemetryVaults.Merchant)
      {:ok, ciphertext} = TelemetryVaults.Merchant.encrypt(@plaintext, key: @merchant)
      capture()

      {:ok, _plaintext} = TelemetryVaults.Merchant.decrypt(ciphertext, key: @merchant)
      {:ok, _rotated} = TelemetryVaults.Merchant.rekey(ciphertext, key: @merchant)

      events = drain()
      expected = Reference.derive(EncryptVaults.reference_subkey(), @merchant)

      assert byte_size(expected) == 22
      assert length(events) >= 10

      Enum.each(events, fn {[:encryptor, name, _half], _m, metadata} ->
        assert name in @span_names
        assert metadata.scope_ref == expected
      end)

      refute expected == Partition.id(TelemetryVaults.Merchant, @merchant)
      refute Partition.id(TelemetryVaults.Merchant, @merchant) in values(events)
    end

    # sabotage: put the key in metadata as `nil` when the option was off -
    # red, because a handler then cannot tell "this host did not opt in" from
    # a value, and a nil in a :telemetry_metrics tag is a dimension value.
    test "the key is absent, not nil, on a vault that did not opt in" do
      start_vault(TelemetryVaults.Quiet)
      capture()

      {:ok, _ciphertext} = TelemetryVaults.Quiet.encrypt(@plaintext, key: @merchant)

      events = drain()
      assert events != []

      Enum.each(events, fn {name, _m, metadata} ->
        refute Map.has_key?(metadata, :scope_ref),
               "#{inspect(name)} carried a scope dimension the vault never opted in to"
      end)
    end

    # sabotage: gave Resolve.context/5 back its own
    # `Reference.derive(config.reference_subkey, selector)` - red, because the
    # context then derives a second time per operation, which amendment A
    # decision 3 calls a defect against it rather than a slow implementation
    # of it: the residual cost of the option is a map write per event, not an
    # HMAC.
    test "the context layer takes the derived reference rather than deriving a second one" do
      start_vault(TelemetryVaults.Merchant)
      {:ok, config} = TelemetryVaults.Merchant.config()

      assert {:ok, context} = Resolve.context(config, "a-threaded-value", [], :encrypt)
      assert context[Encryptor.Context.scope_ref_key()] == "a-threaded-value"
    end

    # sabotage: added a second `Reference.derive/2` call on the emit side -
    # red, and it is the one amendment A decision 3 names: the reference is
    # derived once per operation and threaded, so the residual cost of the
    # option is a map write per event rather than an HMAC per event, and a
    # per-event derivation is a defect against the amendment rather than a
    # slow implementation of it.
    #
    # A per-event derivation produces the same string, so no handler can
    # observe it. This is the assertion that can: the three instrumented
    # paths hold one derivation site between them, in `Resolve`.
    #
    # The scan is deliberately textual and deliberately loose. It reads source
    # rather than behaviour, so a comment naming `Reference.derive(` in
    # `resolve.ex` would fail it and a second derivation reached through a
    # re-alias would pass it. Both are accepted: the assertion exists to stop
    # the obvious regression - an emit site growing its own derivation - and a
    # tighter check would need AST analysis for a defect no reviewer of this
    # module would miss (enc-qjx).
    test "one derivation per operation: the emit sites derive nothing" do
      resolve = File.read!("lib/encryptor/vault/resolve.ex")
      assert resolve |> String.split("Reference.derive(") |> length() == 2

      Enum.each(
        ~w(telemetry.ex vault/encrypt.ex vault/decrypt.ex vault/rekey.ex),
        fn file ->
          refute File.read!("lib/encryptor/" <> file) =~ "Reference",
                 "#{file} names Encryptor.Vault.Reference, so it can derive a second time"
        end
      )
    end

    # sabotage: dropped the `true when profile == :single` refusal from
    # Config - red, because a `:single` vault has no scope to name, and a
    # host that asked for the dimension and quietly did not get it would build
    # a dashboard on a key that is never there (amendment A decision 1).
    test "a single-key vault refuses the option, and its spans carry nothing" do
      assert {:error, %Error{reason: reason}} = TelemetryVaults.AppOptedIn.start_link([])
      assert reason == {:invalid_config, :telemetry_scope_ref, :vault_is_single_profile}

      start_vault(TelemetryVaults.App)
      capture()

      {:ok, _ciphertext} = TelemetryVaults.App.encrypt(@plaintext)

      Enum.each(drain(), fn {_name, _m, metadata} ->
        refute Map.has_key?(metadata, :scope_ref)
      end)
    end

    # sabotage: emitted the partition id as the dimension - red, and it is the
    # substitution decision 6 says a well-meaning implementation is most
    # likely to make: ADR-0001 decision 7 truthfully says the partition id is
    # not secret, and it is an unkeyed SHA-256 of the selector, confirmable by
    # anyone who can guess a scope identifier.
    test "the value is the one the message's own context carries" do
      start_vault(TelemetryVaults.Merchant)
      capture()

      {:ok, ciphertext} = TelemetryVaults.Merchant.encrypt(@plaintext, key: @merchant)

      {:ok, info} = Encryptor.Message.describe(ciphertext)
      {_name, _m, metadata} = event(drain(), [:encryptor, :encrypt, :start])

      assert info.encryption_context[Encryptor.Context.scope_ref_key()] == metadata.scope_ref
    end
  end

  describe "the two sites that state the rule" do
    # sabotage: left the moduledoc's unqualified sentence in place - red, and
    # it is the second site the amendment's A6 names: the record states the
    # amended wording and the implementation writes it, so a reader of either
    # gets the same rule.
    #
    # The record keeps its tenant wording; ADR-0009 decision 3 renames the
    # option and the metadata key it names, so the moduledoc states the same
    # sentence under the Scope names. The record half pins the record's own
    # text; the moduledoc half pins that text with exactly those renames.
    test "the moduledoc states amendment A6's amended wording" do
      amended =
        "no event carries a per-tenant dimension unless the vault opted in with " <>
          "`telemetry_tenant_ref: true`, and then it is the keyed `tenant_ref` and " <>
          "never the partition id"

      renamed =
        "no event carries a per-scope dimension unless the vault opted in with " <>
          "`telemetry_scope_ref: true`, and then it is the keyed `scope_ref` and " <>
          "never the partition id"

      {:docs_v1, _a, _b, _c, %{"en" => moduledoc}, _d, _e} = Code.fetch_docs(Telemetry)

      assert String.contains?(normalize(moduledoc), renamed)

      record = File.read!("docs/adr/0006-telemetry-and-observability.md")
      assert String.contains?(record |> String.replace("**", "") |> normalize(), amended)

      refute String.contains?(
               normalize(moduledoc),
               "no event carries a per-scope dimension, keyed or unkeyed"
             )
    end
  end

  defp normalize(text) do
    text |> String.downcase() |> String.replace(~r/\s+/, " ")
  end

  defp values(events) do
    Enum.flat_map(events, fn {_name, _m, metadata} -> Map.values(metadata) end)
  end
end
