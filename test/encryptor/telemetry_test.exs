defmodule Encryptor.TelemetryTest do
  use ExUnit.Case, async: false

  alias Encryptor.Error
  alias Encryptor.LifecycleVaults
  alias Encryptor.Telemetry
  alias Encryptor.TelemetryVaults
  alias Encryptor.Vault
  alias Encryptor.Vault.CacheRecycler
  alias Encryptor.Vault.Partition

  doctest Encryptor.Telemetry

  # ADR-0006 decision 4's metadata table, restated here rather than read off
  # the implementation. A test that asked `Encryptor.Telemetry` what it allows
  # would pass whatever the module happened to emit; this one fails when the
  # module and the record disagree, which is the only failure worth catching.
  @allowed_metadata_keys [
    :vault,
    :operation,
    :span_ref,
    :outcome,
    :reason_tag,
    :provider,
    :callback,
    :cache,
    :profile,
    :reference_check
  ]

  @allowed_measurement_keys [:duration, :system_time, :size, :candidates]

  # Attaches one handler id per event name, which is what `events/0` is for:
  # `attach_many/4`'s detach is total, so a raising branch would take every
  # event with it.
  defp capture(events \\ Telemetry.events()) do
    parent = self()
    id = "enc-3jr-#{System.unique_integer([:positive])}"

    Enum.each(events, fn event ->
      handler_id = {id, event}

      :telemetry.attach(
        handler_id,
        event,
        &__MODULE__.forward/4,
        parent
      )

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

  # Drains everything the handler forwarded, so the allow-list assertions can
  # run over a whole scenario rather than one event at a time.
  defp drain(acc \\ []) do
    receive do
      {:telemetry, name, measurements, metadata} ->
        drain([{name, measurements, metadata} | acc])
    after
      0 -> Enum.reverse(acc)
    end
  end

  describe "the vocabulary" do
    # sabotage: dropped [:encryptor, :cache, :recycled] from @vault_events -
    # red, because a host attaching against events/0 then silently never sees
    # the only recurring runtime event in the package.
    test "events/0 is the closed list ADR-0006 decision 3 fixes" do
      assert Telemetry.events() == [
               [:encryptor, :vault, :started],
               [:encryptor, :vault, :stopped],
               [:encryptor, :vault, :start_refused],
               [:encryptor, :cache, :recycled],
               [:encryptor, :encrypt, :start],
               [:encryptor, :encrypt, :stop],
               [:encryptor, :decrypt, :start],
               [:encryptor, :decrypt, :stop],
               [:encryptor, :rekey, :start],
               [:encryptor, :rekey, :stop],
               [:encryptor, :provider, :start],
               [:encryptor, :provider, :stop]
             ]
    end

    # sabotage: made the {:key_unavailable, _} clause return the whole tuple
    # instead of its head - red, and it is the disclosure decision 5 exists to
    # prevent: the second element is a selector the caller passed.
    test "reason_tag/1 is the head of the reason and never the term" do
      reasons = [
        {:decrypt_failed, :decrypt_failed},
        {{:vault_not_started, MyApp.Vault}, :vault_not_started},
        {{:missing_config, [:cache, :max_age]}, :missing_config},
        {{:invalid_config, :reference_check, :not_a_string}, :invalid_config},
        {{:unknown_key, "acct_9f21"}, :unknown_key},
        {{:encryption_context_conflict, "table"}, :encryption_context_conflict},
        {{:reserved_context_key, "encryptor:v"}, :reserved_context_key},
        {{:key_unavailable, "acct_9f21"}, :key_unavailable},
        {{:invalid_key_descriptor, %{secret: "shape"}}, :invalid_key_descriptor},
        {{:provider_not_started, MyApp.Provider}, :provider_not_started},
        {{:missing_optional_dependency, :argon2_elixir}, :missing_optional_dependency},
        {{:missing_required_context_keys, ["table"]}, :missing_required_context_keys},
        {{:invalid_context_value, :too_large}, :invalid_context_value},
        {{:invalid_selector, 42}, :invalid_selector},
        {{:not_provisionable, MyApp.Provider}, :not_provisionable}
      ]

      Enum.each(reasons, fn {reason, tag} ->
        assert Telemetry.reason_tag(reason) == tag
        assert is_atom(Telemetry.reason_tag(reason))
      end)
    end

    # sabotage: deleted the {:not_provisionable, _} clause - red, because
    # reason_tag/1 is spec'd over the whole of Encryptor.Error.reason/0 and a
    # missing clause raises a FunctionClauseError inside an emit, which is
    # exactly the fallthrough decision 5's closing paragraph refuses.
    test "reason_tag/1 is total over today's error vocabulary" do
      reasons = [
        :decrypt_failed,
        {:vault_not_started, MyApp.Vault},
        {:missing_config, [:provider]},
        {:invalid_config, :cache, :bad},
        {:unknown_key, :default},
        {:encryption_context_conflict, "a"},
        {:reserved_context_key, "a"},
        {:key_unavailable, :default},
        {:invalid_key_descriptor, nil},
        {:provider_not_started, MyApp.Provider},
        {:missing_optional_dependency, :argon2_elixir},
        {:missing_required_context_keys, []},
        {:invalid_context_value, :count},
        {:invalid_selector, nil},
        {:not_provisionable, MyApp.Provider}
      ]

      Enum.each(reasons, fn reason ->
        assert Telemetry.reason_tag(reason) in [
                 :decrypt_failed,
                 :vault_not_started,
                 :missing_config,
                 :invalid_config,
                 :unknown_key,
                 :encryption_context_conflict,
                 :reserved_context_key,
                 :key_unavailable,
                 :invalid_key_descriptor,
                 :provider_not_started,
                 :missing_optional_dependency,
                 :missing_required_context_keys,
                 :invalid_context_value,
                 :invalid_selector,
                 :not_provisionable
               ]
      end)
    end
  end

  describe "[:encryptor, :vault, :started]" do
    # sabotage: removed the Telemetry.vault_started/1 call from started/2 -
    # red, because a vault that came up then says nothing, and cache, profile
    # and reference_check are visible nowhere else at runtime.
    test "a cached single-profile vault reports its cache, profile and check" do
      capture()
      start_vault(LifecycleVaults.Cached)

      assert_receive {:telemetry, [:encryptor, :vault, :started], measurements, metadata}

      assert metadata == %{
               vault: LifecycleVaults.Cached,
               cache: true,
               profile: :single,
               reference_check: :unpinned
             }

      assert %{system_time: system_time} = measurements
      assert is_integer(system_time)
      assert Map.keys(measurements) == [:system_time]
    end

    # sabotage: reported `cache: true` unconditionally instead of reading the
    # resolved bounds - red, because a vault with `cache: false` then looks
    # like one running a recycler and an operator reads a missing
    # :cache.recycled stream as a broken recycler.
    test "a vault with caching off reports cache: false" do
      capture()
      start_vault(LifecycleVaults.Cacheless)

      assert_receive {:telemetry, [:encryptor, :vault, :started], _measurements, metadata}
      assert metadata.cache == false
      assert metadata.vault == LifecycleVaults.Cacheless
    end

    # sabotage: returned :verified whenever the profile was :tenant rather
    # than when a value was pinned - red, because a tenant vault running with
    # no known-answer check then reports that it has one, and the record says
    # this is the only place that finding is visible.
    test "a tenant vault reports whether its known-answer check is pinned" do
      capture()
      start_vault(TelemetryVaults.Pinned)

      assert_receive {:telemetry, [:encryptor, :vault, :started], _m, pinned}

      assert pinned == %{
               vault: TelemetryVaults.Pinned,
               cache: false,
               profile: :tenant,
               reference_check: :verified
             }

      start_vault(TelemetryVaults.Unpinned)

      assert_receive {:telemetry, [:encryptor, :vault, :started], _m2, unpinned}
      assert unpinned.reference_check == :unpinned
      assert unpinned.profile == :tenant
    end
  end

  describe "[:encryptor, :vault, :stopped]" do
    # sabotage: removed the Telemetry.vault_stopped/1 call from terminate/2 -
    # red, because a vault whose frozen configuration was erased then reports
    # nothing, and :started and :stopped stop pairing.
    test "fires from terminate/2, after the frozen configuration is erased" do
      pid = start_vault(LifecycleVaults.Cacheless)
      capture()

      Supervisor.stop(pid)

      assert_receive {:telemetry, [:encryptor, :vault, :stopped], measurements, metadata}
      assert metadata == %{vault: LifecycleVaults.Cacheless}
      assert Map.keys(measurements) == [:system_time]
      refute LifecycleVaults.Cacheless.started?()
    end
  end

  describe "[:encryptor, :vault, :start_refused]" do
    # sabotage: put the whole %Encryptor.Error{} in metadata under :error
    # instead of its tag - red, because the struct carries the reason's second
    # element and the :engine term, and a handler forwards metadata verbatim
    # to an APM the package did not choose (decision 6).
    test "a refused configuration reports its tag and nothing else" do
      capture()

      assert {:error, %Error{} = error} = LifecycleVaults.Unconfigured.start_link([])
      assert Telemetry.reason_tag(error.reason) == :missing_config

      assert_receive {:telemetry, [:encryptor, :vault, :start_refused], measurements, metadata}

      assert metadata == %{
               vault: LifecycleVaults.Unconfigured,
               operation: :start,
               reason_tag: :missing_config
             }

      assert Map.keys(measurements) == [:system_time]
    end

    # sabotage: emitted :start_refused alongside :started on the success path
    # - red, because a refusal counter that also counts successful starts is
    # worse than no counter.
    test "a vault that starts emits no refusal" do
      capture()
      start_vault(LifecycleVaults.Cacheless)

      assert_receive {:telemetry, [:encryptor, :vault, :started], _m, _md}
      refute_receive {:telemetry, [:encryptor, :vault, :start_refused], _m2, _md2}, 50
    end
  end

  describe "[:encryptor, :cache, :recycled]" do
    # sabotage: passed a literal 0 as the duration instead of the measured
    # span - red, because a recycle that reports no duration tells an operator
    # nothing about the window in which the cache's registered name resolves
    # to nothing.
    test "a successful recycle reports its outcome and how long it took" do
      start_vault(LifecycleVaults.Cached)
      capture()

      assert {:ok, _pid} =
               CacheRecycler.recycle(
                 LifecycleVaults.Cached,
                 Vault.supervisor_name(LifecycleVaults.Cached)
               )

      assert_receive {:telemetry, [:encryptor, :cache, :recycled], measurements, metadata}
      assert metadata == %{vault: LifecycleVaults.Cached, outcome: :ok}
      assert Map.keys(measurements) == [:duration]
      assert measurements.duration > 0
    end

    # sabotage: dropped the error branch from cache_recycled/3 and always
    # reported outcome: :ok - red, and it is the defect ADR-0006 decision 10
    # singles out: the missed bound was dropped on the floor here and nothing
    # anywhere said it happened.
    test "a recycle that finds no cache child reports the failure" do
      start_vault(LifecycleVaults.Cacheless)
      capture()

      assert {:error, :not_found} =
               CacheRecycler.recycle(
                 LifecycleVaults.Cacheless,
                 Vault.supervisor_name(LifecycleVaults.Cacheless)
               )

      assert_receive {:telemetry, [:encryptor, :cache, :recycled], _measurements, metadata}

      assert metadata == %{
               vault: LifecycleVaults.Cacheless,
               outcome: :error,
               reason_tag: :vault_not_started
             }
    end

    # sabotage: made handle_info/2 call recycle/2 with the supervisor name in
    # the vault position - red, because every recycled event then names a
    # module no host recognises and the metric cannot be grouped per vault.
    test "the recycler's own tick names the vault the cache belongs to" do
      start_vault(LifecycleVaults.Cached)
      capture([[:encryptor, :cache, :recycled]])

      start_supervised!(
        {CacheRecycler,
         [
           vault: LifecycleVaults.Cached,
           supervisor: Vault.supervisor_name(LifecycleVaults.Cached),
           interval: 10
         ]}
      )

      assert_receive {:telemetry, [:encryptor, :cache, :recycled], _m, %{vault: vault}}, 1_000
      assert vault == LifecycleVaults.Cached
    end
  end

  describe "decision 6: what is never emitted" do
    # sabotage: added `config: config` to the :started metadata - red,
    # because %Encryptor.Vault.Config{} holds the reference subkey, and a
    # handler forwards metadata verbatim to a third-party APM with a
    # retention policy nobody here chose.
    test "no event carries a key outside the record's allow-list" do
      capture()

      start_vault(TelemetryVaults.Pinned)
      start_vault(LifecycleVaults.Cacheless)
      pid = start_vault(LifecycleVaults.Cached)

      CacheRecycler.recycle(LifecycleVaults.Cached, Vault.supervisor_name(LifecycleVaults.Cached))

      CacheRecycler.recycle(
        LifecycleVaults.Cacheless,
        Vault.supervisor_name(LifecycleVaults.Cacheless)
      )

      {:error, %Error{}} = LifecycleVaults.Unconfigured.start_link([])
      Supervisor.stop(pid)

      events = drain()

      assert length(events) >= 5

      Enum.each(events, fn {name, measurements, metadata} ->
        assert Map.keys(metadata) -- @allowed_metadata_keys == [],
               "#{inspect(name)} carried a metadata key the record does not allow"

        assert Map.keys(measurements) -- @allowed_measurement_keys == [],
               "#{inspect(name)} carried a measurement the record does not allow"
      end)
    end

    # sabotage: emitted the pinned `:reference_check` string itself instead of
    # the :verified / :unpinned atom - red, and it is ADR-0004 acceptance
    # amendment 1's failure in a new place: a derived reference published to a
    # backend with worse retention, no authentication and a vendor boundary.
    #
    # The mechanical form of the rule: every value this half emits is an atom,
    # a module or a boolean. A plaintext, a key, a context value, a selector,
    # a partition id and an engine term are all binaries or structs, so a
    # binary or a struct anywhere in metadata is the leak, whatever it is
    # called.
    test "no metadata value is key-, selector-, or partition-shaped" do
      capture()

      start_vault(TelemetryVaults.Pinned)
      pid = start_vault(LifecycleVaults.Cached)

      CacheRecycler.recycle(LifecycleVaults.Cached, Vault.supervisor_name(LifecycleVaults.Cached))
      {:error, %Error{}} = LifecycleVaults.Unconfigured.start_link([])
      Supervisor.stop(pid)

      events = drain()
      values = Enum.flat_map(events, fn {_name, _m, metadata} -> Map.values(metadata) end)

      assert values != []

      Enum.each(values, fn value ->
        refute is_binary(value), "a binary reached telemetry metadata"
        refute is_map(value), "a map or struct reached telemetry metadata"
        refute is_list(value), "a list reached telemetry metadata"
        assert is_atom(value) or is_boolean(value)
      end)

      # Named explicitly, because the partition id is the one a well-meaning
      # implementation is most likely to add: ADR-0001 decision 7 truthfully
      # says it is not secret, and decision 6 refuses it anyway - it is an
      # unkeyed SHA-256 of the selector, confirmable by guess, and unbounded
      # cardinality.
      partition = Partition.id(LifecycleVaults.Cached, "tenant-42")
      subkey = TelemetryVaults.reference_subkey()
      check = TelemetryVaults.pinned_check()

      refute partition in values
      refute subkey in values
      refute check in values
    end
  end
end
