defmodule Encryptor.Telemetry do
  @moduledoc """
  The package's `:telemetry` events.

  No event carries a plaintext, a key of any kind, an encryption context
  value, a `:key` selector, a partition id, or an `Encryptor.Error`'s
  `:engine` term. No event carries a per-scope dimension unless the vault
  opted in with `telemetry_scope_ref: true`, and then it is the keyed
  `scope_ref` and never the partition id.
  Handlers run on the calling process, so a slow handler is a slow encrypt.

  This module is the single definition site for the vocabulary (ADR-0006
  decision 3) and the only module in `lib/` that calls
  `:telemetry.execute/3`. The event set is closed: adding a name, a
  measurement, or a metadata key is additive, and removing or renaming one is
  a breaking change to a consumer's `case` and to their dashboards, so it
  takes an amendment to that record.

  ## Attaching

      :telemetry.attach_many(
        "my-app-encryptor",
        Encryptor.Telemetry.events(),
        &MyApp.Handler.handle/4,
        nil
      )

  `:telemetry` detaches a handler that raises, permanently and silently, for
  the lifetime of the VM. `attach_many/4`'s detach is total, so one malformed
  branch takes every event with it; attaching one handler id per name - which
  is what `events/0` is for - bounds that to the event that raised.

  ## The events

  `:start` and `:stop` name a span pair and nothing else. Every other event is
  a point event, named in the past tense, so an attach list can be read
  without reading the record.

  | Event | Kind | Fires |
  |---|---|---|
  | `[:encryptor, :vault, :started]` | point | a vault's supervisor came up with its configuration frozen |
  | `[:encryptor, :vault, :stopped]` | point | Encryptor.Vault.Lifecycle erased the frozen configuration |
  | `[:encryptor, :vault, :start_refused]` | point | configuration resolution refused, before any process existed |
  | `[:encryptor, :cache, :recycled]` | point | the recycler dropped and restarted the cache child |
  | `[:encryptor, :suspension, :changed]` | point | a vault's suspension state changed: see below |
  | `[:encryptor, :encrypt, :start]` / `[..., :stop]` | span | `encrypt/2` |
  | `[:encryptor, :decrypt, :start]` / `[..., :stop]` | span | `decrypt/2` |
  | `[:encryptor, :rekey, :start]` / `[..., :stop]` | span | `rekey/2` |
  | `[:encryptor, :provider, :start]` / `[..., :stop]` | span | one `encryption_key/2` or `decryption_keys/2` round trip |

  The eight span halves - four pairs - are specified by ADR-0006 and emitted
  by the paths they instrument (that record's decision 10), all of which are
  written. `events/0` returns thirteen names: the five point events above and
  those eight halves.

  ## Measurements

  | Measurement | Unit | On |
  |---|---|---|
  | `duration` | `:native` | every span stop, and `:recycled` |
  | `system_time` | `:native` | every span start and every point event |
  | `size` | bytes | `[:encryptor, :encrypt, :start]` and `[:encryptor, :decrypt, :stop]` |
  | `candidates` | count | `[:encryptor, :provider, :stop]` on a successful `decryption_keys/2` |
  | `count` | count | `[:encryptor, :suspension, :changed]` when `outcome` is `:ok`: the scopes in the view after the action |

  ## Metadata

  Metadata is an **allow-list**. No struct rides verbatim: not a
  `Encryptor.Vault.Config`, not a key descriptor, not a keyring, a CMM, a
  client, a context map, a ciphertext, a plaintext, an `Encryptor.Error` or
  its `:engine` term.

  | Key | Type | On |
  |---|---|---|
  | `vault` | `module()` | every event |
  | `operation` | `t:Encryptor.Error.operation/0` | spans, `:start_refused` |
  | `span_ref` | `reference()` | span halves |
  | `outcome` | `:ok \| :error` | span stops, `:recycled`, `:changed` |
  | `reason_tag` | `t:reason_tag/0` | when `outcome` is `:error` |
  | `provider` | `module()` | provider spans |
  | `callback` | `:encryption_key \\| :decryption_keys` | provider spans |
  | `cache` | `boolean()` | `[:encryptor, :vault, :started]` |
  | `profile` | `:single \\| :scoped` | `[:encryptor, :vault, :started]` |
  | `reference_check` | `:verified \\| :unpinned` | `[:encryptor, :vault, :started]` |
  | `scope_ref` | `String.t()` | the four span names' halves, only when `:telemetry_scope_ref` is on |
  | `action` | `:suspend \| :reinstate \| :refresh` | `[:encryptor, :suspension, :changed]` |
  | `store` | `module()` | `[:encryptor, :suspension, :changed]`: the store module, never its state or options |

  ## Suspension changes

  `[:encryptor, :suspension, :changed]` fires on the process that changed a
  vault's suspension state (ADR-0010 decision 8):

    * after every `Encryptor.Vault.suspend/2` or `Encryptor.Vault.reinstate/2`
      the vault performed, successful or not;
    * under a shared `:suspension_store`, after a refresh that changed the
      view's membership, after a refresh that failed, and after the first
      refresh that succeeds following a failure.

  A refresh that changed nothing emits nothing, so a healthy vault is silent
  between operator actions. The selector is never in it, whatever
  `:telemetry_scope_ref` says: an operator who needs to know which scope was
  suspended reads the store.

  ## The opt-in scope dimension

  With `telemetry_scope_ref: true`, every encrypt, decrypt, rekey and
  provider event carries `scope_ref` - ADR-0003 decision 5's keyed reference
  for the scope the call routed to. It is a pseudonym and not an identifier:
  it does not contain the scope identifier and cannot be reversed into it.
  Anyone holding the vault's reference subkey can re-identify it, by deriving
  the reference for a candidate scope and comparing, and so can anyone who
  can enumerate or guess your scope identifiers. Telemetry metadata is
  forwarded verbatim by handlers you did not write to vendors whose retention
  you did not choose. Turning this on is a decision about that, and it is off
  by default.

  It is vault configuration, refused as `true` on a `:single` vault, and the
  reference is derived once per operation and threaded through both halves of
  the operation span and through the nested provider span's halves. When the
  option is off the key is **absent** from the metadata map rather than
  present as `nil`: a handler tells "this host did not opt in" from any value
  by `Map.has_key?/2`, and a `nil` in a `:telemetry_metrics` tag is a
  dimension value. Cardinality is your scope count, which is what you asked
  for and is your vendor's bill (ADR-0006 amendment A).
  """

  alias Encryptor.Error
  alias Encryptor.Vault.Config

  @vault_events [
    [:encryptor, :vault, :started],
    [:encryptor, :vault, :stopped],
    [:encryptor, :vault, :start_refused],
    [:encryptor, :cache, :recycled],
    [:encryptor, :suspension, :changed]
  ]

  @span_names [:encrypt, :decrypt, :rekey, :provider]

  @span_events for name <- @span_names,
                   half <- [:start, :stop],
                   do: [:encryptor, name, half]

  @events @vault_events ++ @span_events

  @typedoc "The operations that open a span pair."
  @type span_name :: :encrypt | :decrypt | :rekey | :provider

  @typedoc """
  The metadata tag for a failure.

  The head of an `t:Encryptor.Error.reason/0`, never the term: every member
  but `:decrypt_failed` is a tagged tuple whose second element is caller data
  - a selector, a context key, a config path, a module - and that data does
  not leave the process in a metric. The set is closed, and extends only when
  the error vocabulary does, which is itself an ADR-gated act (ADR-0001
  decision 10). That closure is what makes it safe as a metric dimension: a
  backend keying on it has a bounded label set no matter what a caller passes.
  """
  @type reason_tag ::
          :decrypt_failed
          | :vault_not_started
          | :missing_config
          | :invalid_config
          | :unknown_key
          | :encryption_context_conflict
          | :reserved_context_key
          | :key_unavailable
          | :invalid_key_descriptor
          | :provider_not_started
          | :missing_optional_dependency
          | :missing_required_context_keys
          | :invalid_context_value
          | :invalid_selector
          | :not_provisionable
          | :suspension_store_unavailable

  @typedoc "Every metadata key any event may carry, and nothing else."
  @type metadata :: %{
          optional(:vault) => module(),
          optional(:operation) => Error.operation(),
          optional(:span_ref) => reference(),
          optional(:outcome) => :ok | :error,
          optional(:reason_tag) => reason_tag(),
          optional(:provider) => module(),
          optional(:callback) => :encryption_key | :decryption_keys,
          optional(:cache) => boolean(),
          optional(:profile) => Config.profile(),
          optional(:reference_check) => :verified | :unpinned,
          optional(:scope_ref) => String.t(),
          optional(:action) => :suspend | :reinstate | :refresh,
          optional(:store) => module()
        }

  @doc """
  Every event name this package emits. The single definition site.

  A host attaches against this rather than hand-copying names the record may
  later extend.

      iex> [:encryptor, :cache, :recycled] in Encryptor.Telemetry.events()
      true

      iex> length(Encryptor.Telemetry.events())
      13
  """
  @spec events() :: [[atom(), ...], ...]
  def events, do: @events

  @doc """
  The metadata tag for a reason term. Never the term itself.

      iex> Encryptor.Telemetry.reason_tag({:key_unavailable, "acct_9f21"})
      :key_unavailable

      iex> Encryptor.Telemetry.reason_tag(:decrypt_failed)
      :decrypt_failed

  It is deliberately not `elem(reason, 0)`: `:decrypt_failed` is a bare atom,
  and a fallthrough that reached `elem/2` on a term the record did not
  anticipate would either raise inside an emit or leak whatever the term was.
  """
  @spec reason_tag(Error.reason()) :: reason_tag()
  def reason_tag(:decrypt_failed), do: :decrypt_failed
  def reason_tag({:vault_not_started, _vault}), do: :vault_not_started
  def reason_tag({:missing_config, _path}), do: :missing_config
  def reason_tag({:invalid_config, _key, _detail}), do: :invalid_config
  def reason_tag({:unknown_key, _selector}), do: :unknown_key
  def reason_tag({:encryption_context_conflict, _key}), do: :encryption_context_conflict
  def reason_tag({:reserved_context_key, _key}), do: :reserved_context_key
  def reason_tag({:key_unavailable, _selector}), do: :key_unavailable
  def reason_tag({:invalid_key_descriptor, _detail}), do: :invalid_key_descriptor
  def reason_tag({:provider_not_started, _module}), do: :provider_not_started
  def reason_tag({:missing_optional_dependency, _app}), do: :missing_optional_dependency
  def reason_tag({:missing_required_context_keys, _keys}), do: :missing_required_context_keys
  def reason_tag({:invalid_context_value, _detail}), do: :invalid_context_value
  def reason_tag({:invalid_selector, _term}), do: :invalid_selector
  def reason_tag({:not_provisionable, _module}), do: :not_provisionable
  def reason_tag({:suspension_store_unavailable, _module}), do: :suspension_store_unavailable

  @doc false
  # `[:encryptor, :vault, :started]`. The whole of what the frozen
  # configuration is allowed to say about itself: whether this vault runs a
  # cache child at all, which context profile it took, and whether decision
  # 4's known-answer check had a pinned value to check against. The struct
  # itself never rides - it holds the reference subkey.
  @spec vault_started(Config.t()) :: :ok
  def vault_started(%Config{} = config) do
    execute([:encryptor, :vault, :started], %{system_time: System.system_time()}, %{
      vault: config.vault,
      cache: is_map(config.cache),
      profile: config.context_profile,
      reference_check: reference_check(config)
    })
  end

  @doc false
  # `[:encryptor, :vault, :stopped]`. A vault module and a clock reading; a
  # stop has nothing else to report.
  @spec vault_stopped(module()) :: :ok
  def vault_stopped(vault) do
    execute([:encryptor, :vault, :stopped], %{system_time: System.system_time()}, %{vault: vault})
  end

  @doc false
  # `[:encryptor, :vault, :start_refused]`. Which key was missing is in the
  # `{:error, %Encryptor.Error{}}` the caller already holds; the event says a
  # vault refused to start, and the return value says why.
  @spec vault_start_refused(module(), Error.t()) :: :ok
  def vault_start_refused(vault, %Error{} = error) do
    execute([:encryptor, :vault, :start_refused], %{system_time: System.system_time()}, %{
      vault: vault,
      operation: :start,
      reason_tag: reason_tag(error.reason)
    })
  end

  @doc false
  # `[:encryptor, :cache, :recycled]`. The only recurring runtime event in the
  # package, and the branch ADR-0006 decision 10 singles out: a recycle whose
  # `Supervisor.terminate_child/2` returned an error is dropped on the floor
  # today and nothing anywhere says it happened.
  #
  # That failure is a supervisor term rather than an `Encryptor.Error.reason`,
  # so it does not go through `reason_tag/1`. Two sub-cases reach it:
  # `Supervisor.terminate_child/2` answering `{:error, :not_found}`, which is
  # a cache child that was not there to drop; and a terminate that succeeded
  # followed by `Supervisor.restart_child/2` answering
  # `{:error, :running | :restarting | term}`, which is not a not-started
  # vault. Both are tagged `:vault_not_started` because that is the one tag
  # ADR-0006's worked example gives this branch and the vocabulary is closed
  # (that record's decision 5); the gap is recorded in ADR-0006's Note of
  # 2026-09-13, and a second tag would be an amendment rather than a fix here.
  # The supervisor's own term is not forwarded - it is not on the allow-list -
  # but `CacheRecycler.recycle/2` returns it to its caller unchanged, which is
  # where the sub-case is distinguishable.
  @spec cache_recycled(module(), integer(), term()) :: :ok
  def cache_recycled(vault, duration, result) do
    metadata =
      case result do
        {:error, _reason} -> %{vault: vault, outcome: :error, reason_tag: :vault_not_started}
        _ok -> %{vault: vault, outcome: :ok}
      end

    execute([:encryptor, :cache, :recycled], %{duration: duration}, metadata)
  end

  @doc false
  # `[:encryptor, :suspension, :changed]` (ADR-0010 decision 8). The vault,
  # what it did, and the store module - never the store's state or options,
  # and never the selector, which is exactly the per-scope dimension ADR-0006
  # decision 6 refuses. `count` is the size of the view after a successful
  # action, which is bounded by the number of suspended scopes.
  @spec suspension_changed(
          module(),
          :suspend | :reinstate | :refresh,
          module(),
          {:ok, non_neg_integer()} | :error
        ) :: :ok
  def suspension_changed(vault, action, store, {:ok, count}) do
    execute(
      [:encryptor, :suspension, :changed],
      %{system_time: System.system_time(), count: count},
      %{vault: vault, action: action, store: store, outcome: :ok}
    )
  end

  def suspension_changed(vault, action, store, :error) do
    execute(
      [:encryptor, :suspension, :changed],
      %{system_time: System.system_time()},
      %{
        vault: vault,
        action: action,
        store: store,
        outcome: :error,
        reason_tag: :suspension_store_unavailable
      }
    )
  end

  @typedoc false
  @type span :: {reference(), integer()}

  @doc false
  # The `:start` half of one of ADR-0006 decision 3's operation span pairs,
  # emitted by hand: decision 2 refuses `:telemetry.span/3`, because that
  # helper wraps the work in a `rescue` and ADR-0001 decision 10 says this
  # package does not rescue exceptions. The consequence decision 2 states
  # rather than hides is that an entry point which raises leaves an unmatched
  # start, and a consumer pairing on `span_ref` must not assume every start
  # arrives again as a stop.
  #
  # Returns the pair `operation_stop/6` needs: the `span_ref` that is the only
  # correct way to pair the halves, and a monotonic reading, which is what a
  # duration may be measured from and `System.system_time/0` is not.
  @spec operation_start(module(), :encrypt | :decrypt | :rekey, String.t() | nil, map()) :: span()
  def operation_start(vault, operation, scope_ref, measurements \\ %{}) do
    span_ref = make_ref()

    execute(
      [:encryptor, operation, :start],
      Map.put(measurements, :system_time, System.system_time()),
      scope(%{vault: vault, operation: operation, span_ref: span_ref}, scope_ref)
    )

    {span_ref, System.monotonic_time()}
  end

  @doc false
  # The `:stop` half. `outcome` and, on a failure, `reason_tag` and nothing
  # finer: ADR-0006 decision 7's oracle rule holds harder here than in a
  # return value, because an error return goes to the caller who made the call
  # while an event goes to every attached handler whether or not anyone asked.
  @spec operation_stop(
          module(),
          :encrypt | :decrypt | :rekey,
          span(),
          String.t() | nil,
          {:ok, term()} | {:error, Error.t()},
          map()
        ) :: :ok
  def operation_stop(vault, operation, {span_ref, started}, scope_ref, result, extra \\ %{}) do
    metadata =
      %{vault: vault, operation: operation, span_ref: span_ref}
      |> outcome(result)
      |> scope(scope_ref)

    execute(
      [:encryptor, operation, :stop],
      Map.put(extra, :duration, System.monotonic_time() - started),
      metadata
    )
  end

  @doc false
  # ADR-0006 decision 8: provider resolution is a span of its own, nested
  # inside the operation span, and its stop half is what gives an operator a
  # `key_unavailable` rate, an `unknown_key` rate, and the latency
  # distribution of whatever store the host's provider talks to.
  #
  # It wraps the whole of `Encryptor.Vault.Resolve.encryption_key/3` or
  # `decryption_keys/3`, suspension gate included, rather than the provider
  # callback alone. ADR-0005 amendment A decision 4 makes a suspension
  # deliberately indistinguishable from a provider that could not reach its
  # store - both are `{:key_unavailable, selector}`, by design - and a span
  # that reported only one of them would rebuild in a metric the distinction
  # that amendment collapsed.
  #
  # `Encryptor.Vault.Derive` and `provision/2` reach the same two callbacks
  # and are deliberately not instrumented: their `operation` is `:derive` or
  # `:provision`, and decision 4's allow-list admits neither as a metadata
  # value.
  @spec provider_span(
          Config.t(),
          :encryption_key | :decryption_keys,
          :encrypt | :decrypt | :rekey,
          String.t() | nil,
          (-> {:ok, term()} | {:error, Error.t()})
        ) :: {:ok, term()} | {:error, Error.t()}
  def provider_span(%Config{} = config, callback, operation, scope_ref, round_trip) do
    {module, _opts} = config.provider
    base = %{vault: config.vault, provider: module, callback: callback, operation: operation}
    span_ref = make_ref()

    execute(
      [:encryptor, :provider, :start],
      %{system_time: System.system_time()},
      scope(Map.put(base, :span_ref, span_ref), scope_ref)
    )

    started = System.monotonic_time()
    result = round_trip.()

    metadata =
      base
      |> Map.put(:span_ref, span_ref)
      |> outcome(result)
      |> scope(scope_ref)

    execute(
      [:encryptor, :provider, :stop],
      %{duration: System.monotonic_time() - started} |> candidates(callback, result),
      metadata
    )

    result
  end

  # ADR-0002's consequences say a long-lived key owner accumulates candidates
  # and the list grows without bound; this is the measurement that would tell an
  # operator it had. Only on a successful `decryption_keys/2` - there is no
  # candidate list on the write side, and a failure produced none.
  @spec candidates(map(), :encryption_key | :decryption_keys, term()) :: map()
  defp candidates(measurements, :decryption_keys, {:ok, keys}) when is_list(keys),
    do: Map.put(measurements, :candidates, length(keys))

  defp candidates(measurements, _callback, _result), do: measurements

  @spec outcome(map(), {:ok, term()} | {:error, Error.t()}) :: map()
  defp outcome(metadata, {:ok, _answer}), do: Map.put(metadata, :outcome, :ok)

  defp outcome(metadata, {:error, %Error{reason: reason}}),
    do: metadata |> Map.put(:outcome, :error) |> Map.put(:reason_tag, reason_tag(reason))

  # ADR-0006 amendment A decision 3: absent, never `nil`. A handler
  # distinguishes "this host did not opt in" from any value by
  # `Map.has_key?/2`, and a `nil` in a `:telemetry_metrics` tag is a dimension
  # value.
  @spec scope(map(), String.t() | nil) :: map()
  defp scope(metadata, nil), do: metadata

  defp scope(metadata, reference) when is_binary(reference),
    do: Map.put(metadata, :scope_ref, reference)

  # ADR-0006 decision 9: synchronously, on the caller's process, before the
  # entry point returns. No task, no queue, no timeout - the process hop costs
  # more than the problem, and this is the path of every encrypted column read.
  defp execute(event, measurements, metadata) do
    :telemetry.execute(event, measurements, metadata)
  end

  defp reference_check(%Config{reference_check: pinned}) when is_binary(pinned), do: :verified
  defp reference_check(%Config{}), do: :unpinned
end
