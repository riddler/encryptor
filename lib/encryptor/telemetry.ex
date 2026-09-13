defmodule Encryptor.Telemetry do
  @moduledoc """
  The package's `:telemetry` events.

  No event carries a plaintext, a key of any kind, an encryption context
  value, a `:key` selector, a partition id, or an `Encryptor.Error`'s
  `:engine` term. No event carries a per-tenant dimension, keyed or unkeyed.
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
  | `[:encryptor, :encrypt, :start]` / `[..., :stop]` | span | `encrypt/2` |
  | `[:encryptor, :decrypt, :start]` / `[..., :stop]` | span | `decrypt/2` |
  | `[:encryptor, :rekey, :start]` / `[..., :stop]` | span | `rekey/2` |
  | `[:encryptor, :provider, :start]` / `[..., :stop]` | span | one `encryption_key/2` or `decryption_keys/2` round trip |

  The six span halves are specified by ADR-0006 and emitted by the paths they
  instrument, which are not written yet (that record's decision 10). They are
  in `events/0` because the vocabulary is the record's, not the emit site's.

  ## Measurements

  | Measurement | Unit | On |
  |---|---|---|
  | `duration` | `:native` | every span stop, and `:recycled` |
  | `system_time` | `:native` | every span start and every point event |
  | `size` | bytes | `[:encryptor, :encrypt, :start]` and `[:encryptor, :decrypt, :stop]` |
  | `candidates` | count | `[:encryptor, :provider, :stop]` on a successful `decryption_keys/2` |

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
  | `outcome` | `:ok \\| :error` | span stops, `:recycled` |
  | `reason_tag` | `t:reason_tag/0` | when `outcome` is `:error` |
  | `provider` | `module()` | provider spans |
  | `callback` | `:encryption_key \\| :decryption_keys` | provider spans |
  | `cache` | `boolean()` | `[:encryptor, :vault, :started]` |
  | `profile` | `:single \\| :tenant` | `[:encryptor, :vault, :started]` |
  | `reference_check` | `:verified \\| :unpinned` | `[:encryptor, :vault, :started]` |
  """

  alias Encryptor.Error
  alias Encryptor.Vault.Config

  @vault_events [
    [:encryptor, :vault, :started],
    [:encryptor, :vault, :stopped],
    [:encryptor, :vault, :start_refused],
    [:encryptor, :cache, :recycled]
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
          optional(:reference_check) => :verified | :unpinned
        }

  @doc """
  Every event name this package emits. The single definition site.

  A host attaches against this rather than hand-copying names the record may
  later extend.

      iex> [:encryptor, :cache, :recycled] in Encryptor.Telemetry.events()
      true

      iex> length(Encryptor.Telemetry.events())
      12
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
  # so it does not go through `reason_tag/1`. It reaches here only when the
  # cache child is not there to drop, which is what ADR-0006's worked example
  # reports it as: `reason_tag: :vault_not_started`. The supervisor's own term
  # is not forwarded - it is not on the allow-list.
  @spec cache_recycled(module(), integer(), term()) :: :ok
  def cache_recycled(vault, duration, result) do
    metadata =
      case result do
        {:error, _reason} -> %{vault: vault, outcome: :error, reason_tag: :vault_not_started}
        _ok -> %{vault: vault, outcome: :ok}
      end

    execute([:encryptor, :cache, :recycled], %{duration: duration}, metadata)
  end

  # ADR-0006 decision 9: synchronously, on the caller's process, before the
  # entry point returns. No task, no queue, no timeout - the process hop costs
  # more than the problem, and this is the path of every encrypted column read.
  defp execute(event, measurements, metadata) do
    :telemetry.execute(event, measurements, metadata)
  end

  defp reference_check(%Config{reference_check: pinned}) when is_binary(pinned), do: :verified
  defp reference_check(%Config{}), do: :unpinned
end
