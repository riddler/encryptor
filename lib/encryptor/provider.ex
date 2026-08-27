defmodule Encryptor.Provider do
  @moduledoc """
  The key-provider behaviour: a selector in, key descriptors out.

  A provider answers one question - *which key* - and it answers it with an
  `Encryptor.Key` descriptor. It never returns an engine keyring. The vault,
  and only the vault, turns a descriptor into one (ADR-0002 decision 3), which
  is what keeps the engine's namespace out of host code and stops a provider
  quietly choosing its own wrapping algorithm behind the vault's back.

  ## The four callbacks

      @callback init(keyword()) :: {:ok, state()} | {:error, term()}
      @callback child_spec(keyword()) :: Supervisor.child_spec()
      @callback encryption_key(state(), selector()) :: {:ok, descriptor()} | {:error, reason()}
      @callback decryption_keys(state(), selector()) :: {:ok, [descriptor(), ...]} | {:error, reason()}

  `encryption_key/2` and `decryption_keys/2` are required. `init/1` and
  `child_spec/1` are optional.

  ### `init/1` runs once, and its return is frozen

  It runs during vault start, inside configuration resolution, and what it
  returns becomes the provider state that `Encryptor.Vault.Config` publishes
  into `:persistent_term`. State is therefore whatever is constant for the
  life of the vault - a root key, a namespace, an ETS table name, a client
  struct. It is read lock-free on every call and it is not mutable. A provider
  with no configuration to resolve may omit `init/1`, in which case its state
  is the option list as given; `init/2` below is where that fallback lives.

  `init/1` is also where a secret lands, having come from the host vault's own
  `init/1` and therefore from the environment. Key material is never a `use`
  option and never a config file entry - `Encryptor.Vault.Config` raises at
  compile time on the attempt.

  ### `child_spec/1` is the only way a provider gets a process

  When exported, it is added to the vault's supervisor beside the cache. A
  provider that has a process still resolves through the same two callbacks:
  the process is an implementation detail of the callback, never something the
  vault or the host talks to directly.

  ## Both resolution callbacks run on the caller's process

  Synchronously, with no task pool and no vault-side timeout wrapper. A
  provider that performs I/O owns its own timeout; a provider that blocks
  indefinitely hangs the caller's request. The rule is stated rather than
  enforced, because enforcing it would mean a process hop on the hot path of
  every encrypted column read.

  Two obligations make that affordable, and neither is checked by anything:

    * **Resolution is stable.** For a given state and selector,
      `c:encryption_key/2` returns the same descriptor until something outside
      the vault changes - a rotation, an offboarding. It is a lookup, not a
      decision, and it never mints fresh key material as a side effect of
      being asked. Key creation is a rotation procedure reached deliberately,
      not a lazy consequence of the first encrypt after a deploy.
    * **A provider may not add a second unbounded cache.** The engine's
      materials cache already collapses provider round trips to one per
      partition per `max_age`, so a provider-level cache is a second copy of
      the same idea with none of the vault's bounds on it. A provider that
      caches anyway must bound it and document the bound.

  ## `name` is public, it is bound to bytes, and dropping it is what shreds

  The vault treats a descriptor's `:name` as opaque and the provider owns its
  grammar, subject to three obligations that come from the engine rather than
  from taste:

    * **A name is bound to bytes, forever.** `RawAes.unwrap_key/3` accepts an
      encrypted data key only when the header's provider id and key name equal
      the keyring's. Reusing a name for different material therefore makes
      previously written messages undecryptable, silently, at some later date.
      A provider that rotates a key mints a new name. The recommended grammar
      is an opaque reference plus a monotonic version - `"t/<derived>/v<n>"` -
      recommended, not enforced.
    * **A name travels in the clear.** It lands in the encrypted data key's
      provider info, inside a header that is authenticated but not encrypted.
      Anyone holding a ciphertext can read it, so a provider that puts a raw
      tenant identifier there has published that identifier in every row.
    * **Dropping a name is what shreds.** `c:decryption_keys/2` returns every
      name that may still appear in stored ciphertext, newest first, and the
      vault builds the candidate keyring from that list. Removing an entry
      makes the messages written under it permanently unreadable, which is
      precisely the crypto-shred mechanism and is a scheduled procedure, not
      a cleanup. Ordering is a performance property, not a correctness one: a
      wrong-name keyring fails a cheap comparison, not a decryption.

  A one-element candidate list builds a plain `RawAes`; a longer one builds a
  `Multi` with `generator: nil`, which the engine walks in order.

  ## A provider never sees plaintext, ciphertext, or the encryption context

  It sees a selector and its own state. It is not consulted about the
  algorithm suite, the commitment policy, the context, or the cache, all of
  which are configuration. The narrowness is the point: a provider is the
  component a host is most likely to write itself, so it is the component that
  must not be able to weaken anything.

  ## Failures stay distinguishable

  The decrypt path collapses every message-dependent failure to
  `:decrypt_failed` to avoid a decryption oracle. Provider resolution is
  carved out of that rule in both directions, because it happens before any
  ciphertext is examined and depends only on the selector the caller supplied.
  Reporting an unreachable key store as data corruption would send an operator
  looking for the wrong thing at three in the morning.

    * `{:unknown_key, selector}` - resolved, and the selector is not one this
      provider serves. A settled negative answer.
    * `{:key_unavailable, selector}` - could not answer. A network failure, a
      timeout, a throttle. This is the one a caller retries.
    * `{:invalid_key_descriptor, detail}` - answered with something the vault
      cannot build a keyring from. A bug in the provider, not in the caller.
    * `{:provider_not_started, module}` - a provider with a `c:child_spec/1`
      whose process is not alive.
    * `{:missing_optional_dependency, dep}` - returned at start by adapters
      that need the host's optional dependencies.

  A provider's underlying error - a changeset, a client tuple - is carried in
  the `Encryptor.Error` struct's `:engine` field rather than translated into
  the vocabulary above, which is what keeps that vocabulary a closed
  enumeration a `case` can be written against.

  ## The adapters

    * `Encryptor.Provider.Static` - one key, or a candidate list of them, held
      in configuration. The single-key vault, the root vault, and the test
      double.
    * `Encryptor.Provider.Function` - a host-supplied pair of closures. The
      escape hatch, and the day-one path to per-tenant keys before a storage
      adapter exists.

  `Encryptor.Provider.Conformance` is the shared test suite both are held to,
  and it ships in `lib/` so that an adapter in another package is held to the
  same one.

  ## Writing one

      defmodule MyApp.CardKeyProvider do
        @behaviour Encryptor.Provider

        @impl true
        def init(opts), do: {:ok, %{root_key: Keyword.fetch!(opts, :root_key)}}

        @impl true
        def encryption_key(state, merchant_id) do
          case MyApp.KeyVersions.current(merchant_id) do
            {:ok, version} -> {:ok, derive(state, merchant_id, version)}
            :not_found -> {:error, {:unknown_key, merchant_id}}
            {:error, :timeout} -> {:error, {:key_unavailable, merchant_id}}
          end
        end

        @impl true
        def decryption_keys(state, merchant_id) do
          case MyApp.KeyVersions.live(merchant_id) do
            {:ok, [_ | _] = versions} ->
              {:ok, Enum.map(versions, &derive(state, merchant_id, &1))}

            {:ok, []} ->
              {:error, {:unknown_key, merchant_id}}

            {:error, :timeout} ->
              {:error, {:key_unavailable, merchant_id}}
          end
        end
      end

  Records: ADR-0002 decisions 1, 2, 4, 5, 6 and 7; ADR-0005 decision 4.
  """

  alias Encryptor.Error

  @typedoc """
  A key selector, as the vault fixes it: a non-empty `String.t()` in a
  `:tenant` vault, and the atom `:default` in a `:single` one.
  """
  @type selector :: Error.selector()

  @typedoc """
  Whatever `c:init/1` returned, frozen for the life of the vault.
  """
  @type state :: term()

  @typedoc "A member of the closed descriptor set."
  @type descriptor :: Encryptor.Key.t()

  @typedoc """
  The reasons a resolution callback may fail with.

  Every term here is also a member of `t:Encryptor.Error.reason/0`, which is
  the closed vocabulary the whole package matches on.
  """
  @type reason ::
          {:unknown_key, selector()}
          | {:key_unavailable, selector()}
          | {:invalid_key_descriptor, term()}
          | {:provider_not_started, module()}
          | {:missing_optional_dependency, atom()}

  @doc """
  Resolves the provider's configuration into the state the vault freezes.

  Runs once, at vault start. Optional: a provider that needs nothing resolved
  omits it and takes the option list as its state.
  """
  @callback init(opts :: keyword()) :: {:ok, state()} | {:error, term()}

  @doc """
  A child spec for a provider that needs a process, supervised beside the
  cache in the vault's own supervisor.

  Optional, and rare. Resolution still runs through the two callbacks below.
  """
  @callback child_spec(opts :: keyword()) :: Supervisor.child_spec()

  @doc """
  The one key a write should be encrypted under, for this selector.
  """
  @callback encryption_key(state :: state(), selector :: selector()) ::
              {:ok, descriptor()} | {:error, reason()}

  @doc """
  Every key a stored message for this selector might have been written under,
  newest first. Never empty on success.
  """
  @callback decryption_keys(state :: state(), selector :: selector()) ::
              {:ok, [descriptor(), ...]} | {:error, reason()}

  @optional_callbacks init: 1, child_spec: 1

  @doc """
  Runs a provider's `c:init/1`, or falls back to the option list as state.

  This is the "a provider with no configuration may omit `init/1`" clause of
  the contract, in one place rather than at every call site that resolves a
  provider. The vault calls it once, at start.

      iex> Encryptor.Provider.init(Encryptor.Provider.Function, encryption_key: fn _ -> :never_called end)
      {:error, {:missing_config, [:provider, :decryption_keys]}}

  A module that exports no `init/1` keeps its options:

      iex> Encryptor.Provider.init(Encryptor.NoSuchProviderModule, namespace: "myapp")
      {:ok, [namespace: "myapp"]}
  """
  @spec init(module(), keyword()) :: {:ok, state()} | {:error, term()}
  def init(module, opts) when is_atom(module) and is_list(opts) do
    if Code.ensure_loaded?(module) and function_exported?(module, :init, 1) do
      module.init(opts)
    else
      {:ok, opts}
    end
  end
end
