defmodule Encryptor.Vault.Suspension.Store do
  @moduledoc """
  Where a vault's suspended set is agreed.

  `Encryptor.Vault.suspend/2` and `Encryptor.Vault.reinstate/2` write through
  a store, and the vault reads the store back into a per-node view that the
  suspension gate consults on every call (ADR-0010 decisions 1 and 3). The
  gate never asks the store: the hot path stays one table read on the node,
  with no network round trip and no dependency on the store being up.

  A vault takes its store as the `:suspension_store` option, a
  `{module, opts}` pair. It defaults to
  `{Encryptor.Vault.Suspension.Store.Ets, []}`, whose set *is* the view:
  under it a suspension is per node and is lost when the vault restarts,
  exactly as before this behaviour existed (ADR-0010 decision 4).

  ## Writing a shared store

  A store the host implements - usually over its own database - makes one
  suspension reach every node that shares it, and survive restarts. Under any
  store other than the default the vault runs a refresher that calls
  `c:list/1` at start and then `:suspension_poll_interval` milliseconds after
  each call returns, so every other node honours a suspension within one poll
  interval of the write (ADR-0010 decisions 5 and 6).

  The callbacks and what the vault does with their answers:

    * `c:init/2` runs once, while the vault resolves its configuration, and
      performs no I/O. Its state is frozen with the configuration and handed
      to every other callback. An `{:error, term}` refuses the vault's start
      as `{:invalid_config, :suspension_store, :init}`.
    * `c:suspend/2` and `c:reinstate/2` are idempotent. An `{:error, term}`,
      an exit or a raise leaves the view as it was, and the operator's call
      answers `{:suspension_store_unavailable, store}` with the store's term
      in the error's `:engine` field (ADR-0010 decision 7). `c:reinstate/2`
      answers `:ok` for a selector that was never suspended.
    * `c:list/1` answers the whole of this vault's set; order is meaningless
      and duplicates collapse. Until it first answers `{:ok, selectors}` the
      vault denies every scope, and after that a failed call keeps the last
      set it read (ADR-0010 decision 7).

  A store keys its set by the vault it was initialised for, so two vaults
  never share a set. A store's state holds no key material; the vault's
  configuration redacts it when inspected all the same.
  """

  alias Encryptor.Error

  @typedoc "Whatever `c:init/2` built. Opaque to the vault."
  @type state :: term()

  @typedoc "A key selector, as `Encryptor.Error` fixes it."
  @type selector :: Error.selector()

  @doc "Validates the store's options for one vault and builds its state. Performs no I/O."
  @callback init(vault :: module(), opts :: keyword()) :: {:ok, state()} | {:error, term()}

  @doc "Adds the selector to this vault's set. Idempotent."
  @callback suspend(state(), selector()) :: :ok | {:error, term()}

  @doc "Removes the selector from this vault's set. Idempotent, and `:ok` for a selector never in it."
  @callback reinstate(state(), selector()) :: :ok | {:error, term()}

  @doc "The whole of this vault's set."
  @callback list(state()) :: {:ok, [selector()]} | {:error, term()}
end
