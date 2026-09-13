defmodule Encryptor.Vault.Suspension do
  @moduledoc false

  # The suspended set: which selectors this vault refuses to resolve, and the
  # two writes that move a selector in and out of it.
  #
  # ADR-0005 amendment A is the whole of this module's contract. A selector is
  # *suspended* when every entry point fails with
  # `{:key_unavailable, selector}` while the wrappings it resolves to are
  # untouched in the key store (A1): the data is unreadable and intact. The
  # refusal itself is one lookup in `Encryptor.Vault.Resolve`, ahead of the
  # provider and therefore ahead of the materials cache, which is what makes a
  # suspension immediate rather than as prompt as a cache turnover (A5).
  #
  # ## Where the set lives, and why here rather than anywhere else
  #
  # An ETS table owned by the vault's `Encryptor.Vault.Lifecycle` child,
  # created in its `init/1` beside the configuration freeze and dying with it
  # (A8). Every other candidate was refused by a rule this package already
  # holds:
  #
  #   * not `%Encryptor.Vault.Config{}`, which is frozen at start;
  #   * not `:persistent_term`, whose writes and erases trigger a global scan
  #     that `Lifecycle` deliberately confines to a vault's lifecycle
  #     boundary;
  #   * not a `GenServer.call`, which would put a serialization point in front
  #     of the pure function every encrypt and decrypt runs through - the
  #     shape ADR-0001 decision 5 exists to avoid.
  #
  # The table is `:public` because the writes are the caller's: `suspend/2` is
  # invoked from a console or a release task on whatever process the operator
  # has, not on the `Lifecycle` process. It is `read_concurrency: true`
  # because the read is on the hot path of every call and the writes are
  # operational, which is exactly the ratio that option is for.
  #
  # Two properties follow from the owner and are decisions rather than
  # accidents (A8). The set is **not durable**: a restarted vault serves the
  # selector again, because the table went with the process. It is **not
  # cluster-wide**: a host running four nodes has four vaults and suspends on
  # each. A host that needs either uses the provider locus of A3 instead - an
  # IAM binding revoked on the key material itself - and this package ships no
  # distribution and no persistence for it.
  #
  # ## The cache half is hygiene, not correctness
  #
  # A5 puts the gate in front of resolution, so nothing can be read through
  # the vault under a suspension whatever the cache holds. Dropping the table
  # anyway keeps a suspended tenant's data keys from sitting resident for the
  # length of the suspension, and A6 fixes the mechanism: the partition id is
  # a cache-key *input* and not an index, nothing maps a partition to the
  # entries derived from it, so the only eviction this package has is the
  # whole-table recycle `Encryptor.Vault.CacheRecycler` already performs. The
  # cost is one cold miss for every other selector on the vault, which is the
  # recycler's own argument: every entry is derived material that can be
  # re-fetched.

  alias Encryptor.Error
  alias Encryptor.Vault
  alias Encryptor.Vault.CacheRecycler
  alias Encryptor.Vault.Config

  @doc false
  # Named after the vault, like every other per-vault process and table, so
  # two vaults in one node never share a suspended set.
  @spec table(module()) :: atom()
  def table(vault), do: Module.concat(vault, "Suspended")

  @doc false
  # Called from `Encryptor.Vault.Lifecycle.init/1`, so the table exists before
  # the cache, the provider, or any call that reads it.
  @spec create(module()) :: :ets.table()
  def create(vault) do
    :ets.new(table(vault), [:set, :public, :named_table, read_concurrency: true])
  end

  @doc false
  # The gate's read. `:ets.whereis/1` rather than a bare lookup because a
  # vault whose `Lifecycle` child is between a crash and its restart has no
  # table, and a library that raised from the hot path there would report a
  # restart as a caller's error. `false` is also the honest answer: A8 makes
  # the set die with the process, so a vault that restarted is serving the
  # selector again by decision.
  @spec suspended?(module(), Error.selector()) :: boolean()
  def suspended?(vault, selector) do
    case :ets.whereis(table(vault)) do
      :undefined -> false
      tid -> :ets.member(tid, selector)
    end
  end

  @doc false
  # The write, then the eviction, in that order: the gate is the verb and the
  # drop is hygiene, so a failure to find a cache child must not leave a
  # selector un-denied. A6's `cache: false` case arrives here as exactly that
  # - no child, nothing dropped, still `:ok`.
  @spec suspend(Config.t(), Error.selector()) :: :ok | {:error, Error.t()}
  def suspend(%Config{vault: vault}, selector) do
    with :ok <- put(vault, selector) do
      _ = CacheRecycler.recycle(vault, Vault.supervisor_name(vault))

      :ok
    end
  end

  @doc false
  # A7: total, idempotent, and it restores nothing but the gate. It evicts
  # nothing because A5 means no materials were served under the suspension in
  # the first place, and it undoes nothing else - a selector whose wrappings
  # were shredded while it was suspended reads back as
  # `{:unknown_key, selector}` from the provider, which is A4's table read
  # downward and is correct.
  @spec reinstate(Config.t(), Error.selector()) :: :ok | {:error, Error.t()}
  def reinstate(%Config{vault: vault}, selector) do
    delete(vault, selector)
  end

  @spec put(module(), Error.selector()) :: :ok | {:error, Error.t()}
  defp put(vault, selector) do
    with {:ok, tid} <- live(vault) do
      true = :ets.insert(tid, {selector})

      :ok
    end
  end

  @spec delete(module(), Error.selector()) :: :ok | {:error, Error.t()}
  defp delete(vault, selector) do
    with {:ok, tid} <- live(vault) do
      true = :ets.delete(tid, selector)

      :ok
    end
  end

  # A vault whose supervisor answered the lifecycle check a moment ago can
  # still be mid-restart by the time the write lands, and the set is the
  # vault's: with no table there is nothing to write to and nothing that would
  # survive if there were. It is reported as the same not-started error every
  # other entry point gives, so an operator's console session reads one
  # vocabulary.
  @spec live(module()) :: {:ok, :ets.table()} | {:error, Error.t()}
  defp live(vault) do
    case :ets.whereis(table(vault)) do
      :undefined ->
        {:error, %Error{reason: {:vault_not_started, vault}, vault: vault, operation: :start}}

      tid ->
        {:ok, tid}
    end
  end
end
