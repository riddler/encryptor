defmodule Encryptor.KdfWithoutArgon2Test do
  @moduledoc """
  ADR-0003 amendment B decision 5: absence of the optional `:argon2_elixir`
  dependency is detected in two places, and both are exercised here.

  The dependency is present in this repository's own test build - that is what
  makes the primitive testable at all - so absence has to be staged. Taking
  the library's `ebin` directory off the code path and purging the module is
  what `Code.ensure_loaded?/1` sees in a build that never fetched it, and it
  is the only honest way to reach either branch from here.

  That staging is global to the node, so this module is `async: false` and
  restores the path in `on_exit/1`. It lives in its own file rather than in
  `Encryptor.KdfTest`, which is `async: true` and must stay that way.
  """

  use ExUnit.Case, async: false

  alias Encryptor.Error
  alias Encryptor.Kdf
  alias Encryptor.TestVaults
  alias Encryptor.Vault.Config

  @params %{memory_kib: 32_768, iterations: 1, parallelism: 1}
  @salt :binary.copy(<<0x5A>>, 16)

  setup do
    ebin = :argon2_elixir |> Application.app_dir("ebin") |> String.to_charlist()

    true = :code.del_path(ebin)
    :code.purge(Argon2.Base)
    :code.delete(Argon2.Base)
    :code.purge(Argon2.Base)

    on_exit(fn ->
      true = :code.add_patha(ebin)
      {:module, _module} = Code.ensure_loaded(Argon2.Base)
    end)

    refute Code.ensure_loaded?(Argon2.Base)
    :ok
  end

  # Decision 5, second line: a vault that never declared `:slow_hash` cannot
  # be caught at start, so the call site raises. It raises rather than
  # returning `{:error, _}` or degrading to a plain hash, because degrading
  # would quietly write index values at plain-HMAC cost under a column the
  # operator believes is hardened.
  #
  # sabotage: replaced ensure_argon2!/0 with `:ok` - red, with an
  # UndefinedFunctionError instead of the message, which is the failure the
  # check exists to replace.
  test "slow_hash/3 raises, naming the dependency and what to do about it" do
    error = assert_raise RuntimeError, fn -> Kdf.slow_hash("value", @salt, @params) end

    message = Exception.message(error)
    assert message =~ ":argon2_elixir"
    assert message =~ "argon2_elixir, \"~> 4.0\""
  end

  # Decision 5, first line: declaring the parameters is the host saying it
  # intends to hash slowly, so refusing the boot is the earliest honest
  # moment. The reason is one this package already carries, which is why the
  # amendment adds no error vocabulary.
  #
  # sabotage: dropped the slow_hash_dependency/2 step from slow_hash/2 - red,
  # because the vault then starts and fails later, at the first index write.
  test "a vault declaring :slow_hash refuses to start" do
    assert {:error, %Error{reason: reason, operation: :start}} =
             Config.resolve(TestVaults.NoInit, :encryptor, [],
               provider: {TestVaults.Provider, key: "fixture"},
               context_profile: :single,
               slow_hash: [iterations: 3]
             )

    assert reason == {:missing_optional_dependency, :argon2_elixir}
  end

  # The other half of the same decision: a vault that declares nothing is
  # unaffected, which is what "a host whose vaults declare no slow index
  # carries no NIF" means in practice.
  #
  # sabotage: made slow_hash/2 run the dependency check before the fetch - red.
  test "a vault declaring nothing starts exactly as before" do
    assert {:ok, %Config{slow_hash: nil}} =
             Config.resolve(TestVaults.NoInit, :encryptor, [],
               provider: {TestVaults.Provider, key: "fixture"},
               context_profile: :single
             )
  end
end
