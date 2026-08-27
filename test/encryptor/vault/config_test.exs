defmodule Encryptor.Vault.ConfigTest do
  use ExUnit.Case, async: false

  alias Encryptor.Error
  alias Encryptor.TestVaults
  alias Encryptor.Vault.Config

  doctest Encryptor.Vault.Config

  # Fixture key material. Key-shaped, so it never reaches an assertion message
  # on its own - the struct's Inspect implementation redacts it, and that
  # redaction is asserted at the bottom of this file.
  @subkey String.duplicate("s", 32)
  @provider {TestVaults.Provider, key: "fixture"}

  defp single(opts \\ []) do
    Config.resolve(
      TestVaults.NoInit,
      :encryptor,
      [],
      Keyword.merge([provider: @provider, context_profile: :single], opts)
    )
  end

  defp tenant(opts \\ []) do
    Config.resolve(
      TestVaults.NoInit,
      :encryptor,
      [],
      Keyword.merge(
        [provider: @provider, context_profile: :tenant, reference_subkey: @subkey],
        opts
      )
    )
  end

  defp reason({:error, %Error{reason: reason}}), do: reason

  describe "the precedence chain" do
    # sabotage: removed the under_defaults/1 merge's accumulator seed - red,
    # red, because no validator carries a copy of its own default, so every
    # unset key arrives as nil and is refused.
    test "layer 1 supplies the package defaults" do
      assert {:ok, config} = single()

      assert %Config{
               cache: false,
               commitment_policy: :require_encrypt_require_decrypt,
               algorithm_suite_id: 0x0578,
               max_encrypted_data_keys: 10,
               static_encryption_context: %{},
               required_context: []
             } = config
    end

    # sabotage: dropped `defaults()` from the reduce's accumulator seed -
    # red, because init/1 is then handed a list with no EDK limit in it.
    test "the defaults are seeded before init/1 runs, so init/1 can read them" do
      assert {:ok, %Config{static_encryption_context: %{"seen" => "10"}}} =
               Config.resolve(
                 TestVaults.EchoInit,
                 :encryptor,
                 [],
                 provider: @provider,
                 context_profile: :single
               )
    end

    # sabotage: reversed the Keyword.merge/2 arguments - red, because the
    # defaults then win over the use options.
    test "layer 2, the use options, beat the defaults" do
      assert {:ok, %Config{algorithm_suite_id: 0x0478}} =
               Config.resolve(
                 TestVaults.NoInit,
                 :encryptor,
                 [algorithm_suite_id: 0x0478],
                 provider: @provider,
                 context_profile: :single
               )
    end

    # sabotage: removed the app_env layer from the reduce list - red on the
    # first assert, which is the only one that reads it.
    test "layer 3, the application environment, beats the use options" do
      Application.put_env(:encryptor, TestVaults.NoInit, algorithm_suite_id: 0x0478)
      on_exit(fn -> Application.delete_env(:encryptor, TestVaults.NoInit) end)

      assert {:ok, %Config{algorithm_suite_id: 0x0478}} =
               Config.resolve(
                 TestVaults.NoInit,
                 :encryptor,
                 [algorithm_suite_id: 0x0578],
                 provider: @provider,
                 context_profile: :single
               )
    end

    # sabotage: moved start_opts ahead of app_env in the layer list - red,
    # because the application environment then wins.
    test "layer 4, the start_link options, beat the application environment" do
      Application.put_env(:encryptor, TestVaults.NoInit, max_encrypted_data_keys: 4)
      on_exit(fn -> Application.delete_env(:encryptor, TestVaults.NoInit) end)

      assert {:ok, %Config{max_encrypted_data_keys: 2}} = single(max_encrypted_data_keys: 2)
    end

    # sabotage: made apply_init/2 return the merged list unchanged - red,
    # because the provider then stays the fixture rather than init's.
    test "layer 5, the init/1 callback, replaces the merge" do
      assert {:ok, %Config{provider: {TestVaults.Provider, [key: "from-init"]}}} =
               Config.resolve(
                 TestVaults.WithInit,
                 :encryptor,
                 [],
                 provider: @provider,
                 context_profile: :single
               )
    end

    # sabotage: removed the under_defaults/1 call after apply_init/2 - red,
    # because the fresh list init returned then carries no commitment policy
    # and no EDK limit.
    test "an init/1 that returns a fresh list still gets the package defaults" do
      assert {:ok, config} =
               Config.resolve(TestVaults.ReplacingInit, :encryptor, [],
                 max_encrypted_data_keys: 2
               )

      assert %Config{
               commitment_policy: :require_encrypt_require_decrypt,
               algorithm_suite_id: 0x0578,
               max_encrypted_data_keys: 10,
               cache: false
             } = config
    end

    # sabotage: accepted any init/1 return by matching `_other -> {:ok, other}`
    # - red, because the bad return then flows into build/3 as a non-list.
    test "an init/1 that breaks the {:ok, keyword} contract is refused" do
      assert {:invalid_config, :init, :bad_return} =
               reason(
                 Config.resolve(
                   TestVaults.BadInit,
                   :encryptor,
                   [],
                   provider: @provider,
                   context_profile: :single
                 )
               )
    end

    # sabotage: dropped the Keyword.keyword?/1 guard in merge_layers/4 - red
    # with a FunctionClauseError from Keyword.merge instead of the error term.
    test "a layer that is not a keyword list is refused, named by layer" do
      Application.put_env(:encryptor, TestVaults.NoInit, %{algorithm_suite_id: 0x0478})
      on_exit(fn -> Application.delete_env(:encryptor, TestVaults.NoInit) end)

      assert {:invalid_config, :app_env, :not_a_keyword_list} = reason(single())
    end

    # sabotage: deep-merged the cache sub-list across layers - red, because
    # max_messages then survives from the lower layer instead of taking the
    # package default.
    test "a higher layer replaces the whole cache setting rather than deep-merging" do
      assert {:ok, %Config{cache: %{max_age: 300, max_messages: 100}}} =
               Config.resolve(
                 TestVaults.NoInit,
                 :encryptor,
                 [cache: [max_age: 60, max_messages: 5]],
                 provider: @provider,
                 context_profile: :single,
                 cache: [max_age: 300]
               )
    end
  end

  describe "key material in use options" do
    # sabotage: emptied @key_material_options - red for every option in the
    # list, because nothing raises.
    test "every key-material option is a compile-time refusal" do
      for option <- [:key, :keys, :root_key, :private_key, :passphrase, :reference_subkey] do
        assert_raise ArgumentError, ~r/#{option}/, fn ->
          Config.validate_use_opts!(TestVaults.NoInit, [{option, "material"}])
        end
      end
    end

    # sabotage: removed the {:provider, {_module, opts}} clause of
    # refuse_key_material!/2 - red, because a nested secret then passes.
    test "key material nested in a provider option is refused too" do
      assert_raise ArgumentError, ~r/provider option :key/, fn ->
        Config.validate_use_opts!(TestVaults.NoInit, provider: {TestVaults.Provider, key: "oops"})
      end
    end

    # sabotage: made validate_use_opts!/2 return :ok - red on the equality.
    test "clean options pass through unchanged" do
      opts = [otp_app: :my_app, algorithm_suite_id: 0x0478]

      assert ^opts = Config.validate_use_opts!(TestVaults.NoInit, opts)
    end

    # sabotage: dropped the Keyword.keyword?/1 guard in nested_keys/1 - red
    # with a FunctionClauseError from Keyword.keys instead of a pass.
    test "a provider whose options are not a keyword list is not inspected" do
      assert [_ | _] =
               Config.validate_use_opts!(TestVaults.NoInit,
                 provider: {TestVaults.Provider, :opaque}
               )
    end
  end

  describe "the provider" do
    # sabotage: gave :provider a default in defaults/0 - red, because the
    # missing-config error never fires.
    test "is required" do
      assert {:missing_config, [:provider]} =
               reason(Config.resolve(TestVaults.NoInit, :encryptor, [], context_profile: :single))
    end

    # sabotage: removed the is_atom(module) guard - red, because the bad pair
    # is then accepted.
    test "must be a {module, opts} pair" do
      assert {:invalid_config, :provider, :shape} = reason(single(provider: TestVaults.Provider))
      assert {:invalid_config, :provider, :shape} = reason(single(provider: {"static", []}))
    end

    # sabotage: changed the `and` to `or` in provider_options/3 - red for the
    # two single-option cases, which are then also refused.
    test "may carry :key or :keys, but never both" do
      assert {:ok, _config} = single(provider: {TestVaults.Provider, key: "one"})
      assert {:ok, _config} = single(provider: {TestVaults.Provider, keys: [[key: "one"]]})

      assert {:invalid_config, :provider, :key_and_keys} =
               reason(single(provider: {TestVaults.Provider, key: "one", keys: [[key: "two"]]}))
    end
  end

  describe "the commitment policy" do
    # sabotage: added :forbid_encrypt_allow_decrypt to
    # @allowed_commitment_policies - red on the refusal.
    test "defaults to the strictest, relaxes by one step, and refuses the legacy policy" do
      assert {:ok, %Config{commitment_policy: :require_encrypt_require_decrypt}} = single()

      assert {:ok, %Config{commitment_policy: :require_encrypt_allow_decrypt}} =
               single(commitment_policy: :require_encrypt_allow_decrypt)

      assert {:invalid_config, :commitment_policy, :forbidden} =
               reason(single(commitment_policy: :forbid_encrypt_allow_decrypt))

      assert {:invalid_config, :commitment_policy, :unknown} =
               reason(single(commitment_policy: :whatever))
    end
  end

  describe "the EDK limit" do
    # sabotage: removed the nil clause of max_encrypted_data_keys/2 - red,
    # because nil then falls through to :not_a_positive_integer.
    test "defaults to 10, may be tightened, and may never be nil" do
      assert {:ok, %Config{max_encrypted_data_keys: 10}} = single()
      assert {:ok, %Config{max_encrypted_data_keys: 2}} = single(max_encrypted_data_keys: 2)

      assert {:invalid_config, :max_encrypted_data_keys, :unlimited} =
               reason(single(max_encrypted_data_keys: nil))

      assert {:invalid_config, :max_encrypted_data_keys, :not_a_positive_integer} =
               reason(single(max_encrypted_data_keys: 0))
    end
  end

  describe "the algorithm suite" do
    # sabotage: replaced @allowed_algorithm_suite_ids with a wider list - red
    # on the refusal.
    test "defaults to 0x0578, accepts 0x0478, and refuses anything else" do
      assert {:ok, %Config{algorithm_suite_id: 0x0578}} = single()
      assert {:ok, %Config{algorithm_suite_id: 0x0478}} = single(algorithm_suite_id: 0x0478)

      assert {:invalid_config, :algorithm_suite_id, :unsupported} =
               reason(single(algorithm_suite_id: 0x0378))
    end
  end

  describe "the cache bounds" do
    # sabotage: changed defaults/0 to `cache: []` - red, because an empty
    # keyword list then fails on the missing max_age.
    test "a vault runs no cache unless it is configured" do
      assert {:ok, %Config{cache: false}} = single()
      assert {:ok, %Config{cache: false}} = single(cache: false)
    end

    # sabotage: gave :max_age a default in cache_bound/4 - red on the
    # missing-config assert.
    test "max_age is required and has no default" do
      assert {:missing_config, [:cache, :max_age]} = reason(single(cache: []))
    end

    # sabotage: changed @default_max_messages to 1_000 and @recycle_after_
    # multiplier to 10 - red on both derived values.
    test "the other three bounds default well below the engine's ceilings" do
      assert {:ok, %Config{cache: cache}} = single(cache: [max_age: 300])

      assert %{
               max_age: 300,
               max_messages: 100,
               max_bytes: 1_073_741_824,
               recycle_after: 6_000
             } = cache
    end

    # sabotage: made cache_bound/4 ignore the configured value - red on every
    # field.
    test "every bound can be set explicitly" do
      assert {:ok, %Config{cache: cache}} =
               single(cache: [max_age: 60, max_messages: 5, max_bytes: 1_024, recycle_after: 90])

      assert %{max_age: 60, max_messages: 5, max_bytes: 1_024, recycle_after: 90} = cache
    end

    # sabotage: made known_cache_bounds/2 always return :ok - red, because the
    # misspelled bound is then silently ignored.
    test "a misspelled bound is refused rather than silently defaulted" do
      assert {:invalid_config, :cache, {:unknown_bounds, [:max_message]}} =
               reason(single(cache: [max_age: 60, max_message: 5]))
    end

    # sabotage: dropped the `value > 0` guard in cache_bound/4 - red on both.
    test "a bound must be a positive integer" do
      assert {:invalid_config, :cache, {:max_age, :not_a_positive_integer}} =
               reason(single(cache: [max_age: 0]))

      assert {:invalid_config, :cache, {:max_bytes, :not_a_positive_integer}} =
               reason(single(cache: [max_age: 60, max_bytes: "1 GiB"]))
    end

    # sabotage: removed the catch-all clause of cache/2 - red with a
    # CaseClauseError instead of the error term.
    test "the cache setting is false or a keyword list, nothing else" do
      assert {:invalid_config, :cache, :not_false_or_keyword_list} = reason(single(cache: true))
      assert {:invalid_config, :cache, :not_false_or_keyword_list} = reason(single(cache: [1, 2]))
    end
  end

  describe "the context profile" do
    # sabotage: added `context_profile: :single` to defaults/0 - red, because
    # the missing-config error never fires.
    test "is required, and is one of two values" do
      assert {:missing_config, [:context_profile]} =
               reason(Config.resolve(TestVaults.NoInit, :encryptor, [], provider: @provider))

      assert {:invalid_config, :context_profile, :unknown} =
               reason(single(context_profile: :multi))

      assert {:ok, %Config{context_profile: :single}} = single()
      assert {:ok, %Config{context_profile: :tenant}} = tenant()
    end

    # sabotage: made required_keys/2 return the configured list on :tenant -
    # red, because tenant_ref is then absent from the effective set.
    test "the profile contributes its own required keys, ahead of the host's" do
      assert {:ok, %Config{required_keys: ["tenant_ref", "table", "column"]}} =
               tenant(required_context: ["table", "column"])

      assert {:ok, %Config{required_keys: ["purpose"]}} = single(required_context: ["purpose"])
    end

    # sabotage: dropped the Enum.uniq/1 in required_keys/2 - red on the
    # duplicated entry.
    test "the effective required set carries no duplicates" do
      assert {:ok, %Config{required_keys: ["tenant_ref", "table"]}} =
               tenant(required_context: ["tenant_ref", "table"])
    end
  end

  describe "the required context list" do
    # sabotage: removed the is_list/1 head of required_context/3 - red with a
    # FunctionClauseError instead of the error term.
    test "must be a list of non-empty strings" do
      assert {:invalid_config, :required_context, :not_a_list} =
               reason(single(required_context: "table"))

      assert {:invalid_config, :required_context, {:invalid_key, :table}} =
               reason(single(required_context: [:table]))

      assert {:invalid_config, :required_context, {:invalid_key, ""}} =
               reason(single(required_context: [""]))
    end

    # sabotage: removed the profile == :single branch of
    # required_context_keys/3 - red, because the vault then resolves.
    test "may not require tenant_ref on a single-profile vault" do
      assert {:invalid_config, :required_context, {:reserved_key, "tenant_ref"}} =
               reason(single(required_context: ["tenant_ref"]))
    end
  end

  describe "the static encryption context" do
    # sabotage: removed the is_map/1 head of static_encryption_context/3 - red
    # with a FunctionClauseError.
    test "must be a map of non-empty strings" do
      assert {:invalid_config, :encryption_context, :not_a_map} =
               reason(single(static_encryption_context: [app: "my_app"]))

      assert {:invalid_config, :encryption_context, {:invalid_pair, "purpose"}} =
               reason(single(static_encryption_context: %{"purpose" => :pii}))

      assert {:invalid_config, :encryption_context, {:invalid_pair, :app}} =
               reason(single(static_encryption_context: %{:app => "my_app"}))
    end

    # sabotage: emptied @reserved_context_prefixes - red for both prefixes.
    test "refuses a key under a reserved prefix" do
      assert {:reserved_context_key, "aws-crypto-public-key"} =
               reason(single(static_encryption_context: %{"aws-crypto-public-key" => "x"}))

      assert {:reserved_context_key, "encryptor-purpose"} =
               reason(single(static_encryption_context: %{"encryptor-purpose" => "x"}))
    end

    # sabotage: made reserved_context_key?/2 ignore the profile - red, because
    # the single-profile vault is then refused too.
    test "refuses a tenant pair on a tenant vault, and allows it nowhere else to matter" do
      assert {:reserved_context_key, "tenant_ref"} =
               reason(tenant(static_encryption_context: %{"tenant_ref" => "x"}))

      assert {:reserved_context_key, "tenant_id"} =
               reason(tenant(static_encryption_context: %{"tenant_id" => "x"}))

      assert {:ok, _config} = single(static_encryption_context: %{"tenant_id" => "x"})
    end

    # sabotage: raised @max_context_pairs to 64 - red on the refusal.
    test "is bounded at 32 pairs" do
      thirty_two = Map.new(1..32, &{"k#{&1}", "v"})

      assert {:ok, _config} = single(static_encryption_context: thirty_two)

      assert {:invalid_config, :encryption_context, :too_many_pairs} =
               reason(single(static_encryption_context: Map.put(thirty_two, "k33", "v")))
    end

    # sabotage: dropped the 2-byte length prefixes from
    # serialized_context_size/1 - red on the refusal, because the pair is
    # chosen to straddle the cap: 4099 bytes serialized, 4095 without the
    # prefixes the engine actually writes.
    test "is bounded at 4 KiB serialized, prefixes included" do
      assert {:ok, _config} =
               single(static_encryption_context: %{"k" => String.duplicate("v", 4085)})

      assert {:invalid_config, :encryption_context, :too_large} =
               reason(single(static_encryption_context: %{"k" => String.duplicate("v", 4092)}))
    end

    # sabotage: made validate_static_context/3 return {:ok, %{}} - red on the
    # returned map.
    test "a valid context is carried through" do
      static = %{"app" => "my_app", "table" => "payments", "column" => "card_last_four"}

      assert {:ok, %Config{static_encryption_context: ^static}} =
               single(static_encryption_context: static)
    end
  end

  describe "the reference subkey" do
    # sabotage: made the :tenant clause of reference_subkey/3 return
    # {:ok, nil} when the key is absent - red on the missing-config assert.
    test "is required on a tenant vault, at its derived width" do
      assert {:missing_config, [:reference_subkey]} =
               reason(
                 Config.resolve(TestVaults.NoInit, :encryptor, [],
                   provider: @provider,
                   context_profile: :tenant
                 )
               )

      assert {:invalid_config, :reference_subkey, :invalid_length} =
               reason(tenant(reference_subkey: String.duplicate("s", 16)))

      assert {:ok, %Config{context_profile: :tenant}} = tenant()
    end

    # sabotage: removed the :single clause's has_key? check - red, because the
    # mistyped profile is then accepted.
    test "on a single-profile vault means the profile is wrong" do
      assert {:invalid_config, :reference_subkey, :single_profile} =
               reason(single(reference_subkey: @subkey))

      assert {:invalid_config, :reference_check, :single_profile} =
               reason(single(reference_check: "pinned"))
    end
  end

  describe "the known-answer check" do
    # sabotage: made known_answer/1 hash the probe unkeyed - red, because the
    # two subkeys then produce the same value.
    test "is a keyed derivation, stable per subkey" do
      answer = Config.known_answer(@subkey)

      assert is_binary(answer)
      assert answer == Config.known_answer(@subkey)
      refute answer == Config.known_answer(String.duplicate("t", 32))
    end

    # sabotage: inverted the comparison in reference_check/4 - red on both
    # halves.
    test "a pinned value the subkey reproduces starts; one it does not, refuses" do
      pinned = Config.known_answer(@subkey)

      assert {:ok, %Config{reference_check: ^pinned}} = tenant(reference_check: pinned)

      assert {:invalid_config, :reference_subkey, :known_answer_mismatch} =
               reason(tenant(reference_check: Config.known_answer(String.duplicate("t", 32))))
    end

    # sabotage: made the :error clause of reference_check/4 return the
    # missing-config error - red, because a first provisioning cannot start.
    test "is skipped only when no value has been pinned yet" do
      assert {:ok, %Config{reference_check: nil}} = tenant()

      assert {:invalid_config, :reference_check, :not_a_string} =
               reason(tenant(reference_check: :pinned))
    end
  end

  describe "the persistent_term freeze" do
    setup do
      on_exit(fn -> Config.erase(TestVaults.Frozen) end)
      :ok
    end

    # sabotage: made freeze/1 return the config without calling
    # :persistent_term.put/2 - red on the fetch.
    test "publishes under {Encryptor.Vault, vault} and reads back identically" do
      {:ok, config} =
        Config.resolve(TestVaults.Frozen, :encryptor, [],
          provider: @provider,
          context_profile: :single
        )

      assert ^config = Config.freeze(config)
      assert {:ok, ^config} = Config.fetch(TestVaults.Frozen)
      assert ^config = :persistent_term.get({Encryptor.Vault, TestVaults.Frozen})
    end

    # sabotage: replaced the :__not_started__ sentinel with nil - red, because
    # a genuinely absent term then reads as a nil config rather than an error.
    test "an unstarted vault is a typed error, not a raise" do
      assert {:vault_not_started, TestVaults.Frozen} = reason(Config.fetch(TestVaults.Frozen))
    end

    # sabotage: made erase/1 a no-op returning :ok - red, because the fetch
    # then still succeeds.
    test "erase removes the entry" do
      {:ok, config} =
        Config.resolve(TestVaults.Frozen, :encryptor, [],
          provider: @provider,
          context_profile: :single
        )

      Config.freeze(config)

      assert :ok = Config.erase(TestVaults.Frozen)
      assert {:vault_not_started, TestVaults.Frozen} = reason(Config.fetch(TestVaults.Frozen))
    end
  end

  describe "inspecting a config" do
    # sabotage: deleted the defimpl block - red, because the derived Inspect
    # then prints the subkey and the provider options.
    test "never renders the reference subkey or the provider options" do
      {:ok, config} = tenant(provider: {TestVaults.Provider, key: "very-secret-material"})

      rendered = inspect(config)

      refute rendered =~ @subkey
      refute rendered =~ "very-secret-material"
      assert rendered =~ "[redacted]"
      assert rendered =~ "Encryptor.TestVaults.Provider"
    end

    # sabotage: made redact/1 return "[redacted]" for nil too - red, because
    # a single-profile config then claims to be hiding something.
    test "a single-profile config has nothing to redact in the subkey slot" do
      {:ok, config} = single()

      assert inspect(config) =~ "reference_subkey: nil"
    end
  end
end
