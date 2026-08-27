defmodule Encryptor.ContextTest do
  use ExUnit.Case, async: true

  alias AwsEncryptionSdk.Format.EncryptionContext
  alias Encryptor.Context
  alias Encryptor.Error
  alias Encryptor.Vault.Config

  doctest Encryptor.Context

  # `compose/3` reads three fields of a resolved configuration and nothing
  # else, so the tests build the struct rather than going through
  # `Config.resolve/4`. Composition is a per-call concern; what start-time
  # resolution does with the same vocabulary is `Encryptor.Vault.ConfigTest`'s.
  defp config(profile, static \\ %{}) do
    %Config{
      vault: MyApp.Vault,
      context_profile: profile,
      static_encryption_context: static
    }
  end

  defp reason({:error, %Error{reason: reason}}), do: reason

  defp pairs(count), do: Map.new(1..count, fn n -> {"k#{n}", "v"} end)

  describe "the canonical vocabulary" do
    # sabotage: dropped "blob" from @canonical_keys - red, because the list is
    # asserted whole rather than by membership.
    test "is the six host-facing keys of ADR-0004 decision 2, in table order" do
      assert ["tenant_ref", "table", "column", "blob", "purpose", "app"] =
               Context.canonical_keys()
    end

    # sabotage: dropped "aws-crypto-" from @reserved_prefixes - red.
    test "reserves the engine's prefix as well as this package's" do
      assert ["aws-crypto-", "encryptor-"] = Context.reserved_prefixes()
    end

    # sabotage: made reserved_key?/2 test the whole key rather than the prefix -
    # red, because the engine only ever refuses "aws-crypto-public-key" itself
    # and this package refuses everything under the prefix.
    test "refuses a key under a reserved prefix on either profile" do
      for profile <- [:single, :tenant] do
        assert Context.reserved_key?("aws-crypto-public-key", profile)
        assert Context.reserved_key?("aws-crypto-anything-later", profile)
        assert Context.reserved_key?("encryptor-wrapped-key", profile)
      end
    end

    # sabotage: made the tenant_ref arm profile-sensitive - red on the
    # `:single` half, which is the half ADR-0004 decision 2's class column
    # ("refused on :single") fixes.
    test "refuses tenant_ref on either profile and tenant_id only where a tenant exists" do
      assert Context.reserved_key?("tenant_ref", :tenant)
      assert Context.reserved_key?("tenant_ref", :single)
      assert Context.reserved_key?("tenant_id", :tenant)
      refute Context.reserved_key?("tenant_id", :single)
    end

    # sabotage: dropped the `value != ""` clause - red on the empty string,
    # which the engine would serialize as a zero-length pair a reader cannot
    # tell from an absent one.
    test "a context string is a non-empty, valid-UTF-8 binary" do
      assert Context.valid_string?("customers")
      refute Context.valid_string?("")
      refute Context.valid_string?(:customers)
      refute Context.valid_string?(<<0xFF, 0xFE>>)
    end
  end

  describe "the four layers" do
    # sabotage: dropped the per-call layer from merge/4 - red. Reversing the
    # static and per-call merges instead stays green, and that is a property
    # rather than a gap: a differing value is refused as a conflict before the
    # merge runs, so the two layers can only ever agree by the time they meet.
    test "per-call merges over static" do
      config = config(:single, %{"app" => "my_app", "purpose" => "pii"})

      assert {:ok, composed} = Context.compose(config, %{"table" => "customers"})

      assert %{"app" => "my_app", "purpose" => "pii", "table" => "customers"} = composed
    end

    # sabotage: dropped the `:supplied` merge - red, because the vault's own
    # tenant pair never reaches the message.
    test "vault-supplied sits above the caller" do
      config = config(:tenant, %{"app" => "my_app"})

      assert {:ok, composed} =
               Context.compose(config, %{"table" => "customers", "column" => "tax_id"},
                 supplied: %{"tenant_ref" => "6Qk2_1xZ"}
               )

      assert %{
               "tenant_ref" => "6Qk2_1xZ",
               "table" => "customers",
               "column" => "tax_id",
               "app" => "my_app"
             } = composed
    end

    # sabotage: merged `:reserved` before `:supplied` - red, because a
    # package-owned pair is then overridable by a vault-supplied one, and
    # ADR-0004 decision 1 makes it the layer nothing overrides.
    test "package-reserved is the layer nothing overrides" do
      assert {:ok, %{"encryptor-role" => "wrapped-key"}} =
               Context.compose(config(:single), %{},
                 supplied: %{"encryptor-role" => "clobbered"},
                 reserved: %{"encryptor-role" => "wrapped-key"}
               )
    end

    # sabotage: dropped the reserved_key?/2 half of the static scan - red. The
    # start-time check in `Encryptor.Vault.Config` refuses this too; the two
    # are not redundant, because a configuration can be built without going
    # through `resolve/4` and a package-owned pair belongs to the layer above.
    test "a static key under a reserved prefix is refused here too" do
      config = config(:single, %{"encryptor-role" => "wrapped-key"})

      assert {:reserved_context_key, "encryptor-role"} = reason(Context.compose(config, %{}))
    end

    # sabotage: made refuse_conflicts/3 fire on any shared key rather than on a
    # differing value - red, because restating what configuration already says
    # is then an error.
    test "a per-call key that restates a static one at the same value is not a conflict" do
      config = config(:single, %{"app" => "my_app"})

      assert {:ok, %{"app" => "my_app"}} = Context.compose(config, %{"app" => "my_app"})
    end
  end

  describe "the refusals" do
    # sabotage: turned refuse_conflicts/3 into `:ok` - red, because the
    # per-call value then silently wins over configuration, which is the
    # override ADR-0004 decision 1 refuses.
    test "a per-call key colliding with a static one at a different value" do
      config = config(:single, %{"app" => "my_app"})

      assert {:encryption_context_conflict, "app"} =
               reason(Context.compose(config, %{"app" => "other_app"}))
    end

    # sabotage: dropped the `above` half of refuse_reserved/4 - red, because a
    # caller can then overwrite the tenant pair the vault derived from `:key`.
    test "a caller key colliding with a vault-supplied key" do
      config = config(:tenant)

      assert {:reserved_context_key, "region"} =
               reason(
                 Context.compose(config, %{"region" => "caller"},
                   supplied: %{"region" => "vault"}
                 )
               )
    end

    # sabotage: same mutation - red here too, and this is the half that
    # protects a wrapped key's own marking.
    test "a caller key colliding with a package-reserved key" do
      config = config(:single)

      assert {:reserved_context_key, "encryptor-role"} =
               reason(
                 Context.compose(config, %{"encryptor-role" => "mine"},
                   reserved: %{"encryptor-role" => "wrapped-key"}
                 )
               )
    end

    # sabotage: dropped the prefix scan from reserved_key?/2 - red on both,
    # and the second is the one a host reaches by accident.
    test "a caller key under a reserved prefix" do
      config = config(:single)

      assert {:reserved_context_key, "aws-crypto-public-key"} =
               reason(Context.compose(config, %{"aws-crypto-public-key" => "x"}))

      assert {:reserved_context_key, "encryptor-anything"} =
               reason(Context.compose(config, %{"encryptor-anything" => "x"}))
    end

    # sabotage: removed the tenant arms of reserved_key?/2 - red, and the
    # failure it prevents is the silent one: a row encrypted under tenant A's
    # key carrying tenant B's context decrypts for nobody and looks like
    # corruption a year later.
    test "a caller naming a tenant, which is `:key`'s job alone" do
      tenant = config(:tenant)

      assert {:reserved_context_key, "tenant_ref"} =
               reason(Context.compose(tenant, %{"tenant_ref" => "6Qk2_1xZ"}))

      assert {:reserved_context_key, "tenant_id"} =
               reason(Context.compose(tenant, %{"tenant_id" => "acct_A"}))

      assert {:reserved_context_key, "tenant_ref"} =
               reason(Context.compose(config(:single), %{"tenant_ref" => "6Qk2_1xZ"}))
    end

    # sabotage: same mutation - red, because a `:single` vault has no tenant to
    # name twice and the vocabulary is open at the edges.
    test "a `tenant_id` key on a single-profile vault is an ordinary host key" do
      assert {:ok, %{"tenant_id" => "acct_A"}} =
               Context.compose(config(:single), %{"tenant_id" => "acct_A"})
    end

    # sabotage: dropped the second refuse_reserved/4 call - red, because a
    # static key is then merged under a vault-supplied one and silently lost,
    # which is the override ADR-0004 decision 1 refuses from either direction.
    test "a static key colliding with a vault-supplied key" do
      config = config(:tenant, %{"region" => "from-config"})

      assert {:reserved_context_key, "region"} =
               reason(Context.compose(config, %{}, supplied: %{"region" => "from-vault"}))
    end

    # sabotage: dropped Enum.sort/1 from refuse_reserved/4 - red, because which
    # of two reserved keys is named then depends on the runtime's hashing. The
    # map is deliberately over the flatmap boundary: at 32 keys or fewer the
    # runtime already returns them in term order and the sort is unobservable,
    # which is exactly the size at which a passing test would prove nothing.
    test "names the same reserved key on every run when a context has two faults" do
      context = Map.merge(pairs(40), %{"encryptor-z" => "x", "aws-crypto-a" => "x"})

      assert {:reserved_context_key, "aws-crypto-a"} =
               reason(Context.compose(config(:single), context))
    end

    # sabotage: dropped Enum.sort_by/2 from validate_pairs/3 - red, for the
    # same reason and at the same size. The two key names are not arbitrary
    # either: the runtime's hash order puts "zz" ahead of "aa" in this map, so
    # an unsorted scan names the wrong one.
    test "names the same invalid key on every run when a context has two faults" do
      context = Map.merge(pairs(40), %{"zz" => :not_a_string, "aa" => :not_a_string})

      assert {:invalid_context_value, "aa"} = reason(Context.compose(config(:single), context))
    end
  end

  describe "validation" do
    # sabotage: dropped the value half of validate_pairs/3's predicate - red,
    # because an atom then reaches the engine's serializer, which either raises
    # deep inside a `Format` module or writes something a reader cannot
    # reproduce.
    test "a non-string value is refused under its own key" do
      assert {:invalid_context_value, "purpose"} =
               reason(Context.compose(config(:single), %{"purpose" => :pii}))
    end

    # sabotage: dropped the key half of the same predicate - red.
    test "a non-string key is refused, rendered rather than passed through" do
      assert {:invalid_context_value, ":purpose"} =
               reason(Context.compose(config(:single), %{purpose: "pii"}))
    end

    # sabotage: dropped the `value != ""` clause from valid_string?/1 - red for
    # both halves.
    test "an empty key or value is refused" do
      assert {:invalid_context_value, "column"} =
               reason(Context.compose(config(:single), %{"column" => ""}))

      assert {:invalid_context_value, ""} =
               reason(Context.compose(config(:single), %{"" => "tax_id"}))
    end

    # sabotage: dropped the String.valid?/1 clause - red, because the engine's
    # length-prefixed serialization accepts the bytes and no reader can
    # reproduce the map they came from.
    test "a key or value that is not valid UTF-8 is refused" do
      assert {:invalid_context_value, "column"} =
               reason(Context.compose(config(:single), %{"column" => <<0xFF, 0xFE>>}))

      assert {:invalid_context_value, "<<255, 254>>"} =
               reason(Context.compose(config(:single), %{<<0xFF, 0xFE>> => "tax_id"}))
    end

    # sabotage: removed the is_map/1 guard from the first compose/3 clause -
    # red, because a keyword list then reaches Map.merge/2 and raises a
    # BadMapError out of a function contracted to return an error tuple.
    test "an `:encryption_context` that is not a map at all" do
      assert {:invalid_context_value, "encryption_context"} =
               reason(Context.compose(config(:single), table: "customers"))
    end

    # sabotage: made render/1 return the whole pair - red. Values are caller
    # data and can be key-shaped; the key is the only part of a rejected pair
    # that may reach a message or a log line.
    test "a refusal names the key and never the value" do
      value = String.duplicate("k", 32)

      assert {:invalid_context_value, "column"} =
               reason(Context.compose(config(:single), %{"column" => {:secret, value}}))
    end
  end

  describe "the bounds" do
    # sabotage: changed @max_pairs to 33 - red on the second assertion.
    test "at most 32 pairs, counting every layer" do
      assert {:ok, _composed} = Context.compose(config(:single), pairs(32))

      assert {:invalid_context_value, :count} =
               reason(Context.compose(config(:single), pairs(33)))
    end

    # sabotage: bounded the per-call map rather than the composed one - red,
    # because 30 configured pairs plus 3 caller pairs is then under the bound.
    test "the count is of the composed context, not of one layer" do
      assert {:invalid_context_value, :count} =
               reason(
                 Context.compose(config(:single, pairs(30)), %{"a" => "1", "b" => "2"},
                   supplied: %{"c" => "3"},
                   reserved: %{"encryptor-d" => "4"}
                 )
               )
    end

    # sabotage: changed @max_bytes to 4097 - red on the second assertion. The
    # boundary is exact because the size is a per-row storage cost paid forever.
    test "at most 4 KiB serialized" do
      assert {:ok, _composed} =
               Context.compose(config(:single), %{"k" => String.duplicate("v", 4089)})

      assert {:invalid_context_value, :too_large} =
               reason(Context.compose(config(:single), %{"k" => String.duplicate("v", 4090)}))
    end

    # sabotage: dropped one of the two length prefixes from serialized_size/1 -
    # red, because the computed size then understates what the engine writes
    # and the 4 KiB bound stops being the bound.
    test "the serialized size counts the pair count and both length prefixes" do
      assert 15 = Context.serialized_size(%{"app" => "my_app"})
      assert 24 = Context.serialized_size([{"app", "my_app"}, {"blob", "x"}])
    end

    # sabotage: made serialized_size/1 seed its reduce at 2 instead of special-
    # casing the empty context - red. `Format.EncryptionContext.serialize/1`
    # returns `<<>>` for an empty map rather than a zero-valued count, so the
    # obvious `2 + entries` overstates by the two bytes of a count that is
    # never written.
    test "an empty context serializes to nothing at all, not to a zero count" do
      assert 0 = Context.serialized_size(%{})
    end

    # sabotage: changed serialized_size/1's per-entry arithmetic - red. This is
    # the test that keeps the arithmetic honest: `serialized_size/1` exists so
    # a bound check is not a second dependency on the message format, and the
    # price of that is a test that pins it against the engine's own serializer.
    test "agrees with the engine's serializer, which is why it may be arithmetic" do
      for context <- [
            %{},
            %{"app" => "my_app"},
            %{"table" => "customers", "column" => "tax_id"},
            %{"purpose" => "pii", "blob" => String.duplicate("b", 300)}
          ] do
        assert Context.serialized_size(context) ==
                 byte_size(EncryptionContext.serialize(context))
      end
    end
  end

  describe "the error struct" do
    # sabotage: hard-coded :encrypt in error/3 - red, because a rekey's own
    # refusal then reports as an encrypt and an operator reading a log looks in
    # the wrong place.
    test "carries the vault and the operation it was told" do
      config = config(:single, %{"app" => "my_app"})

      assert {:error, %Error{vault: MyApp.Vault, operation: :rekey, engine: nil}} =
               Context.compose(config, %{"app" => "other"}, operation: :rekey)
    end

    # sabotage: changed the `:operation` default to `:decrypt` - red.
    test "defaults to the encrypt operation, which is where a context is composed" do
      assert {:error, %Error{operation: :encrypt}} =
               Context.compose(config(:single), %{"app" => :pii})
    end
  end
end
