defmodule Encryptor.EnvelopeTest do
  use ExUnit.Case, async: false

  alias Encryptor.EncryptVaults
  alias Encryptor.Envelope
  alias Encryptor.Envelope.WrappedKey
  alias Encryptor.EnvelopeVaults
  alias Encryptor.Error
  alias Encryptor.Kdf
  alias Encryptor.Key.Aes
  alias Encryptor.Message

  @merchant "merchant-42"
  @pan "4111111111111111"

  # ADR-0003 decision 4's four keys and its one fixed value, written out here
  # independently of the module under test. A test that read them from
  # `Encryptor.Envelope` would agree with any typo the module made.
  @purpose_key "encryptor-purpose"
  @tenant_ref_key "encryptor-tenant-ref"
  @version_key "encryptor-key-version"
  @namespace_key "encryptor-key-namespace"
  @wrap_purpose "tenant-key-wrap"

  defp start_vault(vault) do
    start_supervised!(Supervisor.child_spec({vault, []}, restart: :temporary))
    vault
  end

  defp provision(vault, selector \\ @merchant, opts \\ []) do
    Envelope.provision(
      vault,
      selector,
      Keyword.put_new(opts, :reference_subkey, EnvelopeVaults.reference_subkey())
    )
  end

  defp provisioned(vault, selector \\ @merchant, opts \\ []) do
    {:ok, wrapped} = provision(vault, selector, opts)
    wrapped
  end

  defp reason({:error, %Error{reason: reason}}), do: reason
  defp engine({:error, %Error{engine: engine}}), do: engine

  defp context(blob) do
    {:ok, info} = Message.describe(blob)
    info.encryption_context
  end

  # The derivation of ADR-0003 decision 5, computed from the record's own
  # formula rather than from the package, so the two are independent.
  defp expected_ref(subkey, selector) do
    Base.url_encode64(
      binary_part(:crypto.mac(:hmac, :sha256, subkey, selector), 0, 16),
      padding: false
    )
  end

  describe "provision/3, minting a tenant master key" do
    # sabotage: returned the plaintext material as a seventh field of the
    # struct - red, and it is the failure the whole narrow surface exists to
    # prevent: a host that can see the key beside the wrapping will store it.
    test "returns the six identity fields and nothing that could be key material" do
      start_vault(EnvelopeVaults.Root)
      wrapped = provisioned(EnvelopeVaults.Root)

      assert %WrappedKey{version: 1, namespace: "encryptor-tenant", bits: 256} = wrapped

      assert wrapped |> Map.keys() |> Enum.sort() ==
               [:__struct__, :bits, :name, :namespace, :tenant_ref, :version, :wrapped]
    end

    # sabotage: derived the material as :crypto.mac(:hmac, :sha256, root,
    # selector) instead of strong_rand_bytes/1 - red, and it is decision 1
    # itself: a derived key cannot be crypto-shredded, because the holder of
    # the root recomputes it from the tenant id forever.
    test "mints independently random material, so two provisions never collide" do
      start_vault(EnvelopeVaults.Root)

      first = provisioned(EnvelopeVaults.Root)
      second = provisioned(EnvelopeVaults.Root)

      {:ok, %Aes{material: one}} = Envelope.unwrap(EnvelopeVaults.Root, first)
      {:ok, %Aes{material: two}} = Envelope.unwrap(EnvelopeVaults.Root, second)

      assert byte_size(one) == 32
      assert one != two
      assert first.wrapped != second.wrapped
    end

    # sabotage: dropped the "encryptor-purpose" pair from the binding - red,
    # because the pair is what stops an unrelated Encryptor message being read
    # as a tenant key.
    test "writes exactly ADR-0003 decision 4's four pairs into the wrapping" do
      start_vault(EnvelopeVaults.Root)
      wrapped = provisioned(EnvelopeVaults.Root, @merchant, version: 3, namespace: "acme-tenant")

      assert context(wrapped.wrapped) == %{
               @purpose_key => @wrap_purpose,
               @tenant_ref_key => wrapped.tenant_ref,
               @version_key => "3",
               @namespace_key => "acme-tenant"
             }
    end

    # sabotage: spelled the version pair with the integer rather than
    # Integer.to_string/1 - red at the engine's context serializer, which is
    # the loud version of a binding that cannot be reproduced.
    test "the version pair is the decimal string of the version" do
      start_vault(EnvelopeVaults.Root)
      wrapped = provisioned(EnvelopeVaults.Root, @merchant, version: 12)

      assert context(wrapped.wrapped)[@version_key] == "12"
    end

    # sabotage: derived the reference with :crypto.hash(:sha256, selector) -
    # red. An unkeyed hash of a short identifier is reversible by anyone who
    # can guess the identifier space, which is the delta decision 5 states.
    test "the tenant reference is the keyed derivation, and the name follows the grammar" do
      start_vault(EnvelopeVaults.Root)
      wrapped = provisioned(EnvelopeVaults.Root, @merchant, version: 2)

      ref = expected_ref(EnvelopeVaults.reference_subkey(), @merchant)

      assert wrapped.tenant_ref == ref
      assert wrapped.name == "t/" <> ref <> "/v2"
    end

    # sabotage: defaulted the namespace to "" and the version to 0 - red on
    # both, and the defaults are the record's own worked example, which
    # provisions with neither named.
    test "defaults are version 1 and the record's namespace" do
      start_vault(EnvelopeVaults.Root)
      wrapped = provisioned(EnvelopeVaults.Root)

      assert wrapped.version == 1
      assert wrapped.namespace == "encryptor-tenant"
      assert String.ends_with?(wrapped.name, "/v1")
    end

    # sabotage: passed the binding as the per-call layer rather than the
    # reserved one - red, because the host's static pair is then refused as a
    # conflict instead of merging underneath.
    test "the host's static context merges underneath the binding" do
      start_vault(EnvelopeVaults.Contextual)
      wrapped = provisioned(EnvelopeVaults.Contextual)

      stored = context(wrapped.wrapped)

      assert stored["app"] == "acme_checkout"
      assert stored[@purpose_key] == @wrap_purpose
    end
  end

  describe "provision/3, what it refuses" do
    # sabotage: merged a caller's :encryption_context into the binding instead
    # of refusing it - red. A caller that can write the context can write a
    # different tenant's reference into its own wrapping.
    test "refuses a caller-supplied encryption context, naming the key" do
      start_vault(EnvelopeVaults.Root)

      result =
        provision(EnvelopeVaults.Root, @merchant,
          encryption_context: %{"zeta" => "1", "alpha" => "2"}
        )

      assert reason(result) == {:reserved_context_key, "alpha"}
    end

    # sabotage: rendered a non-binary key straight into the reason instead of
    # inspecting it - red. A key is the only part of a rejected pair that
    # reaches a failure report, and `{:reserved_context_key, key}` is typed
    # as a `String.t()`.
    test "names a non-string context key without putting the term in the reason" do
      start_vault(EnvelopeVaults.Root)

      assert reason(provision(EnvelopeVaults.Root, @merchant, encryption_context: %{alpha: "2"})) ==
               {:reserved_context_key, ":alpha"}
    end

    # sabotage: accepted an empty :encryption_context map, as Rekey does -
    # red, and the divergence is deliberate: on this path the option has no
    # correct value at all.
    test "refuses even an empty encryption context, naming the option" do
      start_vault(EnvelopeVaults.Root)

      assert reason(provision(EnvelopeVaults.Root, @merchant, encryption_context: %{})) ==
               {:reserved_context_key, "encryption_context"}

      assert reason(provision(EnvelopeVaults.Root, @merchant, encryption_context: :nope)) ==
               {:reserved_context_key, "encryption_context"}
    end

    # sabotage: defaulted a missing :reference_subkey to 32 zero bytes - red.
    # A silently defaulted reference subkey mints rows nobody can find again,
    # against a value ADR-0005 calls effectively permanent.
    test "refuses a missing or wrong-length reference subkey" do
      start_vault(EnvelopeVaults.Root)

      assert reason(Envelope.provision(EnvelopeVaults.Root, @merchant, [])) ==
               {:missing_config, [:reference_subkey]}

      assert reason(provision(EnvelopeVaults.Root, @merchant, reference_subkey: <<1, 2, 3>>)) ==
               {:invalid_config, :reference_subkey, :invalid_length}
    end

    # sabotage: accepted any integer version - red for 0 and -1, either of
    # which produces a name no rotation ordering can read.
    test "refuses a version that is not a positive integer" do
      start_vault(EnvelopeVaults.Root)

      assert reason(provision(EnvelopeVaults.Root, @merchant, version: 0)) ==
               {:invalid_config, :version, :not_a_positive_integer}

      assert reason(provision(EnvelopeVaults.Root, @merchant, version: "2")) ==
               {:invalid_config, :version, :not_a_positive_integer}
    end

    # sabotage: accepted :default as a selector - red. A tenant reference has
    # no meaning for a vault with no tenant, and the row it minted would be
    # unfindable.
    test "refuses a selector that is not a non-empty string" do
      start_vault(EnvelopeVaults.Root)

      assert reason(provision(EnvelopeVaults.Root, :default)) == {:invalid_selector, :default}
      assert reason(provision(EnvelopeVaults.Root, "")) == {:invalid_selector, ""}
      assert reason(provision(EnvelopeVaults.Root, 42)) == {:invalid_selector, 42}
    end

    # sabotage: skipped Keyring.validate/3 in mint/4 - red. A namespace the
    # engine reserves is refused at minting rather than at the first encrypt
    # that tries to use the row.
    test "refuses a namespace the engine reserves, at minting" do
      start_vault(EnvelopeVaults.Root)

      assert {:invalid_key_descriptor, {:reserved_namespace, "aws-kms"}} =
               reason(provision(EnvelopeVaults.Root, @merchant, namespace: "aws-kms-ish"))

      assert {:invalid_key_descriptor, {:invalid_key_field, :namespace, :empty}} =
               reason(provision(EnvelopeVaults.Root, @merchant, namespace: ""))
    end

    # sabotage: had provision/3 supply its own selector to the root vault
    # rather than letting the vault's profile check run - red. A root vault
    # typed as a tenant vault is a configuration error, and it should be loud.
    test "a root vault mistyped as a tenant vault refuses the wrap" do
      start_vault(EnvelopeVaults.MistypedRoot)

      assert reason(provision(EnvelopeVaults.MistypedRoot)) == {:invalid_selector, :default}
    end
  end

  describe "unwrap/2" do
    # sabotage: returned the bare material instead of the descriptor - red,
    # and decision 3 is exactly that there is no such function.
    test "returns the descriptor a provider returns, rebuilt from the row" do
      start_vault(EnvelopeVaults.Root)
      wrapped = provisioned(EnvelopeVaults.Root, @merchant, namespace: "acme-tenant")

      assert {:ok, %Aes{} = descriptor} = Envelope.unwrap(EnvelopeVaults.Root, wrapped)
      assert descriptor.namespace == "acme-tenant"
      assert descriptor.name == wrapped.name
      assert descriptor.bits == 256
      assert byte_size(descriptor.material) == 32
    end

    # sabotage: unwrapped with `bits: 128` hard-coded - red at the keyring
    # validator, which is where a descriptor that cannot form a keyring should
    # be caught rather than at the first encrypt.
    test "the descriptor is one a vault can actually encrypt and decrypt with" do
      start_vault(EnvelopeVaults.Root)
      wrapped = provisioned(EnvelopeVaults.Root)

      {:ok, descriptor} = Envelope.unwrap(EnvelopeVaults.Root, wrapped)
      EnvelopeVaults.resolve_with(descriptor)
      tenant = start_vault(EnvelopeVaults.Tenant)

      ciphertext = tenant.encrypt!(@pan, encryption_context: %{"table" => "cards"})

      assert tenant.decrypt!(ciphertext, encryption_context: %{"table" => "cards"}) == @pan
    end

    # sabotage: compared the binding with Map.get(stored, key, value) - the
    # vault's present-in-both reach - instead of Map.get(stored, key) - red on
    # this test alone, and it is the whole reason the check is the envelope's
    # rather than inherited from ADR-0004 decision 6.
    test "refuses a blob that carries no binding at all" do
      root = start_vault(EnvelopeVaults.Root)
      wrapped = provisioned(root)

      foreign = root.encrypt!("not a tenant key", [])

      assert reason(Envelope.unwrap(root, %WrappedKey{wrapped | wrapped: foreign})) ==
               :decrypt_failed

      assert engine(Envelope.unwrap(root, %WrappedKey{wrapped | wrapped: foreign})) ==
               {:encryption_context_mismatch, @namespace_key}
    end

    # sabotage: dropped the tenant-ref pair from the required binding - red.
    # A blob copied between tenants then unwraps, which is the confused-deputy
    # failure decision 4 exists to make impossible.
    test "a wrapping moved to another tenant's row does not unwrap" do
      start_vault(EnvelopeVaults.Root)
      a = provisioned(EnvelopeVaults.Root, "merchant-a")
      b = provisioned(EnvelopeVaults.Root, "merchant-b")

      swapped = %WrappedKey{b | wrapped: a.wrapped}

      assert reason(Envelope.unwrap(EnvelopeVaults.Root, swapped)) == :decrypt_failed

      assert engine(Envelope.unwrap(EnvelopeVaults.Root, swapped)) ==
               {:encryption_context_mismatch, @tenant_ref_key}
    end

    # sabotage: dropped the version pair from the required binding - red. A
    # blob copied from version 2 to version 3 then unwraps, and the row's
    # version stops meaning anything.
    test "a wrapping moved to another version's row does not unwrap" do
      start_vault(EnvelopeVaults.Root)
      v1 = provisioned(EnvelopeVaults.Root, @merchant, version: 1)
      v2 = provisioned(EnvelopeVaults.Root, @merchant, version: 2)

      swapped = %WrappedKey{v2 | wrapped: v1.wrapped}

      assert engine(Envelope.unwrap(EnvelopeVaults.Root, swapped)) ==
               {:encryption_context_mismatch, @version_key}
    end

    # sabotage: dropped the namespace pair from the required binding - red.
    # The namespace is what RawAes.unwrap_key/3 matches the header's provider
    # id against, so a drifted column is a message no reader can open.
    test "a row whose namespace column has drifted does not unwrap" do
      start_vault(EnvelopeVaults.Root)
      wrapped = provisioned(EnvelopeVaults.Root, @merchant, namespace: "acme-tenant")

      drifted = %WrappedKey{wrapped | namespace: "acme-other"}

      assert engine(Envelope.unwrap(EnvelopeVaults.Root, drifted)) ==
               {:encryption_context_mismatch, @namespace_key}
    end

    # sabotage: dropped require_binding/4's unparseable-header branch - red
    # with a CaseClauseError. A blob whose header this package cannot read is
    # not a blob whose binding was checked, and the collapse is what stops
    # that arriving as a crash instead of a refusal.
    test "a blob that is not a message at all is a collapsed decrypt failure" do
      start_vault(EnvelopeVaults.Root)
      wrapped = provisioned(EnvelopeVaults.Root)

      garbage = %WrappedKey{wrapped | wrapped: :binary.copy(<<0xFF>>, 64)}

      assert reason(Envelope.unwrap(EnvelopeVaults.Root, garbage)) == :decrypt_failed
    end

    # sabotage: skipped binding_for/3's field checks - red. A row whose
    # columns cannot form a descriptor is a store defect, and ADR-0003
    # decision 9 names the reason for it.
    test "a row whose fields cannot form a descriptor names the field" do
      start_vault(EnvelopeVaults.Root)
      wrapped = provisioned(EnvelopeVaults.Root)

      for {field, value} <- [tenant_ref: "", version: 0, namespace: nil, wrapped: ""] do
        broken = Map.put(wrapped, field, value)

        assert reason(Envelope.unwrap(EnvelopeVaults.Root, broken)) ==
                 {:invalid_key_descriptor, {:invalid_wrapped_key_field, field}}
      end
    end

    # sabotage: dropped the Keyring.validate/3 call from unwrap/2's tail - red.
    # `bits` is the one descriptor field the binding does not cover, because
    # decision 4's four pairs do not carry it, so this is where a drifted
    # `bits` column is caught. It is also the answer to ADR-0003 open
    # question 6's shape: what the row claims is checked against what the
    # descriptor needs, not against what the blob says.
    test "a row whose bits column has drifted is an invalid descriptor" do
      start_vault(EnvelopeVaults.Root)
      wrapped = provisioned(EnvelopeVaults.Root)

      assert reason(Envelope.unwrap(EnvelopeVaults.Root, %WrappedKey{wrapped | bits: 128})) ==
               {:invalid_key_descriptor, {:key_length_mismatch, 128, 256}}
    end

    # sabotage: two, run separately. Rendered the detail of
    # {:invalid_key_descriptor, detail} in Encryptor.Error.describe/1 - red on
    # the first assertion. Removed the `@derive {Inspect, except: [:material]}`
    # from Encryptor.Key.Aes - red on the second. Both are the repo rule that
    # a key-shaped value never reaches a failure report or a log line.
    test "no failure report and no descriptor renders anything key-shaped" do
      start_vault(EnvelopeVaults.Root)
      wrapped = provisioned(EnvelopeVaults.Root)
      {:ok, descriptor} = Envelope.unwrap(EnvelopeVaults.Root, wrapped)

      {:error, error} = Envelope.unwrap(EnvelopeVaults.Root, %WrappedKey{wrapped | version: 0})

      assert Exception.message(error) ==
               "the provider returned a key descriptor this vault cannot use " <>
                 "(Encryptor.EnvelopeVaults.Root, decrypt)"

      refute String.contains?(inspect(descriptor), inspect(descriptor.material))
    end
  end

  describe "rewrap/2, root rotation" do
    # sabotage: returned the rekeyed blob under a fresh WrappedKey with
    # version 1 and a recomputed name - red. A rewrap that rewrites identity
    # columns is a re-index pass, which decision 6 exists to avoid.
    test "moves the wrapping onto the new root and leaves every identity field alone" do
      start_vault(EnvelopeVaults.Root)
      staged = start_vault(EnvelopeVaults.Staged)
      rotated = start_vault(EnvelopeVaults.Rotated)

      original = provisioned(EnvelopeVaults.Root, @merchant, version: 4, namespace: "acme-tenant")
      {:ok, rewrapped} = Envelope.rewrap(staged, original)

      assert %WrappedKey{original | wrapped: rewrapped.wrapped} == rewrapped
      assert rewrapped.wrapped != original.wrapped

      # Before: the post-rotation vault cannot open the original at all, which
      # is what makes the read after the rewrap evidence of anything.
      assert reason(Envelope.unwrap(rotated, original)) == :decrypt_failed
      assert {:ok, %Aes{}} = Envelope.unwrap(rotated, rewrapped)
    end

    # sabotage: had rewrap/2 re-encrypt the material under a freshly minted
    # key instead of calling rekey/2 - red: the descriptor changes, and a root
    # rotation that changes tenant key material orphans every ciphertext.
    test "the rewrapped wrapping unwraps to the identical descriptor" do
      start_vault(EnvelopeVaults.Root)
      staged = start_vault(EnvelopeVaults.Staged)
      rotated = start_vault(EnvelopeVaults.Rotated)

      original = provisioned(EnvelopeVaults.Root)
      {:ok, rewrapped} = Envelope.rewrap(staged, original)

      assert Envelope.unwrap(EnvelopeVaults.Root, original) ==
               Envelope.unwrap(rotated, rewrapped)
    end

    # sabotage: had rekey/2 recompose the context from the vault rather than
    # carrying the stored one - red, and the binding would be silently
    # dropped by the very operation meant to preserve it.
    test "the binding is carried across byte for byte" do
      start_vault(EnvelopeVaults.Root)
      staged = start_vault(EnvelopeVaults.Staged)

      original = provisioned(EnvelopeVaults.Root, @merchant, version: 7)
      {:ok, rewrapped} = Envelope.rewrap(staged, original)

      assert context(rewrapped.wrapped) == context(original.wrapped)
    end

    # sabotage: made rewrap/2 return its input unchanged - red on the byte
    # inequality. "Idempotent in effect" is not "idempotent in bytes": a fresh
    # data key and IV go into every message, which is what makes a partial
    # pass safe to resume.
    test "is idempotent in effect and never in bytes" do
      staged = start_vault(EnvelopeVaults.Staged)
      rotated = start_vault(EnvelopeVaults.Rotated)

      original = provisioned(staged)
      {:ok, once} = Envelope.rewrap(staged, original)
      {:ok, twice} = Envelope.rewrap(staged, once)

      assert once.wrapped != twice.wrapped
      assert Envelope.unwrap(rotated, once) == Envelope.unwrap(rotated, twice)
    end

    # sabotage: dropped require_binding/4 from rewrap/2 - red. A rekey of a
    # foreign message writes a blob into the wrapped-key population under a
    # row that claims it is a tenant key.
    test "refuses to rewrap a blob that is not a tenant-key wrapping" do
      staged = start_vault(EnvelopeVaults.Staged)
      wrapped = provisioned(staged)
      foreign = staged.encrypt!("not a tenant key", [])

      assert reason(Envelope.rewrap(staged, %WrappedKey{wrapped | wrapped: foreign})) ==
               :decrypt_failed
    end

    # sabotage: stamped the rewrap failure :decrypt - red. The operation is
    # what the caller asked for, not the half of it the failure landed in.
    test "reports the operation the caller asked for" do
      staged = start_vault(EnvelopeVaults.Staged)
      wrapped = provisioned(staged)

      {:error, %Error{operation: operation}} =
        Envelope.rewrap(staged, %WrappedKey{wrapped | version: 99})

      assert operation == :rekey
    end
  end

  describe "tenant_ref/2" do
    # sabotage: truncated the HMAC tag to 8 bytes instead of 16 - red against
    # the record's own formula, computed here independently.
    test "is ADR-0003 decision 5's derivation, byte for byte" do
      subkey = EnvelopeVaults.reference_subkey()

      assert Envelope.tenant_ref(subkey, @merchant) == {:ok, expected_ref(subkey, @merchant)}
    end

    # sabotage: seeded the derivation with strong_rand_bytes/1 - red. An
    # unstable reference is a row nobody can find again.
    test "is stable per selector and unrelated across selectors and subkeys" do
      subkey = EnvelopeVaults.reference_subkey()
      other = Envelope.root_subkey(EnvelopeVaults.root_key(), "tenant-ref")

      assert Envelope.tenant_ref(subkey, @merchant) == Envelope.tenant_ref(subkey, @merchant)
      refute Envelope.tenant_ref(subkey, @merchant) == Envelope.tenant_ref(subkey, "merchant-43")
      refute Envelope.tenant_ref(subkey, @merchant) == Envelope.tenant_ref(other, @merchant)
    end

    # sabotage: had the encrypt path derive the reference with its own copy of
    # the formula - red. Three call sites, one derivation: a drifted reference
    # is discovered at decrypt time against a permanent subkey.
    test "agrees with what a tenant vault writes into a message header" do
      merchant = start_vault(EncryptVaults.Merchant)

      ciphertext =
        merchant.encrypt!(@pan,
          key: "merchant_a",
          encryption_context: %{"table" => "payment_methods", "column" => "pan"}
        )

      {:ok, ref} = Envelope.tenant_ref(EncryptVaults.reference_subkey(), "merchant_a")

      assert context(ciphertext)["tenant_ref"] == ref
    end

    # sabotage: accepted a short subkey - red. A 16-byte reference subkey is
    # not the value the vault's own start-time check pinned.
    test "refuses a subkey that is not 32 bytes, and a selector with no tenant in it" do
      assert reason(Envelope.tenant_ref(<<1, 2, 3>>, @merchant)) ==
               {:invalid_config, :reference_subkey, :invalid_length}

      assert reason(Envelope.tenant_ref(:not_a_key, @merchant)) ==
               {:invalid_config, :reference_subkey, :invalid_length}

      assert reason(Envelope.tenant_ref(EnvelopeVaults.reference_subkey(), :default)) ==
               {:invalid_selector, :default}
    end

    # sabotage: stamped the standalone failure with a vault and an operation -
    # red. `tenant_ref/2` touches neither, and claiming otherwise sends an
    # operator reading a log line to the wrong place.
    test "a standalone failure names no vault and no operation" do
      {:error, %Error{vault: vault, operation: operation}} =
        Envelope.tenant_ref(<<0>>, @merchant)

      assert vault == nil
      assert operation == nil
    end
  end

  describe "root_subkey/2 and subkey/2" do
    # sabotage: passed the purpose to Kdf.expand/3 as the info string, without
    # label/1 - red. The label is "encryptor/v1/root-wrap", and an expansion
    # under a bare "root-wrap" is a different key for every stored wrapping.
    test "root_subkey/2 expands under decision 6's full labels" do
      root = EnvelopeVaults.root_key()

      assert Envelope.root_subkey(root, "root-wrap") ==
               Kdf.expand(root, "encryptor/v1/root-wrap", 32)

      assert Envelope.root_subkey(root, "tenant-ref") ==
               Kdf.expand(root, "encryptor/v1/tenant-ref", 32)
    end

    # sabotage: made root_subkey/2 ignore its purpose - red, and decision 6's
    # entire point is that the two subkeys have different lifetimes.
    test "the two root purposes are unrelated, and so are two roots" do
      root = EnvelopeVaults.root_key()
      rotated = EnvelopeVaults.rotated_root_key()

      refute Envelope.root_subkey(root, "root-wrap") == Envelope.root_subkey(root, "tenant-ref")
      refute Envelope.root_subkey(root, "root-wrap") == Envelope.root_subkey(rotated, "root-wrap")
      assert byte_size(Envelope.root_subkey(root, "root-wrap")) == 32
    end

    # sabotage: derived the subkey from the descriptor's name rather than its
    # material - red. A subkey that is not a function of the master key does
    # not inherit the master key's shred semantics.
    test "subkey/2 is the labelled expansion of the tenant master key" do
      start_vault(EnvelopeVaults.Root)
      wrapped = provisioned(EnvelopeVaults.Root)
      {:ok, %Aes{material: material} = descriptor} = Envelope.unwrap(EnvelopeVaults.Root, wrapped)

      assert Envelope.subkey(descriptor, "blind-index") ==
               Kdf.expand(material, "encryptor/v1/blind-index", 32)

      refute Envelope.subkey(descriptor, "blind-index") == material
    end

    # sabotage: dropped the root-purpose guard - red. Reusing a label to mean
    # a second thing silently collapses two keys the design says are
    # independent, and decision 6's reservation is one-way.
    test "subkey/2 refuses the root's two purposes" do
      descriptor = %Aes{
        namespace: "acme-tenant",
        name: "t/ref/v1",
        material: :binary.copy(<<7>>, 32),
        bits: 256
      }

      for purpose <- ["root-wrap", "tenant-ref"] do
        assert_raise ArgumentError, fn -> Envelope.subkey(descriptor, purpose) end
      end

      assert_raise ArgumentError, fn -> Envelope.subkey(descriptor, "v1/blind-index") end
    end
  end

  describe "the reserved context layer stays the package's" do
    # sabotage: read the reserved layer from `opts` in Resolve.context/5 - red.
    # A reserved layer reachable through the caller's keyword list is a route
    # for a host to write under a prefix Encryptor.Context refuses it.
    test "a host cannot write an encryptor- pair, by any route" do
      root = start_vault(EnvelopeVaults.Root)

      assert reason(root.encrypt(@pan, encryption_context: %{@purpose_key => @wrap_purpose})) ==
               {:reserved_context_key, @purpose_key}

      ciphertext = root.encrypt!(@pan, reserved: %{@purpose_key => @wrap_purpose})

      refute Map.has_key?(context(ciphertext), @purpose_key)
    end
  end
end
