defmodule Encryptor.Provider.Conformance do
  @moduledoc """
  The shared test suite every `Encryptor.Provider` implementation is held to.

  A provider is easy to write and easy to get subtly wrong: a candidate list
  in the wrong order, a fresh key minted on every call, an encryption key that
  is not among the candidates it will later have to be decrypted with. None of
  those fail loudly. They fail as an undecryptable row, months later, in
  someone else's deploy.

  So the properties are written once, here, and every adapter runs them -
  including adapters in other packages, which is why this module ships in
  `lib/` rather than in this repository's `test/support`.

  ## Using it

      defmodule MyApp.CardKeyProviderTest do
        use Encryptor.Provider.Conformance

        @impl true
        def provider_case do
          %{
            provider: MyApp.CardKeyProvider,
            opts: [root_key: :crypto.strong_rand_bytes(32)],
            selectors: ["merchant-42"],
            unknown: ["no-such-merchant"]
          }
        end
      end

  `use Encryptor.Provider.Conformance` brings in `ExUnit.Case` (with
  `async: true` unless the option list says otherwise) and the conformance
  tests. Put it at the top of the module, define `c:provider_case/0`, and add
  the adapter's own tests in the same module or a sibling one.

  `provider_case/0` is called afresh inside each test, so it may generate key
  material rather than holding it in a module attribute - a module attribute
  is compiled into a `.beam` file, which is what this package refuses to let a
  host do with a real key and is a poor habit to teach with a fixture one.

  ### The keys of a case

    * `:provider` - the module under test. Required.
    * `:opts` - what the host would put in its `:provider` configuration.
      Required; may be `[]`.
    * `:selectors` - selectors the provider is expected to serve. Defaults to
      `[:default]`, which is what a single-key vault takes.
    * `:unknown` - selectors it is expected to refuse with `{:unknown_key, _}`.
      Defaults to `[]`, because a provider that ignores the selector - which
      `Encryptor.Provider.Static` deliberately does - has none.

  ## What it checks

    * The options resolve to a state through `Encryptor.Provider.init/2`,
      whether or not the provider exports `c:Encryptor.Provider.init/1`.
    * `c:Encryptor.Provider.encryption_key/2` answers a descriptor the vault
      can build a keyring from, and `c:Encryptor.Provider.decryption_keys/2`
      answers a non-empty candidate list of
      them. "The vault can build a keyring from it" is the real bar and it is
      checked by asking the vault's builder, not by re-implementing its rules.
    * **The encryption key is the head of the candidate list.** The candidates
      are newest first and the encryption key is the current one, so a
      provider whose head is something else will write messages it cannot read
      back through its own decrypt path.
    * **Candidate names are distinct.** A name is bound to its bytes forever;
      two entries sharing one is the failure the name contract exists to
      prevent.
    * **Resolution is stable.** Two calls with the same state and selector
      return the same descriptor. A provider that mints material on demand
      fails here, which is the point: key creation is a rotation procedure,
      not a side effect of being asked.
    * **The candidate list builds the right keyring.** One element builds a
      bare `RawAes`; more than one builds a `Multi` with `generator: nil` and
      one child per candidate, in the same order.
    * An unserved selector, when the case names one, is
      `{:unknown_key, selector}` - a settled negative answer, never
      `{:key_unavailable, _}` and never a raise.

  ## What it does not check

  The obligations that are documented rather than enforced: that resolution is
  bounded, that a provider adds no unbounded cache of its own, that a name is
  never reused across a deploy. A test suite that ran once cannot see any of
  them.
  """

  import ExUnit.Assertions

  alias AwsEncryptionSdk.Keyring.Multi
  alias AwsEncryptionSdk.Keyring.RawAes
  alias Encryptor.Provider
  alias Encryptor.Vault.Keyring

  @typedoc """
  What an adapter's test module describes about itself.
  """
  @type case_spec :: %{
          required(:provider) => module(),
          required(:opts) => keyword(),
          optional(:selectors) => [Provider.selector(), ...],
          optional(:unknown) => [Provider.selector()]
        }

  @doc """
  Describes the provider under test: the module, the options a host would
  configure it with, and the selectors it does and does not serve.
  """
  @callback provider_case() :: case_spec()

  # The tests are injected here rather than from a `@before_compile` hook,
  # because `ExUnit.Case` registers one of those itself to close its test list:
  # tests added after that hook has run are compiled into the module and never
  # collected, which is a suite that reports zero failures by running nothing.
  @doc false
  defmacro __using__(opts) do
    quote do
      use ExUnit.Case, unquote(Keyword.put_new(opts, :async, true))

      @behaviour unquote(__MODULE__)

      describe "provider conformance" do
        test "resolves its options into a state" do
          unquote(__MODULE__).assert_state(provider_case())
        end

        test "answers one encryption key the vault can build a keyring from" do
          unquote(__MODULE__).assert_encryption_key(provider_case())
        end

        test "answers a non-empty candidate list the vault can build from" do
          unquote(__MODULE__).assert_decryption_keys(provider_case())
        end

        test "puts the encryption key at the head of the candidate list" do
          unquote(__MODULE__).assert_encryption_key_is_head(provider_case())
        end

        test "gives every candidate a distinct name" do
          unquote(__MODULE__).assert_distinct_names(provider_case())
        end

        test "resolves the same descriptor twice for one state and selector" do
          unquote(__MODULE__).assert_stable(provider_case())
        end

        test "builds a bare RawAes from one candidate and a Multi from more" do
          unquote(__MODULE__).assert_candidate_keyring(provider_case())
        end

        test "refuses a selector it does not serve with a settled unknown_key" do
          unquote(__MODULE__).assert_unknown_selectors(provider_case())
        end
      end
    end
  end

  @doc """
  Resolves the case's options into provider state, and returns it.

  Every other assertion below starts here, so a provider whose
  `c:Encryptor.Provider.init/1` refuses its own documented options fails once
  rather than eight times.
  """
  @spec assert_state(case_spec()) :: Provider.state()
  def assert_state(spec) do
    assert {:ok, state} = Provider.init(spec.provider, spec.opts)

    state
  end

  @doc "Asserts `c:Encryptor.Provider.encryption_key/2` answers a buildable
  descriptor."
  @spec assert_encryption_key(case_spec()) :: :ok
  def assert_encryption_key(spec) do
    state = assert_state(spec)

    for selector <- selectors(spec) do
      assert {:ok, descriptor} = spec.provider.encryption_key(state, selector)
      assert {:ok, _keyring} = Keyring.build(__MODULE__, :encrypt, descriptor)
    end

    :ok
  end

  @doc "Asserts `c:Encryptor.Provider.decryption_keys/2` answers a non-empty
  list of buildable descriptors."
  @spec assert_decryption_keys(case_spec()) :: :ok
  def assert_decryption_keys(spec) do
    state = assert_state(spec)

    for selector <- selectors(spec) do
      assert {:ok, [_ | _] = descriptors} = spec.provider.decryption_keys(state, selector)

      for descriptor <- descriptors do
        assert {:ok, _keyring} = Keyring.build(__MODULE__, :decrypt, descriptor)
      end
    end

    :ok
  end

  @doc """
  Asserts the encryption key is the head of the candidate list.

  Not merely a member of it: the list is newest first and the encryption key
  is the current one, so anything else means writes go under a key that is not
  the newest the provider admits to.
  """
  @spec assert_encryption_key_is_head(case_spec()) :: :ok
  def assert_encryption_key_is_head(spec) do
    state = assert_state(spec)

    for selector <- selectors(spec) do
      assert {:ok, current} = spec.provider.encryption_key(state, selector)
      assert {:ok, [head | _rest]} = spec.provider.decryption_keys(state, selector)
      assert head == current
    end

    :ok
  end

  @doc "Asserts no two candidates share a name."
  @spec assert_distinct_names(case_spec()) :: :ok
  def assert_distinct_names(spec) do
    state = assert_state(spec)

    for selector <- selectors(spec) do
      assert {:ok, descriptors} = spec.provider.decryption_keys(state, selector)

      names = Enum.map(descriptors, & &1.name)
      assert names == Enum.uniq(names)
    end

    :ok
  end

  @doc """
  Asserts both callbacks answer identically when asked twice.

  A provider that generates material on demand fails here, and a provider that
  reads a store that changed under it during one test would too - which is
  what "stable until something outside the vault changes" means.
  """
  @spec assert_stable(case_spec()) :: :ok
  def assert_stable(spec) do
    state = assert_state(spec)

    for selector <- selectors(spec) do
      assert spec.provider.encryption_key(state, selector) ==
               spec.provider.encryption_key(state, selector)

      assert spec.provider.decryption_keys(state, selector) ==
               spec.provider.decryption_keys(state, selector)
    end

    :ok
  end

  @doc """
  Asserts the vault's mapping from a candidate list to one keyring: a bare
  `RawAes` for one candidate, a `Multi` with `generator: nil` for more.
  """
  @spec assert_candidate_keyring(case_spec()) :: :ok
  def assert_candidate_keyring(spec) do
    state = assert_state(spec)

    for selector <- selectors(spec) do
      assert {:ok, descriptors} = spec.provider.decryption_keys(state, selector)
      assert {:ok, keyring} = Keyring.build_all(__MODULE__, :decrypt, descriptors)

      case descriptors do
        [_one] ->
          assert %RawAes{} = keyring

        many ->
          assert %Multi{generator: nil, children: children} = keyring
          assert length(children) == length(many)
          assert Enum.map(children, & &1.key_name) == Enum.map(many, & &1.name)
      end
    end

    :ok
  end

  @doc """
  Asserts every selector the case names as unserved resolves to a settled
  `{:unknown_key, selector}` on both callbacks.

  A case that names none passes trivially, which is correct for a provider
  that ignores the selector.
  """
  @spec assert_unknown_selectors(case_spec()) :: :ok
  def assert_unknown_selectors(spec) do
    state = assert_state(spec)

    for selector <- Map.get(spec, :unknown, []) do
      assert {:error, {:unknown_key, ^selector}} =
               spec.provider.encryption_key(state, selector)

      assert {:error, {:unknown_key, ^selector}} =
               spec.provider.decryption_keys(state, selector)
    end

    :ok
  end

  @spec selectors(case_spec()) :: [Provider.selector(), ...]
  defp selectors(spec), do: Map.get(spec, :selectors, [:default])
end
