defmodule Encryptor.EnvelopeVaults do
  @moduledoc """
  Root vaults for the envelope tests, and the root material they expand from.

  These are the vaults of ADR-0003 decision 2: single-key, `cache: false`,
  `Static` provider, holding **the wrapping subkey rather than the root**.
  Every one of them derives its provider material through
  `Encryptor.Envelope.root_subkey/2`, exactly as the record's worked example
  does, so the suite exercises decision 6's label expansion on the way to
  every wrap rather than asserting it only in isolation.

  Three of them together are ADR-0005's procedure P1:

    * `Root` holds generation 1 of the wrapping subkey. It is the deployment
      before a rotation.
    * `Staged` holds both generations, newest first - P1 step 2's
      `keys:` list. It writes under generation 2 and reads either, which is
      what makes the rewrap pass of step 3 safe to run against live traffic.
    * `Rotated` holds generation 2 alone - P1 step 4, after the outgoing entry
      has been dropped. A wrapping the pass never reached does not open here,
      and that is the failure the runbook's ordering exists to avoid.

  The worked domain is card processing, matching the rest of the suite.
  """

  alias Encryptor.Envelope

  # Fixture material, and the only place these bytes are written. Constants
  # rather than `strong_rand_bytes/1` so a failing assertion is reproducible;
  # they are never rendered by a test.
  @root :binary.copy(<<0x66>>, 32)
  @rotated_root :binary.copy(<<0x77>>, 32)
  @reference_root :binary.copy(<<0x88>>, 32)

  @doc "Generation 1 of the deployment's root key material."
  @spec root_key() :: binary()
  def root_key, do: @root

  @doc "Generation 2: what P1 step 1 puts in the wrapping-root secret."
  @spec rotated_root_key() :: binary()
  def rotated_root_key, do: @rotated_root

  @doc """
  The pinned reference root of ADR-0005 decision 5.

  Held separately from the wrapping root so a rotation of one leaves the other
  alone - which is the whole content of that decision.
  """
  @spec reference_root_key() :: binary()
  def reference_root_key, do: @reference_root

  @doc "The `\"encryptor/v1/tenant-ref\"` expansion every `tenant_ref` derives under."
  @spec reference_subkey() :: binary()
  def reference_subkey, do: Envelope.root_subkey(@reference_root, "tenant-ref")

  @doc "Generation `n`'s wrapping subkey, as a `Static` provider entry."
  @spec entry(1 | 2) :: keyword()
  def entry(1),
    do: [key: Envelope.root_subkey(@root, "root-wrap"), namespace: "encryptor-root", name: "r/v1"]

  def entry(2),
    do: [
      key: Envelope.root_subkey(@rotated_root, "root-wrap"),
      namespace: "encryptor-root",
      name: "r/v2"
    ]

  defmodule Root do
    @moduledoc "The root vault before any rotation. Generation 1 only."

    use Encryptor.Vault,
      otp_app: :encryptor,
      context_profile: :single,
      algorithm_suite_id: 0x0478,
      cache: false

    @doc "Layer 5: the key material a config file must not hold."
    def init(config) do
      {:ok,
       Keyword.put(
         config,
         :provider,
         {Encryptor.Provider.Static, Encryptor.EnvelopeVaults.entry(1)}
       )}
    end
  end

  defmodule Staged do
    @moduledoc """
    P1 step 2: both generations live, newest first.

    Writes go under generation 2 and reads resolve either, so a rewrap pass
    can run for as long as it takes without a window in which some tenant
    cannot resolve.
    """

    use Encryptor.Vault,
      otp_app: :encryptor,
      context_profile: :single,
      algorithm_suite_id: 0x0478,
      cache: false

    @doc "Layer 5: the key material a config file must not hold."
    def init(config) do
      {:ok,
       Keyword.put(
         config,
         :provider,
         {Encryptor.Provider.Static,
          keys: [Encryptor.EnvelopeVaults.entry(2), Encryptor.EnvelopeVaults.entry(1)]}
       )}
    end
  end

  defmodule Rotated do
    @moduledoc "P1 step 4: the outgoing generation has been dropped. Generation 2 only."

    use Encryptor.Vault,
      otp_app: :encryptor,
      context_profile: :single,
      algorithm_suite_id: 0x0478,
      cache: false

    @doc "Layer 5: the key material a config file must not hold."
    def init(config) do
      {:ok,
       Keyword.put(
         config,
         :provider,
         {Encryptor.Provider.Static, Encryptor.EnvelopeVaults.entry(2)}
       )}
    end
  end

  defmodule Contextual do
    @moduledoc """
    A root vault whose host has configured a static context.

    ADR-0003 decision 4: the host's own static context "still merges
    underneath, because that is ADR-0001 decision 4's behaviour and there is
    no reason to special-case it".
    """

    use Encryptor.Vault,
      otp_app: :encryptor,
      context_profile: :single,
      algorithm_suite_id: 0x0478,
      cache: false,
      static_encryption_context: %{"app" => "acme_checkout"}

    @doc "Layer 5: the key material a config file must not hold."
    def init(config) do
      {:ok,
       Keyword.put(
         config,
         :provider,
         {Encryptor.Provider.Static, Encryptor.EnvelopeVaults.entry(1)}
       )}
    end
  end

  defmodule MistypedRoot do
    @moduledoc """
    A root vault a host has configured as a tenant vault by mistake.

    There is no shape of `provision/3` in which a root vault reaches key
    material through a tenant selector, so the refusal is the vault's own
    selector-profile check, one layer above the envelope.
    """

    use Encryptor.Vault,
      otp_app: :encryptor,
      context_profile: :tenant,
      algorithm_suite_id: 0x0478,
      cache: false

    @doc "Layer 5: the key material a config file must not hold."
    def init(config) do
      {:ok,
       config
       |> Keyword.put(:provider, {Encryptor.Provider.Static, Encryptor.EnvelopeVaults.entry(1)})
       |> Keyword.put(:reference_subkey, Encryptor.EnvelopeVaults.reference_subkey())}
    end
  end

  defmodule Tenant do
    @moduledoc """
    A tenant vault built from whatever descriptor a test hands it.

    The provider is a closure over the process dictionary rather than a store,
    because this package defines no storage (ADR-0003 decision 9). What it
    proves is the only thing that matters here: that the descriptor
    `unwrap/2` returns is one a vault can actually encrypt and decrypt with.
    """

    use Encryptor.Vault,
      otp_app: :encryptor,
      context_profile: :single,
      algorithm_suite_id: 0x0478,
      cache: false

    @doc "Layer 5: the key material a config file must not hold."
    def init(config) do
      descriptor = Encryptor.EnvelopeVaults.resolved_descriptor()

      {:ok,
       Keyword.put(
         config,
         :provider,
         {Encryptor.Provider.Function,
          encryption_key: fn :default -> {:ok, descriptor} end,
          decryption_keys: fn :default -> {:ok, [descriptor]} end}
       )}
    end
  end

  @doc """
  Stashes the descriptor `Tenant`'s provider closes over.

  A test unwraps a wrapping and puts the result here before starting the
  vault, so the vault is genuinely built from a key that came out of an
  envelope rather than from a fixture constant.
  """
  @spec resolve_with(Encryptor.Key.Aes.t()) :: :ok
  def resolve_with(descriptor) do
    :persistent_term.put({__MODULE__, :descriptor}, descriptor)
  end

  @doc false
  @spec resolved_descriptor() :: Encryptor.Key.Aes.t()
  def resolved_descriptor, do: :persistent_term.get({__MODULE__, :descriptor})
end
