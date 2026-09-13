defmodule Encryptor.AwsKms.Fake do
  @moduledoc """
  A KMS client that really encrypts, behind the engine's client boundary.

  ADR-0008 decision 9 puts the KMS client in the host's hands - the engine
  dispatches on `client.__struct__` and calls the three `KmsClient` callbacks
  on it - so a fake at that boundary is the whole AWS surface, exactly as
  `Encryptor.GcpKms.Fake` is the whole GCP surface for ADR-0007. Nothing here
  reaches a network and nothing here needs a credential.

  It is a real AEAD rather than a table of canned responses, so a round trip
  through it is evidence that the data key survived the trip and that the
  encryption context bound it. The engine's own
  `AwsEncryptionSdk.Keyring.KmsClient.Mock` is used where a *failure* is the
  subject, because canned responses are the cheaper way to say "KMS refused".

  The keys are fixture bytes standing in for key material AWS would hold and
  never hand out. They are constants so a failing assertion is reproducible.
  """

  @behaviour AwsEncryptionSdk.Keyring.KmsClient

  defstruct keys: %{}

  @type t :: %__MODULE__{keys: %{String.t() => binary()}}

  @acme "arn:aws:kms:us-east-1:111122223333:key/acme-v2"
  @acme_previous "arn:aws:kms:us-east-1:111122223333:key/acme-v1"
  @globex "arn:aws:kms:us-east-1:111122223333:key/globex-v1"
  @mrk "arn:aws:kms:us-east-1:111122223333:key/mrk-acme-v1"

  @doc "The ARN the acme tenant's writes go under."
  @spec acme() :: String.t()
  def acme, do: @acme

  @doc "The ARN acme's older messages were written under."
  @spec acme_previous() :: String.t()
  def acme_previous, do: @acme_previous

  @doc "The ARN the globex tenant's writes go under."
  @spec globex() :: String.t()
  def globex, do: @globex

  @doc "A multi-region key ARN, for the descriptor-to-keyring mapping."
  @spec mrk() :: String.t()
  def mrk, do: @mrk

  @doc "An ARN no fake client holds, which KMS answers as a missing key."
  @spec unheld() :: String.t()
  def unheld, do: "arn:aws:kms:us-east-1:111122223333:key/never-created"

  @doc "A client holding every fixture key."
  @spec new() :: t()
  def new do
    %__MODULE__{
      keys: %{
        @acme => :binary.copy(<<0xA1>>, 32),
        @acme_previous => :binary.copy(<<0xA2>>, 32),
        @globex => :binary.copy(<<0xB1>>, 32),
        @mrk => :binary.copy(<<0xC1>>, 32)
      }
    }
  end

  @impl true
  def generate_data_key(%__MODULE__{} = client, key_id, bytes, context, _grant_tokens) do
    with {:ok, _key} <- key(client, key_id),
         plaintext = :crypto.strong_rand_bytes(bytes),
         {:ok, ciphertext} <- wrap(client, key_id, plaintext, context) do
      {:ok, %{plaintext: plaintext, ciphertext: ciphertext, key_id: key_id}}
    end
  end

  @impl true
  def encrypt(%__MODULE__{} = client, key_id, plaintext, context, _grant_tokens) do
    with {:ok, ciphertext} <- wrap(client, key_id, plaintext, context) do
      {:ok, %{ciphertext: ciphertext, key_id: key_id}}
    end
  end

  @impl true
  def decrypt(%__MODULE__{} = client, key_id, ciphertext, context, _grant_tokens) do
    with {:ok, key} <- key(client, key_id),
         <<iv::binary-12, tag::binary-16, blob::binary>> <- ciphertext,
         plaintext when is_binary(plaintext) <-
           :crypto.crypto_one_time_aead(:aes_256_gcm, key, iv, blob, aad(context), tag, false) do
      {:ok, %{plaintext: plaintext, key_id: key_id}}
    else
      {:error, _reason} = error -> error
      _other -> {:error, {:kms_error, :invalid_ciphertext, "ciphertext did not authenticate"}}
    end
  end

  defp wrap(client, key_id, plaintext, context) do
    with {:ok, key} <- key(client, key_id) do
      iv = :crypto.strong_rand_bytes(12)

      {blob, tag} =
        :crypto.crypto_one_time_aead(:aes_256_gcm, key, iv, plaintext, aad(context), true)

      {:ok, iv <> tag <> blob}
    end
  end

  defp key(%__MODULE__{keys: keys}, key_id) do
    case Map.fetch(keys, key_id) do
      {:ok, key} -> {:ok, key}
      :error -> {:error, {:kms_error, :key_not_found, "no such key"}}
    end
  end

  # The encryption context, byte-stably, as the additional authenticated data.
  # AWS binds it the same way, which is what makes a context mismatch a
  # decrypt failure rather than a silent success.
  defp aad(context) do
    context
    |> Enum.sort()
    |> Enum.map_join("\n", fn {key, value} -> "#{key}=#{value}" end)
  end
end

defmodule Encryptor.AwsKms.Recording do
  @moduledoc """
  The `Fake`, with the encryption context of every call recorded.

  ADR-0004 amendment A decision A5 makes the encryption context a *disclosed*
  property of `Encryptor.Provider.Kms`: the map the vault composes is sent to
  the KMS API and recorded unencrypted in CloudTrail. What the API receives is
  not always that map alone. Under a signing algorithm suite the engine
  inserts its own reserved `aws-crypto-public-key` pair *below* the vault,
  after the vault has finished composing, so the set the API and CloudTrail
  see is the composed map plus that one engine-owned pair; under the unsigned
  suite it is exactly the composed map (ADR-0004, the 2026-09-13 Note on the
  signing suite). A round trip through the `Fake` is evidence that the context
  bound the message; it is no evidence at all about which keys left the
  process, because writer and reader compose the same map and a key added to
  both still round-trips.

  This client can see it. It records the context it is handed at the engine's
  client boundary - below every layer that composes or adds to it - so a test
  can pin the key set the disclosure names rather than infer it.

  The record goes to `self()` rather than to a pid frozen into the struct,
  because the struct is built while the vault starts and the KMS call happens
  in the process that called `encrypt/2` or `decrypt/2`. `assert_received` in
  the test that ran the operation is therefore the whole assertion: a call
  that moved to some other process would fail it rather than pass quietly.

  The inner client is dispatched on the way the engine dispatches - on
  `client.__struct__` (ADR-0008 decision 9) - so any `KmsClient` can be
  wrapped, including the refusing one.
  """

  @behaviour AwsEncryptionSdk.Keyring.KmsClient

  alias Encryptor.AwsKms.Fake

  defstruct inner: nil

  @type t :: %__MODULE__{inner: struct()}

  @doc "A recording client in front of one holding every fixture key."
  @spec new(struct()) :: t()
  def new(inner \\ Fake.new()), do: %__MODULE__{inner: inner}

  @impl true
  def generate_data_key(%__MODULE__{inner: inner}, key_id, bytes, context, grant_tokens) do
    record(:generate_data_key, context)
    inner.__struct__.generate_data_key(inner, key_id, bytes, context, grant_tokens)
  end

  @impl true
  def encrypt(%__MODULE__{inner: inner}, key_id, plaintext, context, grant_tokens) do
    record(:encrypt, context)
    inner.__struct__.encrypt(inner, key_id, plaintext, context, grant_tokens)
  end

  @impl true
  def decrypt(%__MODULE__{inner: inner}, key_id, ciphertext, context, grant_tokens) do
    record(:decrypt, context)
    inner.__struct__.decrypt(inner, key_id, ciphertext, context, grant_tokens)
  end

  @spec record(atom(), map()) :: :ok
  defp record(operation, context) do
    send(self(), {:kms_context, operation, context})
    :ok
  end
end

defmodule Encryptor.AwsKms.Unreachable do
  @moduledoc """
  A KMS client that fails every call the way an IAM denial or a timeout does.

  ADR-0008's failure table maps both onto `{:key_unavailable, selector}` at
  the vault boundary, deliberately: they are the same fact to a caller, and
  distinguishing them would put the shape of the host's IAM into an error
  term.
  """

  @behaviour AwsEncryptionSdk.Keyring.KmsClient

  defstruct []

  @type t :: %__MODULE__{}

  @denied {:error, {:kms_error, :access_denied, "not authorized"}}

  @doc "A client that refuses everything."
  @spec new() :: t()
  def new, do: %__MODULE__{}

  @impl true
  def generate_data_key(_client, _key_id, _bytes, _context, _grant_tokens), do: @denied

  @impl true
  def encrypt(_client, _key_id, _plaintext, _context, _grant_tokens), do: @denied

  @impl true
  def decrypt(_client, _key_id, _ciphertext, _context, _grant_tokens), do: @denied
end

defmodule Encryptor.AwsKmsVaults do
  @moduledoc """
  The vaults the keyring-backed path is exercised through.

  A tenant vault whose provider is `Encryptor.Provider.Kms` against the fake
  client, and a migration vault whose provider answers both descriptor shapes
  for one selector - ADR-0008 decision 6's overlap, which is an ordinary
  rotation window rather than a new mechanism.
  """

  alias Encryptor.AwsKms.Fake
  alias Encryptor.AwsKms.Recording
  alias Encryptor.AwsKms.Unreachable, as: UnreachableClient
  alias Encryptor.Key.Aes
  alias Encryptor.Key.Kms
  alias Encryptor.Provider.Kms, as: KmsProvider

  @legacy_material :binary.copy(<<0xD1>>, 32)

  @static_context %{"app" => "acme-app", "purpose" => "pii"}

  @doc "The AES material acme's pre-migration messages were written under."
  @spec legacy_material() :: binary()
  def legacy_material, do: @legacy_material

  @doc "The AES descriptor acme's pre-migration messages were written under."
  @spec legacy_descriptor() :: Aes.t()
  def legacy_descriptor do
    %Aes{namespace: "acme-app", name: "acme/v1", material: @legacy_material, bits: 256}
  end

  @doc """
  The static context the recording vaults are configured with.

  Two of ADR-0004 decision 2's advisory keys, written by the host about
  itself, so a recorded context carries the static layer as well as the
  derived and per-call ones.
  """
  @spec static_context() :: %{String.t() => String.t()}
  def static_context, do: @static_context

  @doc "The `Kms` provider options behind a recording client."
  @spec recording_provider() :: {module(), keyword()}
  def recording_provider do
    {KmsProvider, client: Recording.new(), keys: %{"acme" => [Fake.acme(), Fake.acme_previous()]}}
  end

  @doc "The `Kms` provider options a single-tenant vault records under."
  @spec recording_root_provider() :: {module(), keyword()}
  def recording_root_provider do
    {KmsProvider, client: Recording.new(), key_id: Fake.acme()}
  end

  @doc "The `Kms` provider options the tenant vault is configured with."
  @spec provider() :: {module(), keyword()}
  def provider do
    {KmsProvider,
     client: Fake.new(),
     keys: %{
       "acme" => [Fake.acme(), Fake.acme_previous()],
       "globex" => Fake.globex()
     }}
  end

  @doc """
  A provider answering the migration overlap for acme: the KMS key first, the
  live AES version after it.
  """
  @spec migration_provider() :: {module(), keyword()}
  def migration_provider do
    kms = %Kms{key_id: Fake.acme(), client: Fake.new()}

    {Encryptor.Provider.Function,
     encryption_key: fn
       "acme" -> {:ok, kms}
       selector -> {:error, {:unknown_key, selector}}
     end,
     decryption_keys: fn
       "acme" -> {:ok, [kms, legacy_descriptor()]}
       selector -> {:error, {:unknown_key, selector}}
     end}
  end

  @doc "A provider answering only the AES version, as the host ran before the migration."
  @spec legacy_provider() :: {module(), keyword()}
  def legacy_provider do
    {Encryptor.Provider.Function,
     encryption_key: fn
       "acme" -> {:ok, legacy_descriptor()}
       selector -> {:error, {:unknown_key, selector}}
     end,
     decryption_keys: fn
       "acme" -> {:ok, [legacy_descriptor()]}
       selector -> {:error, {:unknown_key, selector}}
     end}
  end

  defmodule Tenant do
    @moduledoc "A tenant vault whose keys are KMS keys."

    use Encryptor.Vault, otp_app: :encryptor, context_profile: :tenant

    @doc """
    Layer 5: the provider, the reference subkey, and a derivation salt.

    The salt is configured so that `Encryptor.Vault.derive/3` fails on the
    descriptor rather than on the missing configuration - it is the refusal
    that is the subject, and an unsalted vault would refuse for the wrong
    reason.
    """
    def init(config) do
      {:ok,
       config
       |> Keyword.put(:provider, Encryptor.AwsKmsVaults.provider())
       |> Keyword.put(:reference_subkey, :binary.copy(<<0x55>>, 32))
       |> Keyword.put(:derivation_salt, :binary.copy(<<0x66>>, 32))}
    end
  end

  defmodule Previous do
    @moduledoc "A tenant vault pinned to acme's older KMS key, so a message exists under it."

    use Encryptor.Vault, otp_app: :encryptor, context_profile: :tenant

    @doc "Layer 5: the older key alone, and the reference subkey."
    def init(config) do
      {:ok,
       config
       |> Keyword.put(
         :provider,
         {KmsProvider, client: Fake.new(), key_id: Fake.acme_previous()}
       )
       |> Keyword.put(:reference_subkey, :binary.copy(<<0x55>>, 32))}
    end
  end

  defmodule Unreachable do
    @moduledoc "A tenant vault whose KMS client refuses every call."

    use Encryptor.Vault, otp_app: :encryptor, context_profile: :tenant

    @doc "Layer 5: the refusing client, and the reference subkey."
    def init(config) do
      {:ok,
       config
       |> Keyword.put(
         :provider,
         {KmsProvider, client: UnreachableClient.new(), key_id: Fake.acme()}
       )
       |> Keyword.put(:reference_subkey, :binary.copy(<<0x55>>, 32))}
    end
  end

  defmodule Migrating do
    @moduledoc "The same tenant vault, mid-migration: both descriptor shapes for one selector."

    use Encryptor.Vault, otp_app: :encryptor, context_profile: :tenant

    @doc "Layer 5: the overlap provider and the reference subkey."
    def init(config) do
      {:ok,
       config
       |> Keyword.put(:provider, Encryptor.AwsKmsVaults.migration_provider())
       |> Keyword.put(:reference_subkey, :binary.copy(<<0x55>>, 32))}
    end
  end

  defmodule Recorded do
    @moduledoc """
    The tenant vault, with every KMS call's encryption context recorded.

    `cache: false` so no operation is answered from cached materials: a
    cached data key is a KMS call that did not happen, and an assertion about
    what KMS received cannot be made about a call that was skipped.
    """

    use Encryptor.Vault, otp_app: :encryptor, context_profile: :tenant, cache: false

    @doc "Layer 5: the recording provider, the reference subkey, and the static context."
    def init(config) do
      {:ok,
       config
       |> Keyword.put(:provider, Encryptor.AwsKmsVaults.recording_provider())
       |> Keyword.put(:reference_subkey, :binary.copy(<<0x55>>, 32))
       |> Keyword.put(:static_encryption_context, Encryptor.AwsKmsVaults.static_context())}
    end
  end

  defmodule RecordedUnsigned do
    @moduledoc """
    `Recorded` under the unsigned algorithm suite, `0x0478`.

    The default `:algorithm_suite_id` is `0x0578`, which signs, and under a
    signing suite the engine adds its own reserved `aws-crypto-public-key`
    pair below the vault. `0x0478` is the other value the config allows and
    does not sign, so this is the vault on which the KMS call carries exactly
    the map the vault composed - the other half of the rule the signing-suite
    Note records, and the reason no existing context assertion saw the pair.
    """

    use Encryptor.Vault,
      otp_app: :encryptor,
      context_profile: :tenant,
      algorithm_suite_id: 0x0478,
      cache: false

    @doc "Layer 5: the recording provider, the reference subkey, and the static context."
    def init(config) do
      {:ok,
       config
       |> Keyword.put(:provider, Encryptor.AwsKmsVaults.recording_provider())
       |> Keyword.put(:reference_subkey, :binary.copy(<<0x55>>, 32))
       |> Keyword.put(:static_encryption_context, Encryptor.AwsKmsVaults.static_context())}
    end
  end

  defmodule RecordedRoot do
    @moduledoc """
    A single-tenant vault over KMS, recording, for the envelope's own path.

    `Encryptor.Envelope` is the only caller that writes ADR-0003 decision 4's
    reserved layer, and it wraps under a root vault with no `:key` selector -
    so a `:single` profile is what that path needs, and this is where the
    `encryptor-*` pairs become observable at the KMS boundary.
    """

    use Encryptor.Vault, otp_app: :encryptor, context_profile: :single, cache: false

    @doc """
    Layer 5: the recording provider and the static context.

    No `:reference_subkey`: a `:single` profile refuses one at start
    (`{:invalid_config, :reference_subkey, :single_profile}`), and
    `Encryptor.Envelope.provision/3` takes the subkey in its own options for
    the reason ADR-0005 decision 5 gives.
    """
    def init(config) do
      {:ok,
       config
       |> Keyword.put(:provider, Encryptor.AwsKmsVaults.recording_root_provider())
       |> Keyword.put(:static_encryption_context, Encryptor.AwsKmsVaults.static_context())}
    end
  end

  defmodule Legacy do
    @moduledoc "The tenant vault as it ran before the migration: AES material only."

    use Encryptor.Vault, otp_app: :encryptor, context_profile: :tenant

    @doc "Layer 5: the pre-migration provider and the reference subkey."
    def init(config) do
      {:ok,
       config
       |> Keyword.put(:provider, Encryptor.AwsKmsVaults.legacy_provider())
       |> Keyword.put(:reference_subkey, :binary.copy(<<0x55>>, 32))}
    end
  end
end
