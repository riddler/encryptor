defmodule Encryptor.Vault.Derive do
  @moduledoc false

  # The derived-subkey path: a consumer names a scope, the vault resolves the
  # key material behind it, derives inside this call, and returns derived
  # bytes and nothing else.
  #
  # `Encryptor.Vault.derive/3` is the door; this module is the body. It exists
  # for ADR-0003 amendment A, whose reason for existing is `encryptor_ecto`'s
  # blind index: that package needs a per-scope key and must never receive the
  # key material it was derived from (its ADR-0003 assumptions A8 and A11).
  #
  # ## The one property this module is for
  #
  # **The input key material never leaves this function.** It is resolved from
  # the provider, handed to `Encryptor.Kdf.salted_subkey/5`, and is not held
  # past this call. It is never returned, never put in an error, and never rendered:
  # `{:invalid_key_descriptor, :not_derivable}` names the shape of the
  # descriptor and not the descriptor, for the same reason every other
  # descriptor failure in this package does.
  #
  # Everything else here is the ordinary vault preamble, in the same order the
  # encrypt and decrypt paths take it, and for the same reasons:
  #
  #   1. `Encryptor.Vault.ready/2` - running vault, live provider.
  #   2. The purpose. `"root-wrap"`, `"scope-ref"` and the retired
  #      `"tenant-ref"` are refused, before anything else the caller passed
  #      is read and before the provider is consulted (see `purpose/2`).
  #   3. The selector profile check, before the provider is consulted. A
  #      `:scoped` vault refuses `:default` here exactly as it does at encrypt
  #      (ADR-0004 decision 3); a derivation that fell back to a default key on
  #      a per-scope vault would hand every scope the same subkey.
  #   4. The salt, from configuration. Checked after the selector so that a
  #      caller passing a nonsense selector to an unsalted vault is told about
  #      the selector, which is the argument they control.
  #   5. The provider resolves the selector to one descriptor.
  #   6. The descriptor must be derivable.
  #   7. The derivation.
  #
  # ## Why the encryption key and not the decryption candidates
  #
  # Amendment A decision 7. This asks `encryption_key/2` - the single current
  # key - and never `decryption_keys/2`. A derived subkey is recomputed rather
  # than stored (ADR-0003 decision 7), so there is no historical value to
  # reproduce; a consumer wanting an index under a superseded key version is
  # asking for the re-index pass ADR-0003 decision 6 describes. The asymmetry
  # with encrypt and decrypt is deliberate, and it is recorded so it does not
  # read as an omission.
  #
  # ## No cache, and no context
  #
  # There is no partition id and no CMM stack here, because there is no
  # message: the materials cache caches data keys, and a derivation generates
  # none. There is no encryption context either - nothing is being bound to
  # anything, since nothing is being written.

  alias Encryptor.Error
  alias Encryptor.Kdf
  alias Encryptor.Key.Aes
  alias Encryptor.Vault
  alias Encryptor.Vault.Config
  alias Encryptor.Vault.Resolve

  @default_length 32

  # ADR-0003 decision 6's root purposes and the retired reference purpose
  # (ADR-0009 Amendment A, A2): the labels this package derives for itself,
  # or reserves so nothing later takes them. `Encryptor.Envelope.subkey/2`
  # refuses the same three; the derive test pins that the two lists agree.
  @reserved_purposes ["root-wrap", "scope-ref", "tenant-ref"]

  @doc false
  @spec call(module(), Kdf.purpose(), keyword()) :: {:ok, binary()} | {:error, Error.t()}
  def call(vault, purpose, opts) when is_atom(vault) and is_binary(purpose) and is_list(opts) do
    with {:ok, config} <- Vault.ready(vault, :derive),
         :ok <- purpose(config, purpose),
         {:ok, selector} <- Resolve.selector(config, opts, :derive),
         {:ok, salt} <- salt(config),
         {:ok, info} <- info(config, opts),
         {:ok, length} <- out_length(config, opts),
         {:ok, descriptor} <- Resolve.encryption_key(config, selector, :derive),
         {:ok, material} <- derivable(config, descriptor) do
      {:ok, Kdf.salted_subkey(material, salt, purpose, info, length)}
    end
  end

  # ADR-0003 decision 6 reserves the label space one way: a label this
  # package derives under, or once derived under, is never handed to another
  # use. This path's output is salted and expanded once more under the
  # caller's `:info`, so it never equals the internal root-wrap or scope-ref
  # subkey; what the refusal keeps is the reservation itself, mechanical here
  # as it is in `Encryptor.Envelope.subkey/2` rather than a sentence in the
  # docs. A typed error rather than a raise, because this path reports what
  # its caller passed (`:info`, `:length`) the same way.
  @spec purpose(Config.t(), Kdf.purpose()) :: :ok | {:error, Error.t()}
  defp purpose(config, purpose) when purpose in @reserved_purposes,
    do: {:error, error(config, {:invalid_config, :purpose, :reserved})}

  defp purpose(_config, _purpose), do: :ok

  # Amendment A decision 3: optional at start, required here.
  @spec salt(Config.t()) :: {:ok, binary()} | {:error, Error.t()}
  defp salt(%Config{derivation_salt: nil} = config),
    do: {:error, error(config, {:missing_config, [:derivation_salt]})}

  defp salt(%Config{derivation_salt: salt}), do: {:ok, salt}

  # The caller's info, verbatim and opaque. An absent `:info` is `""`, which
  # amendment A decision 4 calls legitimate rather than a missing argument
  # (its word for the info string is "scope", in the derivation's sense, not
  # the key owner's) - the derivation runs the final expansion either way.
  @spec info(Config.t(), keyword()) :: {:ok, binary()} | {:error, Error.t()}
  defp info(config, opts) do
    case Keyword.get(opts, :info, "") do
      info when is_binary(info) -> {:ok, info}
      _other -> {:error, error(config, {:invalid_config, :info, :not_a_binary})}
    end
  end

  # The upper bound is `Encryptor.Kdf.expand/3`'s, and it is left there rather
  # than restated: a second copy of the RFC's limit is a second thing to keep
  # in step with it. What is checked here is only that the caller passed a
  # positive integer at all, because a non-integer would raise a FunctionClause
  # from inside the KDF rather than return this package's typed error.
  @spec out_length(Config.t(), keyword()) :: {:ok, pos_integer()} | {:error, Error.t()}
  defp out_length(config, opts) do
    case Keyword.get(opts, :length, @default_length) do
      length when is_integer(length) and length > 0 -> {:ok, length}
      _other -> {:error, error(config, {:invalid_config, :length, :not_a_positive_integer})}
    end
  end

  # Amendment A decision 5. An `%Aes{}` derives. A `%Kms{}` does not: its
  # material is not in this process, and obtaining it would mean asking a key
  # manager to export a key, which is the property a key manager exists to
  # refuse. Anything else is a descriptor the vault would not have accepted at
  # encrypt either.
  @spec derivable(Config.t(), term()) :: {:ok, binary()} | {:error, Error.t()}
  defp derivable(_config, %Aes{material: material}) when is_binary(material),
    do: {:ok, material}

  defp derivable(config, _descriptor),
    do: {:error, error(config, {:invalid_key_descriptor, :not_derivable})}

  # The term is never carried in `:engine` here, unlike on the encrypt path. A
  # descriptor holds key material, and this path's whole contract is that key
  # material does not leave it - including through an error struct a caller
  # can inspect.
  @spec error(Config.t(), Error.reason()) :: Error.t()
  defp error(%Config{vault: vault}, reason) do
    %Error{reason: reason, vault: vault, operation: :derive}
  end
end
