defmodule Encryptor.Vault.Keyring do
  @moduledoc false

  # The vault's keyring construction, and the descriptor validation that runs
  # immediately before it.
  #
  # ADR-0002 decision 3 says the vault, and only the vault, turns a descriptor
  # into an engine keyring. This module is where "only the vault" stops being
  # a sentence in a record and becomes a module boundary: it is internal, it
  # is not part of the published surface, and a provider has nothing to call.
  # A provider decides *which key*; this decides *what that means to the
  # engine*.
  #
  # ## Validation is ours even where the engine repeats it
  #
  # Two of the three checks below are checks `RawAes.new/4` also performs. We
  # run them anyway, first, because the engine answers with a bare tuple -
  # `:reserved_provider_id`, `{:invalid_key_length, expected: _, actual: _}` -
  # and a caller reading a failure needs this package's own reason, not the
  # engine's internals leaking one layer up. ADR-0002 decision 3 names both
  # explicitly for that reason.
  #
  # The third - that a namespace and a name are non-empty printable strings -
  # is ours alone. Both are written into the message header in the clear and
  # compared byte-for-byte on unwrap, so a value that cannot survive a round
  # trip through a header is a descriptor that produces undecryptable
  # messages, silently, at some later date.
  #
  # ## The detail term never carries key material
  #
  # Every failure is `{:invalid_key_descriptor, detail}`, and the detail names
  # the constraint that was violated rather than the value that violated it.
  # `:bits` in particular is reported without its value: it is caller-supplied
  # and unvalidated at the point we reject it, so it could hold anything,
  # including bytes. A length in bits is reported, because a length is not
  # material. `Encryptor.Error` does not render the detail into a message
  # either; this is the belt, that is the braces.
  #
  # ## If the engine rejects what we accepted
  #
  # Our validation is a superset of the engine's, so the construction below
  # cannot fail on a descriptor that reached it. If it ever does, the engine's
  # own term arrives as the detail rather than being swallowed - that is a
  # defect in this module's validation, and it should be visible as one.

  alias AwsEncryptionSdk.Keyring.Behaviour, as: EngineKeyring
  alias AwsEncryptionSdk.Keyring.Multi
  alias AwsEncryptionSdk.Keyring.RawAes
  alias Encryptor.Error
  alias Encryptor.Key.Aes
  alias Encryptor.Key.Kms

  @typedoc false
  @type t :: RawAes.t() | Multi.t()

  @doc false
  @spec build(module(), Error.operation(), term()) :: {:ok, t()} | {:error, Error.t()}
  def build(vault, operation, %Aes{} = key) do
    with :ok <- validate_header_string(key.namespace, :namespace),
         :ok <- validate_namespace(key.namespace),
         :ok <- validate_header_string(key.name, :name),
         :ok <- validate_bits(key.bits),
         :ok <- validate_material(key.material, key.bits),
         {:ok, keyring} <-
           RawAes.new(key.namespace, key.name, key.material, wrapping_algorithm(key.bits)) do
      {:ok, keyring}
    else
      {:error, detail} -> {:error, invalid(vault, operation, detail)}
    end
  end

  # Recognized, and deliberately not buildable yet: the KMS mapping ships with
  # the KMS provider, which ADR-0002 decision 5 sequences after the envelope.
  # The detail says "no mapping", not "unknown struct", because the two are
  # different facts and a reader of the failure needs to be able to tell them
  # apart.
  def build(vault, operation, %Kms{}) do
    {:error, invalid(vault, operation, {:no_keyring_mapping, Kms})}
  end

  def build(vault, operation, other) do
    {:error, invalid(vault, operation, {:not_a_descriptor, shape(other)})}
  end

  # The decrypt-side counterpart: a candidate list becomes one keyring.
  #
  # A one-element list builds a plain RawAes rather than a Multi of one, which
  # would be an extra struct and an extra error-wrapping layer for nothing. A
  # longer one builds a Multi with `generator: nil` - permitted by the engine
  # whenever there is at least one child - which walks its children in order
  # and returns the first success. That walk is the whole rotation mechanism:
  # a message written under an older name still decrypts, and a name removed
  # from the list is a message nobody can read again.
  #
  # An empty list is a provider defect rather than a rotation state. The
  # contract types the callback's success as a non-empty list, and a vault
  # that built a keyring from nothing would report "no key" as "wrong
  # ciphertext" one layer later.
  @doc false
  @spec build_all(module(), Error.operation(), term()) :: {:ok, t()} | {:error, Error.t()}
  def build_all(vault, operation, [descriptor]), do: build(vault, operation, descriptor)

  def build_all(vault, operation, [_ | _] = descriptors) do
    with {:ok, keyrings} <- build_each(vault, operation, descriptors),
         {:ok, multi} <- Multi.new(generator: nil, children: keyrings) do
      {:ok, multi}
    else
      {:error, %Error{} = error} -> {:error, error}
      {:error, detail} -> {:error, invalid(vault, operation, detail)}
    end
  end

  def build_all(vault, operation, []),
    do: {:error, invalid(vault, operation, :empty_candidate_list)}

  def build_all(vault, operation, other),
    do: {:error, invalid(vault, operation, {:not_a_candidate_list, shape(other)})}

  @spec build_each(module(), Error.operation(), [term(), ...]) ::
          {:ok, [t(), ...]} | {:error, Error.t()}
  defp build_each(vault, operation, descriptors) do
    descriptors
    |> Enum.reduce_while({:ok, []}, fn descriptor, {:ok, acc} ->
      case build(vault, operation, descriptor) do
        {:ok, keyring} -> {:cont, {:ok, [keyring | acc]}}
        {:error, error} -> {:halt, {:error, error}}
      end
    end)
    |> case do
      {:ok, reversed} -> {:ok, Enum.reverse(reversed)}
      {:error, error} -> {:error, error}
    end
  end

  @spec validate_header_string(term(), :namespace | :name) :: :ok | {:error, term()}
  defp validate_header_string(value, field) do
    cond do
      not is_binary(value) -> {:error, {:invalid_key_field, field, :not_a_string}}
      value == "" -> {:error, {:invalid_key_field, field, :empty}}
      not String.printable?(value) -> {:error, {:invalid_key_field, field, :not_printable}}
      true -> :ok
    end
  end

  # The engine owns the reserved prefix, so the engine is asked rather than
  # the prefix being spelled a second time here. Its answer is translated:
  # what a caller sees is this package's vocabulary.
  @spec validate_namespace(String.t()) :: :ok | {:error, term()}
  defp validate_namespace(namespace) do
    case EngineKeyring.validate_provider_id(namespace) do
      :ok -> :ok
      {:error, :reserved_provider_id} -> {:error, {:reserved_namespace, "aws-kms"}}
    end
  end

  @spec validate_bits(term()) :: :ok | {:error, term()}
  defp validate_bits(bits) when bits in [128, 192, 256], do: :ok
  defp validate_bits(_bits), do: {:error, {:invalid_key_field, :bits, :unsupported}}

  @spec validate_material(term(), Aes.bits()) :: :ok | {:error, term()}
  defp validate_material(material, _bits) when not is_binary(material),
    do: {:error, {:invalid_key_field, :material, :not_a_binary}}

  defp validate_material(material, bits) do
    case byte_size(material) * 8 do
      ^bits -> :ok
      actual -> {:error, {:key_length_mismatch, bits, actual}}
    end
  end

  @spec wrapping_algorithm(Aes.bits()) :: RawAes.wrapping_algorithm()
  defp wrapping_algorithm(128), do: :aes_128_gcm
  defp wrapping_algorithm(192), do: :aes_192_gcm
  defp wrapping_algorithm(256), do: :aes_256_gcm

  # Enough of an unrecognized term to debug with, and no more. The term itself
  # is not carried: an arbitrary map handed to a vault can hold anything,
  # including key material, and this value ends up inside an error struct that
  # a host may well log.
  @spec shape(term()) :: module() | :not_a_struct
  defp shape(%module{}), do: module
  defp shape(_other), do: :not_a_struct

  @spec invalid(module(), Error.operation(), term()) :: Error.t()
  defp invalid(vault, operation, detail) do
    %Error{
      reason: {:invalid_key_descriptor, detail},
      vault: vault,
      operation: operation,
      engine: nil
    }
  end
end
