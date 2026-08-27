defmodule Encryptor.Message do
  @moduledoc """
  The one place this package reads the engine's message format.

  A ciphertext written by this package is an AWS Encryption SDK message, and
  its header carries in the clear - to anyone holding the bytes - the
  encryption context, the algorithm suite, and the provider and key name of
  every encrypted data key. This module parses that header and nothing else.
  It holds no state, reads no configuration, touches no vault and no provider,
  and needs no key material.

  ## The dependency is deliberate and it is here

  ADR-0002 open question 1 was reluctant to depend on the engine's message
  layout at all. Three accepted decisions then required it: `describe/1`
  (ADR-0004 decision 12), the vault-side reproduced-context value comparison
  (ADR-0004 decision 6), and `rekey/2`'s reproduction of the stored context
  from the message (ADR-0004 decision 11). ADR-0005 open question 3 records
  that a fourth caller - the rotation census - wants the same function.

  Building it once, as a pure parse, is what makes the other three cheap. It
  also means the dependency has a single address: if the engine's header
  layout changes, or this package moves off `aws_encryption_sdk`, this module
  is the file to read.

  ## Nothing here authenticates anything

  `AwsEncryptionSdk.Format.Header.deserialize/1` reads the header's fields; it
  does not check the header authentication tag, because checking that tag
  requires the data key, which requires a keyring, a provider, and everything
  this module exists to avoid needing. Every value this module returns is
  therefore an *unverified claim* by whoever wrote the bytes. See
  `describe/1`.

  Records: ADR-0004 decision 12; ADR-0001 open question 1 as answered there;
  ADR-0005 open question 3.
  """

  alias AwsEncryptionSdk.AlgorithmSuite
  alias AwsEncryptionSdk.Format.Header
  alias AwsEncryptionSdk.Materials.EncryptedDataKey
  alias Encryptor.Error
  alias Encryptor.Message.Info

  # The raw-AES provider info the engine writes is
  # `key_name <> <<tag_length_bits::32, iv_length::32, iv::binary>>`, with no
  # length prefix on the name - a reader that does not already know the
  # keyring's key name recovers it by removing a fixed-size trailer. These
  # three constants are the engine's, mirrored here rather than reached for,
  # because `AwsEncryptionSdk.Keyring.RawAes` keeps them private and its
  # `deserialize_provider_info/2` needs the keyring this module does not have.
  @raw_aes_tag_length_bits 128
  @raw_aes_iv_length 12
  @raw_aes_trailer_bytes 4 + 4 + @raw_aes_iv_length

  @doc """
  Reads what a message says about itself, without a key and without
  verifying it.

  **The return is an unverified claim.** The header authentication tag is not
  checked - checking it needs the data key - so every field is what whoever
  wrote the bytes says, not what this package has confirmed. Use it for
  support tooling, for a migration that needs to know which key version wrote
  a row, and for an operator holding a row they cannot explain. **Never make
  an authorization or routing decision on it.** A host that reads
  `"tenant_ref"` out of the context and shows the row to that tenant has built
  an access check out of an attacker-editable field.

  Offering this at all is an exception to ADR-0001 decision 10's collapse
  rule, and it is exempt for exactly one reason: it discloses nothing the
  ciphertext did not already disclose to its holder. It is not a decryption
  oracle, because it answers no question that depends on a key.

  It is `describe` and not `inspect` so that a generated vault module defining
  it does not shadow `Kernel.inspect/1` inside its own body.

      iex> {:error, error} = Encryptor.Message.describe("not an ESDK message")
      iex> error.reason
      :decrypt_failed
      iex> error.engine
      {:unsupported_version, 110}

  ## What "success" means here

  A parse succeeds when the header is complete and well-formed. The message
  body is not read and not required, so a truncated message whose header
  survived describes itself perfectly well - which is the honest behaviour for
  a function whose whole contract is "unverified", and is what makes it usable
  on a corrupted row.

  Records: ADR-0004 decision 12, ADR-0001 decision 10 and open question 1.
  """
  @spec describe(binary()) :: {:ok, Info.t()} | {:error, Error.t()}
  def describe(message) when is_binary(message) do
    case Header.deserialize(message) do
      {:ok, header, _body} -> {:ok, info(header)}
      {:error, engine} -> {:error, unreadable(engine)}
    end
  end

  @spec info(Header.t()) :: Info.t()
  defp info(%Header{} = header) do
    %Info{
      encryption_context: header.encryption_context,
      algorithm_suite_id: header.algorithm_suite.id,
      committed?: AlgorithmSuite.committed?(header.algorithm_suite),
      encrypted_data_keys: Enum.map(header.encrypted_data_keys, &edk/1)
    }
  end

  @spec edk(EncryptedDataKey.t()) :: Info.edk()
  defp edk(%EncryptedDataKey{} = edk) do
    %{
      provider_id: edk.key_provider_id,
      key_name: key_name(edk.key_provider_info)
    }
  end

  # A KMS provider writes the key ARN as the provider info and there is
  # nothing to strip. A raw keyring writes the name followed by the trailer
  # described above. Both are recognised by shape rather than by matching on a
  # provider id, because the reserved-namespace rule ("aws-kms...") constrains
  # the KMS keyrings and says nothing about what a third-party provider id may
  # be. When neither reading applies the provider info is returned whole,
  # which is the only answer that invents nothing.
  @spec key_name(binary()) :: String.t()
  defp key_name(provider_info) when byte_size(provider_info) > @raw_aes_trailer_bytes do
    name_size = byte_size(provider_info) - @raw_aes_trailer_bytes

    case provider_info do
      <<name::binary-size(name_size), @raw_aes_tag_length_bits::32, @raw_aes_iv_length::32,
        _iv::binary-size(@raw_aes_iv_length)>> ->
        if String.valid?(name), do: name, else: provider_info

      _other ->
        provider_info
    end
  end

  defp key_name(provider_info), do: provider_info

  # The reason vocabulary (ADR-0001 decision 10, as `Encryptor.Error` closes
  # it) partitions failures by whether they depend on the message: those that
  # do collapse to `:decrypt_failed`, and a header this module cannot parse
  # depends on nothing else. The engine's term is carried in `:engine`
  # unchanged, as it is everywhere.
  #
  # `:operation` is `nil` rather than one of the four terms in
  # `t:Encryptor.Error.operation/0`. Reading a header is not an encrypt, a
  # decrypt, a rekey or a start, and `:operation` is already documented as
  # optional; naming one of the four here would misdescribe the call, and
  # adding a fifth term is an amendment to ADR-0001 decision 10 rather than an
  # implementation choice. See this bead's note.
  @spec unreadable(term()) :: Error.t()
  defp unreadable(engine) do
    %Error{reason: :decrypt_failed, vault: nil, operation: nil, engine: engine}
  end
end
