defmodule Encryptor.EngineReader do
  @moduledoc """
  Reads a message with the engine directly, under a context the test names.

  Since `aws_encryption_sdk` 1.1 a required pair is bound to a message
  without being stored in its header (ADR-0004 Amendment B), so a test can no
  longer read what a vault bound out of `Encryptor.Message.describe/1`. It
  reads it this way instead: the engine opens the message under a reproduced
  context that agrees with what the writer bound, and refuses one that does
  not. The reader is a bare `Default` CMM over a `RawAes` keyring built from
  the descriptor the writer's provider resolves to, so nothing of this
  package's own read path is in the evidence.
  """

  alias AwsEncryptionSdk.Client
  alias AwsEncryptionSdk.Cmm.Default
  alias AwsEncryptionSdk.Keyring.RawAes
  alias Encryptor.Key.Aes

  @doc "Decrypts `ciphertext` under `key` with `context` as the reproduced context."
  @spec read(binary(), Aes.t(), %{String.t() => String.t()}) :: {:ok, map()} | {:error, term()}
  def read(ciphertext, %Aes{} = key, context) do
    {:ok, keyring} = RawAes.new(key.namespace, key.name, key.material, :aes_256_gcm)

    keyring
    |> Default.new()
    |> Client.new()
    |> Client.decrypt(ciphertext, encryption_context: context)
  end
end
