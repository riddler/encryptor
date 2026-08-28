defmodule Encryptor.Vault.Reference do
  @moduledoc false

  # The keyed tenant reference, in one place.
  #
  # ADR-0003 decision 5 fixes the derivation, and ADR-0004's acceptance
  # amendment 1 moves the reference subkey into tenant-vault configuration so
  # that the vault itself can compute it on the encrypt path:
  #
  #     tenant_ref =
  #       Base.url_encode64(
  #         binary_part(HMAC-SHA256(reference_subkey, selector), 0, 16),
  #         padding: false
  #       )
  #
  # Two properties are what the derivation is bought for. It is **stable**, so
  # the same tenant always resolves to the same reference and the row can be
  # found. And it is **unguessable without the subkey**, so a header discloses
  # that two ciphertexts belong to the same tenant without disclosing which
  # tenant that is - which an unkeyed hash of a short slug would not.
  #
  # ## Why this module exists rather than a second copy of six lines
  #
  # Three call sites want the same bytes: the vault's start-time known-answer
  # check (`Encryptor.Vault.Config.known_answer/1`), the encrypt path's
  # injection of `tenant_ref` into the context, and - when it lands -
  # `Encryptor.Envelope.tenant_ref/2`, whose public signature ADR-0003 fixes.
  # A derivation spelled three times is a derivation that can drift in two of
  # them, and a drifted reference is not a failed check: it is a message no
  # correct reader can open, discovered at decrypt time against a subkey that
  # is permanent.
  #
  # ## What the output is not
  #
  # It is not secret. It travels in the clear in every message header, both as
  # the context pair and inside the encrypted data key's name, so nothing here
  # is written to resist a timing observation. The **input** is secret, and
  # this module never renders it: no argument reaches a message, a log line,
  # or a failure report.

  # ADR-0003 decision 5's width. Sixteen bytes of an HMAC-SHA256 tag, encoded
  # url-safe and unpadded so the value is usable in a key name and in a
  # context value without escaping.
  @bytes 16

  @doc false
  @spec derive(binary(), String.t()) :: String.t()
  def derive(reference_subkey, selector)
      when is_binary(reference_subkey) and is_binary(selector) do
    :hmac
    |> :crypto.mac(:sha256, reference_subkey, selector)
    |> binary_part(0, @bytes)
    |> Base.url_encode64(padding: false)
  end
end
