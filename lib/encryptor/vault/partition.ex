defmodule Encryptor.Vault.Partition do
  @moduledoc """
  Derives the fixed-width cache partition id a vault hands the caching CMM.

  One cache process serves every partition within a vault (ADR-0001 decision
  3), so the thing that keeps one scope's data key out of another scope's
  cache lookup is the partition id, not a second process. Decision 7 fixes
  the derivation:

      partition_id = binary_part(sha256(vault_namespace, 0, encoded_selector), 0, 16)

  and this module is the only place it is computed. The result is what the
  vault hands the engine's caching CMM as `:partition_id`.

  ## Both sides also carry the key, and the key's bytes

  The engine's encryption cache id hashes the partition id, the suite and the
  context, and never the key that wrapped the entry's data key. With the
  formula above alone, a write after a new key version is minted finds the
  warm entry from before the mint and wraps its data key under the old
  version. So the partition a vault hands the caching CMM on the write side
  (an encrypt, and a rekey's write half) also carries the resolved key's
  identity - the namespace and name of an `Encryptor.Key.Aes`, the key id of
  an `Encryptor.Key.Kms` - in a length-prefixed pre-image, and a new version
  is a new partition, cold at once (ADR-0001 Amendment B).

  A name is not enough on its own. A whole-scope shred deletes a store's rows,
  and a provision for the same scope at the same version mints the same name
  over new bytes. With names alone, a decryption entry warmed before the shred
  then serves the old message again, and the next write reuses an encryption
  entry whose data key is wrapped under the destroyed bytes. So an AES key's
  identity also carries a fingerprint of its material, and the read side (a
  decrypt, and a rekey's read half) is partitioned by the identity of every
  candidate the provider answered, in order (ADR-0001 Amendment C). Two
  different byte strings under one name never share a cache entry, on either
  side.

  The fingerprint is a domain-separated SHA-256 of the material, computed in
  the pre-image and never kept: what leaves this module is the 16-byte
  truncation of a hash over it, which is not key material and is never put
  in telemetry, a message or a store. A `Encryptor.Key.Kms` key carries no
  material here; its key id names bytes that only the key manager holds.

  ## Why the width is fixed, and why it is 16

  The engine's cache-id computation (`compute_encryption_cache_id/3` in the
  `aws_encryption_sdk` caching CMM) concatenates
  the partition id into the cache id pre-image **with no length prefix**. A
  variable-width partition id therefore makes the pre-image ambiguous, and two
  different partitions could in principle hash to one cache id - which is two
  scopes sharing a data key. Sixteen bytes is the width of the UUID the
  engine generates when no partition id is given, so matching it removes the
  ambiguity by construction rather than by argument.

  Nothing here may be relaxed into "any binary": the width is load-bearing.

  ## What a partition id is not

  It is a cache-key input only. It is not key material, it is not secret, and
  it never reaches a message. Deriving it by hash rather than using the raw
  selector keeps scope identifiers out of a structure this package does not
  control the lifetime of, and buys the uniform width for free.

  Records: ADR-0001 decisions 3 and 7 and Amendments B and C; the selector
  type is ADR-0004 decision 3.
  """

  alias Encryptor.Error
  alias Encryptor.Key.Aes
  alias Encryptor.Key.Kms

  # Decision 7's width, and the reason it is not configurable is in the
  # moduledoc: the engine's pre-image has no length prefix.
  @bytes 16

  # The selector is `:default` on a `:single` vault and a non-empty string on
  # a `:scoped` vault (ADR-0004 decision 3). The two live in one hash
  # pre-image, so they are tagged apart: without the tag, a `:scoped` vault
  # holding the scope `"default"` and a `:single` vault would derive the same
  # partition. Neither vault can hold both selector shapes today, so the tag
  # costs a byte and removes a whole class of future collision.
  @default_tag 0
  @string_tag 1

  # The write side's key identity, tagged by descriptor shape for the same
  # reason the selector is: an AES namespace and name and a KMS key id live in
  # one pre-image.
  @aes_tag 0
  @kms_tag 1

  # The domain separator of the material fingerprint (ADR-0001 Amendment C).
  # It is the only input hashed beside the bytes, so no other SHA-256 this
  # package computes over the same bytes shares a pre-image with it.
  @fingerprint_label "encryptor partition fingerprint v1"

  @doc """
  The 16-byte partition id for a vault and a key selector.

  This is ADR-0001 decision 7's selector-only formula. The vault no longer
  hands it to the caching CMM: both sides partition by the keys as well
  (Amendments B and C), through derivations that are internal to the vault.

  Pure, total over the selector types ADR-0004 decision 3 admits, and
  allocating nothing that outlives the call.

      iex> id = Encryptor.Vault.Partition.id(MyApp.Vault, "scope-42")
      iex> byte_size(id)
      16

      iex> Encryptor.Vault.Partition.id(MyApp.Vault, "scope-42") ==
      ...>   Encryptor.Vault.Partition.id(MyApp.Vault, "scope-43")
      false

      iex> Encryptor.Vault.Partition.id(MyApp.Vault, :default) ==
      ...>   Encryptor.Vault.Partition.id(MyApp.OtherVault, :default)
      false
  """
  @spec id(module(), Error.selector()) :: binary()
  def id(vault, selector) when is_atom(vault) do
    :sha256
    |> :crypto.hash([Atom.to_string(vault), 0, encoded(selector)])
    |> binary_part(0, @bytes)
  end

  @doc false
  # The write side's partition: the vault, the selector and the resolved key,
  # each field length-prefixed so that the pre-image parses back to exactly
  # one triple, and no two triples share it. ADR-0001 Amendment B's formula,
  # with Amendment C's fingerprint in the key's identity. The digest and the
  # truncation are decision 7's, so the width is the engine's 16 bytes.
  #
  # `@doc false` because no host calls it: `Encryptor.Vault.Encrypt` builds
  # the write-side stack with it, and a test pins the derivation. The key is
  # a descriptor `Encryptor.Vault.Keyring.build/3` has already accepted, so
  # there is deliberately no clause for any other term.
  @spec encryption_id(module(), Error.selector(), Aes.t() | Kms.t()) :: binary()
  def encryption_id(vault, selector, key) when is_atom(vault) do
    :sha256
    |> :crypto.hash([
      prefixed(Atom.to_string(vault)),
      prefixed(encoded(selector)),
      identity(key)
    ])
    |> binary_part(0, @bytes)
  end

  @doc false
  # The read side's partition (ADR-0001 Amendment C): the vault, the selector
  # and every candidate the provider answered, newest first. The count is
  # prefixed and each identity is self-delimiting, so the pre-image parses
  # back to exactly one candidate list. A list that gains, loses, reorders or
  # re-mints a key is a new partition.
  #
  # The candidates are descriptors `Encryptor.Vault.Keyring.build_all/3` has
  # already accepted, which is a non-empty list.
  @spec decryption_id(module(), Error.selector(), [Aes.t() | Kms.t(), ...]) :: binary()
  def decryption_id(vault, selector, [_ | _] = candidates) when is_atom(vault) do
    :sha256
    |> :crypto.hash([
      prefixed(Atom.to_string(vault)),
      prefixed(encoded(selector)),
      <<length(candidates)::32>>,
      Enum.map(candidates, &identity/1)
    ])
    |> binary_part(0, @bytes)
  end

  @doc """
  The width every partition id has, in bytes.

      iex> Encryptor.Vault.Partition.bytes()
      16
  """
  @spec bytes() :: pos_integer()
  def bytes, do: @bytes

  # A selector outside decision 3's two shapes never reaches here: the profile
  # check refuses it in the vault, before the provider is consulted and before
  # any partition is derived. There is deliberately no catch-all clause, so a
  # future caller that skips that check fails loudly rather than silently
  # partitioning two distinct selectors together.
  @spec encoded(Error.selector()) :: binary()
  defp encoded(:default), do: <<@default_tag>>
  defp encoded(selector) when is_binary(selector), do: <<@string_tag, selector::binary>>

  # The fields the message header records for the key that wraps a data key:
  # the provider id and key name of a raw AES keyring, the key id of a KMS
  # keyring. A raw AES key also carries its material's fingerprint, because a
  # name can come back over other bytes after a shred (Amendment C).
  @spec identity(Aes.t() | Kms.t()) :: iodata()
  defp identity(%Aes{namespace: namespace, name: name, material: material}),
    do: [@aes_tag, prefixed(namespace), prefixed(name), fingerprint(material)]

  defp identity(%Kms{key_id: key_id}), do: [@kms_tag, prefixed(key_id)]

  # Fixed width, so it needs no prefix of its own.
  @spec fingerprint(binary()) :: binary()
  defp fingerprint(material) when is_binary(material),
    do: :crypto.hash(:sha256, [prefixed(@fingerprint_label), material])

  @spec prefixed(binary()) :: iodata()
  defp prefixed(field) when is_binary(field), do: [<<byte_size(field)::32>>, field]
end
