defmodule Encryptor.Vault.Partition do
  @moduledoc """
  Derives the fixed-width cache partition id a vault hands the caching CMM.

  One cache process serves every partition within a vault (ADR-0001 decision
  3), so the thing that keeps one tenant's data key out of another tenant's
  cache lookup is the partition id, not a second process. Decision 7 fixes
  the derivation:

      partition_id = binary_part(sha256(vault_namespace, 0, encoded_selector), 0, 16)

  and this module is the only place it is computed. The result is what the
  vault hands the engine's caching CMM as `:partition_id`; the call path that
  builds that CMM is the encrypt path's, and lands with it.

  ## Why the width is fixed, and why it is 16

  `AwsEncryptionSdk.Cmm.Caching.compute_encryption_cache_id/3` concatenates
  the partition id into the cache id pre-image **with no length prefix**. A
  variable-width partition id therefore makes the pre-image ambiguous, and two
  different partitions could in principle hash to one cache id - which is two
  tenants sharing a data key. Sixteen bytes is the width of the UUID the
  engine generates when no partition id is given, so matching it removes the
  ambiguity by construction rather than by argument.

  Nothing here may be relaxed into "any binary": the width is load-bearing.

  ## What a partition id is not

  It is a cache-key input only. It is not key material, it is not secret, and
  it never reaches a message. Deriving it by hash rather than using the raw
  selector keeps tenant identifiers out of a structure this package does not
  control the lifetime of, and buys the uniform width for free.

  Records: ADR-0001 decisions 3 and 7; the selector type is ADR-0004
  decision 3.
  """

  alias Encryptor.Error

  # Decision 7's width, and the reason it is not configurable is in the
  # moduledoc: the engine's pre-image has no length prefix.
  @bytes 16

  # The selector is `:default` on a `:single` vault and a non-empty string on
  # a `:tenant` vault (ADR-0004 decision 3). The two live in one hash
  # pre-image, so they are tagged apart: without the tag, a `:tenant` vault
  # holding the tenant `"default"` and a `:single` vault would derive the same
  # partition. Neither vault can hold both selector shapes today, so the tag
  # costs a byte and removes a whole class of future collision.
  @default_tag 0
  @string_tag 1

  @doc """
  The 16-byte partition id for a vault and a key selector.

  Pure, total over the selector types ADR-0004 decision 3 admits, and
  allocating nothing that outlives the call.

      iex> id = Encryptor.Vault.Partition.id(MyApp.Vault, "tenant-42")
      iex> byte_size(id)
      16

      iex> Encryptor.Vault.Partition.id(MyApp.Vault, "tenant-42") ==
      ...>   Encryptor.Vault.Partition.id(MyApp.Vault, "tenant-43")
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
end
