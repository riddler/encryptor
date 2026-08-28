defmodule Encryptor.Kdf do
  @moduledoc """
  HKDF-SHA256 key derivation: the one place this package expands a key into a
  labelled subkey.

  This module is the primitive underneath ADR-0003 decisions 6 and 7. It holds
  no state, reads no configuration, touches no vault, and depends on nothing
  but `:crypto`. Everything above it - the root vault's wrapping material, the
  tenant reference subkey, and any purpose-separated subkey of a tenant master
  key - is a call into `derive_subkey/3` with a different purpose.

  ## Expand only on the wrapping trees, and why

  RFC 5869 splits HKDF into `extract` (condense arbitrary, possibly biased
  input keying material into a pseudorandom key) and `expand` (stretch a
  pseudorandom key into labelled output). Both are implemented here, and they
  are not used on the same trees.

  `"encryptor/v1/root-wrap"` and `"encryptor/v1/tenant-ref"` are **expand
  only**, because every input those two derive from is already a uniformly
  random key of at least 256 bits:

    * the root key material is supplied to the host vault's `init/1` as
      deployment-supplied key material (ADR-0001 decision 5), and
    * a tenant master key is 32 bytes from the CSPRNG, generated once and
      never derived (ADR-0003 decision 1).

  RFC 5869 section 3.3 names exactly this case - "if the input key material is
  already a good pseudorandom key" - as the one where the extract step may be
  skipped. Both accepted records say `HKDF-Expand` rather than `HKDF`, and
  those two trees implement what they say. Salting them would change the root
  vault's provider material and every stored `tenant_ref`, which is a rewrap
  of every stored wrapping and a re-index of every stored row.

  The 32-byte guard on the pseudorandom key is what makes that reasoning
  enforceable rather than aspirational: a caller cannot expand from a short
  or low-entropy input by accident.

  ## The salted tree

  ADR-0003 amendment A (proposed, 2026-08-28) adds `extract/2` and one tree
  that uses it: the derived-subkey surface a downstream consumer reaches
  through `Encryptor.Vault.derive/3`. Its output leaves this package, so it
  is salted with a per-deployment value that the consumer cannot supply, and
  two deployments provisioned from the same tenant key material derive
  unrelated subkeys.

  `salted_subkey/5` is that whole construction, and it is deliberately three
  steps rather than two:

      PRK         = HKDF-Extract(salt, key_material)
      purpose_key = HKDF-Expand(PRK, "encryptor/v1/<purpose>", 32)
      derived     = HKDF-Expand(purpose_key, caller_info, length)

  The label and the caller's `info` are never concatenated into one expansion,
  because purpose `"a"` with info `"b"` and purpose `"ab"` with info `""`
  would spell the same string, and that collision is the label reuse ADR-0003
  decision 6 forbids. The nesting is unambiguous: the purpose is consumed by a
  whole expansion before the caller's info is read.

  The final expansion always runs, including when `info` is `""`. That costs
  one HMAC and keeps `purpose_key` from ever leaving the package: every byte
  a caller receives is one expansion further from the tree's root than
  anything held internally.

  ## The label grammar

  Every derivation in this package is labelled, and the label is composed
  here rather than at the call site:

      "encryptor/" <> version <> "/" <> purpose

  The version is currently `v1`. `label/1` is the only thing that writes that
  prefix, so a caller supplies the purpose - `"root-wrap"`, `"tenant-ref"` -
  and cannot spell the namespace differently by hand.

  ADR-0003 decision 6 fixes two purposes and reserves the rest of the space:

  | Label | Use | Record |
  |---|---|---|
  | `"encryptor/v1/root-wrap"` | the root vault's `Static` provider material | ADR-0003 d6 |
  | `"encryptor/v1/tenant-ref"` | the keyed tenant reference derivation | ADR-0003 d5, d6 |
  | `"encryptor/v1/blind-index"` | downstream index keys, through `Encryptor.Vault.derive/3` | ADR-0003 d7, amendment A |

  **The reservation is one-way.** Any future purpose-separated key takes a
  *new* `"encryptor/v<n>/<purpose>"` label and never reuses an existing one
  (ADR-0003 decision 6). Reusing a label to mean a second thing is what
  silently collapses two keys that the design says are independent.

  One use is deliberately unlabelled: a tenant master key is used *directly*
  as `RawAes` material on the encryption path. That use predates and defines
  the key, and labelling it would invalidate every stored ciphertext
  (ADR-0003 decision 7).

  ## What domain separation buys, and what it does not

  HKDF-Expand with distinct `info` strings under one pseudorandom key yields
  outputs that are computationally independent: an adversary holding one
  derived subkey learns nothing usable about another, and cannot recover the
  key they were expanded from. Three guarantees follow, and they are the
  reason the labels exist:

    * **Independent lifecycles.** The wrapping subkey can be replaced by a
      rewrap pass while every stored `tenant_ref` stays valid, because the two
      are separate expansions of the same material (ADR-0003 decision 6).
    * **No cross-purpose reuse.** A subkey derived for one purpose is not the
      key any other purpose uses, so a component handed one of them cannot
      perform the other's operation with it.
    * **Shred semantics are inherited, not weakened.** A derived subkey is
      never stored; it is recomputed on demand from the key it was expanded
      from. Destroying that key destroys every subkey of it (ADR-0003
      decision 7).

  What it does **not** buy is capability separation. Deriving a subkey
  requires the key it is expanded from, so a component that can derive a
  tenant's index key necessarily holds that tenant's master key and can
  therefore also decrypt. ADR-0003 decision 7 states this plainly and holds
  the door open for independently wrapped, independently stored keys if a
  genuine search-only capability is ever wanted. Nothing in this module
  provides one.

  ## Nested derivation

  `expand/3` takes the `info` string verbatim, which is what lets a consumer
  derive *within* a purpose it was given. A downstream package that owns a
  purpose-separated key tree derives its own key under this package's label
  first, then expands again under its own info string:

      index_key = Encryptor.Kdf.derive_subkey(tenant_master_key, "blind-index")
      field_key = Encryptor.Kdf.expand(index_key, downstream_info, 32)

  Both steps are HKDF-Expand and the outer label stays this package's, so the
  reservation above still holds over the whole tree. What the inner `info`
  string is, and what it identifies, belongs to whichever package owns that
  tree; this module only makes the nesting expressible.

  ## Why these functions raise rather than return `{:error, _}`

  The package convention is that a function which can fail returns
  `{:ok, value} | {:error, %Encryptor.Error{}}`. Nothing here can fail at
  runtime. A too-short key, an empty purpose, a purpose containing the
  separator, an output length past the RFC bound: each is a caller-supplied
  constant that is wrong in the source, not an event that happens to a correct
  program. ADR-0003's contract agrees - `root_subkey/2` and `subkey/2` are
  specified returning a bare `binary()`, with no error half to return into.

  Every raised message names the constraint and never the value, because a
  key-length violation is the one place a raise could otherwise put key
  material into a log line or a test failure report.

  Records: ADR-0003 decisions 5, 6, 7 and amendment A. RFC 5869 sections 2.2,
  2.3 and 3.3.
  """

  # RFC 5869 with SHA-256: HashLen is 32, and L may not exceed 255 * HashLen.
  @hash_length 32
  @max_length 255 * @hash_length

  # ADR-0003 decision 6's label grammar. `@label_version` moves only when a
  # record says a new version of the whole label space exists; it is never
  # bumped to re-mint one purpose.
  @label_namespace "encryptor"
  @label_version "v1"

  @typedoc """
  The purpose half of a label, as ADR-0003 decision 6 spells them:
  `"root-wrap"`, `"tenant-ref"`, or a new purpose a later record adds.

  A purpose is the part a caller supplies. The `"encryptor/v1/"` prefix is
  `label/1`'s, never a caller's.
  """
  @type purpose :: String.t()

  @doc """
  Composes the full label for a purpose.

  This is the only place the `"encryptor/v1/"` prefix is written. ADR-0003
  decision 6 states the two fixed labels in full; the worked example in the
  same record calls the derivation with the purpose alone. Composing here is
  what makes both readings true at once.

      iex> Encryptor.Kdf.label("root-wrap")
      "encryptor/v1/root-wrap"

      iex> Encryptor.Kdf.label("tenant-ref")
      "encryptor/v1/tenant-ref"

  A purpose must be a non-empty binary and must not contain the separator,
  because a purpose carrying a `/` could spell an existing label from a
  different starting point and defeat the reservation:

      iex> Encryptor.Kdf.label("v1/root-wrap")
      ** (ArgumentError) a derivation purpose may not contain "/"

      iex> Encryptor.Kdf.label("")
      ** (ArgumentError) a derivation purpose may not be empty
  """
  @spec label(purpose()) :: String.t()
  def label(purpose) when is_binary(purpose) do
    if purpose == "" do
      raise ArgumentError, "a derivation purpose may not be empty"
    end

    if String.contains?(purpose, "/") do
      raise ArgumentError, ~s(a derivation purpose may not contain "/")
    end

    @label_namespace <> "/" <> @label_version <> "/" <> purpose
  end

  @doc """
  Derives a labelled subkey from key material.

  This is ADR-0003 decision 6's root subkey expansion and decision 7's
  purpose-separated tenant subkey expansion - one operation, called with a
  different purpose and different material. The default length is 32 bytes,
  which is what both decisions specify.

      iex> root = :binary.copy(<<0x0B>>, 32)
      iex> byte_size(Encryptor.Kdf.derive_subkey(root, "root-wrap"))
      32

  Distinct purposes yield unrelated subkeys from the same material:

      iex> root = :binary.copy(<<0x0B>>, 32)
      iex> Encryptor.Kdf.derive_subkey(root, "root-wrap") == Encryptor.Kdf.derive_subkey(root, "tenant-ref")
      false

  The same purpose and material always yield the same subkey, which is what
  makes a derived key recomputable rather than stored:

      iex> root = :binary.copy(<<0x0B>>, 32)
      iex> Encryptor.Kdf.derive_subkey(root, "tenant-ref") == Encryptor.Kdf.derive_subkey(root, "tenant-ref")
      true

  Key material shorter than 32 bytes is refused here rather than one call
  further down, so the message names the argument the caller actually passed:

      iex> Encryptor.Kdf.derive_subkey(:binary.copy(<<0>>, 16), "root-wrap")
      ** (ArgumentError) key material for a labelled derivation must be at least 32 bytes
  """
  @spec derive_subkey(binary(), purpose(), pos_integer()) :: binary()
  def derive_subkey(key_material, purpose, length \\ @hash_length)
      when is_binary(key_material) do
    if byte_size(key_material) < @hash_length do
      raise ArgumentError,
            "key material for a labelled derivation must be at least #{@hash_length} bytes"
    end

    expand(key_material, label(purpose), length)
  end

  @doc """
  HKDF-Expand with SHA-256, per RFC 5869 section 2.3.

  `prk` is a pseudorandom key of at least 32 bytes - see the "Expand only"
  section of the moduledoc for why that guard is the security argument rather
  than a convenience. `info` is used verbatim; `derive_subkey/3` is the way to
  get this package's label grammar applied to it.

      iex> prk = Base.decode16!("077709362C2E32DF0DDC3F0DC47BBA6390B6C73BB50F9C3122EC844AD7C2B3E5")
      iex> Encryptor.Kdf.expand(prk, Base.decode16!("F0F1F2F3F4F5F6F7F8F9"), 42) |> Base.encode16(case: :lower)
      "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"

  `length` is bounded at `255 * 32` bytes by the construction itself; a
  request above that has no defined output and raises.

      iex> Encryptor.Kdf.expand(:binary.copy(<<0>>, 32), "info", 8161)
      ** (ArgumentError) HKDF-SHA256 cannot expand more than 8160 bytes, or fewer than one

      iex> Encryptor.Kdf.expand(:binary.copy(<<0>>, 31), "info")
      ** (ArgumentError) a pseudorandom key must be at least 32 bytes
  """
  @spec expand(binary(), binary(), pos_integer()) :: binary()
  def expand(prk, info, length \\ @hash_length)
      when is_binary(prk) and is_binary(info) and is_integer(length) do
    if byte_size(prk) < @hash_length do
      raise ArgumentError, "a pseudorandom key must be at least #{@hash_length} bytes"
    end

    if length < 1 or length > @max_length do
      raise ArgumentError,
            "HKDF-SHA256 cannot expand more than #{@max_length} bytes, or fewer than one"
    end

    blocks = div(length + @hash_length - 1, @hash_length)

    prk
    |> okm(info, blocks)
    |> binary_part(0, length)
  end

  @doc """
  HKDF-Extract with SHA-256, per RFC 5869 section 2.2.

  `PRK = HMAC-SHA256(salt, ikm)`: the salt is the HMAC key and the input key
  material is the message, which is the way round that trips people up.

  This is the unguarded primitive. It accepts any salt length, including the
  empty salt, because RFC 5869 does and because that is what makes the RFC's
  own appendix A vectors runnable against this function rather than against a
  reimplementation of it. The 32-byte deployment guard belongs to
  `salted_subkey/5` and to `Encryptor.Vault.Config`, which is where a salt
  stops being an HKDF argument and starts being configuration.

  RFC 5869 appendix A.1, the basic SHA-256 case:

      iex> ikm = :binary.copy(<<0x0B>>, 22)
      iex> salt = Base.decode16!("000102030405060708090A0B0C")
      iex> Encryptor.Kdf.extract(salt, ikm) |> Base.encode16(case: :lower)
      "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"

  Appendix A.3, with an empty salt - the case the RFC defines as `HashLen`
  zero bytes:

      iex> ikm = :binary.copy(<<0x0B>>, 22)
      iex> Encryptor.Kdf.extract("", ikm) |> Base.encode16(case: :lower)
      "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04"

  The output is always 32 bytes, which is `HashLen` for SHA-256 and therefore
  a valid pseudorandom key for `expand/3` without any further check.
  """
  @spec extract(binary(), binary()) :: binary()
  def extract(salt, ikm) when is_binary(salt) and is_binary(ikm) do
    :crypto.mac(:hmac, :sha256, salt, ikm)
  end

  @doc """
  The salted derived-subkey construction of ADR-0003 amendment A.

  Extract under the deployment's salt, expand once under this package's label
  for `purpose`, then expand again under the caller's `info` for `length`
  bytes. The moduledoc's "The salted tree" section says why it is three steps
  and not two, and why the middle value never leaves the package.

  This is the only derivation in the package that takes a salt, and the only
  one whose output is handed to a caller outside it.

      iex> master = :binary.copy(<<0x0B>>, 32)
      iex> salt = :binary.copy(<<0x5A>>, 32)
      iex> byte_size(Encryptor.Kdf.salted_subkey(master, salt, "blind-index", "orders.email", 32))
      32

  A different salt is a different deployment, and the same scope derives an
  unrelated key under it:

      iex> master = :binary.copy(<<0x0B>>, 32)
      iex> a = Encryptor.Kdf.salted_subkey(master, :binary.copy(<<0x5A>>, 32), "blind-index", "orders.email", 32)
      iex> b = Encryptor.Kdf.salted_subkey(master, :binary.copy(<<0x5B>>, 32), "blind-index", "orders.email", 32)
      iex> a == b
      false

  An empty `info` is a scope like any other, not a missing argument, and it
  does not yield the intermediate purpose key:

      iex> master = :binary.copy(<<0x0B>>, 32)
      iex> salt = :binary.copy(<<0x5A>>, 32)
      iex> derived = Encryptor.Kdf.salted_subkey(master, salt, "blind-index", "", 32)
      iex> purpose_key = Encryptor.Kdf.expand(Encryptor.Kdf.extract(salt, master), "encryptor/v1/blind-index", 32)
      iex> derived == purpose_key
      false

  A salt short enough to be a placeholder rather than a deployment constant is
  refused here, where the constraint is this package's rather than the RFC's:

      iex> Encryptor.Kdf.salted_subkey(:binary.copy(<<0x0B>>, 32), :binary.copy(<<0x5A>>, 31), "blind-index", "", 32)
      ** (ArgumentError) a derivation salt must be at least 32 bytes
  """
  @spec salted_subkey(binary(), binary(), purpose(), binary(), pos_integer()) :: binary()
  def salted_subkey(key_material, salt, purpose, info, length \\ @hash_length)
      when is_binary(key_material) and is_binary(salt) and is_binary(info) do
    if byte_size(key_material) < @hash_length do
      raise ArgumentError,
            "key material for a labelled derivation must be at least #{@hash_length} bytes"
    end

    if byte_size(salt) < @hash_length do
      raise ArgumentError, "a derivation salt must be at least #{@hash_length} bytes"
    end

    salt
    |> extract(key_material)
    |> expand(label(purpose), @hash_length)
    |> expand(info, length)
  end

  # T(1) | T(2) | ... | T(n), where T(0) is empty and
  # T(i) = HMAC-SHA256(prk, T(i - 1) | info | i). RFC 5869 section 2.3.
  @spec okm(binary(), binary(), pos_integer()) :: binary()
  defp okm(prk, info, blocks) do
    {_last, output} =
      Enum.reduce(1..blocks, {<<>>, <<>>}, fn counter, {previous, acc} ->
        block = :crypto.mac(:hmac, :sha256, prk, <<previous::binary, info::binary, counter>>)
        {block, <<acc::binary, block::binary>>}
      end)

    output
  end
end
