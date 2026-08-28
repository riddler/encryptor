defmodule Encryptor.Envelope.WrappedKey do
  @moduledoc """
  One tenant master key, wrapped, plus the identity a store has to give back.

  This is what `Encryptor.Envelope.provision/3` returns and what
  `Encryptor.Envelope.unwrap/2` and `Encryptor.Envelope.rewrap/2` consume. It
  is the whole of this package's storage contract: `encryptor_ecto` owns the
  table, the migration, the repo and the transaction, and this package owns
  the six fields (ADR-0003 decision 9).

      %Encryptor.Envelope.WrappedKey{
        tenant_ref: "9f2cQ1n5Zk8mMvJ0Yl3xRg",
        version: 1,
        namespace: "encryptor-tenant",
        name: "t/9f2cQ1n5Zk8mMvJ0Yl3xRg/v1",
        bits: 256,
        wrapped: wrapped
      }

  ## The six fields, and why each one has to be stored

  ADR-0003 decision 9 fixes "the minimum a store must be able to give back,
  because a store missing any of it cannot reconstruct a descriptor":

    * `:wrapped` - the wrapping. A complete `Encryptor` message produced by a
      root vault (decision 2), so this package defines no wire format of its
      own. It is the only field that is secret-adjacent, and it is secret only
      in combination with the root key: decision 10's table is explicit that
      the wrapped-key store alone reads nothing.
    * `:tenant_ref` and `:version` - they reproduce the encryption context and
      therefore gate the unwrap (decision 4). A row whose `tenant_ref` has
      been edited does not unwrap; that is the confused-deputy defence, not a
      validation.
    * `:namespace` and `:name` - what the encrypted data key matches on.
      `RawAes.unwrap_key/3` compares the header's provider id to the keyring's
      namespace and the deserialized provider info's key name to the keyring's
      name, so both are part of what a decrypt years from now reproduces
      exactly.
    * `:bits` - always `256` on this path. ADR-0003 decision 1 fixes the size
      at 256 because ADR-0001's suites both use AES-256-GCM for the data key
      "and there is no reason for the wrapping key to be the weaker link",
      even though `%Encryptor.Key.Aes{}` permits 128 and 192 for other
      providers.

  Ordering information - enough to return live versions newest first, per
  ADR-0002 decision 4 - is the store's, not this struct's. So is every other
  column a host wants: soft deletes, shred timestamps, audit trails.

  ## The plaintext is not a field here, and that is the design

  There is no `:material`. ADR-0003 decision 3 is explicit that the plaintext
  key never appears in a return value and that no function in this package
  returns a bare tenant master key as a binary: "the one thing a host is
  likely to do wrong with this API is persist the plaintext key beside the
  wrapping 'for convenience', and an API that never hands it over makes that
  require obvious effort."

  A caller that wants usable material calls `Encryptor.Envelope.unwrap/2`,
  which returns an `%Encryptor.Key.Aes{}` - the descriptor a provider returns
  (ADR-0002 decision 3), whose own `:material` is redacted from `inspect/2`.

  Records: ADR-0003 decisions 1, 3, 4 and 9.
  """

  @typedoc """
  The wrapping key size on this path. Fixed at 256 by ADR-0003 decision 1;
  the wider `t:Encryptor.Key.Aes.bits/0` is for providers this package does
  not mint keys for.
  """
  @type bits :: 256

  @type t :: %__MODULE__{
          tenant_ref: String.t(),
          version: pos_integer(),
          namespace: String.t(),
          name: String.t(),
          bits: bits(),
          wrapped: binary()
        }

  @enforce_keys [:tenant_ref, :version, :namespace, :name, :bits, :wrapped]
  defstruct @enforce_keys
end
