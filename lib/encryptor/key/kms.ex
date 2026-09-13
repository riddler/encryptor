defmodule Encryptor.Key.Kms do
  @moduledoc """
  An AWS KMS key, referenced by id, with the client that reaches it.

  The second and last member of the descriptor set. AWS KMS is the only key
  manager other than raw AES material that the engine can dispatch on as a
  keyring, which is why it gets a descriptor of its own rather than being
  reduced to bytes like every other remote key manager.

      %Encryptor.Key.Kms{
        key_id: "arn:aws:kms:us-east-1:111122223333:key/abcd1234",
        client: client
      }

  ## The three fields

    * `:key_id` - the key id or ARN, as AWS spells it. Required, and on this
      path it is the version identity: the ARN, not a name this package mints
      (ADR-0008 decision 3).
    * `:mrk` - whether the key is a multi-region key. Defaults to `false`, and
      it is what selects between the single-region and multi-region keyrings.
    * `:client` - the engine's KMS client struct, built once in the provider's
      `c:Encryptor.Provider.init/1` and copied onto every descriptor the
      provider answers with. Defaults to `nil`, which the vault's keyring
      builder refuses with `{:missing_client, Encryptor.Key.Kms}`.

  `:client` is not enforced, because the struct shipped at 0.2.0 without it
  and enforcing a new key would break a host that had built one by hand. It
  is redacted from `inspect/2` for the reason `:material` is on the AES
  descriptor: the engine's shipped client carries a free-form `config`
  keyword, which is where a static access key id and secret conventionally
  live, and a descriptor reaches an `Encryptor.Error`'s `:engine` field on
  some paths (ADR-0008 decision 2).

  ## What this descriptor does not have

  No `namespace` and no `name`. On the keyring-backed path this package writes
  no header field at all: the engine writes the provider id `"aws-kms"` and
  the key ARN into the encrypted data key itself. A field that never reached a
  header would be a field two readers would disagree about.

  The consequences are not cosmetic, and ADR-0008 decision 4's table is where
  they are reconciled. Two of them matter most: dropping a `%Encryptor.Key.Kms{}`
  from a candidate list is **not** a crypto-shred - it hides the data from
  this vault while KMS can still decrypt it, and the shred is
  `ScheduleKeyDeletion` on the key - and a vault whose provider answers this
  descriptor has no two-level envelope, so `Encryptor.Vault.derive/3` and
  `Encryptor.Envelope` are unavailable on it.

  Records: ADR-0002 decisions 3 and 5; ADR-0008 decisions 1, 2, 3 and 4.
  """

  @type t :: %__MODULE__{
          key_id: String.t(),
          mrk: boolean(),
          client: struct() | nil
        }

  @derive {Inspect, except: [:client]}
  @enforce_keys [:key_id]
  defstruct [:key_id, :client, mrk: false]
end
