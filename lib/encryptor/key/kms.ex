defmodule Encryptor.Key.Kms do
  @moduledoc """
  An AWS KMS key, referenced by id.

  The second and last member of the descriptor set. AWS KMS is the only key
  manager other than raw AES material that the engine can dispatch on as a
  keyring, which is why it gets a descriptor of its own rather than being
  reduced to bytes like every other remote key manager.

      %Encryptor.Key.Kms{key_id: "arn:aws:kms:us-east-1:111122223333:key/abcd1234"}

  ## The two fields

    * `:key_id` - the key id or ARN, as AWS spells it. Required.
    * `:mrk` - whether the key is a multi-region key. Defaults to `false`, and
      it is what selects between the single-region and multi-region keyrings.

  ## The keyring mapping is not here yet

  This struct is the closed set's second member and it ships with the set, so
  that the set is closed from the day it exists rather than being widened
  later. Turning one into an engine keyring - one of the engine's AWS KMS
  keyrings, against a client built once in the provider's `init/1` - ships
  with the KMS key provider, which ADR-0002 decision 5 sequences after the
  per-tenant envelope, because a KMS key per tenant is a cost and quota
  decision the envelope record has to make first.

  Until then the vault-internal keyring builder recognizes this struct and
  declines it, which is a different answer from the one an unrecognized term
  gets. Nothing can produce one in the meantime: the KMS provider is the only
  adapter that returns it.

  Records: ADR-0002 decisions 3 and 5.
  """

  @type t :: %__MODULE__{
          key_id: String.t(),
          mrk: boolean()
        }

  @enforce_keys [:key_id]
  defstruct [:key_id, mrk: false]
end
