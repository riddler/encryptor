defmodule Encryptor.Message.Info do
  @moduledoc """
  What a message says about itself.

  Every field is read from the message header without verifying the header
  authentication tag, because verification needs the data key. Treat this as
  an unverified claim. It is for support tooling and migrations; it is never
  an authorization input.

  ## Why this is a struct and not a map

  ADR-0004 decision 12 asks for a named struct rather than a bare map so the
  value reads as a claim rather than as a fact at every call site that holds
  one. A `%Encryptor.Message.Info{}` in a stack trace, a log line, or an
  `IO.inspect/1` names the module whose documentation says the contents are
  unauthenticated; `%{encryption_context: ...}` names nothing.

  ## What it does not contain

  No key material, and nothing that could hold any. The message id, the header
  authentication tag, the frame length, the header IV, and the encrypted data
  key ciphertexts are all in the header this struct is built from, and none of
  them is carried here: the fields are exactly the four ADR-0004 decision 12
  fixes, because the safety argument for exposing this surface at all is that
  it discloses nothing an operator could not already read - not that it
  discloses everything they could.

  The `key_name` in each entry of `encrypted_data_keys` is the wrapping key's
  name, which under ADR-0003 decision 5 is a keyed derivation and not a tenant
  identifier. It is a pseudonym, and `Encryptor.Message.describe/1`'s
  documentation says what that buys.

  Records: ADR-0004 decision 12; ADR-0001 open question 1 as answered there.
  """

  @typedoc """
  One encrypted data key, as the header names it: which provider wrapped the
  data key, and under which of that provider's key names.

  Only the identifying pair is carried. The wrapped ciphertext is in the
  header and is deliberately not here.
  """
  @type edk :: %{provider_id: String.t(), key_name: String.t()}

  @typedoc """
  The stored encryption context: the header's additional authenticated data,
  as ADR-0004 spells the type - string keys, string values.
  """
  @type context :: %{optional(String.t()) => String.t()}

  @type t :: %__MODULE__{
          encryption_context: context(),
          algorithm_suite_id: non_neg_integer(),
          committed?: boolean(),
          encrypted_data_keys: [edk()]
        }

  @enforce_keys [:encryption_context, :algorithm_suite_id, :committed?, :encrypted_data_keys]
  defstruct @enforce_keys
end
