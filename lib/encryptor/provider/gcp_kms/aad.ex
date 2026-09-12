defmodule Encryptor.Provider.GcpKms.Aad do
  @moduledoc false

  # ADR-0007 decision 5: ADR-0003 decision 4's four-pair encryption context,
  # rendered into the single byte string GCP KMS takes as
  # `additionalAuthenticatedData`.
  #
  # The encoding is fixed to the byte because "canonical" is not a
  # specification. Two implementations that both sort and both length-prefix
  # can still disagree on prefix width, on whether key names are included, and
  # on how the integer is rendered - and that disagreement is discovered as a
  # permanent `Decrypt` failure against a key GCP will not let anyone delete.
  #
  #     <<byte_size(k)::unsigned-big-16, k::binary,
  #       byte_size(v)::unsigned-big-32, v::binary>>
  #
  # concatenated over the pairs sorted bytewise ascending by key. Both halves
  # of every pair are included, so a renamed field cannot go unnoticed. The
  # widths differ because the keys are a closed, short set and the values are
  # host-influenced; both are big-endian because every other length in the
  # engine's message format is. No field count is prefixed and none is needed:
  # every field is length-delimited, so the concatenation is unambiguous.
  #
  # ## Why this module is not public
  #
  # ADR-0007 open question 3 records that one caller is not yet a format: if a
  # Vault transit provider ever wants the same bytes, the encoding should be
  # promoted to a package-level format and recorded there. Until then it is
  # this provider's, and `@moduledoc false` is what says so.

  @doc false
  # ADR-0007 decision 5's worked vector is asserted against this function in
  # the provider's tests, so a change to the encoding fails as the format
  # change it is rather than passing as a refactor.
  @spec encode(%{String.t() => String.t()}) :: binary()
  def encode(context) when is_map(context) do
    for {key, value} <- Enum.sort(context), into: <<>> do
      <<byte_size(key)::unsigned-big-16, key::binary, byte_size(value)::unsigned-big-32,
        value::binary>>
    end
  end
end
