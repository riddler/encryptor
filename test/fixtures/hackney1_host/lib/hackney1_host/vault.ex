defmodule Hackney1Host.Vault do
  @moduledoc """
  A vault declared on the hackney 1.x stack, so that compiling this host
  expands the vault's `use` against the resolved engine.
  """

  use Encryptor.Vault, otp_app: :hackney1_host
end
