defmodule EncryptorTest do
  use ExUnit.Case, async: true

  doctest Encryptor

  test "the package scaffold compiles and the root module is loadable" do
    assert Code.ensure_loaded?(Encryptor)
  end
end
