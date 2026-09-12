defmodule Encryptor.Provider.GcpKmsWithoutGothTest do
  @moduledoc """
  ADR-0007 decision 9: the GCP stack is optional, and its absence is detected
  at start rather than at a customer's first write.

  `goth` is present in this repository's own test build - that is what makes
  the bare-name form testable at all - so absence has to be staged. Taking the
  library's `ebin` directory off the code path and purging the module is what
  `Code.ensure_loaded?/1` sees in a build that never fetched it, and it is the
  only honest way to reach the branch from here. The staging is global to the
  node, so this module is `async: false` and restores the path in `on_exit/1`.

  It follows `Encryptor.KdfWithoutArgon2Test`, which stages `:argon2_elixir`
  the same way for the same reason.
  """

  use ExUnit.Case, async: false

  alias Encryptor.GcpKmsCase
  alias Encryptor.Provider.GcpKms

  setup do
    ebin = :goth |> Application.app_dir("ebin") |> String.to_charlist()

    true = :code.del_path(ebin)
    :code.purge(Goth)
    :code.delete(Goth)
    :code.purge(Goth)

    on_exit(fn ->
      true = :code.add_patha(ebin)
      {:module, _module} = Code.ensure_loaded(Goth)
    end)

    refute Code.ensure_loaded?(Goth)

    :ok
  end

  # mutation: check for the token server at first use instead of at start - a
  # deploy with no goth then boots and fails on the first customer write.
  test "refuses to start when the token server's library is absent" do
    assert {:error, {:missing_optional_dependency, :goth}} =
             GcpKms.init(GcpKmsCase.opts(goth: MyApp.Goth))
  end

  # The named-module form does not depend on goth at all, which is what lets a
  # host run its own token server and what lets this suite run without one.
  test "still accepts a named token server module" do
    assert {:ok, _state} = GcpKms.init(GcpKmsCase.opts())
  end
end
