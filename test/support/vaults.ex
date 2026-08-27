defmodule Encryptor.TestVaults do
  @moduledoc """
  Vault modules the configuration tests resolve against.

  These stand in for what the `use Encryptor.Vault` macro will generate. They
  exist only to exercise layer 5 of the precedence chain - the optional
  `init/1` callback - which `Encryptor.Vault.Config.resolve/4` reads by
  `function_exported?/3` rather than by any behaviour.
  """

  defmodule NoInit do
    @moduledoc "A vault module that exports no `init/1`."
  end

  defmodule WithInit do
    @moduledoc "A vault whose `init/1` supplies what config files must not hold."

    @doc "Layer 5: replaces the merged list, as ADR-0001 decision 5 specifies."
    def init(config) do
      {:ok, Keyword.put(config, :provider, {Encryptor.TestVaults.Provider, key: "from-init"})}
    end
  end

  defmodule ReplacingInit do
    @moduledoc "A vault whose `init/1` builds a fresh list instead of adding to the one it was handed."

    @doc "Returns a complete-looking configuration that names no package default."
    def init(_config) do
      {:ok,
       [
         provider: {Encryptor.TestVaults.Provider, key: "only"},
         context_profile: :single
       ]}
    end
  end

  defmodule EchoInit do
    @moduledoc "A vault whose `init/1` reports one value out of the list it was handed."

    @doc "Records the EDK limit layer 1 seeded, so the seed is observable."
    def init(config) do
      seen = config |> Keyword.get(:max_encrypted_data_keys, "absent") |> to_string()

      {:ok, Keyword.put(config, :static_encryption_context, %{"seen" => seen})}
    end
  end

  defmodule BadInit do
    @moduledoc "A vault whose `init/1` breaks the `{:ok, keyword}` contract."

    @doc "Returns the wrong shape on purpose."
    def init(_config), do: :not_ok
  end

  defmodule Frozen do
    @moduledoc "A vault used only as a `:persistent_term` key."
  end

  defmodule Provider do
    @moduledoc "A stand-in provider module. Only its name is read here."
  end
end
