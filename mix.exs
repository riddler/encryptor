defmodule Encryptor.MixProject do
  use Mix.Project

  @version "0.3.0"
  @source_url "https://github.com/riddler/encryptor"

  def project do
    [
      app: :encryptor,
      version: @version,
      elixir: "~> 1.18",
      elixirc_paths: elixirc_paths(Mix.env()),
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      # ADR-0003 amendment B decision 5: a compile warning about an optional
      # module is exactly the warning an optional dependency is supposed to
      # produce, and exactly the one that trains a reader to ignore warnings.
      # `Encryptor.Kdf.slow_hash/3` checks for the module at runtime instead,
      # and so does `Encryptor.Provider.Kms.init/1` for the engine's shipped
      # KMS client - which the engine itself compiles only when the host has
      # added `:ex_aws_kms` (ADR-0008 decision 9).
      xref: [exclude: [Argon2.Base, AwsEncryptionSdk.Keyring.KmsClient.ExAws, Goth]],
      name: "Encryptor",
      description:
        "Ergonomic envelope encryption for Elixir - vault module, pluggable key providers, per-tenant keys",
      source_url: @source_url,
      docs: docs(),
      package: package(),
      test_coverage: [tool: ExCoveralls],
      dialyzer: [plt_add_apps: [:ex_unit]],
      preferred_cli_env: [
        coveralls: :test,
        "coveralls.detail": :test,
        "coveralls.html": :test
      ]
    ]
  end

  def application do
    [
      extra_applications: [:logger]
    ]
  end

  defp elixirc_paths(:test), do: ["lib", "test/support"]
  defp elixirc_paths(_), do: ["lib"]

  # Hexdocs configuration. These paths are read off the publisher's disk at
  # `mix docs` time and need no entry in package()'s files: list - the docs
  # tarball hexdocs hosts is built separately from the package tarball
  # `mix deps.get` fetches.
  defp docs do
    [
      name: "Encryptor",
      source_ref: "v#{@version}",
      canonical: "https://hexdocs.pm/encryptor",
      source_url: @source_url,
      main: "readme",
      extras: [
        "README.md",
        "guides/getting-started.md",
        "guides/secrets-at-start.md",
        "guides/selector-boundaries.md",
        "guides/rotation-runbook.md",
        "CHANGELOG.md"
      ],
      groups_for_extras: [
        Guides: ~r{^guides/}
      ],
      skip_undefined_reference_warnings_on: ["CHANGELOG.md"]
    ]
  end

  defp package do
    [
      name: "encryptor",
      licenses: ["Apache-2.0"],
      files: ~w(lib mix.exs README.md LICENSE CHANGELOG.md),
      links: %{
        "GitHub" => @source_url,
        "Changelog" => "#{@source_url}/blob/main/CHANGELOG.md"
      }
    ]
  end

  defp deps do
    [
      {:aws_encryption_sdk, "~> 1.0"},

      # Optional: only a host whose vaults declare `:slow_hash` carries the
      # NIF (ADR-0003 amendment B decision 5).
      {:argon2_elixir, "~> 4.0", optional: true},

      # Optional: only a host running `Encryptor.Provider.GcpKms` carries a
      # token server for Application Default Credentials (ADR-0007 decision
      # 9). The HTTP client is deliberately not a dependency at all - the
      # provider takes the host's own module, because this package will not
      # pick between finch, req and hackney for a host that already runs one.
      {:goth, "~> 1.4", optional: true},

      # Dev / test
      {:ex_quality, "~> 0.14", only: :dev, runtime: false},
      {:credo, "~> 1.7", only: [:dev, :test], runtime: false},
      {:dialyxir, "~> 1.4", only: [:dev, :test], runtime: false},
      {:excoveralls, "~> 0.18", only: :test},
      {:ex_doc, "~> 0.40", only: :dev, runtime: false}
    ]
  end
end
