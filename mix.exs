defmodule Encryptor.MixProject do
  use Mix.Project

  @version "0.1.0"
  @source_url "https://github.com/riddler/encryptor"

  def project do
    [
      app: :encryptor,
      version: @version,
      elixir: "~> 1.18",
      elixirc_paths: elixirc_paths(Mix.env()),
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      name: "Encryptor",
      description:
        "Ergonomic envelope encryption for Elixir - vault module, pluggable key providers, per-tenant keys",
      source_url: @source_url,
      docs: docs(),
      package: package()
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
        "README.md"
      ]
    ]
  end

  defp package do
    [
      name: "encryptor",
      licenses: ["MIT"],
      files: ~w(lib mix.exs README.md LICENSE),
      links: %{
        "GitHub" => @source_url
      }
    ]
  end

  # The quality tooling (ex_quality, credo, dialyxir, excoveralls) and ex_doc
  # are added by the beads that follow this one in the bootstrap stack.
  defp deps do
    [
      {:aws_encryption_sdk, "~> 1.0"}
    ]
  end
end
