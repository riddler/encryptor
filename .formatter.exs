# Used by "mix format"
#
# The test inputs are listed by subdirectory so that the dependencies
# fetched into test/fixtures/hackney1_host/deps are never formatted. The
# fixture's own tracked mix.exs and lib/ are still checked.
[
  inputs: [
    "{mix,.formatter}.exs",
    "{config,lib}/**/*.{ex,exs}",
    "bench/**/*.exs",
    "test/*.{ex,exs}",
    "test/{encryptor,interop,support}/**/*.{ex,exs}",
    "test/fixtures/hackney1_host/mix.exs",
    "test/fixtures/hackney1_host/lib/**/*.{ex,exs}"
  ]
]
