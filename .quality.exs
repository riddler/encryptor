# Quality configuration for encryptor.
#
#   mix quality                 - full gate: format, compile, credo, dialyzer,
#                                 deps audit, full test suite with coverage.
#                                 Run before every commit.
#
#   mix quality --profile loop  - inner loop while implementing: skips dialyzer
#                                 and coverage, runs only the tests covering
#                                 changed code. Use between edits.
#
# Agents: prefer `--format json --report -` when you want to route on results.
#
# Deliberately smaller than statifier-ex's gate. That repo's custom stages -
# the gate guard, the ADR guard and judge, the regression ratchet - all exist
# to protect a conformance corpus and an accepted ADR set this package does
# not have. "Corpus" there means a body of recorded fixture cases a ratchet
# can hold a pass/fail baseline over; the provider conformance SUITE this
# package does run - Encryptor.Provider.Conformance in
# lib/encryptor/provider/conformance.ex, which every provider test `use`s -
# is a different thing: properties compiled into the ordinary test run, with
# no recorded case list for a ratchet to count. Adopting any of them here is
# a decision to record when there is something for it to protect, not a
# default to inherit.
#
# There is deliberately no .credo.exs either: credo's own defaults under
# --strict are the gate until this package has a reason to deviate from one.
#
# Recorded deviation from the satellite shape - coveralls.json carries
# "treat_no_relevant_lines_as_covered": true on top of the shared
# minimum_coverage: 90. Six modules here carry no executable lines at all, so
# excoveralls records zero relevant lines for each of them: lib/encryptor.ex
# is a moduledoc-only namespace module, and lib/encryptor/envelope/wrapped_key.ex,
# lib/encryptor/key.ex, lib/encryptor/key/aes.ex, lib/encryptor/key/kms.ex and
# lib/encryptor/message/info.ex declare structs and types only. Without the
# flag excoveralls reports each of those as 0.0% - a false "uncovered" reading
# for a file with nothing to cover.
#
# The flag is NOT what keeps the gate green: minimum_coverage is checked
# against the run total, and that total is 97.1% with the flag on or off
# (measured 2026-09-13 under enc-xr1; the full gate passes the 90% floor
# either way). It is kept for the honesty of the per-file table, not to clear
# the bar, and the condition it covers is structural rather than a stage the
# package grows out of. Carried from the same deviation statifier_blocks
# recorded under sb-p6s.

[
  format: [
    check: true
  ],
  compile: [
    warnings_as_errors: true
  ],
  credo: [
    strict: true
  ],
  profiles: [
    loop: [
      stages: [:format, :compile, :credo, :test],
      test: [scope: :changed, coverage: false]
    ]
  ]
]
