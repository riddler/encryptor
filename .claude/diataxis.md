---
# The docs manifest the documentation tools read. Generated from the family's manifest
# table: change a key there and regenerate. The two prose lines below may be sharpened.
product: encryptor
family: foundation
audience: Elixir developers who encrypt data before it reaches the database
tone: "plain, second person, no marketing"
terminology:
  use:
    - execution
    - chart
    - document
    - revision
  avoid:
    - "run (noun)"
    - workflow instance
example_world: none
docs_root: docs
quadrants:
  tutorials: docs/tutorials
  how_to: guides
  reference: docs/reference
  explanation: docs/explanation
readme: README.md
reference_generator: ex_doc
publish: hexdocs
contributor_paths:
  - docs/adr
  - docs/plans
  - docs/spikes
  - docs/research
  - docs/design
  - docs/measurements
  - CLAUDE.md
executed_snippets:
  - test/guides_test.exs
  - test/secrets_at_start_test.exs
readme_max_lines: 250
---

Application-layer encryption for Elixir: a vault, key providers, envelopes, rotation.
Examples are domain-free: a foundation package teaches no domain.
