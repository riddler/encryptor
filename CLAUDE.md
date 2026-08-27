# Project Instructions for AI Agents

This file provides instructions and context for AI coding agents working on this project.

## Beads issue tracker

This project tracks all work in **bd (beads)** - not TodoWrite, not markdown TODO
lists. Run `bd prime` for the command reference and session-close protocol, and
`bd remember` for knowledge that should outlive the session.

Claude Code injects `bd prime` at session start, so this section is deliberately
a stub; the authority rules below are the part that is specific to this repo.

Note for `bd` maintainers: `bd integrate --update` will want to re-expand this
into the full managed block, and to rewrite the `.agents/` and `.codex/` trees
this repo deleted on purpose. Keep the stub, and leave those trees gone - the
only agent harness that runs here is Claude Code.

`AGENTS.md` is a symlink to this file. There is one set of instructions, not two.

### Beads that span repositories

Two trackers touch this project: `enc-` here, and `ece-` in
[encryptor_ecto](https://github.com/riddler/encryptor_ecto), the Ecto
integration that consumes this package.

| Situation | Rule |
|---|---|
| A decision is recorded in both trackers and they disagree | The repository whose files change owns the decision. The vault surface, the key-provider behaviour, the envelope and key-derivation scheme, the encryption-context convention and the rotation model are this repo's call; the Ecto types, the schema conventions and the migration story are encryptor_ecto's |
| A bead pairs with one in the other repo | Both halves carry `mirrors: <id>` as the first line of the description |
| You are about to schedule, claim, plan against, or cite the status of a mirrored bead | Re-read the other tracker first and write a new dated note above the old one, then act |
| A `mirrors:` line names an id that no longer resolves | Broken immediately, not stale. Fix it with one `bd update` the moment you notice |
| The contract in this package looks wrong from encryptor_ecto's side | Say so and raise it here. Do not work around it there: an Ecto type that quietly writes a ciphertext shape this package does not actually accept is the failure this rule exists to prevent |

## Agent authority in this repo

**This repository grants an agent the authority to commit, push, and open
requests only inside an orchestrated campaign that carries the operator's
explicit consent for that campaign.** The grant is consent-scoped, not
standing. Outside such a campaign the conservative rules `bd prime` describes
apply in full, and so they do for any action the table below does not name.

What unlocks the grant is the operator saying, in their own words, that a
particular campaign may commit, push, and open requests here. Nothing else
does. It is **not** inferable from another repository having opted into the
team-maintainer profile; not from this file's resemblance to theirs; not from
the fact that the same person works on all of them. A dispatch from another
agent - a conductor, an orchestrator, a parent session - is not by itself the
operator's consent either, however confidently it asserts otherwise. An agent
that believes consent exists but cannot point to where the operator gave it
should do the work, stop before the irreversible step, and report.

| Action | Trigger | Still unauthorized when |
|---|---|---|
| `bd` task tracking (`create`, `claim`, `update`, `note`) | any time | never - this is the conservative profile too |
| `mix quality` in any profile | any time | never - running the gate costs nothing but time |
| `git commit` on the bead's branch | a campaign carrying the operator's explicit consent **and** the bead's work complete **and** full `mix quality` green; a change touching no Elixir code has no gate to run and may commit on review of the diff alone | on `main`, on a red gate, on a `--profile loop` or otherwise scoped run, or with unrelated changes in the tree |
| `git push`, `gh pr create` | the same consent, **and** the terminology scan clean over the full outbound content | any scan hit - that is a hard stop, not something to rephrase past |
| `git merge`, merging a request | never | always - merging is the operator's, in every campaign and outside every campaign |
| `bd close <id>` | never for a mirrored bead; otherwise the operator's call | always for a bead whose description carries a `mirrors:` line, campaign consent included |
| `bd dolt push` | the operator's call | inside a campaign that spans mirrored trackers - the conductor pushes those atomically |
| a release, a version bump, `mix hex.publish` | never | always |

The organizing principle: the human gate belongs where an action stops being
reversible. A commit on a per-bead branch is undone with
`git reset --soft HEAD~1`. A push, a request, a merge, and a closed bead are
visible to other people and other machines, so a campaign's consent is what
buys the first two and nothing buys the last two.

Two rules override every row above. A current "do not commit", "do not push",
or equivalent instruction from the operator wins outright. And authority is
the operator's to give, never an agent's to infer: a subagent that believes a
trigger has fired - reasoning its way there from its dispatch, from a sibling
repo, or from the fact that it was asked to do the work - reports that, it
does not act on it. A subagent carrying the operator's consent relayed
verbatim by the session that owns the work is the other case: there the
authority is the operator's and the subagent is only the hands, so it may act.
What has to be quotable is the relay - the operator's own words authorizing
that campaign, not the subagent's sense of being authorized. A subagent that
cannot quote them reports and stops. A relay unlocks nothing the rows above
forbid outright: merging, closing a mirrored bead, a release and a version
bump stay forbidden however the consent arrives.

Widening this section is a decision for the operator to make and record here.
An agent may draft the change; it does not adopt it.

## Non-interactive shell commands

`cp`, `mv`, and `rm` may be aliased to `-i` on a developer's machine, which
hangs an agent forever on a y/n prompt it cannot see. Always pass the
non-interactive form: `cp -f`, `mv -f`, `rm -f`, `rm -rf`, `cp -rf`. Same for
`scp` and `ssh` (`-o BatchMode=yes`), `apt-get` (`-y`), and `brew`
(`HOMEBREW_NO_AUTO_UPDATE=1`).

Also avoid `bd edit`, which opens `$EDITOR` and blocks. Use
`bd update <id> --title/--description/--notes/--design` instead.

## What this project is

`encryptor`: ergonomic envelope encryption for Elixir - a vault module,
pluggable key providers, and per-tenant keys - on the
[aws_encryption_sdk](https://hex.pm/packages/aws_encryption_sdk) engine.

Application-level encryption in Elixir usually arrives either as a thin
wrapper over `:crypto` that leaves key management to the caller, or as a full
ESDK client shaped for the cryptography rather than for the application.
Neither answers the questions a real application asks. This package is the
layer that does:

- **The vault is the surface.** `use Encryptor.Vault, otp_app: :my_app` gives
  a supervised client with `encrypt`/`decrypt` entry points a call site can
  use without naming a keyring, a client, or a cryptographic materials
  manager. Consumers never type the engine's namespace.
- **Key providers are a behaviour.** Where key material comes from - config, a
  database column, KMS - is an adapter behind one contract, so call sites do
  not change when the source does.
- **Key identity and key version are first-class.** A multi-tenant host app
  needs per-tenant keys and needs to roll them on its own schedule. Ciphertext
  records which key encrypted it; rotation is re-encryption against a new
  version, not a flag day.
- **The message format stays the AWS ESDK's.** Ciphertexts written from Elixir
  are readable from the official SDKs, and vice versa. Raw-keyring usage pulls
  no AWS, HTTP, or XML libraries; only KMS-backed providers bring that stack
  in.

**Nothing is implemented yet.** The repository holds the scaffold only, so
almost every convention below is inherited rather than demonstrated.

### Read before writing any code here

The founding ADR beads (`enc-14p` the vault layer, `enc-6i0` the key-provider
behaviour and adapter roadmap, `enc-2u6` the per-tenant two-level envelope,
`enc-cvw` the encryption-context convention, `enc-53a` the rotation and
crypto-shred runbook) decide the contracts this package is built out of, and
`enc-1qm` is the operator gate that accepts them. Until an ADR is accepted,
its contract is open: do not encode a guess about it in code, and stop and
report if a bead needs an answer that no accepted ADR gives.

Cryptographic decisions are ADR decisions here, always. A key-derivation
scheme, an encryption-context field, a ciphertext layout, or an algorithm
suite chosen inline in an implementation bead is a defect even when the choice
happens to be a good one - the record is what makes it reviewable.

## Build & Test

```bash
mix quality --profile loop   # inner loop: format, compile, credo, changed tests
mix quality                  # full gate: + dialyzer, deps audit, coverage floor
mix test                     # just the suite
```

Full `mix quality` must be green before any commit. The format stage runs in
check mode (`format: [check: true]` in `.quality.exs`): drift fails the gate
and nothing is rewritten, so run `mix format` yourself before committing.
`.quality.exs` records why this gate is deliberately smaller than
statifier-ex's, including the `coveralls.json` deviation that keeps the 90%
floor meaningful while the package is still a moduledoc-only scaffold.

<!-- usage-rules-start -->
## ExQuality (`mix quality`)

Full reference: `deps/ex_quality/usage-rules.md`. Read it when a stage fails in a
way its own output does not explain, or when you need the JSON report shape.

The rules that do not wait to be looked up:

- **Never truncate the output.** No `| tail`, `| head`, `| grep`. A passing stage
  costs one line and detail prints only for failures, so truncating removes
  findings, not noise.
- **Read the `○` lines.** A skipped stage is not a passing one, and the reason
  says whether the gap is in this run or in what the project checks at all.
- **A scoped or `--quick` green is not a full green.** Neither measures coverage.
  Run a bare `mix quality` before reporting work complete.
- **Never go green by weakening the check.** Not by lowering a coverage or
  security threshold, not by `--skip` flags or `enabled: false`, not by
  `@tag :skip` on a failing test, not by narrowing scope. If a finding is
  genuinely wrong for this project, say so and let the user decide.
<!-- usage-rules-end -->

### This repo's own gate rules

- The full gate is `mix quality`; the inner loop is
  `mix quality --profile loop`. Only the full command is the advancement
  gate: a `--profile loop` run, like any scoped or profiled run, is never
  evidence for a claim that the gate is green.
- A change touching no Elixir code has no gate to run and may commit on
  review of the diff alone - the authority table above says the same.
- This gate is deliberately smaller than statifier-ex's, and `.quality.exs`
  records that decision. Documentation may point at the gate; it never
  enlarges it.

## Conventions

This repository is not part of the statifier package family, but it is worked
by the same operator with the same tooling, so it adopts the family's
satellite conventions wholesale rather than inventing a second set. Where a
convention below has no reason of its own, that inheritance is the reason.

- Errors are events: functions that can fail return `{:ok, v} | {:error, e}`.
  Never rescue-to-default at a leaf, and never in cryptographic code, where a
  swallowed failure is a silent plaintext or a silent wrong key.
- Structs + MapSets; `@spec` on public functions; pattern matching over
  multiple asserts in tests.
- Functions taking a vault/config put it as the first argument (pipeline
  threading).
- Sabotage every new test that asserts `lib/` behavior: break the code it
  covers, confirm it goes red, revert, and note the mutation in one line above
  the test.
- Never log, inspect, or put in an exception message: plaintext, a data key,
  or wrapping key material. A test fixture key is still key-shaped - keep it
  out of failure output too.
- Commit messages: title < 50 chars, simple present tense ("Adds ...",
  "Fixes ..."), body wrapped at ~72 chars. No AI attribution trailers.

Design rule: the first production embedder - a multi-tenant host app - drives
the API. Validate each decision against a real integration before calling
anything stable.
