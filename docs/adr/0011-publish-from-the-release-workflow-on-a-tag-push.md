# ADR-0011: A version tag pushed on the default branch publishes the package from the release workflow, and nobody publishes by hand

Status: proposed

## Context

Until this record, a release of this package was four steps, and only the
last one was a person's. The release prep - the version bump and the
changelog promotion - lands as an ordinary request on a release bead; once
it is merged, the conductor or the session that owns the release bead tags
the merged commit with the new version and pushes the tag (`CLAUDE.md`, the
"Release preps" paragraph and the authority table's release-prep row). The
publish itself, `mix hex.publish`, was the operator's one release step, run
by hand with the operator's own Hex credentials. Cites in
this record to files on `main` were read at `682353e`.

Two things made that last step worth moving. It was the only release step
whose inputs nobody checked by machine: nothing compared the version being
published with the tag, nothing proved the published tree was the tree on
`main`, and nothing ran the gate on that exact tree immediately before the
upload. And it needed a Hex credential wherever the person publishing sat.

CI already has every piece except the upload. `.github/workflows/ci.yml`
provisions the toolchain from `mise.toml` (the "Read the toolchain out of
mise.toml" step and `erlef/setup-beam@v1`), caches `deps` and `_build`, and
runs the full gate by reading `gate.full` out of `.claude/wurk.json` (the
"Full quality gate" step), which is `mix quality` today. `mix.exs` states the
package version once, as `@version`, and `project/0` reads it.

Hex supports an unattended publish: `mix hex.publish --yes` publishes without
a confirmation prompt, and Hex reads the `HEX_API_KEY` environment variable
in place of a logged-in user (`mix help hex.publish`, `mix help hex.config`).

## Decision

1. **The release workflow is `.github/workflows/release.yml`, and a tag push
   is its only trigger.** It runs on a push of a tag matching `v*.*.*` and on
   nothing else: no branch push, no pull request, no `workflow_dispatch`. The
   move to tag-push publishing was ruled by the operator, 2026-10-04; the
   absence of a manual trigger was decided by the conductor under a standing
   consent, 2026-10-03.

2. **Three conditions hold at the tagged commit, or nothing is published.**
   Each is a step of the one job, and each stops the run when it fails:
   - *The tagged commit is on the default branch.* The default branch is read
     from the push event (`github.event.repository.default_branch`), never
     written into the file, fetched by that name, and asked about with
     `git merge-base --is-ancestor` (the steps "Fetch the default branch" and
     "Check the tagged commit is on the default branch"). That branch is
     `main` here.
   - *The tag names the version.* The tag without its leading `v` equals
     `@version` in `mix.exs` at the tagged commit (the step "Check the tag
     names the version in mix.exs").
   - *The full gate is green at the tagged commit.* The toolchain, the cache,
     the dependencies and the gate are provisioned and run exactly as
     `ci.yml` does - its steps are copied, not shared - so the gate is
     `gate.full` from `.claude/wurk.json` (the step "Full quality gate").

   Both checks of the first two conditions run before the toolchain is
   installed. The workflow runs the gate itself rather than looking up CI's
   result for the commit; where the version and the branch are read from, and
   that the toolchain is copied from `ci.yml`, were decided by the conductor
   under a standing consent, 2026-10-03.

3. **A version Hex already shows is reported, never published again.**
   Before the toolchain, the step "Check Hex does not already show this
   version" asks hex.pm's release resource for `encryptor` at the tag's
   version: not found continues, found stops the run with a report, and any
   other answer stops it too. This also makes a re-run of a run that did
   publish stop instead of trying again. Decided by the conductor under a
   standing consent, 2026-10-04.

4. **The registry is Hex, and the key is the `HEX_API_KEY` secret.** The
   step "Publish to Hex" runs `mix hex.publish --yes` with `HEX_API_KEY` set
   from that secret in its own `env:`, and no other step sees it. The secret
   is an organisation secret the operator created and scoped to this
   repository; nothing in the repository holds a key, and no agent or session
   reads, writes or prints one. The workflow's own token is read-only
   (`permissions: contents: read`). Ruled by the operator, 2026-10-04. The
   last step prints the published version's addresses on hex.pm and
   hexdocs.pm.

5. **The docs publish with the package.** `mix hex.publish --yes` builds the
   docs and publishes them with the package, as it does by default, so
   hexdocs.pm keeps every version's documentation. The docs that publish are
   the docs the gate has just built. Decided by the conductor under a
   standing consent, 2026-10-04.

6. **A failed publish is not retried by the workflow.** A run stopped by a
   check or by a red gate publishes nothing, and the tag stands as the record
   of what was attempted: the fix lands on the default branch and the next
   version is tagged; a tag is never moved or pushed again. A run whose
   publish step failed on a registry or network error is re-run once, by
   hand, from the run's page in the Actions tab; a gate that failed is never
   re-run, and a second failure of the publish step is the operator's. One
   run per tag is in progress at a time, and a run in progress is never
   cancelled (`concurrency` on the tag, `cancel-in-progress: false`). Decided
   by the conductor under a standing consent, 2026-10-04.

7. **Nobody publishes by hand.** An agent or a session never runs `mix
   hex.publish` in any form; the release workflow publishes on the tag push
   the release-prep row already allows, and a failed workflow is re-run from
   its Actions page, never worked round by a local publish. `CLAUDE.md`'s
   authority table (the row "a release, `mix hex.publish`") and its "Release
   preps" paragraph say so in the operator's words. Ruled by the operator,
   2026-10-04.

## Consequences

- The tag push is now the release. Pushing a `v*.*.*` tag on a commit of
  the default branch whose `mix.exs` names that version publishes it, with no
  further step, once the gate is green; the tagging rules in `CLAUDE.md` are
  therefore the last human-readable control before Hex.
- A published version stands. Hex lets a new version of an existing package
  be replaced or reverted only within one hour of its publication (`mix help
  hex.publish`, "Reverting a package"), and after that it can only be
  retired (`mix help hex.retire`); none of those is an agent's command. A
  mistake past that hour is fixed by the next version.
- A wrong tag costs seconds, not a release: the branch, version and registry
  checks run before the toolchain is installed.
- The release workflow repeats CI's toolchain and gate steps rather than
  sharing them. A change to how `ci.yml` provisions or runs the gate has to
  be made in both files; the copied steps carry the same comments in each.
- Every release now runs the full gate one more time, on the runner, at the
  tagged commit.
- GitHub starts no workflow for tags when more than three are pushed at once,
  so a tag is pushed in its own `git push`.
- Nothing about the package changes: no file under `lib/` moves, and the
  published artefact is the one `mix hex.publish` built before.
- This record stays proposed until the workflow has published a version of
  this package; it is then verified against that run.

## The contract as typespecs

None. This record decides how the package reaches Hex, not anything the
package exposes; no module, function or type changes.

## Worked example: releasing 0.7.0

A release prep moves `@version` in `mix.exs` from `"0.6.0"` to `"0.7.0"` and
promotes the changelog, and is merged to `main`. The session that owns the
release bead tags the merged commit `v0.7.0` and pushes that one tag.

The push starts the release workflow on `v0.7.0`. The checkout has full
history; `main` is fetched by the name the push event gives; the tagged
commit is an ancestor of `origin/main`, so the branch check passes; `0.7.0`
equals `@version`, so the version check passes; hex.pm does not show
`encryptor` 0.7.0, so the registry check passes. The toolchain is read out
of `mise.toml`, the dependencies are fetched, and `mix quality` runs green.
`mix hex.publish --yes` publishes the package and its docs with the
`HEX_API_KEY` secret, and the run prints
`https://hex.pm/packages/encryptor/0.7.0` and
`https://hexdocs.pm/encryptor/0.7.0`.

Had the prep not been merged when the tag was pushed, the branch check
would have stopped the run before the toolchain, and nothing would have
been published. Had the tag been `v0.7.1` on the same commit, the version
check would have. Had the gate been red, the run would have stopped there;
the fix lands on `main` and `v0.7.1` is prepared and tagged.

## Open questions

None the record leaves open. The first publish through the workflow is the
first time its steps from the toolchain on run on a tag; that run is the
evidence this record is verified against before it is accepted.
