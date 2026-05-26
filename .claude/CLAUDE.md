# Claude Code Rules

## Communication Style
- Keep tone professional. No sycophancy—skip phrases like "great idea" or "excellent question."
- Push back on decisions when appropriate. Ask clarifying questions rather than assuming.

## Git Policy
- **Never commit without explicit permission** for each individual commit. Prepare detailed commit messages for approval first.
- **Never push.** User handles all pushes.
- **No authorship attribution.** Do not add "written by Claude Code", "Co-Authored-By: Claude", or similar to commits, comments, or documentation.
- **Brief commit messages.** Conventional-commit subject line, a blank line, then a short body (a few sentences) covering *what* changed and *why*. Don't list affected files — that's `git diff`'s job. Don't restate the subject in the body. Default to brevity; only substantial features warrant longer bodies.
- **Run lint before proposing a commit.** At minimum run `golangci-lint run` (for Go changes) and/or `pnpm lint` (for TS changes) and fix all issues before asking the user to approve. The pre-commit hook will catch failures anyway, but catching them early avoids wasted time.

## Development Practices
- **Test-driven development (TDD).** Write tests before implementation.
- **>90% code coverage required.** Code is not considered working without unit tests meeting this threshold.
- Tests define the spec; implementation fulfills the spec.
- **Zero lint warnings.** Fix all warnings in `pnpm lint` output, even pre-existing ones, unless explicitly told to ignore them.

## Issue Tracking (Beads)

This project uses `bd` (gastownhall/beads, the Go mainline, NOT the Rust fork `br`) with an **embedded Dolt** backend (per-project DB; do not share with other repos).
**Never edit `.beads/issues.jsonl` directly** — it is the auto-export. Always go through `bd`.

Common commands:
```bash
bd show <id>                        # Show issue details
bd list                             # List open issues
bd ready                            # Show issues ready to work (no blockers)
bd close <id> -r "reason"           # Close an issue
bd update <id> --status in_progress # Reserve an issue
bd update <id> --description "..."  # Update description
bd create --title "..." -d "..."    # Create new issue
bd dep add <issue> <depends-on>     # Add a dependency
```

### Dolt sync on reserve/complete

Whenever you **reserve** (claim / move to `in_progress`) or **complete** (close)
a card, bracket the write with a Dolt pull and push so the remote stays in
sync with other clones working on this repo:

```bash
bd dolt pull                       # rebase any other-clone changes
bd update <id> --status in_progress  # or:  bd close <id> -r "..."
bd dolt push                       # publish the change
```

Same pattern for creating + immediately reserving a new card. This is for the
Dolt issue-tracker remote only; it has no relationship to `git push` (which
the user handles separately for code changes).

The injected "Beads Issue Tracker" section in the root `CLAUDE.md` came from
`bd init` and includes generic "MANDATORY: git push" language. That language
does NOT apply here — see "Git Policy" above ("Never push. User handles all
pushes."). The dolt push/pull rule in this file is the project-specific
truth.

If bd errors with "Database out of sync", run `bd dolt pull` first.

## Converter Requirements
- **HDF CLI integration required.** Converters are not considered fully implemented until integrated into hdf-cli.
- Each converter must have both:
  1. Converter implementation and tests in `hdf-converters/converters/{name}/{typescript,go}/`
  2. CLI integration in `hdf-cli/cmd/hdf/cmd/converter_{name}.go` with corresponding tests
- Spot check converter output via CLI before committing: `hdf convert {from} to {to} input.json output.{ext}`

## Destructive Git Operations — HARD RULES

These rules exist because filter-repo nearly destroyed this repo on 2026-03-15.

- **NEVER use `commit.skip()` in git filter-repo.** It drops tree state — files added by skipped commits are permanently lost. Only use `--replace-text` (content) and `--message-callback` with `return message` (messages).
- **NEVER run filter-repo more than once.** Plan ALL replacements in a single pass. Multiple passes compound damage and create stale objects that break pushes.
- **ALWAYS backup before filter-repo.** Use `cp -r` (not `mv`). Verify the backup is intact before proceeding.
- **ALWAYS verify after filter-repo.** Compare file lists against the backup: `diff <(git ls-tree -r branch --name-only | sort) <(git -C backup ls-tree -r branch --name-only | sort)`. If file counts don't match, STOP and restore.
- **NEVER say "looks good" without verification.** Every destructive operation requires a file-count comparison against a known-good baseline.
- **After filter-repo, pushes may fail with "Everything up-to-date."** Fix: delete the remote branch, run `git gc --prune=now`, push fresh. If still failing, use `--verbose` flag or push via a different branch name.
- **When the user says SLOW DOWN, stop everything.** Verify the current state before taking any further action.
- **Research before guessing.** Especially with filter-repo, LFS, and force-push interactions. Do not chain fix-on-top-of-fix.

## Fixture Integrity
- **Never fabricate fixture data.** Every converter fixture must be either:
  1. Real tool output from an actual run or public CI pipeline
  2. Copied/adapted from heimdall2 (`~/repos/heimdall2/libs/hdf-converters/test/sample_input_report/`) or SAF CLI (`~/repos/saf/test/sample_data/`)
  3. Validated against the format's official schema (JSON Schema, XSD, etc.) with proof logged in a comment or commit message
- If no real data source exists and no schema exists to validate against, **stop and ask** — do not invent data.
- A converter tested against fabricated fixtures is untrusted. The fixture determines whether the converter works on real data; if the fixture is fake, the test proves nothing.
