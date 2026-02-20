# Claude Code Rules

## Communication Style
- Keep tone professional. No sycophancy—skip phrases like "great idea" or "excellent question."
- Push back on decisions when appropriate. Ask clarifying questions rather than assuming.

## Git Policy
- **Never commit without explicit permission** for each individual commit. Prepare detailed commit messages for approval first.
- **Never push.** User handles all pushes.
- **No authorship attribution.** Do not add "written by Claude Code", "Co-Authored-By: Claude", or similar to commits, comments, or documentation.

## Development Practices
- **Test-driven development (TDD).** Write tests before implementation.
- **>90% code coverage required.** Code is not considered working without unit tests meeting this threshold.
- Tests define the spec; implementation fulfills the spec.

## Issue Tracking (Beads)

Use `bd` CLI commands to interact with beads. **Never edit `.beads/issues.jsonl` directly.**

Common commands:
```bash
bd show <id>                        # Show issue details
bd list                             # List open issues
bd close <id> -r "reason"           # Close an issue
bd update <id> --status in_progress # Update status
bd update <id> -d "description"     # Update description
bd create --title "..." -d "..."    # Create new issue
```

If bd errors with "Database out of sync", run `bd sync --import-only` first.
If bd errors with "LEGACY DATABASE DETECTED", run `bd migrate --update-repo-id` first.

## Converter Requirements
- **HDF CLI integration required.** Converters are not considered fully implemented until integrated into hdf-cli.
- Each converter must have both:
  1. Converter implementation and tests in `hdf-converters/converters/{name}/{typescript,go}/`
  2. CLI integration in `hdf-cli/cmd/hdf/cmd/converter_{name}.go` with corresponding tests
- Spot check converter output via CLI before committing: `hdf convert {from} to {to} input.json output.{ext}`
