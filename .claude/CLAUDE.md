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

## Fixture Integrity
- **Never fabricate fixture data.** Every converter fixture must be either:
  1. Real tool output from an actual run or public CI pipeline
  2. Copied/adapted from heimdall2 (`~/repos/heimdall2/libs/hdf-converters/test/sample_input_report/`) or SAF CLI (`~/repos/saf/test/sample_data/`)
  3. Validated against the format's official schema (JSON Schema, XSD, etc.) with proof logged in a comment or commit message
- If no real data source exists and no schema exists to validate against, **stop and ask** — do not invent data.
- A converter tested against fabricated fixtures is untrusted. The fixture determines whether the converter works on real data; if the fixture is fake, the test proves nothing.
