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

## Converter Requirements
- **HDF CLI integration required.** Converters are not considered fully implemented until integrated into hdf-cli.
- Each converter must have both:
  1. Converter implementation and tests in `hdf-converters/converters/{name}/{typescript,go}/`
  2. CLI integration in `hdf-cli/cmd/hdf/cmd/converter_{name}.go` with corresponding tests
- Spot check converter output via CLI before committing: `hdf convert {from} to {to} input.json output.{ext}`
