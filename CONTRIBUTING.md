# Contributing to HDF Libraries

## Project scope

HDF Libraries is a **data format and converter library**. Its purpose is to define the HDF schema, provide converters that normalize security tool outputs into HDF format, and offer utilities for working with HDF documents.

Contributions should align with the library's core purpose: **schema definitions, format converters, parsing utilities, validation, and CLI tooling.** New scanner converters are especially welcome.

Features beyond data format and conversion — such as application-level capabilities — are built by downstream projects that consume hdf-libs. If you're unsure whether your idea fits this repo, open a discussion first and we'll help find the right home for it.

## Getting started

1. Fork the repository on GitHub and clone your fork.

2. Install the required tools — see [Prerequisites](./README.md#prerequisites) in the root README.

3. Install npm dependencies and build all packages:

   ```bash
   pnpm install
   pnpm build
   ```

4. Verify everything works before making changes:

   ```bash
   pnpm test
   pnpm lint
   ```

## Development workflow

- Create a branch from `main` for your change.
- Write tests before implementation — this project follows test-driven development.
- Run `pnpm build && pnpm test` before opening a PR. All tests must pass.
- Run `pnpm lint` and resolve any new warnings.

## Code coverage

Coverage is enforced at **90% minimum** across all packages. Tests that drop below threshold will fail in CI. Check your coverage before submitting:

```bash
pnpm test:coverage
```

## Pull requests

- Target `main`.
- Keep PRs focused — one feature or fix per PR.
- Include a clear description of what the change does and why.
- Tests must pass and coverage must meet the threshold before review.

## Adding a converter

Converters require dual implementations (TypeScript and Go) plus CLI integration. A converter is not considered complete until it is wired into `hdf-cli`.

See **[CONVERTER_GUIDE.md](./hdf-converters/CONVERTER_GUIDE.md)** for the full step-by-step process. The short version:

1. Implement the TypeScript converter in `hdf-converters/converters/{tool}/typescript/`
2. Add test fixtures in `hdf-converters/converters/{tool}/fixtures/`
3. Port to Go in `hdf-converters/converters/{tool}/go/`
4. Add CLI integration in `hdf-cli/cmd/hdf/cmd/converter_{tool}.go`
5. Add tests for both implementations; test fixtures live in `hdf-converters/converters/{tool}/fixtures/`.

Spot-check the converter output via the CLI before submitting:

```bash
hdf convert {from} to {to} input.json output.json
```

## Questions

Open an issue or start a discussion on GitHub.
