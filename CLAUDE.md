# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## CRITICAL: No "Pre-Existing" Issues — We Own This Code

**There is no such thing as a "pre-existing" issue. If we find it, we fix it. Period.**

- NEVER skip a failing test/coverage gap by saying "that's pre-existing"
- NEVER add `continue-on-error` to mask a real failure
- If a CI step fails, find the root cause and fix it properly
- If coverage is below threshold, write the missing tests
- If code doesn't compile, fix the code
- We own ALL code in this repository — every line, every test, every config

## Project Overview

HDF (Heimdall Data Format) Libraries is a TypeScript monorepo providing a standardized JSON schema for representing security assessment baselines and results across diverse tools and platforms. The project normalizes outputs from vulnerability scanners, compliance checkers, configuration auditors, and cloud security tools into a unified format.

**Key Capabilities:**
- Unified security assessment data model
- Conversion from 30+ security tool formats
- Framework mappings (CCI, NIST 800-53, CIS, CMMC)
- Cryptographic integrity verification
- Multi-language type generation (TypeScript, Go, Python)

**Technology Stack:**
- Node.js 20+ with pnpm 9+ (workspace monorepo)
- TypeScript 5.6+ with strict mode
- Vitest 2.0 for testing
- ESLint 9.0 for linting
- JSON Schema for data validation

## Critical Commands

### Development
```bash
# Install dependencies (from root)
pnpm install

# Build all packages
pnpm build

# Run tests across all packages
pnpm test

# Run tests with coverage
pnpm test:coverage

# Run linting
pnpm lint

# Fix linting issues
pnpm lint:fix

# Clean build artifacts
pnpm clean
```

### Working with Individual Packages
```bash
# Work in a specific package
cd hdf-schema

# Build single package
pnpm build

# Run single package tests
pnpm test

# Watch mode for tests
pnpm test:watch

# Generate types (hdf-schema only)
pnpm generate:types
```

### Testing Requirements
- ALL tests must pass before committing
- Target coverage: 70% minimum (goal: 95% once stable)
- Tests use Vitest with v8 coverage provider
- Test files: `test/**/*.test.ts` or `test/**/*.spec.ts`

## Architecture

### Monorepo Structure
This is a pnpm workspace monorepo with packages in individual `hdf-*` directories at root level (NOT in a `packages/` folder). Workspace configuration in `pnpm-workspace.yaml` uses pattern `hdf-*` to match all packages.

```
hdf-libs/
├── hdf-schema/           # JSON schemas + type generation
├── hdf-mappings/         # Framework mappings (planned)
├── hdf-utilities/        # Generic utilities (planned)
├── hdf-parsers/          # Parse and flatten HDF (planned)
├── hdf-converters/       # Convert 30+ formats to HDF (planned)
├── hdf-generators/       # Generate templates (planned)
├── hdf-validators/       # Validate HDF documents (planned)
├── hdf-integrity/        # Cryptographic integrity (planned)
├── package.json          # Root workspace configuration
├── pnpm-workspace.yaml   # Workspace definition
└── tsconfig.base.json    # Shared TypeScript config
```

### Current Implementation Status

#### hdf-schema (COMPLETE ✅)
- **Purpose**: JSON schemas and multi-language type definitions for HDF
- **Location**: `/hdf-schema`
- **Status**: Library complete with JSON schemas, TypeScript/Python/Go type generation, 100% test coverage
- **Key Files**:
  - `src/schemas/hdf-baseline.json` - Baseline schema (requirements without results)
  - `src/schemas/hdf-results.json` - Results schema (assessments with pass/fail)
  - `test/schema-validation.test.ts` - Schema validation tests (406 tests passing)
- **Generated Types**: TypeScript, Go, Python (via quicktype)
- **Dependencies**: ajv, ajv-formats (runtime); quicktype-core (devDependencies)
- **Coverage**: 95% threshold (actual: 100%)

#### Planned Packages (See Design Docs)

Libraries must be built in this specific order due to dependencies:

1. **hdf-schema** ✅ - JSON schemas + multi-language types (CURRENT)
2. **hdf-mappings** - CCI/NIST/CIS/CMMC framework mappings + Mapping Engine
3. **hdf-utilities** - Generic utilities (XML, CSV, hash operations)
4. **hdf-parsers** - Parse and flatten HDF documents
5. **hdf-converters** - Convert 30+ security tool formats to HDF (depends on hdf-mappings)
6. **hdf-generators** - Generate templates and baseline documents
7. **hdf-validators** - Validate HDF documents against schemas
8. **hdf-integrity** - Cryptographic checksums, amendment chains, digital signatures

**External Dependencies** (not part of hdf-libs):
- `@mitre/inspec-objects` - XCCDF/OVAL → InSpec (separate npm package)
- All HDF ecosystem apps use CCI mappings from hdf-mappings, not mitre/inspec-objects

### TypeScript Configuration
All packages extend `tsconfig.base.json`:
- **Target**: ES2020
- **Module**: ESNext with bundler resolution
- **Strict Mode**: Enabled with all strict flags
- **Key Flags**: `noUncheckedIndexedAccess`, `verbatimModuleSyntax`, `isolatedModules`

### Testing Strategy
- **Framework**: Vitest with Node.js environment
- **Coverage**: V8 provider, HTML/JSON/text reporters
- **Thresholds**: 70% minimum (statements, branches, functions, lines)
- **Test Patterns**: `test/**/*.test.ts`, `test/**/*.spec.ts`
- **Exclusions**: Generated code (`src/generated/**`), type definitions (`src/**/*.d.ts`)

## HDF Schema Types

### HDF Results
Assessment results from running security checks against a target system:
- Target system information (hosts, containers, cloud accounts)
- Evaluated baselines with requirement results
- Pass/fail status for each check
- Statistics and timing data

**Required Fields**: `platform`, `profiles`, `statistics`, `version`

### HDF Baseline
Security requirement definitions without results:
- Requirement metadata (title, description, severity)
- Check and fix instructions
- Framework mappings (NIST, CIS, etc.)
- Dependencies between requirements

**Required Fields**: `name`, `supports`, `controls`, `groups`, `sha256`

## Design Documentation

Planning docs are in the `docs/` directory of this repository:
- **docs/architecture/hdf-v2-document-ecosystem.md**: Full v2 ecosystem architecture
- **docs/architecture/hdf-v2-readers-guide.md**: Narrative guide with walkthroughs
- **docs/design/decisions.md**: Design decisions with research rationale
- **docs/design/developer-guide.md**: Contributor patterns and practices
- **docs/plans/2026-03-14-hdf-v2-ecosystem-plan.md**: Implementation plan with phase cards

## Development Workflow

### Package Development Pattern
1. Create package directory: `hdf-<name>/`
2. Add `package.json` with standard scripts (build, test, lint, clean)
3. Extend `tsconfig.base.json` in local `tsconfig.json`
4. Configure Vitest in `vitest.config.ts`
5. Implement TDD: write tests first, then implementation
6. Ensure 70%+ test coverage (goal: 95%)
7. Run linting and fix all issues before commit

### Type Generation (hdf-schema)
The hdf-schema package uses quicktype to generate types from JSON schemas:
- **Script**: `pnpm generate:types` (to be implemented)
- **Output**: `src/generated/{typescript,go,python}/`
- **Workflow**: Edit JSON schema → regenerate types → update tests

### Integrity Features (hdf-integrity - Planned)
HDF supports 5 trust levels for tamper detection:
- **Level 0**: No integrity protection (default)
- **Level 1**: SHA-256 checksums (`originalChecksum`, `resultsChecksum`)
- **Level 2**: Amendment chain verification (`previousChecksum`)
- **Level 3**: Digital signatures (JWK, PEM, PKCS#11, GPG, passkeys)
- **Level 4**: External audit log (blockchain, timestamp authorities, QLDB)

## Common Patterns

### Schema Validation
```typescript
import Ajv from 'ajv';
import addFormats from 'ajv-formats';
import hdfResultsSchema from '../src/schemas/hdf-results.json';

const ajv = new Ajv({ strict: false, allErrors: true });
addFormats(ajv);
const validate = ajv.compile(hdfResultsSchema);

const isValid = validate(document);
if (!isValid) {
  console.error(validate.errors);
}
```

### Test Structure
```typescript
import { describe, it, expect } from 'vitest';

describe('Feature', () => {
  it('should validate correct input', () => {
    const result = functionUnderTest(validInput);
    expect(result).toBe(expectedOutput);
  });

  it('should reject invalid input', () => {
    const result = functionUnderTest(invalidInput);
    expect(result).toBe(false);
  });
});
```

## Code Quality Standards

### Testing Requirements
- **WE DO NOT COMMIT BROKEN CODE EVER**
- **Write tests FIRST** - Test-driven development (TDD): Red → Green → Refactor
- **95%+ coverage target** - Current minimum 70%, goal is 95% once stable
- **All tests must pass** before committing
- **No compilation errors** - Code must compile cleanly
- **No linting errors** - Run `pnpm lint:fix` before committing
- **No known security vulnerabilities** - Run `pnpm security` before committing. This checks both TS deps (`pnpm audit`) and Go deps (`govulncheck`). If vulnerabilities are discovered, fix them immediately — bump the dependency version or add a pnpm override — even if the vulnerable code is unrelated to the current session's work. The pre-commit hook runs `pnpm check` (lint + test + security) to enforce this automatically.

### Development Principles
- **Single responsibility** - Each library does ONE thing well
- **Zero duplication** - DRY principle across all libraries
- **Type safety** - No `any` types in TypeScript (strict mode enabled)
- **ES modules** - Use `.js` extensions in imports for proper ES module support
- **NEVER use quick fixes** - Always use proper solutions following established patterns
- **Root cause analysis** - For every test failure, determine if it's test, code, or fixture issue
- **Fix the actual problem** - Never test around bugs or failures

### Documentation Standards
- **Document as you go** - Don't defer documentation
- **No TODO comments in code** - Code should be production-ready
- **Session context files** - Create `context-YYYY-MM-DD.md` for each work session in `docs/sessions/`
- **Planning files** - Track todos in `docs/planning/` markdown files
- **Context files contain**: What we're working on, decisions made, progress status, next steps, blockers

## Git Workflow Requirements

- **NEVER use `git add -A` or `git add .`** - Add files individually and explicitly
- **Always run `git status`** first to examine what files have changed
- **Commit signatures**: Use `Authored by: Aaron Lippold<lippold@gmail.com>`
- **NO Claude signatures** in commits (no "Generated with Claude Code" or "Co-Authored-By: Claude")
- **Sign all commits** with `-s` flag: `git commit -s -m "message"`
- **Ask for confirmation before committing** - Show `git status` and proposed commit command
- **Commit frequently** - Every 30-60 minutes of working code
- **Keep commits atomic** - One logical change per commit
- Use conventional commit prefixes: `feat:`, `fix:`, `test:`, `docs:`, `refactor:`, `chore:`

## Project Status & Task Tracking

### Beads Issue Tracker
This project uses Beads (git-backed task tracker) for tracking development:
- **Location**: `.beads/` directory in this repository
- **Development branch**: `hdf-libs-development` (current active branch)
- **Note**: `main` branch only has initial README/LICENSE - all development happens here
- **Commands**: `bd init` (first time), `bd list`, `bd ready`, `bd show <id>`, `bd create`, `bd update`
- **Sync**: `bd sync` to push updates
- **Learn more**: https://github.com/steveyegge/beads

### Current Sprint Status
- **hdf-schema**: COMPLETE ✅ (100% coverage, 406 tests passing)
- **hdf-utilities**: COMPLETE ✅ (100% coverage, peer-reviewed A- grade)
- **hdf-mappings**: COMPLETE ✅ (CCI/NIST skeleton, 100% coverage)
- **v1→v2 converter**: COMPLETE ✅ (TypeScript implementation, 100% coverage)
- **Differential testing framework**: COMPLETE ✅ (TypeScript + Go test utilities)
- **IN PROGRESS**: Go v1-to-v2 converter (hdf-libs-j27)
- **IN PROGRESS**: hdf-cli convert command (hdf-libs-s0m)

### Key Architectural Decisions (from beads comments)
1. **Dual Implementation Strategy**: Maintain both TypeScript (npm) and Go (CLI) converters
   - TypeScript: `hdf-converters` npm package for programmatic use
   - Go: Native converters in `hdf-cli` for security, distribution, UX
   - Differential testing ensures parity between implementations
2. **CLI Pattern**: `hdf convert <src-format> to <dest-format> <input> [output]`
3. **Coverage Standards**: 95% minimum for runtime libraries
4. **TDD Approach**: Write tests first (Red → Green → Refactor)

## Source Repositories

Code is being extracted and refactored from:
- **heimdall2/libs/inspecjs/** - HDF schemas and types
- **heimdall2/libs/hdf-converters/** - Security tool converters and CCI mappings
- **heimdall2/apps/frontend/src/utilities/** - Frontend CCI/NIST utilities (to consolidate)

## Quality Gates

Before any library can be published:
- ✅ All tests passing
- ✅ 95%+ test coverage
- ✅ No linting errors
- ✅ Clean compilation (zero TypeScript errors)
- ✅ README.md with clear examples
- ✅ API documentation generated
- ✅ CHANGELOG.md updated

## Key References

- **Source Material**: Schemas extracted from `heimdall2/libs/inspecjs/schemas/`
- **JSON Schema Spec**: https://json-schema.org/
- **quicktype Docs**: https://quicktype.io/
- **Ajv Validator**: https://ajv.js.org/
- **MITRE HDF Ecosystem**: https://github.com/mitre/hdf-libs

## License

Apache 2.0 - Approved for Public Release; Distribution Unlimited. Case Number 18-3678.
