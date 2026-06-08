# Converter Implementation Guide

## Overview

HDF converters are maintained in **dual implementations**: TypeScript and Go.

- **TypeScript**: For npm package (`@mitre/hdf-converters`) used by web apps and Node.js tools
- **Go**: For CLI (`hdf-cli`) - single binary, no runtime dependencies, better security posture

## Why Dual Implementations?

**Security**: Go eliminates Node.js attack surface (~30MB runtime + npm supply chain)
**Distribution**: CLI users get single binary, no Node.js required
**Flexibility**: TypeScript for programmatic/web use, Go for standalone tool

## Directory Structure

```
converters/
└── {converter-name}/
    ├── typescript/
    │   ├── index.ts           # Public API exports
    │   ├── converter.ts       # Main conversion logic
    │   ├── converter.test.ts  # Unit tests
    │   └── differential.test.ts  # Parity tests vs Go
    ├── go/
    │   ├── converter.go       # Main conversion logic
    │   ├── converter_test.go  # Unit tests
    │   ├── detect.go          # Format detection (optional)
    │   └── types.go           # Input format types
    └── fixtures/
        ├── input/             # Sample tool output
        └── expected/          # Expected HDF output

shared/
├── typescript/    # Shared TypeScript utilities
└── go/           # Shared Go utilities
```

## Adding a New Converter

### 1. Create Directory Structure

```bash
mkdir -p converters/{tool-name}/{typescript,go,fixtures/{input,expected}}
```

### 2. TypeScript Implementation

**Start with TypeScript** (it's the reference implementation):

```typescript
// converters/{tool-name}/typescript/converter.ts
import type { ExecutionResult } from '@mitre/hdf-schema';

export function convertToolToHdf(input: string): ExecutionResult {
  const toolData = JSON.parse(input); // or parseXml(input), parseCsv(input)

  return {
    baselines: [
      {
        id: 'tool-scan',
        title: toolData.scan_name,
        requirements: toolData.findings.map(finding => ({
          id: finding.id,
          // ... map fields
        }))
      }
    ],
    targets: [/* ... */],
    statistics: {/* ... */}
  };
}
```

**Key points**:
- Use utilities from `@mitre/hdf-utilities` (parseXml, parseCsv, hashObject, etc.)
- Use mappings from `@mitre/hdf-mappings` (NIST controls, CWE, etc.)
- Import HDF types from `@mitre/hdf-schema`

### 3. Add Test Fixtures

Save real tool output in `fixtures/input/`:
```bash
# Example files
fixtures/input/basic-scan.json
fixtures/input/complex-scan.xml
fixtures/input/empty-results.json
```

Generate expected HDF output in `fixtures/expected/`:
```bash
# Run TypeScript converter to generate
pnpm run convert:fixtures
```

**Fixture location: local vs shared.** Converter fixtures stay in
`converters/{tool-name}/fixtures/` as the converter's *tested contract* —
that's the default. The repo also has a shared workspace package,
`@mitre/hdf-fixtures` (`../hdf-fixtures/`), for fixtures actively consumed
by **two or more workspace packages** (parsers, validators, hdf-extension-
graph, hdf-diff, etc.). The boundary rule:

- **Single-consumer → stays here.** Only your converter loads the file →
  it stays in `converters/{tool-name}/fixtures/`.
- **Multi-consumer → moves to `hdf-fixtures`.** Another workspace package
  starts loading the file → move it to `../hdf-fixtures/`, update your
  converter test to import via `@mitre/hdf-fixtures`, delete the original.
  **No duplicates.**
- **Inclusion bar is strict.** "Might be useful someday" or "good for test
  breadth" doesn't qualify. Promote only when a second active consumer
  materializes.

See `../hdf-fixtures/README.md` for the boundary rule with examples and
the rationale (bead `hdf-libs-e95o`).

### 4. Write Tests

```typescript
// converters/{tool-name}/typescript/converter.test.ts
import { describe, it, expect } from 'vitest';
import { convertToolToHdf } from './converter';
import { readFileSync } from 'fs';
import { join } from 'path';

describe('Tool Converter', () => {
  it('should convert basic scan', () => {
    const input = readFileSync(
      join(__dirname, '../fixtures/input/basic-scan.json'),
      'utf-8'
    );
    const result = convertToolToHdf(input);

    expect(result.baselines).toHaveLength(1);
    expect(result.baselines[0].requirements).toBeDefined();
  });
});
```

### 5. Port to Go

```go
// converters/{tool-name}/go/converter.go
package toolname

import (
    "encoding/json"
    hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
)

func ConvertToHDF(input []byte) (*hdf.ExecutionResult, error) {
    var toolData ToolOutput
    if err := json.Unmarshal(input, &toolData); err != nil {
        return nil, err
    }

    return &hdf.ExecutionResult{
        Baselines: []hdf.Baseline{
            {
                ID:    "tool-scan",
                Title: toolData.ScanName,
                // ... map fields
            },
        },
    }, nil
}
```

### 6. Differential Testing

Ensures TypeScript and Go implementations produce identical output:

```typescript
// converters/{tool-name}/typescript/differential.test.ts
import { describe, it, expect } from 'vitest';
import { convertToolToHdf } from './converter';
import { readFileSync, writeFileSync } from 'fs';
import { join } from 'path';

describe('Differential Tests', () => {
  const fixtures = ['basic-scan', 'complex-scan'];

  fixtures.forEach(fixture => {
    it(`should match expected output: ${fixture}`, () => {
      const input = readFileSync(
        join(__dirname, `../fixtures/input/${fixture}.json`),
        'utf-8'
      );
      const result = convertToolToHdf(input);
      const expected = JSON.parse(
        readFileSync(
          join(__dirname, `../fixtures/expected/${fixture}.json`),
          'utf-8'
        )
      );

      expect(result).toEqual(expected);
    });
  });
});
```

Go differential tests read the same fixtures and compare against expected output.

## Testing Requirements

- **Unit tests**: >90% code coverage for TypeScript and Go
- **Differential tests**: All fixtures must pass in both implementations
- **Real-world data**: Include at least one real tool output sample

## Common Patterns

### Security Tool Output Formats

**XML (Nessus, XCCDF, Nikto)**:
```typescript
import { parseXml, parseXmlWithArrays } from '@mitre/hdf-utilities';

const parsed = parseXmlWithArrays(input, ['ReportItem', 'finding']);
```

**CSV (Prisma)**:
```typescript
import { parseCsv } from '@mitre/hdf-utilities';

const rows = parseCsv<ToolRow>(input);
```

**JSON (most tools)**:
```typescript
import { parseJSON } from '@mitre/hdf-utilities';

const data = parseJSON(input);
```

### NIST Control Mapping

```typescript
import { getNessusNistControl } from '@mitre/hdf-mappings';

const nistControl = getNessusNistControl(pluginFamily, pluginId);
```

### Severity Mapping

```typescript
function mapSeverity(toolSeverity: string): number {
  const map: Record<string, number> = {
    'critical': 1.0,
    'high': 0.7,
    'medium': 0.5,
    'low': 0.3,
    'info': 0.0
  };
  return map[toolSeverity.toLowerCase()] ?? 0.5;
}
```

### Generating IDs

```typescript
import { sha256 } from '@mitre/hdf-utilities';

const requirementId = sha256(`${baselineId}-${finding.id}`);
```

## CI/CD Integration

Tests run automatically on pull requests:
```yaml
- Lint: pnpm lint (TypeScript + Go)
- Build: pnpm build (all packages)
- TypeScript tests: pnpm test (95% coverage required)
- Go tests: go test ./...
- Coverage: Upload to Codecov
```

**Branch protection** on `main` requires all CI checks to pass before merge.

## Tips

1. **Start simple**: Get basic structure working first, then add mappings/enrichment
2. **Use real data**: Test with actual tool output, not synthetic data
3. **Follow the pattern**: Copy structure from `legacyhdf` converter
4. **TypeScript first**: Get TS working and tested before porting to Go
5. **Differential tests catch bugs**: If implementations diverge, tests will fail
6. **Ask for help**: Check existing converters for similar tools

## Reference Implementation

See `converters/legacyhdf/` for complete example with:
- TypeScript converter
- Go converter
- Comprehensive tests
- Multiple fixtures
- Differential testing
