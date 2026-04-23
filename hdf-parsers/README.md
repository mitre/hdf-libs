# @mitre/hdf-parsers

Parse and load Heimdall Data Format (HDF) documents with validation. Provides a simple, type-safe API for reading HDF Results and Baselines from JSON with automatic schema validation.

## Scope and Responsibilities

**hdf-parsers** provides validated parsing of HDF documents:
- Parse HDF Results and Baseline documents from JSON
- Automatic schema validation via hdf-validators
- Auto-detection of document type (Results vs Baseline)
- Type-safe output using hdf-schema types
- Detailed error reporting with validation messages
- Support for both TypeScript and Go implementations

### hdf-parsers vs. hdf-validators

| hdf-parsers | hdf-validators |
|-------------|----------------|
| Parse JSON → typed objects | Validate JSON against schema |
| "Load and validate this HDF file" | "Is this valid HDF?" |
| Returns typed HdfResults/HdfBaseline | Returns validation errors |
| One-step parse + validate | Schema validation only |
| Used by CLI commands and tools | Used internally by parsers |

**Example:**
- `validateResults(data)` → `{ valid: true, errors: [] }` (validators - just validates)
- `parseResults(json)` → `{ success: true, data: HdfResults }` (parsers - validates AND parses)

## Installation

```bash
npm install @mitre/hdf-parsers
```

## Usage

### TypeScript

```typescript
import { parseResults, parseBaseline, parse } from '@mitre/hdf-parsers';

// Parse HDF Results
const json = '{"baselines":[...],"targets":[],"statistics":{}}';
const result = parseResults(json);

if (result.success) {
  console.log('Parsed HDF Results:', result.data);
  console.log('Number of baselines:', result.data.baselines?.length);
} else {
  console.error('Parse failed:', result.error);
}
```

```typescript
// Parse HDF Baseline
const baselineJson = '{"name":"My Baseline","requirements":[...],...}';
const baselineResult = parseBaseline(baselineJson);

if (baselineResult.success) {
  console.log('Baseline name:', baselineResult.data.name);
  console.log('Requirements:', baselineResult.data.requirements.length);
}
```

```typescript
// Auto-detect document type
const unknownJson = '...'; // Could be Results or Baseline
const autoResult = parse(unknownJson);

if (autoResult.success) {
  console.log('Document type:', autoResult.type); // "results" or "baseline"
  console.log('Parsed data:', autoResult.data);
}
```

```typescript
// Parse from Uint8Array (e.g., file reads)
import { readFileSync } from 'fs';

const bytes = readFileSync('scan-results.json');
const result = parseResults(bytes);
```

### Go

```go
package main

import (
	"fmt"
	"os"

	parsers "github.com/mitre/hdf-libs/hdf-parsers/go"
)

func main() {
	// Read HDF file
	data, err := os.ReadFile("results.json")
	if err != nil {
		panic(err)
	}

	// Parse HDF Results
	result := parsers.ParseResults(data)

	if result.Success {
		fmt.Println("✓ Parsed HDF Results")
		fmt.Printf("Baselines: %d\n", len(result.Data.Baselines))
	} else {
		fmt.Println("✗ Parse failed:")
		fmt.Println(result.Error)
		os.Exit(1)
	}
}
```

```go
// Parse HDF Baseline
result := parsers.ParseBaseline(baselineData)

if result.Success {
	fmt.Println("Baseline name:", result.Data.Name)
	fmt.Printf("Requirements: %d\n", len(result.Data.Requirements))
}
```

```go
// Auto-detect document type
result := parsers.Parse(data)

if result.Success {
	fmt.Println("Document type:", result.Type) // "results" or "baseline"
}
```

## API Reference

### TypeScript

#### `parseResults(input: string | Uint8Array): ParseResult<HdfResults>`

Parse HDF Results document from JSON string or bytes.

- **Parameters:**
  - `input` - JSON string or Uint8Array to parse
- **Returns:** `ParseResult<HdfResults>` with parsed data or error

#### `parseBaseline(input: string | Uint8Array): ParseResult<HdfBaseline>`

Parse HDF Baseline document from JSON string or bytes.

- **Parameters:**
  - `input` - JSON string or Uint8Array to parse
- **Returns:** `ParseResult<HdfBaseline>` with parsed data or error

#### `parse(input: string | Uint8Array): ParseResult<HdfResults | HdfBaseline>`

Parse HDF document with auto-detection of type (Results vs Baseline).

- **Parameters:**
  - `input` - JSON string or Uint8Array to parse
- **Returns:** `ParseResult` with parsed data, type indicator, or error

#### `ParseResult<T>`

```typescript
interface ParseResult<T> {
  success: boolean;           // True if parsing succeeded
  data?: T;                   // Parsed data (undefined if failed)
  error?: string;             // Error message (undefined if succeeded)
  type?: 'results' | 'baseline';  // Document type (only for parse())
}
```

### Go

#### `ParseResults(input []byte) ResultsParseResult`

Parse HDF Results document from JSON bytes.

- **Parameters:**
  - `input` - JSON bytes to parse
- **Returns:** `ResultsParseResult` with parsed data or error

#### `ParseBaseline(input []byte) BaselineParseResult`

Parse HDF Baseline document from JSON bytes.

- **Parameters:**
  - `input` - JSON bytes to parse
- **Returns:** `BaselineParseResult` with parsed data or error

#### `Parse(input []byte) ParseResult`

Parse HDF document with auto-detection of type.

- **Parameters:**
  - `input` - JSON bytes to parse
- **Returns:** `ParseResult` with parsed data, type indicator, or error

#### Parse Result Types

```go
type ResultsParseResult struct {
    Success bool            `json:"success"`
    Data    *hdf.HDFResults `json:"data,omitempty"`
    Error   string          `json:"error,omitempty"`
}

type BaselineParseResult struct {
    Success bool             `json:"success"`
    Data    *hdf.HDFBaseline `json:"data,omitempty"`
    Error   string           `json:"error,omitempty"`
}

type ParseResult struct {
    Success bool        `json:"success"`
    Data    interface{} `json:"data,omitempty"`
    Error   string      `json:"error,omitempty"`
    Type    string      `json:"type,omitempty"` // "results" or "baseline"
}
```

## Common Parse Errors

### Invalid JSON Syntax

```
error: "Invalid JSON: Unexpected token } in JSON at position 42"
```

Ensure the input is valid JSON. Check for:
- Missing or extra commas
- Unquoted property names
- Trailing commas in objects/arrays

### Schema Validation Failure

```
error: "Schema validation failed: baselines: is required"
```

The JSON is valid but doesn't match the HDF schema. Common issues:
- Missing required fields (baselines, name, requirements)
- Wrong field types (string instead of number)
- Invalid enum values (status must be passed/failed/error/etc.)

### Empty Input

```
error: "Input is empty"
```

Provide non-empty JSON content.

### Trailing Data

```
error: "Invalid JSON: unexpected trailing data after end of object"
```

The JSON has extra characters after the closing brace. Remove any trailing content.

## Use Cases

### CLI Commands

Parse HDF files for CLI operations:

```typescript
import { parseResults } from '@mitre/hdf-parsers';
import { readFileSync } from 'fs';

const data = readFileSync(inputFile, 'utf-8');
const result = parseResults(data);

if (!result.success) {
  console.error(`Failed to parse ${inputFile}: ${result.error}`);
  process.exit(1);
}

// Process the validated HDF data
processResults(result.data);
```

### Converter Input Validation

Validate HDF input before conversion:

```typescript
import { parseResults } from '@mitre/hdf-parsers';

export function convertHdfToCsv(hdfJson: string): string {
  const result = parseResults(hdfJson);

  if (!result.success) {
    throw new Error(`Invalid HDF input: ${result.error}`);
  }

  // Convert validated data
  return buildCsv(result.data);
}
```

### HTTP API Endpoints

Parse and validate HDF uploads:

```typescript
app.post('/api/upload', async (req, res) => {
  const result = parseResults(req.body);

  if (!result.success) {
    return res.status(400).json({
      error: 'Invalid HDF document',
      details: result.error
    });
  }

  // Store validated HDF data
  await storeResults(result.data);
  res.json({ success: true });
});
```

### Type-Safe Processing

Get type-safe HDF objects:

```typescript
import { parseResults } from '@mitre/hdf-parsers';
import type { HdfResults } from '@mitre/hdf-schema';

function processResults(data: HdfResults) {
  // TypeScript knows the exact structure
  for (const baseline of data.baselines ?? []) {
    console.log(`Baseline: ${baseline.name}`);

    for (const req of baseline.requirements ?? []) {
      console.log(`  Requirement ${req.id}: ${req.results?.length ?? 0} results`);
    }
  }
}

const result = parseResults(jsonData);
if (result.success) {
  processResults(result.data); // Type-safe!
}
```

## Error Handling Best Practices

### Always Check success Flag

```typescript
const result = parseResults(data);

if (!result.success) {
  // Handle error - data is undefined here
  console.error(result.error);
  return;
}

// TypeScript knows data exists here
console.log(result.data.baselines);
```

### Provide User-Friendly Error Messages

```typescript
const result = parseResults(userInput);

if (!result.success) {
  if (result.error.includes('JSON')) {
    console.error('File contains invalid JSON syntax');
  } else if (result.error.includes('Schema validation')) {
    console.error('File does not match HDF format');
  } else {
    console.error('Failed to parse HDF file');
  }

  console.error('Details:', result.error);
}
```

### Log Validation Errors for Debugging

```typescript
import { parseResults } from '@mitre/hdf-parsers';
import { validateResults } from '@mitre/hdf-validators';

// For detailed debugging, use validator directly
const validationResult = validateResults(jsonData);

if (!validationResult.valid) {
  console.error('Validation errors:');
  for (const error of validationResult.errors) {
    console.error(`  ${error.field}: ${error.message}`);
  }
}

// For normal use, parser is simpler
const parseResult = parseResults(jsonData);
```

## Development

```bash
# Install dependencies
pnpm install

# Run TypeScript tests
pnpm test:ts

# Run Go tests
pnpm test:go

# Run all tests
pnpm test

# Run tests with coverage
pnpm test:coverage

# Build TypeScript package
pnpm build

# Lint code
pnpm lint
```

## Test Coverage

Both TypeScript and Go implementations maintain **>95% test coverage** with comprehensive parsing tests. Run `pnpm test:coverage` to view current coverage report.

## License

Apache-2.0 © MITRE Corporation
