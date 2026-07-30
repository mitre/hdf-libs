# @mitre/hdf-validators

JSON Schema validation for Heimdall Data Format (HDF) documents. Validates all 7 HDF document types against their official schemas to ensure structural correctness and data integrity.

## Scope and Responsibilities

**hdf-validators** provides schema-based validation:
- Validate all HDF document types: Results, Baseline, System, Plan, Amendments, Evidence Package, Comparison
- Auto-detect document type via the generic `validate()` function
- Detailed error reporting with field-level validation messages
- Support for both TypeScript and Go implementations

### hdf-validators vs. hdf-utilities

| hdf-validators | hdf-utilities |
|----------------|---------------|
| HDF schema validation | Format syntax validation |
| "Is this valid HDF?" | "Is this valid JSON/XML/CSV?" |
| "Does baselines exist and is it an array?" | "Can this string be parsed as JSON?" |
| Validates structure and types | Validates syntax only |
| HDF-specific semantic rules | Generic format handling |

**Example:**
- `isValidJSON('{"foo": "bar"}')` → `true` (utilities - just checks JSON syntax)
- `validateResults({foo: 'bar'})` → `false`, missing baselines field (validators - checks HDF schema)

## Installation

```bash
npm install @mitre/hdf-validators
```

## Usage

### TypeScript

```typescript
import { validateResults, validateBaseline } from '@mitre/hdf-validators';

// Validate HDF Results
const hdfResults = {
  baselines: [{
    name: 'My Baseline',
    checksum: { algorithm: 'sha256', value: 'abc123' },
    requirements: [{
      id: 'REQ-001',
      descriptions: [{ label: 'default', data: 'Test requirement' }],
      impact: 0.7,
      tags: { nist: ['AC-1'] },
      results: [{
        status: 'passed',
        codeDesc: 'Control check',
        startTime: '2025-01-01T00:00:00Z'
      }]
    }]
  }],
  targets: [],
  statistics: {}
};

const result = validateResults(hdfResults);

if (result.valid) {
  console.log('✓ Valid HDF Results document');
} else {
  console.error('✗ Validation failed:');
  console.error(result.getErrorMessage());

  // Or access individual errors
  result.errors.forEach(error => {
    console.error(`  ${error.field}: ${error.message}`);
  });
}
```

```typescript
// Validate HDF Baseline
const hdfBaseline = {
  name: 'Security Baseline',
  title: 'Example Security Baseline',
  version: '1.0.0',
  checksum: { algorithm: 'sha256', value: 'def456' },
  requirements: [{
    id: 'REQ-001',
    title: 'Access Control',
    descriptions: [{ label: 'default', data: 'Requirement description' }],
    impact: 0.7,
    tags: { nist: ['AC-1', 'AC-2'] }
  }]
};

const baselineResult = validateBaseline(hdfBaseline);

if (!baselineResult.valid) {
  console.error('Validation errors:', baselineResult.errors);
}
```

```typescript
// Auto-detect document type
import { validate } from '@mitre/hdf-validators';

const autoResult = validate(someHdfDocument);
// Automatically determines if it's Results or Baseline and validates accordingly
```

### Go

```go
package main

import (
	"encoding/json"
	"fmt"
	"os"

	validators "github.com/mitre/hdf-libs/hdf-validators/go/v3"
)

func main() {
	// Read HDF file
	data, err := os.ReadFile("results.json")
	if err != nil {
		panic(err)
	}

	// Validate HDF Results
	result := validators.ValidateResults(data)

	if result.Valid {
		fmt.Println("✓ Valid HDF Results document")
	} else {
		fmt.Println("✗ Validation failed:")
		fmt.Println(result.Error())

		// Access individual errors
		for _, e := range result.Errors {
			fmt.Printf("  %s: %s\n", e.Field, e.Description)
		}
		os.Exit(1)
	}
}
```

```go
// Validate HDF Baseline
result := validators.ValidateBaseline(baselineData)

// Use custom schema directory (for development/testing)
validators.SetSchemaDir("./custom-schemas")
result = validators.ValidateResults(data) // Will use schemas from custom directory

// Reset to embedded schemas
validators.SetSchemaDir("")
```

## API Reference

### TypeScript

#### `validateResults(data: unknown): ValidationResult`

Validate data against the HDF Results schema.

- **Parameters:**
  - `data` - JavaScript object to validate
- **Returns:** `ValidationResult` with validation status and errors

#### `validateBaseline(data: unknown): ValidationResult`

Validate data against the HDF Baseline schema.

- **Parameters:**
  - `data` - JavaScript object to validate
- **Returns:** `ValidationResult` with validation status and errors

#### `validateComparison(data: unknown): ValidationResult`

Validate data against the HDF Comparison schema.

- **Parameters:**
  - `data` - JavaScript object to validate
- **Returns:** `ValidationResult` with validation status and errors

#### `validateSystem(data: unknown): ValidationResult`

Validate data against the HDF System schema.

- **Parameters:**
  - `data` - JavaScript object to validate
- **Returns:** `ValidationResult` with validation status and errors

#### `validatePlan(data: unknown): ValidationResult`

Validate data against the HDF Plan schema.

- **Parameters:**
  - `data` - JavaScript object to validate
- **Returns:** `ValidationResult` with validation status and errors

#### `validateAmendments(data: unknown): ValidationResult`

Validate data against the HDF Amendments schema.

- **Parameters:**
  - `data` - JavaScript object to validate
- **Returns:** `ValidationResult` with validation status and errors

#### `validateEvidencePackage(data: unknown): ValidationResult`

Validate data against the HDF Evidence Package schema.

- **Parameters:**
  - `data` - JavaScript object to validate
- **Returns:** `ValidationResult` with validation status and errors

#### `validate(data: unknown): ValidationResult`

Auto-detect document type and validate.

- **Parameters:**
  - `data` - JavaScript object to validate
- **Returns:** `ValidationResult` with validation status and errors

#### `ValidationResult`

```typescript
interface ValidationResult {
  valid: boolean;                    // True if validation passed
  errors: ValidationError[];         // Array of validation errors (empty if valid)
  getErrorMessage(): string;         // Formatted error message
}
```

#### `ValidationError`

```typescript
interface ValidationError {
  field: string;      // JSON path to the field with error
  message: string;    // Description of the validation error
  value?: unknown;    // The invalid value (optional)
}
```

### Go

#### `ValidateResults(data []byte) ValidationResult`

Validate JSON bytes against the HDF Results schema.

- **Parameters:**
  - `data` - JSON bytes to validate
- **Returns:** `ValidationResult` with validation status and errors

#### `ValidateBaseline(data []byte) ValidationResult`

Validate JSON bytes against the HDF Baseline schema.

- **Parameters:**
  - `data` - JSON bytes to validate
- **Returns:** `ValidationResult` with validation status and errors

#### `Validate(data []byte, schemaType SchemaType) ValidationResult`

Validate JSON bytes against specified schema type.

- **Parameters:**
  - `data` - JSON bytes to validate
  - `schemaType` - one of `TypeResults`, `TypeBaseline`, `TypeComparison`, `TypeSystem`, `TypePlan`, `TypeAmendments`, `TypeEvidencePackage`
- **Returns:** `ValidationResult` with validation status and errors

#### `SetSchemaDir(dir string)`

Configure package to load schemas from a directory instead of embedded schemas.

- **Parameters:**
  - `dir` - Directory path (empty string to revert to embedded schemas)

#### `GetSchemaDir() string`

Get the current schema directory (empty if using embedded schemas).

- **Returns:** Current schema directory path

#### `ValidationResult`

```go
type ValidationResult struct {
    Valid  bool                `json:"valid"`    // True if validation passed
    Errors []ValidationError   `json:"errors"`   // Validation errors (empty if valid)
}

func (r ValidationResult) Error() string  // Formatted error message
```

#### `ValidationError`

```go
type ValidationError struct {
    Field       string `json:"field"`        // JSON path to invalid field
    Description string `json:"description"`  // Error description
    Value       any    `json:"value"`        // Invalid value (optional)
}
```

## Common Validation Errors

### Missing Required Fields

```
baselines: is required
```

HDF Results must have a `baselines` array.

### Invalid Field Types

```
baselines: must be array
baselines[0].name: is required
```

The `name` field is required for each baseline.

### Invalid Enum Values

```
results[0].status: must be equal to one of the allowed values
```

Result status must be one of: `passed`, `failed`, `error`, `notApplicable`, `notReviewed`.

### Invalid Numeric Ranges

```
impact: must be >= 0 and <= 1
```

Impact scores must be between 0.0 and 1.0.

## Use Cases

### Converter Output Validation

Validate that your converter produces valid HDF:

```typescript
import { convertNessusToHdf } from '@mitre/hdf-converters';
import { validateResults } from '@mitre/hdf-validators';

const hdf = convertNessusToHdf(nessusXml);
const result = validateResults(JSON.parse(hdf));

if (!result.valid) {
  throw new Error(`Invalid HDF output: ${result.getErrorMessage()}`);
}
```

### Pre-Upload Validation

Validate HDF before uploading to Heimdall:

```typescript
const hdfData = JSON.parse(fs.readFileSync('scan-results.json', 'utf-8'));
const result = validateResults(hdfData);

if (result.valid) {
  uploadToHeimdall(hdfData);
} else {
  console.error('Cannot upload invalid HDF:', result.getErrorMessage());
}
```

### CI/CD Pipeline Validation

```bash
# Validate HDF file in CI
hdf validate results.json

# Exit code 0 if valid, non-zero if invalid
if hdf validate scan.json --quiet; then
  echo "✓ HDF validation passed"
else
  echo "✗ HDF validation failed"
  exit 1
fi
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

Both TypeScript and Go implementations maintain **>95% test coverage** with comprehensive validation tests covering:
- Valid HDF Results and Baseline documents
- Invalid documents (missing fields, wrong types, invalid values)
- Error message formatting
- Custom schema directory loading (Go)
- Integration tests with real HDF fixtures

## License

Apache-2.0 © MITRE Corporation
