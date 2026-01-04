# Converter Differential Testing

This directory contains the differential testing framework that ensures TypeScript and Go converter implementations produce identical outputs.

## Directory Structure

```
tests/converters/
├── fixtures/              # Shared test fixtures for all converters
│   ├── v1-to-v2/         # v1-to-v2 converter test cases
│   │   ├── input/        # v1.0 HDF files
│   │   └── expected/     # Expected v2.0 HDF output
│   ├── burpsuite/        # Future: Burpsuite converter tests
│   ├── xccdf/            # Future: XCCDF converter tests
│   └── ...
├── output/               # Test run outputs (gitignored)
│   ├── typescript/       # TypeScript converter outputs
│   └── go/              # Go converter outputs
├── scripts/              # Test utilities
│   ├── run-ts-tests.ts  # TypeScript test runner
│   ├── run-go-tests.sh  # Go test runner wrapper
│   └── compare.ts       # Output comparison utility
└── README.md            # This file
```

## Philosophy

### Single Source of Truth
- Test fixtures define correctness
- Both implementations must pass the same tests
- No duplicate test logic in each language

### Differential Testing Benefits
1. **Parity Enforcement**: Guarantees implementations match
2. **Reduced Duplication**: Write test cases once, not twice
3. **Regression Detection**: Catches divergence immediately
4. **CI/CD Integration**: Automated validation on every commit

## Test Case Structure

Each converter has input/expected pairs:

```
fixtures/v1-to-v2/
├── input/
│   ├── minimal.json           # Simplest valid v1.0 file
│   ├── complex.json           # Complex nested structures
│   ├── edge-cases.json        # Unusual but valid inputs
│   └── container-scan.json    # Real-world example
└── expected/
    ├── minimal.json           # Expected v2.0 output
    ├── complex.json
    ├── edge-cases.json
    └── container-scan.json
```

## Running Tests

### TypeScript Converters
```bash
# Run all converter tests
pnpm test:converters

# Run specific converter
pnpm test:converters -- v1-to-v2

# Generate output for comparison
pnpm test:converters:generate -- v1-to-v2
```

### Go Converters
```bash
# Run all converter tests
cd hdf-cli && go test ./pkg/converters/...

# Run specific converter
go test ./pkg/converters/v1tov2

# Generate output for comparison
go test ./pkg/converters/v1tov2 -generate
```

### Differential Comparison
```bash
# Compare TypeScript vs Go outputs
./scripts/compare-outputs.sh v1-to-v2

# Run full parity check (TS + Go + compare)
./scripts/parity-check.sh v1-to-v2
```

## CI/CD Integration

GitHub Actions runs differential tests on every PR:

1. Run TypeScript converters → output to `tests/converters/output/typescript/`
2. Run Go converters → output to `tests/converters/output/go/`
3. Compare outputs with `compare.ts`
4. Fail if any differences detected

## Adding a New Converter

1. **Create fixture directory:**
   ```bash
   mkdir -p fixtures/my-converter/{input,expected}
   ```

2. **Add test cases:**
   - Put source format files in `input/`
   - Put expected HDF output in `expected/`
   - Name them identically (e.g., `basic.xml` → `basic.json`)

3. **Implement TypeScript converter:**
   - Add to `hdf-converters/src/my-converter/`
   - Export converter function
   - Run `pnpm test:converters:generate -- my-converter`

4. **Implement Go converter:**
   - Create `hdf-cli/pkg/converters/myconverter/`
   - Implement conversion logic
   - Run `go test ./pkg/converters/myconverter -generate`

5. **Validate parity:**
   ```bash
   ./scripts/parity-check.sh my-converter
   ```

## Test Fixture Guidelines

### Good Test Cases
- **Minimal**: Smallest valid input (tests required fields only)
- **Complete**: All optional fields populated
- **Edge cases**: Empty arrays, null values, boundary conditions
- **Real-world**: Actual scanner output (anonymized if needed)
- **Regression**: Known bugs that were fixed

### Naming Convention
- `minimal.{ext}` - Minimal valid input
- `complete.{ext}` - All fields populated
- `edge-*.{ext}` - Specific edge case (e.g., `edge-empty-arrays.xml`)
- Descriptive names for real-world examples

## Comparison Logic

The `compare.ts` utility performs deep JSON comparison:

- **Exact match**: JSON structure must be identical
- **Normalization**: Timestamps, UUIDs ignored if marked
- **Flexible ordering**: Array order preserved unless marked as unordered
- **Clear diffs**: Shows exactly what differs when tests fail

## Debugging Failed Comparisons

When parity tests fail:

1. Check output files:
   ```bash
   diff tests/converters/output/typescript/v1-to-v2/minimal.json \
        tests/converters/output/go/v1-to-v2/minimal.json
   ```

2. Use comparison tool:
   ```bash
   npx compare tests/converters/output/typescript/v1-to-v2/minimal.json \
                tests/converters/output/go/v1-to-v2/minimal.json
   ```

3. Check for:
   - Field name differences (typos, casing)
   - Type mismatches (string vs number)
   - Missing fields
   - Different array ordering
   - Timestamp/UUID differences

## Maintenance

### When Schema Changes
1. Update expected outputs in `fixtures/*/expected/`
2. Run both test suites
3. Verify parity

### When Converter Logic Changes
1. Update TypeScript implementation
2. Update Go implementation
3. Run differential tests
4. Both must pass before merging

### Adding Test Coverage
Prefer adding test cases over adding language-specific unit tests. A single fixture pair provides validation for both implementations.
