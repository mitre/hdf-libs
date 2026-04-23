# Using hdf-mappings in Converters

This document establishes the generalizable pattern for using hdf-mappings alongside converters to enrich HDF output with mapped control references.

## Pattern Overview

When converting security tool output to HDF format, you may encounter standardized identifiers (CCI, CWE, OWASP, etc.) that can be mapped to other control frameworks (NIST, etc.). The hdf-mappings library provides these mappings.

### TypeScript Pattern

```typescript
// 1. Import mapping functions from hdf-mappings
import { getCCINistMappings } from '@mitre/hdf-mappings';

// 2. Extract source identifiers from input data
const cciIds = parseComplianceRef(item['compliance-reference'], 'CCI');
tags.cci = cciIds;

// 3. Map each identifier and deduplicate results
// Pattern: Extract source IDs → Map each ID → Flatten results → Deduplicate
const mappedControls = cciIds.flatMap(cci => getCCINistMappings(cci) ?? []);
tags.nist = [...new Set(mappedControls)];
```

**Key Points:**
- Use `flatMap()` to handle one-to-many mappings (one CCI → multiple NIST controls)
- Use nullish coalescing (`??`) to provide empty array fallback for unmapped IDs
- **Always deduplicate** using `new Set()` - mapping data may contain duplicates, and multiple CCIs may map to the same controls
- Results in a flat, deduplicated array

**Example:**
```typescript
// Input: ['CCI-000366']
// getCCINistMappings('CCI-000366') returns: ['CM-6 b', 'CM-6.1 (iv)', 'CM-6 b']
// After deduplication: ['CM-6 b', 'CM-6.1 (iv)']
```

### Go Pattern

```go
import "github.com/mitre/hdf-libs/hdf-mappings/go/cci"

// Pattern: Extract source IDs → Map each ID → Flatten results → Deduplicate
cciTags := parseComplianceRef(item.ComplianceReference, "CCI")
tags["cci"] = cciTags

// Map each CCI to NIST controls and deduplicate
seen := make(map[string]bool)
var nistControls []string
for _, cciID := range cciTags {
	mappings := cci.GetCCINistMappings(cciID)
	if mappings != nil {
		for _, control := range mappings {
			if !seen[control] {
				seen[control] = true
				nistControls = append(nistControls, control)
			}
		}
	}
}
tags["nist"] = nistControls
```

**Key Points:**
- Use a map for deduplication (Go doesn't have Set built-in)
- Check `mappings != nil` before processing
- Maintain insertion order while deduplicating

## Available Mappers

### TypeScript Mappers
- **CCI to NIST**: `getCCINistMappings(cciId: string): string[] | undefined`
- **CCI Description**: `getCCIDescription(cciId: string): string | undefined`
- **Nessus to NIST**: `getNessusNistControl(pluginFamily: string, pluginID: string): string | undefined`
- **OWASP to CWE**: Multiple mapping functions in `@mitre/hdf-mappings/owasp`
- **CWE Utilities**: `getCWEDescription()`, `getCWESeverity()`, etc.

### Go Mappers
- **CCI to NIST**: `cci.GetCCINistMappings(cciID string): []string` (from `github.com/mitre/hdf-libs/hdf-mappings/go/cci`)
- **CCI Description**: `cci.GetCCIDescription(cciID string): string`
- **CCI Validation**: `cci.CCIExists(cciID string): bool`
- **List all CCIs**: `cci.GetAllCCIIDs(): []string`

### Needed Go Ports
- Nessus mappings (for vulnerability scan converters)
- OWASP/CWE mappings
- Other mappers as needed

## When to Use Mappings

Use mappers when:
1. **Source data contains standardized identifiers** (CCI, CWE, OWASP, etc.)
2. **Target framework is NIST or other control framework**
3. **Mapping enhances traceability** for compliance workflows

Don't use mappers when:
1. Source data already provides target controls
2. No standardized identifiers available
3. Mapping would be lossy or inaccurate

## Error Handling

Mappers return `undefined` (TypeScript) or empty arrays (Go pattern) when:
- Identifier not found in mapping database
- Invalid identifier format
- Null/empty input

Always handle missing mappings gracefully:
```typescript
// Good: Provides empty array fallback
tags.nist = cciIds.flatMap(cci => getCCINistMappings(cci) ?? []);

// Bad: Could result in undefined in array
tags.nist = cciIds.map(cci => getCCINistMappings(cci));
```

## Testing Mappings

Add tests to verify mappings work:
```typescript
it('should map CCI to NIST controls using hdf-mappings', () => {
  const result = convertToHdf(inputData);
  const req = result.baselines[0].requirements[0];
  
  expect(req.tags.nist).toBeDefined();
  expect(Array.isArray(req.tags.nist)).toBe(true);
  expect(req.tags.nist.length).toBeGreaterThan(0);
  expect(req.tags.nist).toContain('CM-6 b'); // Known mapping
});
```

## Examples

### Nessus Compliance Scan (TypeScript)
See: `hdf-converters/converters/nessus-to-hdf/typescript/converter.ts:290-299`

### Future: SARIF with CWE (Pattern)
```typescript
import { getCWENistMappings } from '@mitre/hdf-mappings';

// Extract CWE IDs from SARIF
const cweIds = extractCweIds(result.message.text);
tags.cwe = cweIds;

// Map to NIST (once CWE→NIST mapping exists)
tags.nist = cweIds.flatMap(cwe => getCWENistMappings(cwe) ?? []);
```

## Contributing New Mappers

When adding new mapping functions to hdf-mappings:
1. Follow existing pattern: `getXToY(sourceId: string): string[] | undefined`
2. Return `undefined` for not found, not empty array
3. Return array for one-to-many mappings
4. Add comprehensive tests with known mappings
5. Update this document with new mapper availability
