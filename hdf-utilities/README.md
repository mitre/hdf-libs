# @mitre/hdf-utilities

Generic utility functions used throughout the HDF library ecosystem: safe parsing and building for common data formats (JSON, XML, CSV), cryptographic hashing, and the shared primitives that keep converters consistent — timestamp parsing and normalization, CVSS scoring, CPE and PURL identifiers, severity and status vocabularies, input-size guards, and object and string helpers.

## Scope and Responsibilities

**hdf-utilities** provides low-level format handling utilities:
- Parse and build JSON, XML, CSV documents
- Validate format syntax (well-formed XML, parseable JSON, etc.)
- Generate cryptographic hashes for data integrity
- Sanitize values for safe output

**What this library does NOT do:**
- Validate HDF document semantics (use `@mitre/hdf-validators` for schema validation)
- Parse HDF-specific structures (use `@mitre/hdf-parsers` for HDF traversal)
- Convert between security tool formats (use `@mitre/hdf-converters`)

### Why the Go and TypeScript surfaces differ

The two languages do not export the same modules, and that is deliberate. This
package holds cross-language **policy** — decisions both implementations must
agree on — while each language uses its own serializer.

The plumbing in `hash` and `json` has no Go counterpart because Go's standard library already provides it: `crypto/sha256`, `encoding/json`. Wrapping `parseJSON`, `stringifyJSON` or `generateHash` in Go would add a layer with no decision in it. The TypeScript side needs those wrappers because JavaScript ships no equivalent, and the wrapper is where safe defaults get centralised. The policy in those modules does exist in both: Go's `CanonicalJSON`, `ChecksumJSON` and `SHA256Hex` are the twins of TypeScript's `canonicalJson` and `canonicalChecksum`. The canonical byte form a checksum is taken over (sorted keys, `<`, `>` and `&` escaped, null-valued keys dropped) is a decision both implementations must agree on, so it is pinned against shared vectors rather than left to each serializer.

`csv` exists in both, but the two surfaces are deliberately different sizes: the
TypeScript module parses and builds CSV, while the Go one carries only the
formula-injection policy and leaves writing to `encoding/csv`.

XML shows the pattern most clearly. Go's `xml.go` exports an XXE-safety policy
(`InspectXMLPrologue`, `ContainsXMLDoctype` and `ContainsXMLEntityDeclarations`)
and one domain helper (`ExtractXMLRootElement`), and leaves parsing to
`encoding/xml`. The
TypeScript `xml/` module wraps fast-xml-parser and carries the same policy in its
defaults.

So the test for whether something belongs in both languages is not "does the
other one have it" but "is it a decision, or is it plumbing". Formula-injection
sanitizing (`SanitizeCSVValue` / `sanitizeCsvValue`) is a decision: which leading
characters a spreadsheet will execute, and what neutralises them. It exists in
both, pinned to one shared table in `testdata/csv-sanitize-cases.json`, because a
trigger added on one side alone would leave the other exporting CSVs a
spreadsheet runs. CSV *writing* is plumbing, and stays with each language's
serializer.

### hdf-utilities vs. hdf-validators

| hdf-utilities | hdf-validators |
|---------------|----------------|
| Format syntax validation | Schema conformance validation |
| "Is this valid JSON?" | "Is this valid HDF?" |
| "Can this XML be parsed?" | "Does this HDF have required fields?" |
| Generic data format handling | HDF-specific semantic rules |
| No knowledge of HDF schema | Validates against JSON schemas |

**Example:**
- `isValidJSON('{"foo": "bar"}')` → `true` (hdf-utilities - syntax check)
- `validateResults({baselines: []})` → validates against HDF schema (hdf-validators)

## Installation

```bash
npm install @mitre/hdf-utilities
```

## Usage

### JSON Utilities

Safe JSON parsing and stringification with better error handling:

```typescript
import { parseJSON, stringifyJSON, isValidJSON } from '@mitre/hdf-utilities';

// Parse JSON with clear error messages
try {
  const data = parseJSON<HDFResults>(jsonString);
  console.log(data.baselines);
} catch (error) {
  console.error('Invalid JSON:', error.message);
}

// Stringify with pretty printing
const hdf = { baselines: [], targets: [] };
const json = stringifyJSON(hdf, { pretty: true, indent: 2 });

// Check if string is valid JSON before parsing
if (isValidJSON(userInput)) {
  const data = parseJSON(userInput);
}
```

### Hash Utilities

Generate and verify cryptographic hashes for data integrity:

```typescript
import { sha256, sha512, generateHash, hashObject, verifyHash } from '@mitre/hdf-utilities';

// Quick SHA-256 hash (hash functions are async)
const hash = await sha256('content to hash');
console.log(hash); // hex-encoded hash

// Raw bytes hash as they are; text is hashed as its UTF-8 bytes
const fileHash = await sha256(new Uint8Array([0x61, 0x62, 0x63]));

// Hash with custom options
const customHash = await generateHash('data', {
  algorithm: 'sha512',
  encoding: 'base64'
});

// Hash JavaScript objects (deterministic JSON serialization)
const baseline = { name: 'My Baseline', version: '1.0' };
const objectHash = await hashObject(baseline, { algorithm: 'sha256' });

// Verify data integrity
const isValid = await verifyHash('original data', hash, { algorithm: 'sha256' });
if (!isValid) {
  console.error('Data integrity check failed!');
}
```

### XML Utilities

Parse and build XML documents with array handling:

```typescript
import { parseXml, buildXml, parseXmlWithArrays, isValidXml, extractTextFromXml } from '@mitre/hdf-utilities';

// Parse XML to JavaScript object
const xml = '<root><item>value</item></root>';
const obj = parseXml(xml);
console.log(obj); // { root: { item: 'value' } }

// Build XML from object
const data = {
  HdfResults: {
    baselines: {
      baseline: [
        { name: 'Baseline 1' },
        { name: 'Baseline 2' }
      ]
    }
  }
};
const xmlOutput = buildXml(data);
// <?xml version="1.0"?>
// <HdfResults>
//   <baselines>
//     <baseline><name>Baseline 1</name></baseline>
//     <baseline><name>Baseline 2</name></baseline>
//   </baselines>
// </HdfResults>

// Parse XML with automatic array detection
const nessusXml = '<Report><ReportHost>...</ReportHost><ReportHost>...</ReportHost></Report>';
const report = parseXmlWithArrays(nessusXml, ['ReportHost']); // tag names always parsed as arrays

// Check if string is well-formed XML
if (isValidXml(userInput)) {
  const parsed = parseXml(userInput);
}

// Extract plain text from XML (strips all tags)
const plainText = extractTextFromXml('<p>Hello <b>world</b></p>');
console.log(plainText); // "Hello world"
```

### CSV Utilities

Parse and build CSV documents with sanitization:

```typescript
import {
  parseCsv,
  buildCsv,
  isValidCsv,
  sanitizeCsvValue,
  sanitizeCsvArray,
  sanitizeCsvObject
} from '@mitre/hdf-utilities';

// Parse CSV string to array of objects
const csv = 'name,age\nAlice,30\nBob,25';
const rows = parseCsv(csv);
console.log(rows);
// [
//   { name: 'Alice', age: '30' },
//   { name: 'Bob', age: '25' }
// ]

// Build CSV from array of objects
const data = [
  { id: 'REQ-001', status: 'passed', impact: 0.7 },
  { id: 'REQ-002', status: 'failed', impact: 0.9 }
];
const csvOutput = buildCsv(data);
// id,status,impact
// REQ-001,passed,0.7
// REQ-002,failed,0.9

// Validate CSV syntax
if (isValidCsv(fileContent)) {
  const parsed = parseCsv(fileContent);
}

// Sanitize individual values (neutralize formula injection)
console.log(sanitizeCsvValue('=1+1')); // "'=1+1"
console.log(sanitizeCsvValue(' -2+3')); // "' -2+3" (leading whitespace kept)
console.log(sanitizeCsvValue('Value with "quotes" and, commas'));
// 'Value with "quotes" and, commas' — unchanged; quoting is the serializer's job

// Sanitize arrays
const tags = ['AC-1', '=cmd|calc', null];
const safeTags = sanitizeCsvArray(tags);
console.log(safeTags); // ['AC-1', "'=cmd|calc", 'null']

// Sanitize entire objects (flat string map; values stringified)
const requirement = {
  id: 'REQ-001',
  title: 'Title with "quotes"',
  tags: ['AC-1', null]
};
const safeReq = sanitizeCsvObject(requirement);
// { id: 'REQ-001', title: 'Title with "quotes"', tags: 'AC-1,' }
```

### CVSS Scoring

`computeCvssScore` (Go `ComputeCvssScore`) scores a vector of any CVSS version.
It reads the version the vector declares and scores it by that version's own
rules, so the caller never picks an engine: the equations of CVSS 2.0 (FIRST v2
guide §3.2), 3.0 (specification §8) and 3.1 (specification §7), or the
MacroVector engine of CVSS 4.0. The result names the version that scored it;
check it when only some versions apply.

```typescript
import { computeCvssScore } from '@mitre/hdf-utilities';

computeCvssScore('AV:N/AC:M/Au:N/C:P/I:N/A:N');
// { version: '2.0', baseScore: 4.3, temporalScore: 4.3 }

computeCvssScore('CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H/E:U/RL:O/RC:C');
// { version: '3.0', baseScore: 7.5, temporalScore: 6.5 }

computeCvssScore('CVSS:5.0/AV:N'); // throws: CVSS defines no version 5.0
```

## API Reference

### JSON Utilities

#### `parseJSON<T>(input: string): T`

Parse JSON string with clear error messages.

- **Parameters:**
  - `input` - JSON string to parse
- **Returns:** Parsed JSON value with inferred type
- **Throws:** Error with descriptive message if JSON is invalid or empty

#### `stringifyJSON(value: unknown, options?: StringifyOptions): string`

Convert JavaScript value to JSON string.

- **Parameters:**
  - `value` - Value to stringify
  - `options.pretty` - Enable pretty printing (default: `false`)
  - `options.indent` - Spaces for indentation (default: `2`)
- **Returns:** JSON string
- **Throws:** Error if value contains circular references

#### `isValidJSON(input: unknown): boolean`

Check if string can be parsed as JSON.

- **Parameters:**
  - `input` - Value to check (must be string)
- **Returns:** `true` if valid JSON syntax, `false` otherwise

### Hash Utilities

#### `sha256(data: HashInput): Promise<string>`

Generate SHA-256 hash (hex-encoded).

- **Parameters:**
  - `data` - Text or bytes to hash (`HashInput = string | Uint8Array`; text is hashed as its UTF-8 bytes)
- **Returns:** Promise resolving to a hex-encoded hash string

#### `sha512(data: HashInput): Promise<string>`

Generate SHA-512 hash (hex-encoded).

- **Parameters:**
  - `data` - Text or bytes to hash, as for `sha256`
- **Returns:** Promise resolving to a hex-encoded hash string

#### `generateHash(data: HashInput, options?: HashOptions): Promise<string>`

Generate hash with custom algorithm and encoding.

- **Parameters:**
  - `data` - Text or bytes to hash, as for `sha256`
  - `options.algorithm` - Hash algorithm: `'sha256'` | `'sha384'` | `'sha512'` (default: `'sha256'`)
  - `options.encoding` - Output encoding: `'hex'` | `'base64'` (default: `'hex'`)
- **Returns:** Promise resolving to the encoded hash string

#### `hashObject(obj: unknown, options?: HashOptions): Promise<string>`

Generate deterministic hash of JavaScript object.

- **Parameters:**
  - `obj` - Object to hash (will be JSON-stringified)
  - `options` - Same as `generateHash`
- **Returns:** Promise resolving to the hash of the serialized object

#### `verifyHash(data: HashInput, expectedHash: string, options?: HashOptions): Promise<boolean>`

Verify data matches expected hash.

- **Parameters:**
  - `data` - Original data to verify
  - `expectedHash` - Expected hash value
  - `options` - Same hash options used during generation
- **Returns:** Promise resolving to `true` if the hash matches, `false` otherwise

### XML Utilities

#### `parseXml(xml: string, options?: object): object`

Parse XML string to JavaScript object.

- **Parameters:**
  - `xml` - XML string to parse
  - `options` - fast-xml-parser options (optional)
- **Returns:** Parsed object
- **Throws:** Error if XML is malformed

#### `buildXml(obj: object, options?: object): string`

Build XML string from JavaScript object.

- **Parameters:**
  - `obj` - Object to convert to XML
  - `options` - fast-xml-parser builder options (optional)
- **Returns:** XML string with header
- **Throws:** Error if conversion fails

#### `parseXmlWithArrays(xml: string, arrayTags: string[], options?: object): Record<string, unknown>`

Parse XML with the named tags always parsed as arrays.

- **Parameters:**
  - `xml` - XML string to parse
  - `arrayTags` - Bare tag names to treat as arrays wherever they occur (e.g., `'ReportHost'`, not a path)
  - `options` - fast-xml-parser parser options, plus `maxSize`, the maximum input length (optional)
- **Returns:** Parsed object with consistent arrays
- **Throws:** Error if XML is malformed or longer than `maxSize`

#### `isValidXml(xml: string): boolean`

Check if string is well-formed XML.

- **Parameters:**
  - `xml` - String to validate
- **Returns:** `true` if valid XML syntax, `false` otherwise

#### `extractTextFromXml(xml: string): string`

Extract plain text content from XML (strips all tags).

- **Parameters:**
  - `xml` - XML string
- **Returns:** Plain text content with whitespace normalized

### CSV Utilities

#### `parseCsv<T>(csv: string, options?: object): T[]`

Parse CSV string to array of objects.

- **Parameters:**
  - `csv` - CSV string to parse
  - `options` - `Partial<CsvParseOptions>` (header, delimiter, typing and size limit; optional)
- **Returns:** Array of objects (headers become keys)
- **Throws:** Error if CSV is malformed

#### `buildCsv<T>(data: T[], options?: object): string`

Build CSV string from array of objects.

- **Parameters:**
  - `data` - Array of objects to convert
  - `options` - `Partial<CsvBuildOptions> & { sanitize?: boolean }` (optional)
- **Returns:** CSV string with headers

#### `isValidCsv(csv: string): boolean`

Check if string can be parsed as CSV.

- **Parameters:**
  - `csv` - String to validate
- **Returns:** `true` if parseable CSV, `false` otherwise

#### `sanitizeCsvValue(value: unknown): string`

Neutralize formula injection in a value bound for CSV.

- **Parameters:**
  - `value` - Value to sanitize
- **Returns:** `String(value)`, prefixed with `'` when its first non-whitespace
  character is `=`, `+`, `-`, `@`, `|`, or `%`. Nothing else is altered: quotes,
  commas and newlines are passed through for the serializer to quote, and `null`
  / `undefined` stringify to `"null"` / `"undefined"`.

#### `sanitizeCsvArray(values: unknown[]): string[]`

Apply `sanitizeCsvValue` to each element.

- **Parameters:**
  - `values` - Array to sanitize
- **Returns:** Array of sanitized strings

#### `sanitizeCsvObject<T extends Record<string, unknown>>(obj: T): Record<string, string>`

Apply `sanitizeCsvValue` to each own enumerable value of an object.

- **Parameters:**
  - `obj` - Object to sanitize
- **Returns:** A flat string map — one level only, every value stringified (an
  array value becomes its comma-joined `String()` form)

### CVSS Scoring

#### `computeCvssScore(vector: string): CvssScore`

Score a CVSS 2.0, 3.0, 3.1 or 4.0 vector by the rules of the version it
declares. Go: `ComputeCvssScore(vector string) (CvssScore, error)`.

- **Parameters:**
  - `vector` - The vector string; a CVSS 2.0 vector carries no `CVSS:` prefix
- **Returns:** `{ version, baseScore, temporalScore }`. `temporalScore` is the
  Temporal score (2.0, 3.x) or the Threat score (4.0) and equals `baseScore`
  when the vector carries no such metric. CVSS 3.0 and 3.1 share one Round up,
  implemented as the 3.1 specification's Appendix A advises, so floating-point
  error cannot raise a score.
- **Throws:** Error if CVSS does not define the version, a required metric is
  missing, a metric value is outside that version's values, or the vector is
  malformed (a segment that is not `NAME:VALUE`, an empty value, a repeated
  metric): never a guessed score

#### `cvssSeverityForVersion(version: string, score: number): string`

The severity of a CVSS score on its version's scale. Go: `CvssSeverityForVersion`.

- **Parameters:**
  - `version` - `"2.0"`, `"3.0"`, `"3.1"` or `"4.0"`
  - `score` - The score
- **Returns:** For CVSS 2.0, NVD's v2 ranges: `low` 0.0–3.9, `medium` 4.0–6.9,
  `high` 7.0–10.0 (2.0 has no `none` or `critical`). For 3.0, 3.1 and 4.0, the
  specification's scale (`cvssScoreToSeverity`). A negative or non-finite score
  is `none`.

#### `normalizeCvssMetrics(vector: string): CvssMetrics`

The four exposure metrics of a vector of any CVSS version in one vocabulary, the
FIRST CVSS 3.x JSON schema names, for comparing findings across versions. Go:
`NormalizeCvssMetrics`.

- **Parameters:**
  - `vector` - A CVSS 2.0, 3.0, 3.1 or 4.0 vector
- **Returns:** `{ version, attackVector, attackComplexity, privilegesRequired,
  userInteraction, baseScore? }`, each field `"unknown"` when the version has no
  such metric or the value is absent or invalid; `baseScore` when the vector
  scores. Never throws.

| Field | Values | Across versions |
|---|---|---|
| `attackVector` | `NETWORK`, `ADJACENT_NETWORK`, `LOCAL`, `PHYSICAL` | 4.0 `ADJACENT` is `ADJACENT_NETWORK` (same definition) |
| `attackComplexity` | `LOW`, `HIGH`; `MEDIUM` from 2.0 only | 2.0's MEDIUM has no 3.x equivalent; 4.0 Attack Requirements is not folded in |
| `privilegesRequired` | `NONE`, `LOW`, `HIGH` | 2.0 Authentication `N`/`S`/`M` is `NONE`/`LOW`/`LOW`: a library convention, since Authentication counts logins and states no privilege level |
| `userInteraction` | `NONE`, `REQUIRED` | 4.0 `PASSIVE` and `ACTIVE` are `REQUIRED`; 2.0 has no such metric (`unknown`) |

`parseCvssVector` keeps the exact values when the distinctions above matter.

#### `computeCvss40Score(vector: string): CvssScore`

The CVSS 4.0 MacroVector engine that `computeCvssScore` uses for 4.0 vectors;
callers should use `computeCvssScore`. Go: `ComputeCvss40Score`.

## Development

```bash
# Install dependencies
pnpm install

# Run tests
pnpm test

# Run tests with coverage
pnpm test:coverage

# Build the package
pnpm build

# Lint code
pnpm lint
```

## Test Coverage

All utilities maintain **>95% test coverage**. Run `pnpm test:coverage` to view current coverage report.

## License

Apache-2.0 © MITRE Corporation
