# @mitre/hdf-utilities

Generic utility functions for working with common data formats (JSON, XML, CSV) and cryptographic hashing. These utilities provide safe parsing, building, and validation operations used throughout the HDF library ecosystem.

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
- `validateHdfResults({baselines: []})` → validates against HDF schema (hdf-validators)

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

// Quick SHA-256 hash
const hash = sha256('content to hash');
console.log(hash); // hex-encoded hash

// Hash with custom options
const customHash = generateHash('data', {
  algorithm: 'sha512',
  encoding: 'base64'
});

// Hash JavaScript objects (deterministic JSON serialization)
const baseline = { name: 'My Baseline', version: '1.0' };
const objectHash = hashObject(baseline, { algorithm: 'sha256' });

// Verify data integrity
const isValid = verifyHash('original data', hash, { algorithm: 'sha256' });
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
const report = parseXmlWithArrays(nessusXml, {
  arrayPaths: ['Report.ReportHost'] // Force these to always be arrays
});

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

// Sanitize individual values (escape special characters)
const safe = sanitizeCsvValue('Value with "quotes" and, commas');
console.log(safe); // "Value with ""quotes"" and, commas"

// Sanitize arrays
const tags = ['AC-1', 'AC-2', null, undefined];
const safeTags = sanitizeCsvArray(tags);
console.log(safeTags); // ['AC-1', 'AC-2', '', '']

// Sanitize entire objects
const requirement = {
  id: 'REQ-001',
  title: 'Title with "quotes"',
  tags: ['AC-1', null]
};
const safeReq = sanitizeCsvObject(requirement);
// All string values escaped, nulls converted to empty strings
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

#### `sha256(data: string): string`

Generate SHA-256 hash (hex-encoded).

- **Parameters:**
  - `data` - String to hash
- **Returns:** Hex-encoded hash string

#### `sha512(data: string): string`

Generate SHA-512 hash (hex-encoded).

- **Parameters:**
  - `data` - String to hash
- **Returns:** Hex-encoded hash string

#### `generateHash(data: string, options?: HashOptions): string`

Generate hash with custom algorithm and encoding.

- **Parameters:**
  - `data` - String to hash
  - `options.algorithm` - Hash algorithm: `'sha256'` | `'sha512'` (default: `'sha256'`)
  - `options.encoding` - Output encoding: `'hex'` | `'base64'` | `'base64url'` (default: `'hex'`)
- **Returns:** Encoded hash string

#### `hashObject(obj: unknown, options?: HashOptions): string`

Generate deterministic hash of JavaScript object.

- **Parameters:**
  - `obj` - Object to hash (will be JSON-stringified)
  - `options` - Same as `generateHash`
- **Returns:** Hash of serialized object

#### `verifyHash(data: string, expectedHash: string, options?: HashOptions): boolean`

Verify data matches expected hash.

- **Parameters:**
  - `data` - Original data to verify
  - `expectedHash` - Expected hash value
  - `options` - Same hash options used during generation
- **Returns:** `true` if hash matches, `false` otherwise

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

#### `parseXmlWithArrays(xml: string, options: { arrayPaths: string[] }): object`

Parse XML with specified paths forced as arrays.

- **Parameters:**
  - `xml` - XML string to parse
  - `options.arrayPaths` - Dot-notation paths to treat as arrays (e.g., `'Report.ReportHost'`)
- **Returns:** Parsed object with consistent arrays
- **Throws:** Error if XML is malformed

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
  - `options` - PapaParse options (optional)
- **Returns:** Array of objects (headers become keys)
- **Throws:** Error if CSV is malformed

#### `buildCsv<T>(data: T[], options?: object): string`

Build CSV string from array of objects.

- **Parameters:**
  - `data` - Array of objects to convert
  - `options` - PapaParse unparse options (optional)
- **Returns:** CSV string with headers

#### `isValidCsv(csv: string): boolean`

Check if string can be parsed as CSV.

- **Parameters:**
  - `csv` - String to validate
- **Returns:** `true` if parseable CSV, `false` otherwise

#### `sanitizeCsvValue(value: unknown): string`

Escape value for safe CSV output.

- **Parameters:**
  - `value` - Value to sanitize
- **Returns:** Escaped string (quotes escaped, nulls → empty string)

#### `sanitizeCsvArray(values: unknown[]): string[]`

Sanitize array of values for CSV.

- **Parameters:**
  - `values` - Array to sanitize
- **Returns:** Array of sanitized strings

#### `sanitizeCsvObject<T>(obj: T): T`

Recursively sanitize all string values in object.

- **Parameters:**
  - `obj` - Object to sanitize
- **Returns:** New object with sanitized values

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
