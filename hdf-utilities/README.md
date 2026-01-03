# @mitre/hdf-utilities

Utility functions for HDF libraries.

## Installation

```bash
npm install @mitre/hdf-utilities
```

## Usage

### JSON Utilities

Safe JSON parsing and stringification with better error handling:

```typescript
import { parseJSON, stringifyJSON, isValidJSON } from '@mitre/hdf-utilities';

// Parse JSON with error handling
try {
  const data = parseJSON('{"name": "test"}');
  console.log(data); // { name: 'test' }
} catch (error) {
  console.error('Invalid JSON:', error.message);
}

// Stringify with pretty printing
const obj = { name: 'test', value: 123 };
const json = stringifyJSON(obj, { pretty: true });
console.log(json);
// {
//   "name": "test",
//   "value": 123
// }

// Validate JSON strings
if (isValidJSON('{"valid": true}')) {
  console.log('Valid JSON');
}
```

## API

### `parseJSON<T>(input: string): T`

Safely parse a JSON string.

- **Parameters:**
  - `input` - JSON string to parse
- **Returns:** Parsed JSON value
- **Throws:** Error if input is not valid JSON or empty

### `stringifyJSON(value: unknown, options?: StringifyOptions): string`

Safely stringify a value to JSON.

- **Parameters:**
  - `value` - Value to stringify
  - `options` - Stringification options
    - `pretty` - Enable pretty printing (default: false)
    - `indent` - Number of spaces for indentation (default: 2)
- **Returns:** JSON string
- **Throws:** Error if value contains circular references

### `isValidJSON(input: unknown): boolean`

Check if a string is valid JSON.

- **Parameters:**
  - `input` - String to validate
- **Returns:** `true` if input is valid JSON, `false` otherwise

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

## License

Apache-2.0 © MITRE Corporation
