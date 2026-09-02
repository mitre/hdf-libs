import tseslint from '@typescript-eslint/eslint-plugin';
import tsparser from '@typescript-eslint/parser';
import { deprecatedAliasGuardBlock } from '../scripts/eslint-deprecated-alias-guard.mjs';

// The timestamp guard (forbid `new Date(value)` on tool timestamps) is shared
// across the packages that parse timestamps — see
// ../scripts/eslint-timestamp-guard.mjs. Re-exported so the local regression
// test (test/timestamp-guard.test.ts) can assert the guard still fires.
import { DATE_GUARD_RULES } from '../scripts/eslint-timestamp-guard.mjs';
export { DATE_GUARD_RULES };

export default [
  {
    files: ['src/**/*.ts'],
    ignores: ['**/*.test.ts', '**/*.spec.ts'],
    languageOptions: {
      parser: tsparser,
      parserOptions: {
        ecmaVersion: 2022,
        sourceType: 'module',
        project: './tsconfig.json',
      },
    },
    plugins: {
      '@typescript-eslint': tseslint,
    },
    rules: {
      ...tseslint.configs.recommended.rules,
      '@typescript-eslint/no-explicit-any': 'error',
      '@typescript-eslint/explicit-function-return-type': ['warn', {
        allowExpressions: true,
        allowTypedFunctionExpressions: true,
      }],
      '@typescript-eslint/no-unused-vars': ['error', { argsIgnorePattern: '^_' }],
      '@typescript-eslint/no-floating-promises': 'error',
      '@typescript-eslint/await-thenable': 'error',
      'no-console': 'warn',
    },
  },
  {
    files: ['converters/**/*.ts', 'shared/**/*.ts', 'fetchers/**/*.ts'],
    ignores: ['**/*.test.ts', '**/*.spec.ts'],
    languageOptions: {
      parser: tsparser,
      parserOptions: {
        ecmaVersion: 2022,
        sourceType: 'module',
        project: './tsconfig.json',
      },
    },
    plugins: {
      '@typescript-eslint': tseslint,
    },
    rules: {
      ...tseslint.configs.recommended.rules,
      '@typescript-eslint/no-explicit-any': 'error',
      '@typescript-eslint/explicit-function-return-type': ['warn', {
        allowExpressions: true,
        allowTypedFunctionExpressions: true,
      }],
      '@typescript-eslint/no-unused-vars': ['error', { argsIgnorePattern: '^_' }],
      '@typescript-eslint/no-floating-promises': 'error',
      '@typescript-eslint/await-thenable': 'error',
      'no-console': 'warn',
    },
  },
  {
    // Timestamp-handling guard for *-to-hdf input converters. Parsing a
    // tool-supplied timestamp with `new Date(value)` reads a zone-less value as
    // host-local time, diverging from the Go converters (which normalize to
    // UTC). Route all tool timestamps through `parseTimestamp` from
    // @mitre/hdf-utilities instead. See
    // site/docs/contributing/developer-guide.md (Timestamp Handling).
    // Allowed: `new Date()` (now), `new Date(0)` / `new Date('0001-...')`
    // literals, and arithmetic like `new Date(t.getTime() + n)`. See
    // DATE_GUARD_RULES above for the matched argument forms.
    // Both directions: importers parse tool timestamps, and exporters parse HDF's
    // own. Scoping this to *-to-hdf left every hdf-to-* exporter free to call
    // new Date(value) — which reads a zone-less timestamp as host-local where Go
    // reads it as UTC. Exporters were only safe because parseHdf normalises on
    // ingest, an invariant they do not state and cannot rely on locally.
    // Covers shared/ too: converterutil/exportmap/bom/checklist parse timestamps
    // on behalf of the converters and are equally exposed to the footgun.
    // Fetchers pull raw tool API responses, timestamps included, so they get
    // the same guard.
    files: ['converters/**/*.ts', 'shared/**/*.ts', 'fetchers/**/*.ts'],
    ignores: ['**/*.test.ts', '**/*.spec.ts'],
    rules: {
      'no-restricted-syntax': ['error', ...DATE_GUARD_RULES],
    },
  },
  {
    files: ['test/**/*.ts', 'converters/**/*.test.ts', 'shared/**/*.test.ts', 'fetchers/**/*.test.ts'],
    languageOptions: {
      parser: tsparser,
      parserOptions: {
        ecmaVersion: 2022,
        sourceType: 'module',
      },
    },
    plugins: {
      '@typescript-eslint': tseslint,
    },
    rules: {
      ...tseslint.configs.recommended.rules,
      '@typescript-eslint/no-explicit-any': 'off', // Allow 'any' in tests for flexibility
      '@typescript-eslint/no-unused-vars': ['error', { argsIgnorePattern: '^_' }],
      'no-console': 'off', // Allow console in tests
    },
  },
  deprecatedAliasGuardBlock(tsparser, [
    'src/**/*.ts',
    'converters/**/*.ts',
    'shared/**/*.ts',
    'test/**/*.ts',
    'fetchers/**/*.ts',
  ]),
];
