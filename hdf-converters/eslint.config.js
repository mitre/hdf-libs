import tseslint from '@typescript-eslint/eslint-plugin';
import tsparser from '@typescript-eslint/parser';

// Timestamp guard: forbid `new Date(<value>)` on a tool-supplied value in
// *-to-hdf converters (zone-less values are read as host-local; use
// parseTimestamp). Match the first argument across the forms converters
// actually use to feed it — bare identifier, member access, and the coercion
// wrappers `as`/`!`/call/template-literal — so the guard can't be bypassed by
// `new Date(raw as string)`, `new Date(raw!)`, `new Date(String(raw))`, etc.
// Safe forms (no-arg now, numeric/string literals, arithmetic) are not matched.
const DATE_GUARD_MSG =
  'Do not parse a tool timestamp with `new Date(value)` (zone-less values are read as host-local). Use `parseTimestamp` from @mitre/hdf-utilities. See site/docs/contributing/developer-guide.md (Timestamp Handling).';
const DATE_GUARD_RULES = [
  'Identifier',
  'MemberExpression',
  'TSAsExpression',
  'TSNonNullExpression',
  'CallExpression',
  'TemplateLiteral',
].map((argType) => ({
  selector: `NewExpression[callee.name='Date'] > ${argType}.arguments`,
  message: DATE_GUARD_MSG,
}));

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
    files: ['converters/**/*.ts', 'shared/**/*.ts'],
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
    files: ['converters/*-to-hdf/**/*.ts'],
    ignores: ['**/*.test.ts', '**/*.spec.ts'],
    rules: {
      'no-restricted-syntax': ['error', ...DATE_GUARD_RULES],
    },
  },
  {
    files: ['test/**/*.ts', 'converters/**/*.test.ts', 'shared/**/*.test.ts'],
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
];
