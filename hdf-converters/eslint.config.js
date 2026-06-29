import tseslint from '@typescript-eslint/eslint-plugin';
import tsparser from '@typescript-eslint/parser';

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
    // literals, and arithmetic like `new Date(t.getTime() + n)`.
    //
    // `X.arguments` is esquery's field-selector syntax: "an X node located in
    // the parent's `arguments` field" — i.e. a `new Date(...)` call whose first
    // argument is an Identifier or MemberExpression. Verified to flag both
    // `new Date(value)` and `new Date(obj.prop)`.
    files: ['converters/*-to-hdf/**/*.ts'],
    ignores: ['**/*.test.ts', '**/*.spec.ts'],
    rules: {
      'no-restricted-syntax': [
        'error',
        {
          selector: "NewExpression[callee.name='Date'] > Identifier.arguments",
          message:
            'Do not parse a tool timestamp with `new Date(value)` (zone-less values are read as host-local). Use `parseTimestamp` from @mitre/hdf-utilities. See site/docs/contributing/developer-guide.md (Timestamp Handling).',
        },
        {
          selector: "NewExpression[callee.name='Date'] > MemberExpression.arguments",
          message:
            'Do not parse a tool timestamp with `new Date(value)` (zone-less values are read as host-local). Use `parseTimestamp` from @mitre/hdf-utilities. See site/docs/contributing/developer-guide.md (Timestamp Handling).',
        },
      ],
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
