// The workspace's entire TypeScript lint policy, in one file. Each package used
// to carry its own near-copy of this; twelve configs drifted into three
// byte-identical files and nine small variations, and nothing enforced that a
// new package inherited any of it.
//
// A flat-config block only bites if the eslint invocation reaches the files its
// `files` glob names. Running from the root makes that one decision instead of
// twelve, so the globs below are the authoritative statement of what is linted.

import tseslint from '@typescript-eslint/eslint-plugin';
import tsparser from '@typescript-eslint/parser';
import { DATE_GUARD_RULES } from './scripts/eslint-timestamp-guard.mjs';
import { deprecatedAliasGuardBlock } from './scripts/eslint-deprecated-alias-guard.mjs';

// Package source trees. Most packages publish from src/; hdf-parsers and
// hdf-validators from typescript/; hdf-converters also lints the three trees
// that hold converter code.
const SOURCE = [
  '*/src/**/*.ts',
  'hdf-parsers/typescript/**/*.ts',
  'hdf-validators/typescript/**/*.ts',
  'hdf-converters/converters/**/*.ts',
  'hdf-converters/shared/**/*.ts',
  'hdf-converters/fetchers/**/*.ts',
];

const TESTS = ['*/test/**/*.ts', '**/*.test.ts', '**/*.spec.ts'];

// Trees whose code parses timestamps — tool-supplied on the way in, HDF's own
// on the way out. Both directions are exposed to the `new Date(value)` footgun.
//
// Split because the per-package configs this replaces disagreed about tests and
// the difference is load-bearing: hdf-converters excluded them (its converter
// tests build fixture dates with `new Date(literal)` in forms the guard would
// reject), while hdf-diff and hdf-utilities guarded everything under src/,
// tests included. Collapsing the two would either drop coverage on
// hdf-utilities/src/size/size.test.ts or fail 26 pre-existing converter tests.
const TIMESTAMP_GUARDED_EXCLUDING_TESTS = [
  'hdf-converters/converters/**/*.ts',
  'hdf-converters/shared/**/*.ts',
  'hdf-converters/fetchers/**/*.ts',
];
const TIMESTAMP_GUARDED_INCLUDING_TESTS = [
  'hdf-diff/src/**/*.ts',
  'hdf-utilities/src/**/*.ts',
];

// Packages that import types from @mitre/hdf-schema, tests included — the
// original alias drift was in test files.
const ALIAS_GUARDED = [
  'hdf-converters/src/**/*.ts',
  'hdf-converters/converters/**/*.ts',
  'hdf-converters/shared/**/*.ts',
  'hdf-converters/fetchers/**/*.ts',
  'hdf-converters/test/**/*.ts',
  'hdf-engine/src/**/*.ts',
  'hdf-engine/test/**/*.ts',
  'hdf-extension-graph/src/**/*.ts',
  'hdf-extension-graph/test/**/*.ts',
  'hdf-generators/src/**/*.ts',
  'hdf-generators/test/**/*.ts',
  'hdf-parsers/typescript/**/*.ts',
  'hdf-validators/typescript/**/*.ts',
];

// projectService resolves each file against its OWN package's tsconfig. A
// single root-level `project` cannot: it is one path, and the type-aware rules
// need the twelve.
const typeAware = {
  parser: tsparser,
  parserOptions: {
    ecmaVersion: 2022,
    sourceType: 'module',
    projectService: true,
    tsconfigRootDir: import.meta.dirname,
  },
};

const untyped = {
  parser: tsparser,
  parserOptions: { ecmaVersion: 2022, sourceType: 'module' },
};

const site = {
  node: {
    console: 'readonly',
    process: 'readonly',
    URL: 'readonly',
    URLSearchParams: 'readonly',
    Buffer: 'readonly',
    fetch: 'readonly',
    structuredClone: 'readonly',
    TextEncoder: 'readonly',
    TextDecoder: 'readonly',
    setTimeout: 'readonly',
    clearTimeout: 'readonly',
  },
  browser: {
    console: 'readonly',
    document: 'readonly',
    window: 'readonly',
    location: 'readonly',
    navigator: 'readonly',
    localStorage: 'readonly',
    requestAnimationFrame: 'readonly',
    setTimeout: 'readonly',
    clearTimeout: 'readonly',
  },
};

// The site is plain ESM JavaScript with no TypeScript, so it takes ESLint's own
// correctness rules rather than the typescript-eslint set. They are listed
// because @eslint/js is only a transitive dependency here.
const correctness = {
  'no-undef': 'error',
  'no-unused-vars': ['error', { argsIgnorePattern: '^_' }],
  'no-const-assign': 'error',
  'no-dupe-args': 'error',
  'no-dupe-keys': 'error',
  'no-duplicate-case': 'error',
  'no-func-assign': 'error',
  'no-invalid-regexp': 'error',
  'no-irregular-whitespace': 'error',
  'no-prototype-builtins': 'error',
  'no-self-assign': 'error',
  'no-sparse-arrays': 'error',
  'no-unreachable': 'error',
  'no-unsafe-negation': 'error',
  'no-useless-escape': 'error',
  'no-cond-assign': 'error',
  'no-constant-condition': 'error',
  'no-empty': 'error',
  'no-fallthrough': 'error',
  'require-atomic-updates': 'error',
  'use-isnan': 'error',
  'valid-typeof': 'error',
};

export default [
  {
    ignores: [
      '**/node_modules/**',
      '**/dist/**',
      '**/coverage/**',
      '.pnpm-store/**',
      'site/.vitepress/dist/**',
      'site/.vitepress/cache/**',
      'site/v*/**',
      'hdf-schema/generated/**',
    ],
  },
  {
    files: SOURCE,
    ignores: TESTS,
    languageOptions: typeAware,
    plugins: { '@typescript-eslint': tseslint },
    rules: {
      ...tseslint.configs.recommended.rules,
      '@typescript-eslint/no-explicit-any': 'error',
      '@typescript-eslint/explicit-function-return-type': [
        'warn',
        { allowExpressions: true, allowTypedFunctionExpressions: true },
      ],
      '@typescript-eslint/no-unused-vars': ['error', { argsIgnorePattern: '^_' }],
      '@typescript-eslint/no-floating-promises': 'error',
      '@typescript-eslint/await-thenable': 'error',
      'no-console': 'warn',
    },
  },
  {
    // See scripts/eslint-timestamp-guard.mjs for the matched argument forms and
    // site/docs/contributing/developer-guide.md for the convention.
    files: TIMESTAMP_GUARDED_EXCLUDING_TESTS,
    ignores: TESTS,
    rules: { 'no-restricted-syntax': ['error', ...DATE_GUARD_RULES] },
  },
  {
    // No `ignores`: a co-located test under src/ carries the guard, as it did
    // before. hdf-utilities/src/size/size.test.ts is the only such file today.
    files: TIMESTAMP_GUARDED_INCLUDING_TESTS,
    rules: { 'no-restricted-syntax': ['error', ...DATE_GUARD_RULES] },
  },
  {
    // These two build the schema bundle and the generated types; they are CLI
    // scripts and report progress on stdout.
    files: ['hdf-schema/src/bundle-schemas.ts', 'hdf-schema/src/generate-types.ts'],
    rules: { 'no-console': 'off' },
  },
  {
    files: TESTS,
    languageOptions: untyped,
    plugins: { '@typescript-eslint': tseslint },
    rules: {
      ...tseslint.configs.recommended.rules,
      '@typescript-eslint/no-explicit-any': 'off',
      '@typescript-eslint/no-unused-vars': ['error', { argsIgnorePattern: '^_' }],
      'no-console': 'off',
    },
  },
  deprecatedAliasGuardBlock(tsparser, ALIAS_GUARDED),
  {
    // Generator scripts and the test suite: Node ESM. Matched at any depth so a
    // file added in a new subdirectory is linted rather than silently skipped.
    files: ['site/**/*.mjs', 'site/**/*.js'],
    ignores: ['site/.vitepress/theme/**'],
    languageOptions: { ecmaVersion: 2023, sourceType: 'module', globals: site.node },
    rules: correctness,
  },
  {
    // VitePress bundles the config before evaluating it, so the CJS module
    // globals are defined even though the file is .mjs.
    files: ['site/.vitepress/config.mjs'],
    languageOptions: {
      ecmaVersion: 2023,
      sourceType: 'module',
      globals: { ...site.node, __dirname: 'readonly', __filename: 'readonly' },
    },
    rules: correctness,
  },
  {
    // Theme code runs in the browser, not in Node.
    files: ['site/.vitepress/theme/**/*.js', 'site/.vitepress/theme/**/*.mjs'],
    languageOptions: { ecmaVersion: 2023, sourceType: 'module', globals: site.browser },
    rules: correctness,
  },
];
