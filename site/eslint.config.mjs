// Flat config for the site package. The sibling packages spread
// `tseslint.configs.recommended.rules`; this package is plain ESM JavaScript
// with no TypeScript, and ESLint's own recommended set ships in `@eslint/js`,
// which is only a transitive dependency here and so is not resolvable. The
// correctness rules are therefore listed explicitly rather than adding a
// root dependency for one package.
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

const nodeGlobals = {
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
};

export default [
  {
    ignores: ['node_modules/**', '.vitepress/dist/**', '.vitepress/cache/**', 'v*/**'],
  },
  {
    // Generator scripts and the test suite: Node ESM. Matched at any depth so a
    // file added in a new subdirectory is linted rather than silently skipped —
    // flat config passes over a file no block matches, with no error and a
    // green exit. The theme is excluded here so it gets browser globals only.
    files: ['**/*.mjs', '**/*.js'],
    ignores: ['.vitepress/theme/**'],
    languageOptions: {
      ecmaVersion: 2023,
      sourceType: 'module',
      globals: nodeGlobals,
    },
    rules: correctness,
  },
  {
    // VitePress bundles the config before evaluating it, so the CJS module
    // globals are defined here even though the file is .mjs.
    files: ['.vitepress/config.mjs'],
    languageOptions: {
      ecmaVersion: 2023,
      sourceType: 'module',
      globals: { ...nodeGlobals, __dirname: 'readonly', __filename: 'readonly' },
    },
    rules: correctness,
  },
  {
    // Theme code runs in the browser, not in Node.
    files: ['.vitepress/theme/**/*.js', '.vitepress/theme/**/*.mjs'],
    languageOptions: {
      ecmaVersion: 2023,
      sourceType: 'module',
      globals: {
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
    },
    rules: correctness,
  },
];
