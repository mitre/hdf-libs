// Shared Node-builtin import guard for ESLint flat configs.
//
// Forbids importing a Node built-in module (`node:crypto`, `fs`, ...) in a
// package whose entry point must bundle for the browser. One such import in any
// module the entry re-exports breaks every browser consumer at build time, even
// one that never calls the code behind it. Use a platform API that exists in
// both runtimes instead (Web Crypto through `sha256` from @mitre/hdf-utilities,
// `TextEncoder`, `URL`).
//
// ESLint replaces a rule's options when two blocks set the same rule for one
// file, so a tree that also carries another `no-restricted-imports` guard must
// pass that guard's restriction in as `alsoRestrict`; this block then enforces
// both.

import { builtinModules } from 'node:module';

export const NODE_BUILTIN_MSG =
  'Do not import a Node built-in here: this package must bundle for the browser. Use an API available in both runtimes (e.g. `sha256` from @mitre/hdf-utilities for hashing).';

const BARE_BUILTINS = builtinModules.filter((name) => !name.startsWith('_') && !name.startsWith('node:'));

export const NODE_BUILTIN_IMPORT_RESTRICTION = {
  paths: BARE_BUILTINS.map((name) => ({ name, message: NODE_BUILTIN_MSG })),
  patterns: [{ group: ['node:*'], message: NODE_BUILTIN_MSG }],
};

/**
 * A standalone flat-config block applying the Node-builtin guard to the given
 * globs, merged with any other import restriction those files already carry.
 */
export function nodeBuiltinGuardBlock(parser, files, alsoRestrict = {}) {
  return {
    files,
    languageOptions: {
      parser,
      parserOptions: { ecmaVersion: 2022, sourceType: 'module' },
    },
    rules: {
      'no-restricted-imports': [
        'error',
        {
          paths: [...(alsoRestrict.paths ?? []), ...NODE_BUILTIN_IMPORT_RESTRICTION.paths],
          patterns: [...(alsoRestrict.patterns ?? []), ...NODE_BUILTIN_IMPORT_RESTRICTION.patterns],
        },
      ],
    },
  };
}
