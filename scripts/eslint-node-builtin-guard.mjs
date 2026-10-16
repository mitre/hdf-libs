// Shared Node-builtin import guard for ESLint flat configs.
//
// Forbids importing a Node built-in module (`node:crypto`, `fs`, ...) in a
// package whose entry point must bundle for the browser. One such import in any
// module the entry re-exports breaks every browser consumer at build time, even
// one that never calls the code behind it. Use a platform API that exists in
// both runtimes instead (Web Crypto through `sha256` from @mitre/hdf-utilities,
// `TextEncoder`, `URL`).
//
// `no-restricted-imports` does not see dynamic `import()`, and a lazy
// `await import('node:crypto')` breaks a browser build exactly as a static one
// does, so the dynamic form is caught separately through `no-restricted-syntax`.
//
// ESLint replaces a rule's options when two blocks set the same rule for one
// file, so a tree that also carries another `no-restricted-imports` or
// `no-restricted-syntax` guard must pass those in as `alsoRestrict` /
// `alsoRestrictSyntax`; this block then enforces all of them. hdf-utilities/src
// carries the timestamp guard on `no-restricted-syntax`, which is why that
// parameter exists.

import { builtinModules } from 'node:module';

export const NODE_BUILTIN_MSG =
  'Do not import a Node built-in here: this package must bundle for the browser. Use an API available in both runtimes (e.g. `sha256` from @mitre/hdf-utilities for hashing).';

const BARE_BUILTINS = builtinModules.filter((name) => !name.startsWith('_') && !name.startsWith('node:'));

export const NODE_BUILTIN_IMPORT_RESTRICTION = {
  paths: BARE_BUILTINS.map((name) => ({ name, message: NODE_BUILTIN_MSG })),
  patterns: [{ group: ['node:*'], message: NODE_BUILTIN_MSG }],
};

// `/` must be escaped along with the regex metacharacters: builtin subpaths
// ("fs/promises", "stream/web") carry it, and esquery delimits an attribute
// regex with slashes, so a bare one truncates the pattern mid-group.
const BARE_BUILTIN_ALTERNATION = BARE_BUILTINS.map((name) => name.replace(/[/.*+?^${}()|[\]\\]/g, '\\$&')).join('|');

// The dynamic-import half of the guard. `no-restricted-imports` covers
// ImportDeclaration and re-exports only, so without these a dynamic import of a
// builtin lints clean and then fails the browser build.
export const NODE_BUILTIN_SYNTAX_RESTRICTION = [
  {
    selector: 'ImportExpression > Literal[value=/^node:/]',
    message: NODE_BUILTIN_MSG,
  },
  {
    selector: `ImportExpression > Literal[value=/^(${BARE_BUILTIN_ALTERNATION})$/]`,
    message: NODE_BUILTIN_MSG,
  },
  // import(`node:fs`) — a template with no interpolation is as static as a
  // literal. One with interpolation cannot be resolved here and is left to the
  // bundler.
  {
    selector: 'ImportExpression > TemplateLiteral[expressions.length=0] > TemplateElement[value.raw=/^node:/]',
    message: NODE_BUILTIN_MSG,
  },
];

/**
 * A standalone flat-config block applying the Node-builtin guard to the given
 * globs, merged with any other import or syntax restriction those files already
 * carry. Place it AFTER any block that sets either rule on the same files.
 */
export function nodeBuiltinGuardBlock(parser, files, alsoRestrict = {}, alsoRestrictSyntax = []) {
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
      'no-restricted-syntax': ['error', ...alsoRestrictSyntax, ...NODE_BUILTIN_SYNTAX_RESTRICTION],
    },
  };
}
