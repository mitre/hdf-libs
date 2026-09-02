// Shared deprecated-alias import guard for ESLint flat configs.
//
// Forbids importing the deprecated Hdf* type aliases (HdfResults, HdfBaseline,
// ...) from @mitre/hdf-schema in internal code. The aliases exist ONLY for
// external consumers' backward compatibility (added by PR #77's Hdf* → HDF*
// rename); internal code must use the canonical HDF* names so the aliases can
// eventually be dropped without touching this repo. PR #75 crossed PR #77's
// rename sweep and reintroduced alias imports silently — this guard makes that
// drift a lint failure instead (bead hdf-libs-d1ci).
//
// Deliberately NOT restricted: hdf-diff's own HdfComparison/HdfDiff public
// types (its API, imported from hdf-diff, not @mitre/hdf-schema) and the
// "HdfResults" XML element name in hdf-to-xml (a wire-format string, not an
// import).
//
// Imported by the eslint.config.js of every package that imports types from
// @mitre/hdf-schema, in a standalone config block that also covers test files
// (some packages exclude tests from their main lint blocks — the original
// drift was in test files).

export const DEPRECATED_ALIAS_MSG =
  'Import the canonical HDF* type names, not the deprecated Hdf* aliases — the aliases exist only for external consumers (see hdf-schema create-index.ts).';

export const DEPRECATED_ALIAS_IMPORT_RESTRICTION = {
  paths: [
    {
      name: '@mitre/hdf-schema',
      importNames: [
        'HdfResults',
        'HdfBaseline',
        'HdfComparison',
        'HdfSystem',
        'HdfPlan',
        'HdfAmendments',
        'HdfEvidencePackage',
      ],
      message: DEPRECATED_ALIAS_MSG,
    },
  ],
};

/**
 * A standalone flat-config block applying only the deprecated-alias guard to
 * every TypeScript file in the given globs (tests included). Needs a parser
 * for TS syntax but no type information, so no `project` option.
 */
export function deprecatedAliasGuardBlock(parser, files) {
  return {
    files,
    languageOptions: {
      parser,
      parserOptions: { ecmaVersion: 2022, sourceType: 'module' },
    },
    rules: {
      'no-restricted-imports': ['error', DEPRECATED_ALIAS_IMPORT_RESTRICTION],
    },
  };
}
