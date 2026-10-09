// The tracked Spectral ruleset for the generated documents.
//
// Core `oas` rules only. The OWASP API Security ruleset is NOT loaded, and that is a
// measured deferral rather than an oversight — re-checked 2026-10-09:
//
//   - @stoplight/spectral-owasp-ruleset is 2.0.1, last published 2024-03-12 (941 days),
//     with no successor package under any obvious name.
//   - Loading it needs either spectral-cli, whose latest release 6.17.0 still pins
//     `fast-glob ~3.2.12` -> micromatch -> braces and so still carries
//     GHSA-vfj7-8cjw-p6xm; or spectral-ruleset-bundler, still on `rollup ^2.80.0`, which
//     cannot import that ruleset's CommonJS build.
//   - braces still has no release past 3.0.3, so the advisory's 3.0.4 floor has never
//     shipped and no override can resolve it.
//
// The library packages used here carry neither braces nor fast-glob: both are absent from
// the lockfile entirely. So Spectral runs, advisory-free, with the core ruleset — the OWASP
// subset is what remains deferred.
import { oas } from '@stoplight/spectral-rulesets';

export default {
  extends: [oas],
  overrides: [
    {
      // Scoped to the one path, not the rule: `Input_Constraints.allowedValues` is declared
      // `type: array` with no `items`, which is a real schema defect tracked separately.
      // Turning the rule off repo-wide would hide the next one; this waiver disappears when
      // that card lands and the schema declares its item type.
      files: ['**#/components/schemas/Input_Constraints/properties/allowedValues'],
      rules: { 'array-items': 'off' },
    },
  ],
};
