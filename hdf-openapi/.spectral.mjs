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
import { createRulesetFunction } from '@stoplight/spectral-core';

/**
 * A deprecated operation must say when it was deprecated AND when it stops working, and
 * must not claim to sunset before it was deprecated.
 *
 * ADR-0008 §3 requires this and notes there is no built-in rule for it: Spectral's
 * oas-deprecated checks only that `deprecated` is boolean. Without both dates a client has
 * no notice period to plan against, which is the whole point of RFC 9745 and RFC 8594.
 */
const deprecationDates = createRulesetFunction(
  { input: { type: 'object' }, options: null },
  (operation, _options, context) => {
    if (operation.deprecated !== true) return;
    const results = [];
    for (const field of ['x-hdf-deprecation', 'x-hdf-sunset']) {
      if (typeof operation[field] !== 'string') {
        results.push({
          message: `a deprecated operation must carry ${field}`,
          path: [...context.path],
        });
      }
    }
    const from = operation['x-hdf-deprecation'];
    const until = operation['x-hdf-sunset'];
    if (typeof from === 'string' && typeof until === 'string' && from > until) {
      results.push({
        message: `x-hdf-deprecation (${from}) is after x-hdf-sunset (${until})`,
        path: [...context.path],
      });
    }
    return results;
  },
);

export default {
  extends: [oas],
  rules: {
    'hdf-deprecation-dates': {
      description:
        'A deprecated operation carries x-hdf-deprecation and x-hdf-sunset, and deprecates no later than it sunsets.',
      // {{error}} surfaces the function's own message, which names the missing field or
      // the inverted pair. Without it Spectral reports only the description, and a
      // developer is told a rule failed without being told what to fix.
      message: '{{error}}',
      severity: 'error',
      given: '$.paths[*][get,put,post,delete,patch,options,head]',
      then: { function: deprecationDates },
    },
  },
  overrides: [
    {
      // Scoped to the one path, not the rule: `Input_Constraints.allowedValues` is declared
      // `type: array` with no `items`, which is a real schema defect tracked separately.
      // Turning the rule off repo-wide would hide the next one; this waiver disappears when
      // that card lands and the schema declares its item type.
      files: ['**#/components/schemas/Input_Constraints/properties/allowedValues'],
      rules: { 'array-items': 'off' },
    },
    {
      // oas3-operation-security-defined requires every scope in a security requirement to
      // appear in the scheme's own `scopes` map — which only exists for oauth2 and
      // openIdConnect flows. This document declares one `http`/`bearer` scheme, and
      // OpenAPI 3.1.1 §4.8.30 says that for a non-oauth2 scheme "the array MAY contain a
      // list of role names" with no corresponding declaration, so the construct is legal
      // and the rule has nothing to validate it against. The closed vocabulary is still
      // advertised, as `x-hdf-scopes` on the scheme, and a test asserts every operation's
      // scopes come from it.
      files: ['**/dist/hdf-api.oas.json'],
      rules: { 'oas3-operation-security-defined': 'off' },
    },
    {
      // No `servers`, deliberately: ADR-0008 §6 records that this document describes a
      // contract rather than a deployment, and a templated server whose default is `/`
      // fails oas3-server-variables because every substitution must yield a valid URL.
      files: ['**/dist/hdf-api.oas.json'],
      rules: { 'oas3-api-servers': 'off' },
    },
    {
      // engine.statusCounts and engine.thresholdConfig are registered because the MCP
      // exposes them, and referenced by no operation because the reply they are parts of
      // has no whole-response shape yet — which RESPONSE_SHAPE_EXEMPT.hdf_compliance
      // records. A test asserts these are the ONLY unreferenced components, so this waiver
      // cannot absorb a third.
      files: ['**/dist/hdf-api.oas.json'],
      rules: { 'oas3-unused-component': 'off' },
    },
  ],
};
