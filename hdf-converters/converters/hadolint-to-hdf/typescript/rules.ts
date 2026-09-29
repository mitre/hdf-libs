/**
 * Rule documentation links for the hadolint converter.
 *
 * hadolint's report carries a one-line message per finding and nothing else.
 * Each rule's rationale and fix live on a wiki page, and the two rule families
 * are documented in different projects, so every requirement links its own.
 *
 * Twin of go/rules.go.
 */

const HADOLINT_RULE_BASE = 'https://github.com/hadolint/hadolint/wiki';
const SHELLCHECK_RULE_BASE = 'https://github.com/koalaman/shellcheck/wiki';

/** Matches hadolint's own rule codes and the shellcheck codes it surfaces. */
const RULE_CODE = /^(DL|SC)\d+$/;

/** hadolint surfaces shellcheck's findings in its own report. */
function isShellcheck(code: string): boolean {
  return code.startsWith('SC');
}

/**
 * The published documentation for a rule, or an empty string when the code is
 * not one. The code is checked first, so a report carrying a crafted code
 * cannot steer the link somewhere of its choosing.
 */
export function ruleReferenceUrl(code: string): string {
  if (!RULE_CODE.test(code)) return '';
  return `${isShellcheck(code) ? SHELLCHECK_RULE_BASE : HADOLINT_RULE_BASE}/${code}`;
}
