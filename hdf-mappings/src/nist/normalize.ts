/**
 * NIST SP 800-53 identifier spelling normalization.
 *
 * Mirrors NormalizeID in go/nist/exists.go; both are pinned by the shared case
 * table go/nist/testdata/nist-id-spelling-cases.json.
 */

// Family, control number, then any run of enhancement numbers or statement
// letters, each written as " 3", "(3)" or " (3)", in any letter case. Keep identical to the Go pattern.
const NIST_ID = /^([A-Za-z]{2})-(\d{1,2})((?: ?\((?:\d{1,2}|[A-Za-z])\)| (?:\d{1,2}|[A-Za-z]))*)$/;
const NIST_ID_TOKEN = /\d+|[A-Za-z]/g;

function padNumber(token: string): string {
  return /^\d/.test(token) ? token.padStart(2, '0') : token;
}

/**
 * Normalize a NIST SP 800-53 identifier to the description-table spelling:
 * uppercase family, lowercase statement letters, zero-padded numbers and
 * space-separated parts.
 *
 * @param nistId - An identifier such as 'AC-2', 'AC-2(3)', 'AC-2 (3)', 'AC-02 03', 'AC-1 a 1' or 'ac-2'
 * @returns The table spelling (e.g. 'AC-02 03'), or undefined if the input is not
 *   a NIST identifier spelling. A defined result is not proof NIST defines the
 *   control; use nistExists for that.
 *
 * @example
 * ```typescript
 * normalizeNistId('AC-2 (3)');  // 'AC-02 03'
 * normalizeNistId('AC-2(3)(a)'); // 'AC-02 03 a'
 * normalizeNistId('SV-230221'); // undefined
 * ```
 */
export function normalizeNistId(nistId: string): string | undefined {
  if (typeof nistId !== 'string') {
    return undefined;
  }
  const match = NIST_ID.exec(nistId);
  if (!match) {
    return undefined;
  }
  const [, family, control, parts] = match;
  const tokens = parts!.match(NIST_ID_TOKEN) ?? [];
  return [
    `${family!.toUpperCase()}-${padNumber(control!)}`,
    ...tokens.map((token) => padNumber(token.toLowerCase())),
  ].join(' ');
}
