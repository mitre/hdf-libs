/**
 * hadolint format fingerprint.
 *
 * Detects a bare JSON array of findings carrying code, file, level, line and
 * message. A rule code in hadolint's own namespace (DL or SC) is the
 * distinguishing signal and scores 1.0; the field shape alone scores 0.6,
 * because another line-oriented linter could share it.
 *
 * Twin of go/fingerprint.go.
 */

import { registerFingerprint, getFingerprint, type ConverterFingerprint } from '../../../shared/typescript/registry.js';

const RULE_CODE = /^(DL|SC)\d+$/;
const LEVELS = new Set(['error', 'warning', 'info', 'style', '']);

function fingerprintFinding(obj: Record<string, unknown>): number {
  if (typeof obj.code !== 'string') return 0;
  if (typeof obj.file !== 'string' || typeof obj.message !== 'string') return 0;
  if (typeof obj.line !== 'number') return 0;
  if (typeof obj.level !== 'string' || !LEVELS.has(obj.level)) return 0;
  return RULE_CODE.test(obj.code) ? 1.0 : 0.6;
}

export const hadolintFingerprint: ConverterFingerprint = {
  id: 'hadolint-to-hdf',
  label: 'hadolint',
  direction: 'ingest',
  inputFamily: 'json',
  outputType: 'results',
  fingerprint: (input: unknown): number => {
    // An empty array is a clean run and indistinguishable from any other empty
    // array, so it scores nothing rather than claiming the input.
    if (!Array.isArray(input) || input.length === 0) return 0;
    const first = input[0] as Record<string, unknown>;
    if (typeof first !== 'object' || first === null) return 0;
    return fingerprintFinding(first);
  },
};

export function register(): void {
  if (getFingerprint('hadolint-to-hdf')) return;
  registerFingerprint(hadolintFingerprint);
}
