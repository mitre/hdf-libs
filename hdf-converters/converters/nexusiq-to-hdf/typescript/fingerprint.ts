/**
 * Nexus IQ policy-evaluation result fingerprint.
 *
 * Keys on the envelope every IQ CLI result carries, including one with no
 * violations; an alert's policyViolationId confirms it.
 */

import {
  registerFingerprint,
  getFingerprint,
  type ConverterFingerprint,
} from '../../../shared/typescript/registry.js';

function isObject(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

export function fingerprintObject(obj: Record<string, unknown>): number {
  if (typeof obj.applicationId !== 'string') return 0;
  if (typeof obj.scanId !== 'string') return 0;
  const result = obj.policyEvaluationResult;
  if (!isObject(result)) return 0;
  const alerts = result.alerts;
  if (Array.isArray(alerts) && alerts.length > 0) {
    const alert = alerts[0];
    if (isObject(alert) && isObject(alert.trigger) && typeof alert.trigger.policyViolationId === 'string') {
      return 1.0;
    }
  }
  return 0.9;
}

export const nexusiqFingerprint: ConverterFingerprint = {
  id: 'nexusiq-to-hdf',
  label: 'Nexus IQ',
  direction: 'ingest',
  inputFamily: 'json',
  outputType: 'results',
  fingerprint: (input: unknown): number => (isObject(input) ? fingerprintObject(input) : 0),
};

export function register(): void {
  if (getFingerprint('nexusiq-to-hdf')) return;
  registerFingerprint(nexusiqFingerprint);
}
