/**
 * AWS Security Finding Format (ASFF) fingerprint.
 *
 * ASFF's distinctive marker is a finding's `ProductArn`; a second ASFF-shaped
 * field (GeneratorId / Types / Resources) raises confidence. Input may be a
 * `{ "Findings": [...] }` envelope, a bare array, or a single finding object.
 */

import { registerFingerprint, getFingerprint, type ConverterFingerprint } from '../../../shared/typescript/registry.js';

function isAsffFinding(obj: Record<string, unknown>): number {
  if (typeof obj.ProductArn !== 'string' || obj.ProductArn === '') return 0;
  if ('GeneratorId' in obj || 'Types' in obj || 'Resources' in obj) return 0.95;
  return 0.8;
}

export const asffFingerprint: ConverterFingerprint = {
  id: 'asff-to-hdf',
  label: 'AWS Security Finding Format',
  direction: 'ingest',
  inputFamily: 'json',
  outputType: 'results',
  fingerprint: (input: unknown): number => {
    if (typeof input !== 'object' || input === null) return 0;

    // { "Findings": [...] } envelope
    if (!Array.isArray(input) && 'Findings' in input) {
      const findings = (input as { Findings: unknown }).Findings;
      if (!Array.isArray(findings) || findings.length === 0) return 0;
      const first = findings[0];
      if (typeof first !== 'object' || first === null) return 0;
      return isAsffFinding(first as Record<string, unknown>);
    }

    // Bare array of findings
    if (Array.isArray(input)) {
      if (input.length === 0) return 0;
      const first = input[0];
      if (typeof first !== 'object' || first === null) return 0;
      return isAsffFinding(first as Record<string, unknown>);
    }

    // Single finding object
    return isAsffFinding(input as Record<string, unknown>);
  },
};

export function register(): void {
  if (getFingerprint('asff-to-hdf')) return;
  registerFingerprint(asffFingerprint);
}
