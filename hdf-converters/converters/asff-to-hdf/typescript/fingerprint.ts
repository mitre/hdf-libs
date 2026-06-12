/**
 * ASFF (AWS Security Finding Format) fingerprint.
 *
 * Exports a ConverterFingerprint object (data only, no converter import).
 * Detects JSON with the standard `{"Findings": [...]}` envelope where each
 * finding carries the AWS-specific SchemaVersion + ProductArn shape.
 */

import { registerFingerprint, getFingerprint, type ConverterFingerprint } from '../../../shared/typescript/registry.js';

export const asffFingerprint: ConverterFingerprint = {
  id: 'asff-to-hdf',
  label: 'ASFF (AWS Security Finding Format)',
  direction: 'ingest',
  inputFamily: 'json',
  outputType: 'results',
  fingerprint: (input: unknown): number => {
    if (typeof input !== 'object' || input === null) return 0;
    const obj = input as Record<string, unknown>;
    if (!Array.isArray(obj.Findings) || obj.Findings.length === 0) return 0;
    const first = obj.Findings[0];
    if (typeof first !== 'object' || first === null) return 0;
    const f = first as Record<string, unknown>;
    const hasSchemaVersion = 'SchemaVersion' in f;
    const hasProductArn = typeof f.ProductArn === 'string' && (f.ProductArn as string).length > 0;
    if (hasSchemaVersion && hasProductArn) return 1.0;
    if (hasProductArn) return 0.7;
    return 0;
  },
};

export function register(): void {
  if (getFingerprint('asff-to-hdf')) return;
  registerFingerprint(asffFingerprint);
}
