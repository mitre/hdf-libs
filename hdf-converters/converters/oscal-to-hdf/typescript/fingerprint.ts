/**
 * OSCAL document type fingerprints.
 *
 * Registers 7 separate ConverterFingerprint entries, one for each OSCAL
 * document type. Each checks for its specific top-level JSON key.
 *
 * No converter imports — data only, safe for client bundles.
 */

import { registerFingerprint, getFingerprint, type ConverterFingerprint, type OutputType } from '../../../shared/typescript/registry.js';

interface OscalFingerprintSpec {
  key: string;
  id: string;
  label: string;
  outputType: OutputType;
}

const OSCAL_SPECS: OscalFingerprintSpec[] = [
  { key: 'system-security-plan', id: 'oscal-ssp-to-hdf', label: 'OSCAL SSP', outputType: 'raw' },
  { key: 'assessment-plan', id: 'oscal-sap-to-hdf', label: 'OSCAL SAP', outputType: 'plan' },
  { key: 'assessment-results', id: 'oscal-sar-to-hdf', label: 'OSCAL SAR', outputType: 'results' },
  { key: 'plan-of-action-and-milestones', id: 'oscal-poam-to-hdf', label: 'OSCAL POA&M', outputType: 'amendments' },
  { key: 'profile', id: 'oscal-profile-to-hdf', label: 'OSCAL Profile', outputType: 'baseline' },
  { key: 'catalog', id: 'oscal-catalog-to-hdf', label: 'OSCAL Catalog', outputType: 'baseline' },
  { key: 'component-definition', id: 'oscal-component-to-hdf', label: 'OSCAL Component', outputType: 'baseline' },
];

function oscalDetectVersion(rootKey: string, input: unknown): string {
  if (typeof input !== 'object' || input === null) return '';
  const obj = input as Record<string, unknown>;
  const root = obj[rootKey] as Record<string, unknown> | undefined;
  if (!root || typeof root !== 'object') return '';
  const meta = root.metadata as Record<string, unknown> | undefined;
  if (!meta || typeof meta !== 'object') return '';
  return typeof meta['oscal-version'] === 'string' ? meta['oscal-version'] : '';
}

function buildFingerprint(spec: OscalFingerprintSpec): ConverterFingerprint {
  return {
    id: spec.id,
    label: spec.label,
    direction: 'ingest',
    inputFamily: 'json',
    outputType: spec.outputType,
    fingerprint: (input: unknown): number => {
      if (typeof input !== 'object' || input === null || Array.isArray(input)) return 0;
      const obj = input as Record<string, unknown>;
      if (spec.key in obj) return 1.0;
      return 0;
    },
    detectVersion: (input: unknown): string => oscalDetectVersion(spec.key, input),
  };
}

export const oscalFingerprints: ConverterFingerprint[] = OSCAL_SPECS.map(buildFingerprint);

export function register(): void {
  for (const fp of oscalFingerprints) {
    if (getFingerprint(fp.id)) continue;
    registerFingerprint(fp);
  }
}
