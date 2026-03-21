/**
 * Conveyor format fingerprint.
 *
 * Exports a ConverterFingerprint object (data only, no converter import).
 * Detects JSON with api_response.results structure.
 */

import { registerFingerprint, getFingerprint, type ConverterFingerprint } from '../../../shared/typescript/registry.js';

export const conveyorFingerprint: ConverterFingerprint = {
  id: 'conveyor-to-hdf',
  label: 'Conveyor',
  direction: 'ingest',
  inputFamily: 'json',
  outputType: 'results',
  fingerprint: (input: unknown): number => {
    if (typeof input !== 'object' || input === null) return 0;
    const obj = input as Record<string, unknown>;
    // Primary: api_response with results
    if (typeof obj.api_response === 'object' && obj.api_response !== null) {
      const resp = obj.api_response as Record<string, unknown>;
      if (typeof resp.results === 'object' && resp.results !== null) return 1.0;
      // Has api_response but no results — still likely Conveyor
      return 0.6;
    }
    // Secondary: has api_server_version (Conveyor-specific field)
    if (typeof obj.api_server_version === 'string') return 0.5;
    return 0;
  },
};

export function register(): void {
  if (getFingerprint('conveyor-to-hdf')) return;
  registerFingerprint(conveyorFingerprint);
}
