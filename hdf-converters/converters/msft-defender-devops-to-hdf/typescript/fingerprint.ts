/**
 * Microsoft Defender for DevOps (MSDO) SARIF format fingerprint.
 *
 * Exports a ConverterFingerprint object (data only, no converter import).
 * This is SARIF input enriched with MSDO-specific properties.
 * Confidence 0.95 so it outranks the generic SARIF fingerprint at 0.9.
 * Detects by checking for `version` + `runs[]` (SARIF) AND a tool.driver
 * containing 'Microsoft' or 'DevOps' in name/organization/product/fullName.
 */

import { registerFingerprint, getFingerprint, type ConverterFingerprint } from '../../../shared/typescript/registry.js';

function isMsdoDriver(driver: Record<string, unknown>): boolean {
  const fields = [
    driver.name,
    driver.organization,
    driver.product,
    driver.fullName,
  ];
  for (const field of fields) {
    if (typeof field === 'string') {
      const lower = field.toLowerCase();
      if (lower.includes('microsoft') || lower.includes('devops')) return true;
    }
  }
  return false;
}

export const msftDefenderDevopsFingerprint: ConverterFingerprint = {
  id: 'msft-defender-devops-to-hdf',
  label: 'Microsoft Defender for DevOps',
  direction: 'ingest',
  inputFamily: 'json',
  outputType: 'results',
  fingerprint: (input: unknown): number => {
    if (typeof input !== 'object' || input === null) return 0;
    const obj = input as Record<string, unknown>;
    // Must be SARIF: version string + runs array
    if (typeof obj.version !== 'string' || !Array.isArray(obj.runs)) return 0;
    // Check runs for MSDO-specific tool driver
    for (const run of obj.runs) {
      if (typeof run !== 'object' || run === null) continue;
      const r = run as Record<string, unknown>;
      const tool = r.tool as Record<string, unknown> | undefined;
      if (!tool || typeof tool !== 'object') continue;
      const driver = tool.driver as Record<string, unknown> | undefined;
      if (!driver || typeof driver !== 'object') continue;
      if (isMsdoDriver(driver)) return 0.95;
    }
    return 0;
  },
};

export function register(): void {
  if (getFingerprint('msft-defender-devops-to-hdf')) return;
  registerFingerprint(msftDefenderDevopsFingerprint);
}
