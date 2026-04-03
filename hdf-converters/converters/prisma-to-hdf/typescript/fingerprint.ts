/**
 * Prisma Cloud CSV format fingerprint.
 *
 * Exports a ConverterFingerprint object (data only, no converter import).
 * Confidence 0.85 — text/CSV input with Prisma-specific column headers.
 */

import { registerFingerprint, getFingerprint, type ConverterFingerprint } from '../../../shared/typescript/registry.js';

/** Columns that uniquely identify Prisma Cloud CSV output */
const PRISMA_COLUMNS = ['Hostname', 'Compliance ID', 'Severity', 'Type', 'Description'];

export const prismaFingerprint: ConverterFingerprint = {
  id: 'prisma-to-hdf',
  label: 'Prisma Cloud CSV',
  direction: 'ingest',
  inputFamily: 'text',
  outputType: 'results',
  fingerprint: (input: unknown): number => {
    if (typeof input !== 'string') return 0;
    // Get the first line (header row) from the CSV
    const firstNewline = input.indexOf('\n');
    const headerLine = firstNewline === -1 ? input : input.substring(0, firstNewline);
    if (!headerLine.trim()) return 0;

    // Check if all required Prisma columns are present in the header
    const matchCount = PRISMA_COLUMNS.filter(col => headerLine.includes(col)).length;
    if (matchCount === PRISMA_COLUMNS.length) return 0.85;
    // Partial match — at least 3 of 5 columns suggests Prisma-like CSV
    if (matchCount >= 3) return 0.4;
    return 0;
  },
};

export function register(): void {
  if (getFingerprint('prisma-to-hdf')) return;
  registerFingerprint(prismaFingerprint);
}
