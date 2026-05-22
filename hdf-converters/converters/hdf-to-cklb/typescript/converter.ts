import { hdfToChecklist, serializeCklb } from '../../../shared/typescript/checklist/index.js';

/**
 * Convert HDF Results JSON into a DISA STIG Viewer 3.x checklist (.cklb, JSON).
 *
 * The HDF->checklist mapping and CKLB serialization live in the shared
 * checklist module; this converter is a thin wrapper. Any HDF input produces a
 * valid CKLB: when the HDF carries checklist passthrough (it originated from a
 * CKL/CKLB via the reverse converters), the original fields are reproduced
 * losslessly; otherwise the required checklist fields are synthesized
 * best-effort from the HDF requirements, tags, and results.
 *
 * @param input HDF Results JSON string
 * @returns CKLB JSON string
 */
export function convertHdfToCklb(input: string): string {
  return serializeCklb(hdfToChecklist(input));
}
