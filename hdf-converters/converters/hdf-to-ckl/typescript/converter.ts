import { hdfToChecklist, serializeCkl } from '../../../shared/typescript/checklist/index.js';

/**
 * Convert HDF Results JSON into a DISA STIG Viewer checklist (.ckl XML).
 *
 * This is a thin wrapper over the shared checklist module, mirroring the
 * hdf-to-csv reverse converter. It produces a STIG Viewer 2.x .ckl from ANY
 * HDF: when the HDF carries checklist passthrough (extensions/tags written by
 * a prior ckl/cklb-to-hdf conversion) the original fields are reproduced
 * losslessly; otherwise the required checklist fields are synthesized
 * best-effort (id->Vuln_Num, nist->CCI reverse, status reverse) with safe
 * defaults. Mirrors heimdall2 PR #4841.
 *
 * @param input HDF Results JSON string
 * @returns CKL XML string (with the `<?xml ...?>` header)
 */
export function convertHdfToCkl(input: string): string {
  return serializeCkl(hdfToChecklist(input));
}
