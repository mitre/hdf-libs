import type { Checksum } from '@mitre/hdf-schema';
import { inputChecksum, validateInputSize } from '../../../shared/typescript/converterutil.js';
import { parseCklb, checklistToHdf } from '../../../shared/typescript/checklist/index.js';

/**
 * Convert a DISA STIG Viewer 3.x .cklb document to HDF Results JSON.
 *
 * Parsing and the HDF mapping live in the shared checklist module. v3.2
 * classification: controlType is derived per-rule from CCI->NIST;
 * verificationMethod and applicability are omitted (the checklist format
 * cannot substantiate them — see the Go package doc and build-converter
 * skill Step 4d).
 */
export async function convertCklbToHdf(input: string): Promise<string> {
  validateInputSize(input, 'cklb-to-hdf');
  const resultsChecksum: Checksum = await inputChecksum(input);
  const checklist = parseCklb(input);
  return JSON.stringify(checklistToHdf(checklist, resultsChecksum), null, 2);
}
