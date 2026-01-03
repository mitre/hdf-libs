/**
 * Extract CCI and NIST mapping data from heimdall2 TypeScript files
 * and convert them to JSON format.
 *
 * Run with: tsx scripts/extract-data.ts
 */

import { writeFileSync, mkdirSync } from 'fs';
import { join } from 'path';

// Import the data directly from heimdall2 (using absolute path)
const cciUtilPath = '/home/testuser/repos/mitre/heimdall2/apps/frontend/src/utilities/cci_util';
const nistUtilPath = '/home/testuser/repos/mitre/heimdall2/apps/frontend/src/utilities/nist_util';

async function extractData(): Promise<void> {
  const DATA_DIR = join(process.cwd(), 'src', 'data');
  mkdirSync(DATA_DIR, { recursive: true });

  console.log('Extracting CCI data...');
  try {
    const cciModule = await import(cciUtilPath);
    const cciData = cciModule.CCI_DESCRIPTIONS;
    const cciOutputPath = join(DATA_DIR, 'cci-mappings.json');
    writeFileSync(cciOutputPath, JSON.stringify(cciData, null, 2));
    console.log(`  ✓ Wrote ${Object.keys(cciData).length} CCI mappings`);
  } catch (error) {
    console.error('Failed to extract CCI data:', error);
  }

  console.log('Extracting NIST data...');
  try {
    const nistModule = await import(nistUtilPath);
    const nistData = nistModule.NIST_DESCRIPTIONS;
    const nistOutputPath = join(DATA_DIR, 'nist-descriptions.json');
    writeFileSync(nistOutputPath, JSON.stringify(nistData, null, 2));
    console.log(`  ✓ Wrote ${Object.keys(nistData).length} NIST descriptions`);
  } catch (error) {
    console.error('Failed to extract NIST data:', error);
  }

  console.log('Done.');
}

extractData().catch((error) => {
  console.error('Extraction failed:', error);
  process.exit(1);
});
