// Re-records test/baseline/contract.json. Run it after deliberately bumping API_VERSION,
// and review the diff: a digest moving with no version change is the thing the baseline
// exists to refuse.
import { writeFileSync } from 'fs';
import { dirname, join } from 'path';
import { fileURLToPath } from 'url';

const HERE = dirname(fileURLToPath(import.meta.url));
const { generateApiDocument, contractDigest, API_VERSION } = await import(
  join(HERE, '..', 'dist', 'index.js')
);

const target = join(HERE, '..', 'test', 'baseline', 'contract.json');
const recorded = {
  $comment:
    "The reference API's identity. A changed digest under an unchanged version fails " +
    'test/contract-version.test.ts: bump API_VERSION in src/generate-api.ts, then re-record ' +
    'with `pnpm run contract:update`. The digest covers the whole document except info, so it ' +
    'moves for a schema change, a golden change, a binding or conventions change, and a ' +
    'generator change.',
  version: API_VERSION,
  digest: contractDigest(generateApiDocument()),
};
writeFileSync(target, `${JSON.stringify(recorded, null, 2)}\n`);
process.stdout.write(`contract baseline: v${recorded.version} ${recorded.digest}\n`);
