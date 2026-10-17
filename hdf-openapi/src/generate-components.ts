import { mkdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { stringify as stringifyYaml } from 'yaml';
import { buildComponentsDocument } from './components.js';
import { EMBED_DIR, loadBundles } from './embed.js';
import { loadProblemDocs } from './problems.js';
import { writeArtifact } from './write-artifact.js';

const HERE = dirname(fileURLToPath(import.meta.url));

/** Build entry point: writes the JSON and YAML artifacts into dist/. */
export function main(): void {
  const outDir = join(HERE, '..', 'dist');
  mkdirSync(outDir, { recursive: true });
  const doc = buildComponentsDocument(loadBundles(EMBED_DIR));
  writeArtifact(join(outDir, 'hdf-components.oas.json'), `${JSON.stringify(doc, null, 2)}\n`);
  writeArtifact(join(outDir, 'hdf-components.oas.yaml'), stringifyYaml(doc, { lineWidth: 0 }));
  // RFC 9457 §3.1.1 wants a type URI to dereference to documentation, so the table that
  // documents them ships with the documents that declare them.
  writeArtifact(join(outDir, 'problems.json'), `${JSON.stringify(loadProblemDocs(), null, 2)}\n`);
  const count = Object.keys(doc.components.schemas).length;
  process.stdout.write(`hdf-components.oas.{json,yaml}: ${count} schemas at v${doc.info.version}\n`);
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  main();
}
