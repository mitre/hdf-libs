import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { stringify as stringifyYaml } from 'yaml';
import { buildComponentsDocument } from './components.js';
import { EMBED_DIR, loadBundles } from './embed.js';

const HERE = dirname(fileURLToPath(import.meta.url));

/** Build entry point: writes the JSON and YAML artifacts into dist/. */
export function main(): void {
  const outDir = join(HERE, '..', 'dist');
  mkdirSync(outDir, { recursive: true });
  const doc = buildComponentsDocument(loadBundles(EMBED_DIR));
  writeFileSync(join(outDir, 'hdf-components.oas.json'), `${JSON.stringify(doc, null, 2)}\n`);
  writeFileSync(join(outDir, 'hdf-components.oas.yaml'), stringifyYaml(doc, { lineWidth: 0 }));
  const count = Object.keys(doc.components.schemas).length;
  process.stdout.write(`hdf-components.oas.{json,yaml}: ${count} schemas at v${doc.info.version}\n`);
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  main();
}
