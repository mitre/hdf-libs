// The hand-authored shape inputs, and the rules that keep them the ONLY ones.
//
// ADR-0008 §2 admits src/conventions/ as the single place a shape may be authored rather
// than generated, on three conditions: each component carries an example that is checked,
// none redefines an HDF document type, and the binding table references them by name only.
// This module supplies the names and the loader; the tests enforce the conditions.

import { readFileSync, readdirSync } from 'fs';
import { dirname, join } from 'path';
import { fileURLToPath } from 'url';
import { parse as parseYaml } from 'yaml';

const HERE = dirname(fileURLToPath(import.meta.url));
export const CONVENTIONS_DIR = join(HERE, 'conventions');

export interface ConventionComponent {
  file: string;
  /** The component name the binding table references, derived from the title. */
  name: string;
  schema: Record<string, unknown>;
}

/** PascalCase from the title, so the file, the title and the reference cannot disagree. */
export function componentName(title: string): string {
  return title
    .replace(/[^A-Za-z0-9]+/g, ' ')
    .trim()
    .split(' ')
    .filter((w) => w.length > 0)
    // charAt rather than [0]: an index read is possibly-undefined under this tsconfig,
    // and a title that reduces to no words should yield '' rather than throw.
    .map((w) => w.charAt(0).toUpperCase() + w.slice(1))
    .join('');
}

export function loadConventions(dir: string = CONVENTIONS_DIR): ConventionComponent[] {
  return readdirSync(dir)
    .filter((f) => f.endsWith('.yaml'))
    .sort()
    .map((file) => {
      const schema = parseYaml(readFileSync(join(dir, file), 'utf-8')) as Record<string, unknown>;
      const title = schema.title;
      if (typeof title !== 'string' || title.length === 0) {
        throw new Error(`${file} carries no title, so it has no component name`);
      }
      return { file, name: componentName(title), schema };
    });
}
