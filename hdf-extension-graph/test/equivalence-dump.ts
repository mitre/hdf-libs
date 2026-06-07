// Produces the canonical JSON description of an extension graph consumed by
// cross-language-equivalence.test.ts. The matching Go producer lives at
// ../go/cmd/equivalence-dump/main.go; both must emit the same shape with the
// same array orderings (baselines by name; requirements by baselineName then
// id; extendsFromNames/extendedByNames sorted; modifications sorted by field;
// extensionChainNames preserved in chain order).
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { normalizeTimestamps } from '@mitre/hdf-parsers';
import type { HDFResults } from '@mitre/hdf-schema';
import { buildExtensionGraph } from '../src/index.js';

interface ModDump {
  field: string;
  originalValue: unknown;
  newValue: unknown;
  inBaseline: string;
}

interface BaselineDump {
  name: string;
  parentBaseline: string | null;
  extendsFromNames: string[];
  extendedByNames: string[];
  requirementCount: number;
}

interface ReqDump {
  baselineName: string;
  id: string;
  isRoot: boolean;
  rootBaselineName: string;
  rootId: string;
  isRedundant: boolean;
  fullCodeSHA256: string;
  extensionChainNames: string[];
  modifications: ModDump[];
}

export interface EquivalenceDump {
  baselineCount: number;
  requirementCount: number;
  baselines: BaselineDump[];
  requirements: ReqDump[];
}

function sha256Hex(s: string): string {
  if (!s) return '';
  return createHash('sha256').update(s).digest('hex');
}

// undefined → null so the shape matches Go's JSON-marshaled `any` nil.
function normalizeValue(v: unknown): unknown {
  return v === undefined ? null : v;
}

export function dump(results: HDFResults): EquivalenceDump {
  const g = buildExtensionGraph(results);

  // All sorts use code-point order (raw `<`/`>`) to match Go's byte-wise
  // string comparison — localeCompare is case-insensitive in some locales and
  // would diverge (e.g. "simple" vs "SV-*").
  const cp = (a: string, b: string): number => (a < b ? -1 : a > b ? 1 : 0);

  const baselines: BaselineDump[] = g.baselines.map((b) => ({
    name: b.data.name,
    parentBaseline: b.data.parentBaseline ?? null,
    extendsFromNames: [...b.extendsFrom.map((p) => p.data.name)].sort(cp),
    extendedByNames: [...b.extendedBy.map((c) => c.data.name)].sort(cp),
    requirementCount: b.requirements.length,
  })).sort((a, b) => cp(a.name, b.name));

  const requirements: ReqDump[] = g.requirements.map((r) => {
    const root = r.root;
    return {
      baselineName: r.sourcedFrom.data.name,
      id: r.data.id,
      isRoot: r.extendsFrom.length === 0,
      rootBaselineName: root.sourcedFrom.data.name,
      rootId: root.data.id,
      isRedundant: r.isRedundant,
      fullCodeSHA256: sha256Hex(r.fullCode),
      extensionChainNames: r.extensionChain.map((c) => c.data.name),
      modifications: r.modifications
        .map((m) => ({
          field: m.field,
          originalValue: normalizeValue(m.originalValue),
          newValue: normalizeValue(m.newValue),
          inBaseline: m.inBaseline,
        }))
        .sort((a, b) => cp(a.field, b.field)),
    };
  }).sort((a, b) => {
    if (a.baselineName !== b.baselineName) return cp(a.baselineName, b.baselineName);
    return cp(a.id, b.id);
  });

  return {
    baselineCount: g.baselines.length,
    requirementCount: g.requirements.length,
    baselines,
    requirements,
  };
}

// Fixtures emit timezone-less timestamps (real InSpec output shape) that
// Go's time.Time JSON unmarshal rejects. Both sides apply hdf-parsers'
// normalizeTimestamps so they read the same canonical string.
export function loadFixture(path: string): HDFResults {
  const raw = normalizeTimestamps(readFileSync(path, 'utf-8'));
  return JSON.parse(raw) as HDFResults;
}

// CLI mode: `pnpm tsx test/equivalence-dump.ts <fixture.json>` for local debugging.
if (import.meta.url === `file://${process.argv[1]}`) {
  if (process.argv.length !== 3) {
    process.stderr.write('usage: equivalence-dump.ts <fixture.json>\n');
    process.exit(2);
  }
  const results = loadFixture(process.argv[2]!);
  process.stdout.write(JSON.stringify(dump(results), null, 2) + '\n');
}
