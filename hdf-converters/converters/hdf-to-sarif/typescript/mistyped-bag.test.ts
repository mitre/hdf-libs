import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { parseTimestamp } from '@mitre/hdf-utilities';
import { validateResults } from '@mitre/hdf-validators';
import { convertSarifToHdf } from '../../sarif-to-hdf/typescript/converter.js';
import { convertHdfToSarif } from './converter.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const TEST_VERSION = '0.0.0';

type Json = Record<string, unknown>;

interface MistypedBagCase {
  on: 'run' | 'rule' | 'result';
  key: string;
  value: unknown;
  why: string;
}

// The Go peer, go/mistyped_bag_test.go, reads the same table.
const cases = (
  JSON.parse(readFileSync(join(__dirname, '..', 'fixtures', 'mistyped-bag-cases.json'), 'utf-8')) as {
    cases: MistypedBagCase[];
  }
).cases;

/** The grype exporter fixture with a waiver on its first requirement, as in Go. */
function seededOverrideHdf(): string {
  const raw = readFileSync(join(__dirname, '..', 'fixtures', 'input', 'grype-cve.hdf.json'), 'utf8');
  const doc = JSON.parse(raw) as Json;
  const req = ((doc.baselines as Json[])[0]!.requirements as Json[])[0]!;
  req.statusOverrides = [{
    type: 'waiver', status: 'passed', reason: 'ISSM accepted',
    appliedBy: {type: 'username', identifier: 'jane.doe'},
    appliedAt: '2026-01-15T00:00:00Z',
    expiresAt: '2099-12-31T00:00:00Z',
  }];
  return JSON.stringify(doc);
}

/** The exported SARIF with the case's key set to its value, or removed. */
function mistypedBagDoc(sarif: string, c: MistypedBagCase, set: boolean): string {
  const doc = JSON.parse(sarif) as Json;
  const run = (doc.runs as Json[])[0]!;
  const rule = (((run.tool as Json).driver as Json).rules as Json[])[0]!;
  let bag: Json | undefined;
  if (c.on === 'run') bag = (run.properties as Json).hdf as Json;
  if (c.on === 'rule') bag = (rule.properties as Json).hdf as Json;
  if (c.on === 'result') {
    const res = (run.results as Json[]).find(r => r.ruleId === rule.id)!;
    bag = ((res.properties as Json).hdf as Json).result as Json;
  }
  expect(bag, `no ${c.on} bag to mangle`).toBeDefined();
  if (set) bag![c.key] = c.value;
  else delete bag![c.key];
  return JSON.stringify(doc);
}

/** The default expiry is a calendar year on, as in Go's AddDate(1, 0, 0). */
function addYears(ms: number, years: number): number {
  const d = new Date();
  d.setTime(ms);
  d.setUTCFullYear(d.getUTCFullYear() + years);
  return d.getTime();
}

/** Masks what differs between two conversions, as Go's comparableBaseline does. */
function comparableBaseline(hdf: string, start: number, end: number): unknown {
  const b = ((JSON.parse(hdf) as Json).baselines as Json[])[0]!;
  delete b.resultsChecksum;
  const mask = (v: unknown): unknown => {
    if (Array.isArray(v)) return v.map(mask);
    if (v && typeof v === 'object') {
      const o = v as Json;
      delete o.rawSourceRecord;
      for (const k of Object.keys(o)) o[k] = mask(o[k]);
      return o;
    }
    if (typeof v === 'string') {
      const ms = parseTimestamp(v)?.getTime();
      if (ms !== undefined && [0, 1].some(years => ms >= addYears(start, years) && ms <= addYears(end, years))) {
        return '<conversion time>';
      }
    }
    return v;
  };
  return mask(b);
}

describe('sarif-to-hdf restore of a mistyped hdf bag value', () => {
  it.each(cases.map(c => [`${c.on}/${c.key}=${JSON.stringify(c.value)}`, c] as const))(
    'drops %s', async (_name, c) => {
      const sarif = await convertHdfToSarif(seededOverrideHdf(), TEST_VERSION);
      const start = Date.now() - 1000;
      const got = await convertSarifToHdf(mistypedBagDoc(sarif, c, true), TEST_VERSION);
      const want = await convertSarifToHdf(mistypedBagDoc(sarif, c, false), TEST_VERSION);
      const end = Date.now() + 1000;

      const v = validateResults(JSON.parse(got));
      expect(v.valid, `${c.why}: ${v.getErrorMessage()}`).toBe(true);
      expect(comparableBaseline(got, start, end), c.why).toEqual(comparableBaseline(want, start, end));
    });
});
