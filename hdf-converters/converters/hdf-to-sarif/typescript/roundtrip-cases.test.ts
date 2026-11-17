import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { convertSarifToHdf } from '../../sarif-to-hdf/typescript/converter.js';
import { convertHdfToSarif } from './converter.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const TEST_VERSION = '0.0.0';

type Json = Record<string, unknown>;

/** fixtures/roundtrip-cases.json; go/roundtrip_cases_test.go reads the same table. */
interface RoundTripCases {
  multiLocation: {
    source: string;
    run: number;
    keepRules: number;
    keepResults: number[];
    resultBags: (Json | null)[];
  };
  levelAgainstSecuritySeverity: { wantLevel: string; sarif: Json };
}

const cases = JSON.parse(
  readFileSync(join(__dirname, '..', 'fixtures', 'roundtrip-cases.json'), 'utf-8'),
) as RoundTripCases;

/** Trims the source document to the kept elements and writes the table's bags. */
function multiLocationInput(): Json {
  const c = cases.multiLocation;
  const doc = JSON.parse(readFileSync(join(__dirname, '..', '..', c.source), 'utf-8')) as Json;
  const run = (doc.runs as Json[])[c.run]!;
  const driver = (run.tool as Json).driver as Json;
  driver.rules = (driver.rules as Json[]).slice(0, c.keepRules);
  const all = run.results as Json[];
  run.results = c.keepResults.map((idx, pos) => {
    const res = all[idx]!;
    const bag = c.resultBags[pos];
    if (bag) res.properties = bag;
    return res;
  });
  doc.runs = [run];
  return doc;
}

async function roundTrip(input: Json): Promise<Json> {
  const hdf = await convertSarifToHdf(JSON.stringify(input), TEST_VERSION);
  return JSON.parse(await convertHdfToSarif(hdf, TEST_VERSION)) as Json;
}

function physical(loc: Json): Json {
  return loc.physicalLocation as Json;
}

describe('SARIF -> HDF -> SARIF, shared round-trip cases', () => {
  // A result at N locations becomes N results, and each must come back at the
  // location it was expanded from and with the bag of the result it came from.
  it('gives each expanded result its own location and bag', async () => {
    const input = multiLocationInput();
    const want: { location: Json; bag?: Json }[] = [];
    for (const res of (input.runs as Json[])[0]!.results as Json[]) {
      for (const location of res.locations as Json[]) {
        want.push({ location, bag: res.properties as Json | undefined });
      }
    }
    expect(want.length, 'the case must hold a result with more than one location').toBeGreaterThan(
      cases.multiLocation.keepResults.length,
    );

    const after = await roundTrip(input);
    const got = (after.runs as Json[])[0]!.results as Json[];
    expect(got).toHaveLength(want.length);
    got.forEach((res, i) => {
      const locs = res.locations as Json[];
      expect(locs, `result ${i}`).toHaveLength(1);
      const gotPhys = physical(locs[0]!);
      const wantPhys = physical(want[i]!.location);
      expect(gotPhys.region, `result ${i}: region`).toEqual(wantPhys.region);
      expect((gotPhys.artifactLocation as Json).uri, `result ${i}: uri`).toBe(
        (wantPhys.artifactLocation as Json).uri,
      );

      const gotBag = (res.properties as Json | undefined) ?? {};
      const mine = want[i]!.bag ?? {};
      for (const [k, v] of Object.entries(mine)) {
        expect(gotBag[k], `result ${i}: bag key ${k}`).toEqual(v);
      }
      for (const other of cases.multiLocation.resultBags) {
        for (const k of Object.keys(other ?? {})) {
          if (!(k in mine)) expect(gotBag, `result ${i} carries another result's bag`).not.toHaveProperty(k);
        }
      }
    });
  });

  // Impact derives from security-severity on import, so re-deriving the level from
  // impact on export rewrites a rule level the tool stated.
  it('keeps a rule level that security-severity disagrees with', async () => {
    const c = cases.levelAgainstSecuritySeverity;
    const after = await roundTrip(c.sarif);
    const run = (after.runs as Json[])[0]!;
    const rule = (((run.tool as Json).driver as Json).rules as Json[])[0]!;
    const ruleDefault = (rule.defaultConfiguration as Json | undefined)?.level;
    expect(ruleDefault, 'rule defaultConfiguration.level').toBe(c.wantLevel);
    const res = (run.results as Json[])[0]!;
    // A failing result's resolved level is its own, else the rule's (SARIF 3.27.10).
    expect((res.level as string | undefined) ?? ruleDefault, 'resolved result level').toBe(c.wantLevel);
  });
});
