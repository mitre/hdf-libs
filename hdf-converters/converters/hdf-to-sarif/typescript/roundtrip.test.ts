import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { convertSarifToHdf } from '../../sarif-to-hdf/typescript/converter.js';
import { convertHdfToSarif } from './converter.js';

const __dirname = dirname(fileURLToPath(import.meta.url));

/** Matches the Go peer so both languages assert the same invariant. */
const TEST_VERSION = '0.0.0';

type Json = Record<string, unknown>;

/**
 * The round-trip invariant is defined once, on the epic's evaluation card, and this
 * file asserts exactly it — the TypeScript peer of go/roundtrip_test.go. Both must
 * assert the same thing: a loss one language catches and the other does not is how
 * the two drift.
 */

function sarifFixture(name: string): string {
  return readFileSync(join(__dirname, '..', '..', 'sarif-to-hdf', 'fixtures', 'input', name), 'utf8');
}

async function sarifToHdfToSarif(name: string): Promise<{before: Json; after: Json}> {
  const input = sarifFixture(name);
  const hdf = await convertSarifToHdf(input, TEST_VERSION);
  const out = await convertHdfToSarif(hdf, TEST_VERSION);
  return {before: JSON.parse(input) as Json, after: JSON.parse(out) as Json};
}

async function hdfToSarifToHdf(name: string): Promise<{before: Json; after: Json}> {
  const input = readFileSync(join(__dirname, '..', 'fixtures', 'input', name), 'utf8');
  const sarif = await convertHdfToSarif(input, TEST_VERSION);
  const back = await convertSarifToHdf(sarif, TEST_VERSION);
  return {before: JSON.parse(input) as Json, after: JSON.parse(back) as Json};
}

/** Results indexed by rule id, in document order. Identity, not array position. */
function resultsByRule(log: Json): Map<string, Json[]> {
  const out = new Map<string, Json[]>();
  for (const run of (log.runs as Json[] | undefined) ?? []) {
    for (const res of (run.results as Json[] | undefined) ?? []) {
      const id = (res.ruleId as string) ?? '';
      if (!out.has(id)) out.set(id, []);
      out.get(id)!.push(res);
    }
  }
  return out;
}

/** Every `properties` bag, keyed by a stable address — invariant item 7 requires a
 * bag to return to the object it came from, so the address is part of the claim. */
function bagsByObject(log: Json): Map<string, Json> {
  const out = new Map<string, Json>();
  const runs = (log.runs as Json[] | undefined) ?? [];
  runs.forEach((run, ri) => {
    if (run.properties) out.set(`run/${ri}`, run.properties as Json);
    const driver = (run.tool as Json | undefined)?.driver as Json | undefined;
    for (const rule of (driver?.rules as Json[] | undefined) ?? []) {
      if (rule.properties && rule.id) out.set(`rule/${ri}/${rule.id as string}`, rule.properties as Json);
    }
    ((run.results as Json[] | undefined) ?? []).forEach((res, si) => {
      if (res.properties) out.set(`result/${ri}/${si}`, res.properties as Json);
    });
  });
  return out;
}

describe('SARIF -> HDF -> SARIF', () => {
  const fixtures = ['sarif_input.sarif', 'rich.sarif', 'gosec.sarif', 'spotbugs.sarif'];

  it.each(fixtures)('%s: preserves the referenced rule set', async fixture => {
    const {before, after} = await sarifToHdfToSarif(fixture);
    const ids = (log: Json) => [...resultsByRule(log).keys()].filter(Boolean).sort();
    // Declared-but-unreferenced rules are outside the invariant: a results document
    // represents findings, not a scanner's rule catalog.
    expect(ids(after)).toEqual(ids(before));
  });

  it.each(fixtures)('%s: preserves result count, kind and message', async fixture => {
    const {before, after} = await sarifToHdfToSarif(fixture);
    const got = resultsByRule(after);
    for (const [ruleId, want] of resultsByRule(before)) {
      const have = got.get(ruleId) ?? [];
      expect(have, `result count for ${ruleId}`).toHaveLength(want.length);
      want.forEach((w, i) => {
        // 3.27.9 defaults an absent kind to "fail", so normalize or an omitted kind
        // reads as a change.
        expect((have[i]!.kind as string) ?? 'fail').toBe((w.kind as string) ?? 'fail');
        const wantMsg = ((w.message as Json | undefined)?.text as string) ?? '';
        // An originally-absent message has nothing to preserve, and SARIF REQUIRES
        // result.message, so the exporter must emit something.
        if (wantMsg !== '') {
          expect(((have[i]!.message as Json).text as string)).toBe(wantMsg);
        }
      });
    }
  });

  // region.snippet has no structured HDF home — it reaches codeDesc as prose — so it
  // survives only because sarif-to-hdf carries it on the per-result location and the
  // exporter reads it back. sarif_input.sarif carries 77.
  it('preserves region snippets', async () => {
    const {before, after} = await sarifToHdfToSarif('sarif_input.sarif');
    const count = (log: Json) => {
      let n = 0;
      for (const run of (log.runs as Json[] | undefined) ?? []) {
        for (const res of (run.results as Json[] | undefined) ?? []) {
          for (const loc of (res.locations as Json[] | undefined) ?? []) {
            const region = (loc.physicalLocation as Json | undefined)?.region as Json | undefined;
            if (region?.snippet) n++;
          }
        }
      }
      return n;
    };
    const want = count(before);
    expect(want, 'fixture carries no snippet to assert on').toBeGreaterThan(0);
    expect(count(after), 'region snippets did not survive').toBe(want);
  });

  it.each(fixtures)('%s: preserves every property bag', async fixture => {
    const {before, after} = await sarifToHdfToSarif(fixture);
    const got = bagsByObject(after);
    for (const [addr, want] of bagsByObject(before)) {
      const have = got.get(addr);
      expect(have, `bag at ${addr} did not survive`).toBeDefined();
      for (const [k, v] of Object.entries(want)) {
        expect(have![k], `bag at ${addr} lost key ${k}`).toBeDefined();
        if (k === 'tags') {
          // setBag MERGES tags rather than replacing: SARIF's tags is a reserved
          // string array whose members must be distinct (ADR-0014 3.4). A superset
          // is correct; a missing member is not.
          for (const tag of v as unknown[]) {
            expect(have!.tags as unknown[], `bag at ${addr} lost tag ${String(tag)}`).toContain(tag);
          }
        } else {
          expect(have![k]).toEqual(v);
        }
      }
    }
  });
  /** §3.27.10: the rule default applies ONLY to a failing result. For any other
   * kind the level is "none", stated or not, so inheriting the rule default there
   * would disagree with the spec rather than with the converter. */
  const resolvedLevel = (res: Json, ruleDefault: string): string => {
    if (((res.kind as string) ?? 'fail') !== 'fail') return 'none';
    const own = res.level as string | undefined;
    if (own) return own;
    return ruleDefault || 'warning';
  };
  const ruleDefaultLevel = (log: Json, ruleId: string): string => {
    for (const run of (log.runs as Json[] | undefined) ?? []) {
      const driver = (run.tool as Json | undefined)?.driver as Json | undefined;
      for (const rule of (driver?.rules as Json[] | undefined) ?? []) {
        if (rule.id !== ruleId) continue;
        return ((rule.defaultConfiguration as Json | undefined)?.level as string) ?? '';
      }
    }
    return '';
  };
  it.each(fixtures)('%s: preserves each result\'s resolved level', async fixture => {
    const {before, after} = await sarifToHdfToSarif(fixture);
    const got = resultsByRule(after);
    for (const [ruleId, want] of resultsByRule(before)) {
      const have = got.get(ruleId) ?? [];
      if (have.length !== want.length) continue;
      const wd = ruleDefaultLevel(before, ruleId);
      const gd = ruleDefaultLevel(after, ruleId);
      want.forEach((w, i) => {
        expect(resolvedLevel(have[i]!, gd), `${ruleId}[${i}] resolved level`).toBe(resolvedLevel(w, wd));
      });
    }
  });
  it.each(fixtures)('%s: preserves each result\'s first location', async fixture => {
    const {before, after} = await sarifToHdfToSarif(fixture);
    const first = (res: Json) => {
      const loc = ((res.locations as Json[] | undefined) ?? [])[0];
      const phys = loc?.physicalLocation as Json | undefined;
      return {
        uri: ((phys?.artifactLocation as Json | undefined)?.uri as string) ?? '',
        line: ((phys?.region as Json | undefined)?.startLine as number) ?? 0,
      };
    };
    const got = resultsByRule(after);
    for (const [ruleId, want] of resultsByRule(before)) {
      const have = got.get(ruleId) ?? [];
      if (have.length !== want.length) continue;
      want.forEach((w, i) => {
        const wl = first(w);
        if (wl.uri === '' && wl.line === 0) return;
        expect(first(have[i]!), `${ruleId}[${i}] first location`).toEqual(wl);
      });
    }
  });
  it.each(fixtures)('%s: preserves each result\'s fingerprints', async fixture => {
    const {before, after} = await sarifToHdfToSarif(fixture);
    const got = resultsByRule(after);
    for (const [ruleId, want] of resultsByRule(before)) {
      const have = got.get(ruleId) ?? [];
      if (have.length !== want.length) continue;
      want.forEach((w, i) => {
        for (const field of ['fingerprints', 'partialFingerprints']) {
          const wf = w[field] as Json | undefined;
          if (!wf || Object.keys(wf).length === 0) continue;
          const gf = (have[i]![field] as Json | undefined) ?? {};
          for (const [k, v] of Object.entries(wf)) {
            expect(gf[k], `${ruleId}[${i}] ${field}[${k}]`).toEqual(v);
          }
        }
      });
    }
  });
  it('preserves each accepted suppression', async () => {
    // rich.sarif is the only committed forward fixture carrying suppressions.
    const {before, after} = await sarifToHdfToSarif('rich.sarif');
    const accepted = (res: Json) =>
      ((res.suppressions as Json[] | undefined) ?? [])
        // 3.35.3: an absent status means accepted.
        .filter(sp => sp.status === undefined || sp.status === 'accepted');
    const got = resultsByRule(after);
    let checked = 0;
    for (const [ruleId, want] of resultsByRule(before)) {
      const have = got.get(ruleId) ?? [];
      if (have.length !== want.length) continue;
      want.forEach((w, i) => {
        for (const sp of accepted(w)) {
          checked++;
          expect(accepted(have[i]!).some(
            g => g.justification === sp.justification && g.kind === sp.kind),
            `${ruleId}[${i}] lost accepted suppression`).toBe(true);
        }
      });
    }
    expect(checked, 'fixture carries no accepted suppression to assert on').toBeGreaterThan(0);
  });
});

describe('HDF -> SARIF -> HDF', () => {
  /** Requirements by id. Identity, not position: the exporter groups runs by baseline. */
  const byId = (doc: Json) => {
    const out = new Map<string, Json>();
    for (const b of (doc.baselines as Json[] | undefined) ?? []) {
      for (const r of (b.requirements as Json[] | undefined) ?? []) {
        out.set(r.id as string, r);
      }
    }
    return out;
  };
  const descByLabel = (req: Json) => {
    const out = new Map<string, unknown>();
    for (const d of (req.descriptions as Json[] | undefined) ?? []) {
      out.set(d.label as string, d.data);
    }
    return out;
  };

  // Per fixture, because impact is recomputed from security-severity, which the
  // exporter emits only where the requirement carries CVSS. flawfinder has none, so
  // its impact survives; grype-cve does, so its impact is recomputed. Matches the Go
  // peer's expectations exactly.
  const cases: [string, string[]][] = [
    ['flawfinder.hdf.json', ['descriptions[default]', 'results[].codeDesc']],
    ['grype-cve.hdf.json', ['descriptions[default]', 'results[].codeDesc', 'impact']],
  ];

  it.each(cases)('%s: preserves the invariant, with the ruled losses', async (fixture, wantLosses) => {
    const {before, after} = await hdfToSarifToHdf(fixture);
    const got = byId(after);
    const losses = new Set<string>();

    for (const [id, want] of byId(before)) {
      const have = got.get(id);
      expect(have, `requirement ${id} did not survive`).toBeDefined();
      expect(have!.title).toEqual(want.title);

      const haveDescs = descByLabel(have!);
      for (const [label, data] of descByLabel(want)) {
        if (label === 'default') {
          if (haveDescs.get(label) !== data) losses.add('descriptions[default]');
          continue;
        }
        expect(haveDescs.has(label), `requirement ${id} lost description ${label}`).toBe(true);
        expect(haveDescs.get(label)).toEqual(data);
      }

      const wantRows = (want.results as Json[] | undefined) ?? [];
      const haveRows = (have!.results as Json[] | undefined) ?? [];
      expect(haveRows, `result count for ${id}`).toHaveLength(wantRows.length);
      wantRows.forEach((w, i) => {
        expect(haveRows[i]!.status).toEqual(w.status);
        if (haveRows[i]!.codeDesc !== w.codeDesc) losses.add('results[].codeDesc');
      });

      if (have!.impact !== want.impact) losses.add('impact');
    }

    // The ruled losses for THIS fixture and nothing else. A new entry means
    // something that survives today stopped; a missing one means a loss was fixed
    // and this expectation is stale.
    expect([...losses].sort()).toEqual([...wantLosses].sort());
  });

  // The source values here DIFFER from what the importer would otherwise assert —
  // `manual-by-design` against its constant `automated`, and a real
  // appliedBy/appliedAt/expiresAt against the identity, conversion time and default
  // expiry it invents. A fixture carrying the constant's own value cannot see the
  // difference, which is how the restore sat unreachable while every test passed.
  it('restores asserted values rather than invented ones', async () => {
    const raw = readFileSync(join(__dirname, '..', 'fixtures', 'input', 'grype-cve.hdf.json'), 'utf8');
    const doc = JSON.parse(raw) as Json;
    const req = ((doc.baselines as Json[])[0]!.requirements as Json[])[0]!;
    const reqId = req.id as string;
    req.verificationMethod = 'manual-by-design';
    req.statusOverrides = [{
      type: 'waiver', status: 'passed', reason: 'ISSM accepted',
      appliedBy: {type: 'username', identifier: 'jane.doe'},
      appliedAt: '2026-01-15T00:00:00Z', expiresAt: '2099-12-31T00:00:00Z',
    }];

    const sarif = await convertHdfToSarif(JSON.stringify(doc), TEST_VERSION);
    const after = JSON.parse(await convertSarifToHdf(sarif, TEST_VERSION)) as Json;
    const got = byId(after).get(reqId);
    expect(got, `requirement ${reqId} did not survive`).toBeDefined();

    expect(got!.verificationMethod,
      "the importer's constant must not outrank a carried verificationMethod").toBe('manual-by-design');
    const ov = (got!.statusOverrides as Json[])[0]!;
    expect(ov.appliedAt, 'invented appliedAt replaced the real one').toBe('2026-01-15T00:00:00Z');
    expect(ov.expiresAt, 'invented expiry replaced the real one').toBe('2099-12-31T00:00:00Z');
    expect((ov.appliedBy as Json).identifier, 'invented identity replaced the real one').toBe('jane.doe');
  });

  // CWE lives in tags["cwe"] on a SARIF-sourced document, not the first-class cwe
  // field, so an exporter reading only the first-class field emitted no CWE tags and
  // the importer — which recovers CWE from exactly those tags — rebuilt an empty
  // list. The NIST and CCI tags derive from that list, so they degraded with it.
  // Asserted together because they fail together. Order is not asserted: the
  // exporter dedupes through a set and re-emits sorted.
  it('preserves CWE and the tags derived from it', async () => {
    const {before, after} = await hdfToSarifToHdf('flawfinder.hdf.json');
    const got = byId(after);
    let checked = 0;
    for (const [id, want] of byId(before)) {
      const have = got.get(id);
      if (!have) continue;
      const wt = (want.tags ?? {}) as Record<string, string[]>;
      const gt = (have.tags ?? {}) as Record<string, string[]>;
      for (const field of ['cwe', 'nist', 'cci']) {
        if (!wt[field]?.length) continue;
        checked++;
        expect([...(gt[field] ?? [])].sort(), `${id} tags.${field}`).toEqual([...wt[field]].sort());
      }
    }
    expect(checked, 'fixture exercises none of the tag families').toBeGreaterThan(0);
  });

  // resource and resourceId have no SARIF field at all, so they survive only via the
  // row hdf-to-sarif puts on each SARIF result's own bag.
  it('restores result resource fields', async () => {
    const {before, after} = await hdfToSarifToHdf('grype-cve.hdf.json');
    const got = byId(after);
    let checked = 0;
    for (const [id, want] of byId(before)) {
      const have = got.get(id);
      if (!have) continue;
      const wr = (want.results as Json[] | undefined) ?? [];
      const gr = (have.results as Json[] | undefined) ?? [];
      if (wr.length !== gr.length) continue;
      wr.forEach((w, i) => {
        for (const field of ['resource', 'resourceId']) {
          if (w[field] === undefined) return;
          checked++;
          expect(gr[i]![field], `${id}[${i}] ${field} must be restored`).toEqual(w[field]);
        }
      });
    }
    expect(checked, 'fixture exercises neither resource nor resourceId').toBeGreaterThan(0);
  });

  it('restores the fields SARIF cannot express', async () => {
    const {before, after} = await hdfToSarifToHdf('grype-cve.hdf.json');
    const got = byId(after);
    let checked = 0;
    for (const [id, want] of byId(before)) {
      const have = got.get(id);
      if (!have) continue;
      for (const field of ['cvss', 'epss', 'refs', 'affectedPackages', 'code', 'effectiveChecksum']) {
        if (want[field] === undefined) continue;
        checked++;
        expect(have[field], `${id}.${field} has no SARIF expression and must be restored`).toEqual(want[field]);
      }
    }
    expect(checked, 'fixture exercises none of the unexpressible fields').toBeGreaterThan(0);
  });
});
