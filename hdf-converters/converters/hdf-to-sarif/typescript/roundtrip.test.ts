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

  // One ADDITION is by design and is listed per fixture rather than tolerated
  // generally: a run that declared executionSuccessful: false gains a synthesized
  // requirement on import, and that requirement exports as a rule of its own. Mirrors
  // the Go peer's table.
  const addedRules: Record<string, string[]> = {'spotbugs.sarif': ['SpotBugs-run-failed']};

  it.each(fixtures)('%s: preserves the referenced rule set', async fixture => {
    const {before, after} = await sarifToHdfToSarif(fixture);
    const ids = (log: Json) => [...resultsByRule(log).keys()].filter(Boolean).sort();
    // Declared-but-unreferenced rules are outside the invariant: a results document
    // represents findings, not a scanner's rule catalog.
    expect(ids(after)).toEqual([...ids(before), ...(addedRules[fixture] ?? [])].sort());
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

  // A failed invocation reaches HDF as a requirement, and that requirement survives
  // the trip back out as a SARIF result. The invocations array itself does not —
  // the exporter has no source from which to rebuild one, so it emits none rather
  // than inventing it. Mirrors Go's
  // TestRoundTrip_SarifToHDFToSarif_DoesNotRebuildAFailedInvocation.
  it('does not rebuild a failed invocation', async () => {
    const {before, after} = await sarifToHdfToSarif('failed-run.sarif');

    const beforeRun = (before.runs as Json[])[0]!;
    const invs = beforeRun.invocations as Json[];
    expect(invs[0]!.executionSuccessful, 'fixture precondition').toBe(false);

    const afterRun = (after.runs as Json[])[0]!;
    expect(afterRun.invocations).toBeUndefined();

    // What does survive: the synthesized requirement, as a result of its own.
    const ids = ((afterRun.results as Json[] | undefined) ?? []).map(r => r.ruleId);
    expect(ids).toContain('eslint-run-failed');

    // And nothing was written to the baseline: a baseline is a policy document.
    const block = (afterRun.properties as Json).hdf as Json;
    expect(block.statusMessage).toBeUndefined();
  });

  // The requirement survives a full circle but its STATUS does not. HDF 'error'
  // exports as SARIF kind 'open', and the importer maps 'open' back to 'failed' —
  // SARIF has no kind meaning "the check threw", so the two collapse. Pre-existing
  // and documented on statusKinds; pinned so restoring the distinction is a
  // deliberate decision rather than an accident. Mirrors Go's
  // TestRoundTrip_SarifToHDFToSarifToHDF_DegradesErrorToFailed.
  it('degrades the error status to failed on re-import', async () => {
    const input = sarifFixture('failed-run.sarif');

    const first = JSON.parse(await convertSarifToHdf(input, TEST_VERSION)) as Json;
    const firstReq = ((first.baselines as Json[])[0]!.requirements as Json[])[0]!;
    expect(firstReq.id, 'precondition').toBe('eslint-run-failed');
    expect(((firstReq.results as Json[])[0]!).status, 'precondition').toBe('error');

    const sarifOut = await convertHdfToSarif(JSON.stringify(first), TEST_VERSION);
    const second = JSON.parse(await convertSarifToHdf(sarifOut, TEST_VERSION)) as Json;
    const secondReq = ((second.baselines as Json[])[0]!.requirements as Json[])[0]!;

    expect(secondReq.id).toBe('eslint-run-failed');
    expect(((secondReq.results as Json[])[0]!).status).toBe('failed');
  });
});

describe('HDF -> SARIF -> HDF', () => {
  // Baseline-level restore, the TypeScript peer of Go's
  // TestRoundTrip_HDFToSarifToHDF_RestoresBaselineIdentity. The owner's ruling, per
  // field: every field describing the POLICY is restored, because SARIF's
  // toolComponent describes the scanner and has no way to say them; name and
  // resultsChecksum are derived from the SARIF; integrity and originalChecksum are
  // refused, because both are tamper-evidence and a round trip transforms the thing
  // they cover — Integrity covers "the HDF file" and carries a signature and signedBy.
  const seededBaseline = (): string => {
    const raw = readFileSync(join(__dirname, '..', 'fixtures', 'input', 'flawfinder.hdf.json'), 'utf8');
    const doc = JSON.parse(raw) as Json;
    // A generator this converter would never stamp, so the refusal assertion cannot
    // pass by coincidence: the fixture's own generator is already sarif-to-hdf.
    doc.generator = {name: 'grype-to-hdf', version: '1.2.3'};
    const b = (doc.baselines as Json[])[0]!;
    Object.assign(b, {
      title: 'ACME Hardening Policy', version: '9.9.9',
      summary: 'a summary', description: 'a description',
      maintainer: 'Team Blue', copyright: 'ACME Corp',
      copyrightEmail: 'sec@example.invalid', license: 'Apache-2.0',
      status: 'loaded', statusMessage: 'a status note',
      parentBaseline: 'parent-policy',
      labels: {team: 'blue', environment: 'prod'},
      supports: [{platform: 'linux'}],
      depends: [{name: 'dep-a'}],
      groups: [{id: 'g1', title: 'Group One', requirements: ['V-1']}],
      inputs: [{name: 'threshold', type: 'Numeric'}],
      integrity: {algorithm: 'sha256', checksum: 'a'.repeat(64), signature: 'c2ln', signedBy: 'someone@example.invalid'},
      originalChecksum: {algorithm: 'sha256', value: 'b'.repeat(64)},
      externalReferences: [{sourceName: 'ACME', href: 'https://example.invalid/policy'}],
      extensions: {passthrough: {acme: {policyOwner: 'Team Blue'}}},
    });
    return JSON.stringify(doc);
  };

  it('restores the baseline identity', async () => {
    const sarifOut = await convertHdfToSarif(seededBaseline(), TEST_VERSION);
    const back = JSON.parse(await convertSarifToHdf(sarifOut, TEST_VERSION)) as Json;
    const b = (back.baselines as Json[])[0]!;

    expect(b.summary).toBe('a summary');
    expect(b.description).toBe('a description');
    expect(b.maintainer).toBe('Team Blue');
    expect(b.copyright).toBe('ACME Corp');
    expect(b.copyrightEmail).toBe('sec@example.invalid');
    expect(b.license).toBe('Apache-2.0');
    expect(b.status).toBe('loaded');
    expect(b.statusMessage).toBe('a status note');
    expect(b.parentBaseline).toBe('parent-policy');
    expect(b.labels).toEqual({team: 'blue', environment: 'prod'});
    expect(b.supports).toHaveLength(1);
    expect(b.depends).toHaveLength(1);
    expect(b.groups).toHaveLength(1);
    expect(b.inputs).toHaveLength(1);
    expect(b.externalReferences).toHaveLength(1);

    // Restored OVER the invented values, which name the SARIF format, not the policy.
    expect(b.title).toBe('ACME Hardening Policy');
    expect(b.version).toBe('9.9.9');

    // Derived from the SARIF, never the bag.
    expect(b.name).toBe('Flawfinder');
    expect(b.resultsChecksum).toBeDefined();

    // The baseline's own passthrough is producer data SARIF cannot express.
    expect(JSON.stringify(b.extensions)).toContain('policyOwner');

    // Refused.
    expect(b.integrity).toBeUndefined();
    expect(b.originalChecksum).toBeUndefined();
    // Also refused: generator names the converter that produced THIS file.
    expect((back.generator as Json).name).toBe('sarif-to-hdf');
  });

  it('tolerates a malformed baseline bag', async () => {
    const sarifOut = await convertHdfToSarif(seededBaseline(), TEST_VERSION);
    const doc = JSON.parse(sarifOut) as Json;
    const run = (doc.runs as Json[])[0]!;
    const block = (run.properties as Json).hdf as Json;
    block.license = ['not', 'a', 'string'];
    block.groups = 'not a list';
    block.maintainer = 'Team Blue';

    const back = JSON.parse(await convertSarifToHdf(JSON.stringify(doc), TEST_VERSION)) as Json;
    const b = (back.baselines as Json[])[0]!;
    expect(b.license).toBeUndefined();
    expect(b.groups).toBeUndefined();
    expect(b.maintainer).toBe('Team Blue');
  });

  // The adversarial corpus, the same table as Go's adversarialBagValues. Every entry
  // is a value that does not fit the field it addresses, and the contract is identical
  // in both languages: skip the field, keep its neighbours, never fail the conversion.
  //
  // The groups entry is the subtle one. {bogusKey: 5} DECODES without error in Go —
  // encoding/json ignores undeclared members and zeroes missing ones — and TypeScript
  // has no types at runtime to reject it, so both languages reached an invalid output
  // by different routes before this. Go now rejects the decode as lossy; this side
  // checks the keys the schema requires.
  it.each([
    ['supports', [1, 2, 3]],
    ['depends', ['not-an-object']],
    ['inputs', [42]],
    ['externalReferences', ['x']],
    ['license', ['not', 'a', 'string']],
    ['labels', {team: 7}],
    ['groups', [{bogusKey: 5}]],
  ] as [string, unknown][])('skips the adversarial %s value', async (field, bad) => {
    const sarifOut = await convertHdfToSarif(seededBaseline(), TEST_VERSION);
    const doc = JSON.parse(sarifOut) as Json;
    const block = ((doc.runs as Json[])[0]!.properties as Json).hdf as Json;
    block[field] = bad;

    const back = JSON.parse(await convertSarifToHdf(JSON.stringify(doc), TEST_VERSION)) as Json;
    const b = (back.baselines as Json[])[0]!;
    expect(b[field], `${field} must be skipped, not taken`).toBeUndefined();

    // Its neighbours are unaffected: one bad entry costs only itself.
    expect(b.maintainer).toBe('Team Blue');
    expect(b.title).toBe('ACME Hardening Policy');
  });

  // Timestamp spellings the carriage must survive — the TypeScript peer of Go's
  // TestRoundTrip_HDFToSarifToHDF_RestoresEveryTimestampSpelling. This side never had
  // the bug (it assigns from the bag rather than decoding), which is exactly why the
  // test belongs here too: Go dropped .100Z, .000Z and +00:00 while TypeScript kept
  // them, so the two languages produced materially different documents from the same
  // SARIF. Asserting the same outcome in both is what catches that class of drift.
  const seededTimestamp = (stamp: string): string => {
    const raw = readFileSync(join(__dirname, '..', 'fixtures', 'input', 'flawfinder.hdf.json'), 'utf8');
    const doc = JSON.parse(raw) as Json;
    const b = (doc.baselines as Json[])[0]!;
    b.requirements = (b.requirements as Json[]).slice(0, 1);
    const req = (b.requirements as Json[])[0]!;
    req.results = (req.results as Json[]).slice(0, 1);
    ((req.results as Json[])[0]!).startTime = stamp;
    req.evidence = [{type: 'log', data: 'a line', capturedAt: stamp}];
    const ref = [{sourceName: 'ACME', href: 'https://example.invalid/a', addedAt: stamp}];
    req.externalReferences = ref;
    b.externalReferences = ref;
    return JSON.stringify(doc);
  };

  it.each([
    '2026-10-09T16:04:26.123Z',
    '2026-10-09T16:04:26.100Z',
    '2026-10-09T16:04:26.000Z',
    '2026-10-09T16:04:26+00:00',
  ])('restores the carriage when the timestamp is spelled %s', async stamp => {
    const sarifOut = await convertHdfToSarif(seededTimestamp(stamp), TEST_VERSION);
    const back = JSON.parse(await convertSarifToHdf(sarifOut, TEST_VERSION)) as Json;
    const b = (back.baselines as Json[])[0]!;
    const req = (b.requirements as Json[])[0]!;

    expect(new Date((req.results as Json[])[0]!.startTime as string).getTime())
      .toBe(new Date(stamp).getTime());
    expect(req.evidence).toHaveLength(1);
    expect(req.externalReferences).toHaveLength(1);
    expect(b.externalReferences).toHaveLength(1);
  });

  it('restores a null input value', async () => {
    const doc = JSON.parse(seededTimestamp('2026-10-09T16:04:26.123Z')) as Json;
    (doc.baselines as Json[])[0]!.inputs = [{name: 'threshold', type: 'Numeric', value: null}];
    const sarifOut = await convertHdfToSarif(JSON.stringify(doc), TEST_VERSION);
    const back = JSON.parse(await convertSarifToHdf(sarifOut, TEST_VERSION)) as Json;
    const inputs = (back.baselines as Json[])[0]!.inputs as Json[];
    expect(inputs).toHaveLength(1);
    expect(inputs[0]!.name).toBe('threshold');
  });

  // An undeclared member must not cost the value it rides on — the TypeScript peer of
  // Go's TestRoundTrip_HDFToSarifToHDF_AnUndeclaredMemberDoesNotCostTheValue.
  //
  // Reference is one of the few carried types the HDF schema leaves OPEN, so
  // {ref, url, title} is a legal refs entry. What each language does with the extra
  // member differs and is recorded rather than asserted: Go decodes into a typed struct
  // so it is dropped, this side assigns the carried value verbatim so it is kept. Both
  // predate this card. What must agree is that the ARRAY and its declared members
  // survive — a guard that rejected the value over the extra member lost all of them.
  it('does not let an undeclared member cost the value it rides on', async () => {
    const raw = readFileSync(
      join(__dirname, '..', '..', 'gitlab-to-hdf', 'fixtures', 'expected', 'minimal-dast.json.hdf.json'), 'utf8');
    const doc = JSON.parse(raw) as Json;
    const req = ((doc.baselines as Json[])[0]!.requirements as Json[])[0]!;
    req.refs = [{
      ref: 'NIST SP 800-53 Rev 5',
      url: 'https://example.invalid/a',
      title: 'Security and Privacy Controls',
    }];

    const sarifOut = await convertHdfToSarif(JSON.stringify(doc), TEST_VERSION);
    const back = JSON.parse(await convertSarifToHdf(sarifOut, TEST_VERSION)) as Json;

    let restored: Json[] | undefined;
    for (const r of (back.baselines as Json[])[0]!.requirements as Json[]) {
      if (Array.isArray(r.refs) && r.refs.length > 0) { restored = r.refs as Json[]; break; }
    }
    expect(restored, 'the array must survive; dropping it loses the declared members too')
      .toHaveLength(1);
    expect(restored![0]!.url).toBe('https://example.invalid/a');
    expect(restored![0]!.ref).toBeDefined();
  });

  it('keeps the invented defaults when no bag is carried', async () => {
    const out = JSON.parse(await convertSarifToHdf(sarifFixture('gosec.sarif'), TEST_VERSION)) as Json;
    const b = (out.baselines as Json[])[0]!;
    expect(b.title).toBe('Static Analysis Results Interchange Format');
    expect(b.license).toBeUndefined();
    expect(b.maintainer).toBeUndefined();
  });

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
