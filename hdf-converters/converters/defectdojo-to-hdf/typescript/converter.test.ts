import {readFileSync} from 'fs';
import {join, dirname} from 'path';
import {fileURLToPath} from 'url';
import {describe, it, expect} from 'vitest';
import {expectValidResults} from '../../../test/helpers/expectValidHdf.js';
import {convertDefectDojoToHdf} from './converter.js';
import type {HDFResults, EvaluatedRequirement} from '@mitre/hdf-schema';

const here = dirname(fileURLToPath(import.meta.url));
const FIXTURES = join(here, '..', 'fixtures', 'input');

function load(name: string): string {
  return readFileSync(join(FIXTURES, name), 'utf-8');
}

function byTriage(reqs: EvaluatedRequirement[], tag: string): EvaluatedRequirement {
  const r = reqs.find(req => (req.tags as Record<string, unknown>)[tag] === true);
  if (!r) throw new Error(`no requirement with ${tag}=true`);
  return r;
}

describe('defectdojo-to-hdf converter', () => {
  it('throws on invalid and empty input', async () => {
    await expect(convertDefectDojoToHdf('not json')).rejects.toThrow();
    await expect(convertDefectDojoToHdf('')).rejects.toThrow();
  });

  it('produces schema-valid HDF grouped by scanner', async () => {
    const hdf = JSON.parse(await convertDefectDojoToHdf(load('findings.json'))) as HDFResults;
    expectValidResults(hdf);
    expect(hdf.generator?.name).toBe('defectdojo-to-hdf');
    expect(hdf.baselines).toHaveLength(1);
    expect(hdf.baselines[0].name).toBe('DefectDojo: Generic Findings Import');
    expect(hdf.baselines[0].requirements).toHaveLength(4);
  });

  it('maps triage state to raw status (raw-primary)', async () => {
    const hdf = JSON.parse(await convertDefectDojoToHdf(load('findings.json'))) as HDFResults;
    const reqs = hdf.baselines[0].requirements;

    expect(byTriage(reqs, 'defectdojo/active').results[0].status).toBe('failed');

    const fp = byTriage(reqs, 'defectdojo/false_p');
    expect(fp.results[0].status).toBe('failed'); // raw stays failed
    expect(fp.effectiveStatus).toBe('notApplicable'); // dismissal rides in a falsePositive override

    const mitigatedOnly = reqs.find(
      r => (r.tags as Record<string, unknown>)['defectdojo/is_mitigated'] === true && (r.tags as Record<string, unknown>)['defectdojo/false_p'] !== true,
    );
    expect(mitigatedOnly?.results[0].status).toBe('passed');
  });

  it('emits a real waiver override from risk-acceptance provenance', async () => {
    const hdf = JSON.parse(await convertDefectDojoToHdf(load('findings.json'))) as HDFResults;
    const ra = byTriage(hdf.baselines[0].requirements, 'defectdojo/risk_accepted');

    expect(ra.results[0].status).toBe('failed'); // raw stays failed
    expect(ra.effectiveStatus).toBe('passed');
    expect(ra.disposition).toBe('waiver');

    expect(ra.statusOverrides).toHaveLength(1);
    const ov = ra.statusOverrides![0];
    expect(ov.type).toBe('waiver');
    expect(ov.status).toBe('passed');
    expect(ov.reason).toContain('WAF virtual patch'); // real decision_details
    expect(ov.appliedBy.identifier).toBe('defectdojo-user-1');
    expect(ov.appliedBy.type).toBe('simple');
    expect(String(ov.expiresAt)).toContain('2099'); // real expiration_date
  });

  it('emits a real falsePositive override from a false-positive dismissal', async () => {
    // Finding 2 in the fixture: false_p=true, mitigated_by=1, mitigated=2026-07-26.
    const hdf = JSON.parse(await convertDefectDojoToHdf(load('findings.json'))) as HDFResults;
    const fp = byTriage(hdf.baselines[0].requirements, 'defectdojo/false_p');

    expect(fp.results[0].status).toBe('failed'); // raw stays failed
    expect(fp.effectiveStatus).toBe('notApplicable'); // a vuln aggregator's FP → N/A
    expect(fp.disposition).toBe('falsePositive');

    expect(fp.statusOverrides).toHaveLength(1);
    const ov = fp.statusOverrides![0];
    expect(ov.type).toBe('falsePositive');
    expect(ov.status).toBe('notApplicable');
    expect(ov.reason).toBe('Some mitigation'); // the finding's mitigation note
    expect(ov.appliedBy.identifier).toBe('defectdojo-user-1');
    expect(ov.appliedBy.type).toBe('simple');
    expect(String(ov.appliedAt)).toContain('2026'); // mitigated date
    expect(String(ov.expiresAt)).toContain('2027'); // appliedAt + 1yr
  });

  it('emits no override for an untriaged finding (raw status unchanged)', async () => {
    const hdf = JSON.parse(await convertDefectDojoToHdf(load('findings.json'))) as HDFResults;
    const active = byTriage(hdf.baselines[0].requirements, 'defectdojo/active');

    expect(active.results[0].status).toBe('failed');
    expect(active.effectiveStatus).toBeUndefined();
    expect(active.disposition).toBeUndefined();
    expect(active.statusOverrides).toBeUndefined();
  });

  it('pins the top-level timestamp to the newest finding date', async () => {
    // The shared snapshot masks timestamp values, so assert the exact source
    // value here. Newest finding date in the fixture is finding 4, 2024-01-04.
    const hdf = JSON.parse(await convertDefectDojoToHdf(load('findings.json'))) as HDFResults;
    expect(hdf.timestamp).toBe('2024-01-04T00:00:00Z');
  });

  it('derives result startTime from the finding date (not now())', async () => {
    // Go's ParseTimestamp has no date-only layout; both languages promote the
    // bare date to UTC midnight so the startTime is source-derived and identical.
    const hdf = JSON.parse(await convertDefectDojoToHdf(load('findings.json'))) as HDFResults;
    const byId = new Map(hdf.baselines[0].requirements.map(r => [r.id, r]));
    expect(byId.get('DefectDojo-Finding-1')!.results[0].startTime).toBe('2021-01-06T00:00:00Z');
    expect(byId.get('DefectDojo-Finding-4')!.results[0].startTime).toBe('2024-01-04T00:00:00Z');
  });

  it('is deterministic — converting twice yields byte-identical output', async () => {
    // Every fixture finding carries a date, so no now() fallback runs; identical
    // output proves the mapped timestamps are source-anchored, not wall-clock.
    const a = await convertDefectDojoToHdf(load('findings.json'));
    const b = await convertDefectDojoToHdf(load('findings.json'));
    expect(a).toBe(b);
  });

  it('omits the top-level timestamp when no finding carries a date', async () => {
    const hdf = JSON.parse(await convertDefectDojoToHdf(JSON.stringify([{id: 1, title: 't', severity: 'High'}]))) as HDFResults;
    expect(hdf.timestamp).toBeUndefined();
  });

  it('synthesizes a passed placeholder for empty input', async () => {
    const hdf = JSON.parse(await convertDefectDojoToHdf(load('empty.json'))) as HDFResults;
    expectValidResults(hdf);
    expect(hdf.baselines).toHaveLength(1);
    expect(hdf.baselines[0].requirements).toHaveLength(1);
    expect(hdf.baselines[0].requirements[0].id).toBe('defectdojo-no-findings');
    expect(hdf.baselines[0].requirements[0].results[0].status).toBe('passed');
  });

  // Branch-coverage unit tests over the mapping surface. These craft minimal
  // DefectDojo findings to exercise each code path; findings.json above remains
  // the real-data contract.
  const base = {id: 1, title: 'T', severity: 'High', date: '2026-01-01'};

  async function convertOne(f: Record<string, unknown>): Promise<EvaluatedRequirement> {
    // bare-array input path
    const hdf = JSON.parse(await convertDefectDojoToHdf(JSON.stringify([{...base, ...f}]))) as HDFResults;
    return hdf.baselines[0].requirements[0];
  }

  it('maps each remaining triage state to the right raw status', async () => {
    expect((await convertOne({out_of_scope: true})).results[0].status).toBe('notApplicable');
    expect((await convertOne({under_review: true})).results[0].status).toBe('notReviewed');
    expect((await convertOne({is_mitigated: true})).results[0].status).toBe('passed');
    // no triage flags at all → default failed
    expect((await convertOne({})).results[0].status).toBe('failed');
  });

  it('maps severity to impact, defaulting unknown to 0.5', async () => {
    const cases: [string, number][] = [
      ['Critical', 0.9],
      ['High', 0.7],
      ['Medium', 0.5],
      ['Low', 0.3],
      ['Info', 0.0],
      ['bogus', 0.5],
    ];
    for (const [severity, impact] of cases) {
      expect((await convertOne({severity})).impact).toBe(impact);
    }
  });

  it('falls back to a valid startTime when the finding has no date', async () => {
    const r = await convertOne({date: undefined});
    expect(r.results[0].startTime).toBeTruthy();
  });

  it('resolves risk-acceptance owner identity by precedence', async () => {
    const withRisk = (ar: Record<string, unknown>): Record<string, unknown> => ({
      risk_accepted: true,
      accepted_risks: [ar],
    });
    const email = await convertOne(withRisk({owner: 5, owner_email: 'a@b.com', owner_username: 'u'}));
    expect(email.statusOverrides![0].appliedBy).toMatchObject({type: 'email', identifier: 'a@b.com'});

    const username = await convertOne(withRisk({owner: 5, owner_username: 'u'}));
    expect(username.statusOverrides![0].appliedBy).toMatchObject({type: 'username', identifier: 'u'});

    const simple = await convertOne(withRisk({owner: 7}));
    expect(simple.statusOverrides![0].appliedBy).toMatchObject({type: 'simple', identifier: 'defectdojo-user-7'});

    const anon = await convertOne(withRisk({}));
    expect(anon.statusOverrides![0].appliedBy).toMatchObject({type: 'simple', identifier: 'defectdojo-risk-acceptance-owner'});
  });

  it('builds waiver reason and expiry with fallbacks', async () => {
    const fromName = await convertOne({risk_accepted: true, accepted_risks: [{name: 'AcceptName'}]});
    expect(fromName.statusOverrides![0].reason).toBe('AcceptName');

    const defaulted = await convertOne({risk_accepted: true, accepted_risks: [{}]});
    expect(defaulted.statusOverrides![0].reason).toBe('Risk accepted in DefectDojo');

    // no expiration_date → one year after applied
    const noExpiry = await convertOne({risk_accepted: true, accepted_risks: [{created: '2030-01-01T00:00:00Z'}]});
    expect(String(noExpiry.statusOverrides![0].expiresAt)).toContain('2031');

    // risk_accepted flag but no accepted_risks → no override
    const flagOnly = await convertOne({risk_accepted: true});
    expect(flagOnly.statusOverrides).toBeUndefined();
  });

  it('resolves false-positive reviewer identity, reason, and appliedAt by precedence', async () => {
    const fp = (extra: Record<string, unknown>): Record<string, unknown> => ({false_p: true, ...extra});

    const email = await convertOne(fp({mitigated_by: 1, mitigated_by_username: 'u', mitigated_by_email: 'a@b.com'}));
    expect(email.statusOverrides![0].appliedBy).toMatchObject({type: 'email', identifier: 'a@b.com'});

    const username = await convertOne(fp({mitigated_by: 1, mitigated_by_username: 'u'}));
    expect(username.statusOverrides![0].appliedBy).toMatchObject({type: 'username', identifier: 'u'});

    const simple = await convertOne(fp({mitigated_by: 7}));
    expect(simple.statusOverrides![0].appliedBy).toMatchObject({type: 'simple', identifier: 'defectdojo-user-7'});

    const system = await convertOne(fp({}));
    expect(system.statusOverrides![0].appliedBy).toMatchObject({type: 'other', identifier: 'defectdojo (false positive triage)'});

    // reason: mitigation note when present, else constant fallback
    expect((await convertOne(fp({mitigation: 'note here'}))).statusOverrides![0].reason).toBe('note here');
    expect((await convertOne(fp({}))).statusOverrides![0].reason).toBe('Marked as false positive in DefectDojo');

    // appliedAt: mitigated date wins over the finding date; expiresAt is +1yr
    const mit = await convertOne(fp({mitigated: '2030-05-01T00:00:00Z', date: '2020-01-01'}));
    expect(String(mit.statusOverrides![0].appliedAt)).toContain('2030');
    expect(String(mit.statusOverrides![0].expiresAt)).toContain('2031');

    // no mitigated date → falls back to the finding date
    const fromDate = await convertOne(fp({date: '2022-03-04'}));
    expect(String(fromDate.statusOverrides![0].appliedAt)).toBe('2022-03-04T00:00:00Z');
  });

  it('prefers the waiver over the false-positive path when a finding is both', async () => {
    const both = await convertOne({
      false_p: true,
      risk_accepted: true,
      accepted_risks: [{name: 'AcceptName'}],
    });
    expect(both.disposition).toBe('waiver');
    expect(both.effectiveStatus).toBe('passed');
    expect(both.statusOverrides![0].type).toBe('waiver');
  });

  it('derives the requirement id from the tool ids with fallback', async () => {
    expect((await convertOne({unique_id_from_tool: 'UID'})).id).toBe('UID');
    expect((await convertOne({unique_id_from_tool: null, vuln_id_from_tool: 'VID'})).id).toBe('VID');
    expect((await convertOne({id: 99})).id).toBe('DefectDojo-Finding-99');
  });

  it('maps CVSS v3/v4 scores, vectors, and severity bands', async () => {
    const both = await convertOne({cvssv3: 'AV:N', cvssv3_score: 9.5, cvssv4_score: 8.0});
    const versions = both.cvss!.map(c => c.version);
    expect(versions).toContain('3.1');
    expect(versions).toContain('4.0');
    expect(both.cvss!.find(c => c.version === '3.1')!.baseVector).toBe('AV:N');

    // vector only (no score)
    const vectorOnly = await convertOne({cvssv3: 'AV:L', cvssv3_score: null});
    expect(vectorOnly.cvss![0].baseScore).toBeUndefined();
    expect(vectorOnly.cvss![0].baseVector).toBe('AV:L');

    // no CVSS at all
    expect((await convertOne({})).cvss).toBeUndefined();

    // each severity band
    for (const score of [9.5, 8.0, 5.0, 2.0, 0.0]) {
      const r = await convertOne({cvssv3_score: score});
      expect(r.cvss![0].baseSeverity).toBeTruthy();
    }
  });

  it('includes EPSS only when a date is present', async () => {
    const withEpss = await convertOne({epss_score: 0.4, epss_percentile: 0.8});
    expect(withEpss.epss).toMatchObject({score: 0.4, percentile: 0.8});

    const noPercentile = await convertOne({epss_score: 0.4});
    expect(noPercentile.epss!.percentile).toBe(0);

    const noDate = await convertOne({date: undefined, epss_score: 0.4});
    expect(noDate.epss).toBeUndefined();
  });

  it('maps CWE to NIST/CWE tags and defaults without a CWE', async () => {
    const withCwe = await convertOne({cwe: 79});
    expect(withCwe.cwe).toEqual(['CWE-79']);

    const noCwe = await convertOne({cwe: null});
    expect(noCwe.cwe).toBeUndefined();
  });

  it('maps CVE from vulnerability_ids into tags.cve (not the requirement id)', async () => {
    const hdf = JSON.parse(await convertDefectDojoToHdf(load('findings.json'))) as HDFResults;
    const byId = new Map(hdf.baselines[0].requirements.map(r => [r.id, r]));

    const first = byId.get('DefectDojo-Finding-1');
    expect(first).toBeDefined(); // id is the native finding id, not the CVE
    expect((first!.tags as Record<string, unknown>).cve).toEqual(['CVE-2020-36234']);
    expect((byId.get('DefectDojo-Finding-2')!.tags as Record<string, unknown>).cve).toEqual(['CVE-2020-36235']);
    expect((byId.get('DefectDojo-Finding-3')!.tags as Record<string, unknown>).cve).toEqual(['CVE-2020-36236']);
  });

  it('collects all CVEs (empty ids dropped) and omits tags.cve when none present', async () => {
    const multi = await convertOne({
      vulnerability_ids: [{vulnerability_id: 'CVE-2021-1'}, {vulnerability_id: ''}, {vulnerability_id: 'CVE-2021-2'}],
    });
    expect((multi.tags as Record<string, unknown>).cve).toEqual(['CVE-2021-1', 'CVE-2021-2']);

    const none = await convertOne({});
    expect((none.tags as Record<string, unknown>).cve).toBeUndefined();
  });

  it('never emits requirement.kev (DefectDojo carries no CISA due date)', async () => {
    const hdf = JSON.parse(await convertDefectDojoToHdf(load('findings.json'))) as HDFResults;
    for (const r of hdf.baselines[0].requirements) {
      expect(r.kev).toBeUndefined();
    }
  });

  it('builds descriptions and a rich code description', async () => {
    const r = await convertOne({
      description: 'd',
      mitigation: 'fix',
      impact: 'bad',
      component_name: 'lodash',
      component_version: '4.17.0',
      file_path: 'src/x.js',
      line: 42,
      vulnerability_ids: [{vulnerability_id: 'CVE-2026-1'}, {vulnerability_id: ''}],
    });
    expect(r.descriptions).toHaveLength(3);
    expect(r.results[0].codeDesc).toContain('Component: lodash@4.17.0');
    expect(r.results[0].codeDesc).toContain('Location: src/x.js:42');
    expect(r.results[0].codeDesc).toContain('CVE: CVE-2026-1');
  });

  it('populates requirement.code with each finding serialized as indented JSON', async () => {
    const raw = JSON.parse(load('findings.json')) as {results: Record<string, unknown>[]};
    const hdf = JSON.parse(await convertDefectDojoToHdf(load('findings.json'))) as HDFResults;
    const reqs = hdf.baselines[0].requirements;
    expect(reqs).toHaveLength(4);
    reqs.forEach((req, i) => {
      expect(req.code).toBeDefined();
      expect(req.code).toContain('\n  '); // indented, not compact
      // value-pinning: code round-trips to the source finding object
      expect(JSON.parse(req.code!)).toEqual(raw.results[i]);
    });
  });

  it('serializes a crafted finding to code that round-trips to the source', async () => {
    const f = {...base, cwe: 79, file_path: 'src/x.js', line: 7};
    const r = await convertOne(f);
    expect(r.code).toBeDefined();
    expect(JSON.parse(r.code!)).toEqual(f);
  });

  it('names the baseline DefectDojo when no scanner is present', async () => {
    const hdf = JSON.parse(await convertDefectDojoToHdf(JSON.stringify([base]))) as HDFResults;
    expect(hdf.baselines[0].name).toBe('DefectDojo: DefectDojo');
  });

  it('promotes file_path/line into structured sourceLocation', async () => {
    // Value-pin against the real fixture: finding 1 → src/first.cpp:13,
    // finding 2 → src/two.cpp:135. Line is a bare number (byte-parity with Go).
    const hdf = JSON.parse(await convertDefectDojoToHdf(load('findings.json'))) as HDFResults;
    const byId = new Map(hdf.baselines[0].requirements.map(r => [r.id, r]));

    expect(byId.get('DefectDojo-Finding-1')!.sourceLocation).toEqual({ref: 'src/first.cpp', line: 13});
    expect(byId.get('DefectDojo-Finding-2')!.sourceLocation).toEqual({ref: 'src/two.cpp', line: 135});
  });

  it('covers every sourceLocation branch', async () => {
    // primary file_path/line
    expect((await convertOne({file_path: 'src/a.go', line: 42})).sourceLocation).toEqual({ref: 'src/a.go', line: 42});

    // file_path present, line absent → ref only, line omitted
    expect((await convertOne({file_path: 'src/a.go', line: null})).sourceLocation).toEqual({ref: 'src/a.go'});

    // file_path absent → SAST source fallback used instead
    expect((await convertOne({sast_source_file_path: 'sast/b.go', sast_source_line: 7})).sourceLocation).toEqual({
      ref: 'sast/b.go',
      line: 7,
    });

    // file_path present wins over sast_source_file_path when both are set
    expect(
      (await convertOne({file_path: 'src/a.go', line: 42, sast_source_file_path: 'sast/b.go', sast_source_line: 7}))
        .sourceLocation,
    ).toEqual({ref: 'src/a.go', line: 42});

    // no locus at all → sourceLocation omitted
    expect((await convertOne({})).sourceLocation).toBeUndefined();
  });
});
