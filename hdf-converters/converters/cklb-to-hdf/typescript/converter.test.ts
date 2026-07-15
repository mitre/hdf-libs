import { readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { describe, it, expect } from 'vitest';
import { convertCklbToHdf } from './converter.js';
import { expectValidResults } from '../../../test/helpers/expectValidHdf.js';
import { runSnapshotTests } from '../../../shared/typescript/snapshot.js';
import {
  assertRequirementCount,
  countJsonItemsUnderKey,
} from '../../../shared/typescript/anchor.js';
import type { HDFResults, EvaluatedRequirement } from '@mitre/hdf-schema';

const __dirname = dirname(fileURLToPath(import.meta.url));
const FIXTURES_DIR = join(__dirname, '..', 'fixtures');

function loadFixture(name: string): string {
  return readFileSync(join(FIXTURES_DIR, 'input', name), 'utf-8');
}

function findReq(reqs: EvaluatedRequirement[], id: string): EvaluatedRequirement {
  const r = reqs.find((req) => req.id === id);
  if (!r) {
    throw new Error(`requirement ${id} not found`);
  }
  return r;
}

// STIG checklist (.cklb) carries no scan time.
runSnapshotTests('cklb-to-hdf', convertCklbToHdf, ['*']);

// Ground-truth anchors (input-derived counts; see shared/typescript/anchor.ts).
describe('cklb-to-hdf ground-truth anchors', () => {
  it('emits one requirement per stigs[].rules[] (firefox)', async () => {
    const input = loadFixture('firefox-stig.cklb');
    assertRequirementCount(
      await convertCklbToHdf(input),
      countJsonItemsUnderKey(input, 'rules'),
      'firefox-stig.cklb: one requirement per stigs[].rules[]',
    );
  });

  it('emits one requirement per stigs[].rules[] (all-passing)', async () => {
    const input = loadFixture('all-passing.cklb');
    assertRequirementCount(
      await convertCklbToHdf(input),
      countJsonItemsUnderKey(input, 'rules'),
      'all-passing.cklb: one requirement per stigs[].rules[]',
    );
  });
});

describe('cklb-to-hdf converter', () => {
  it('throws on empty input', async () => {
    await expect(convertCklbToHdf('')).rejects.toThrow();
  });

  it('throws on non-CKLB JSON', async () => {
    await expect(convertCklbToHdf('not valid json at all')).rejects.toThrow();
  });

  it('produces schema-valid HDF Results', async () => {
    const hdf = JSON.parse(await convertCklbToHdf(loadFixture('firefox-stig.cklb'))) as HDFResults;
    expectValidResults(hdf);
  });

  it('stamps a startTime on every result', async () => {
    const hdf = JSON.parse(await convertCklbToHdf(loadFixture('firefox-stig.cklb'))) as HDFResults;
    for (const req of hdf.baselines[0].requirements) {
      for (const result of req.results) {
        expect(result.startTime).toBeTruthy();
      }
    }
  });

  it('produces the expected top-level HDF structure', async () => {
    const hdf = JSON.parse(await convertCklbToHdf(loadFixture('firefox-stig.cklb'))) as HDFResults;

    expect(hdf.timestamp).toBeTruthy();
    expect(hdf.generator?.name).toBe('cklb-to-hdf');
    expect(hdf.tool?.name).toBe('DISA STIG Viewer');
    expect(hdf.tool?.format).toBe('CKLB');
    expect(hdf.baselines).toHaveLength(1);
    expect(hdf.baselines[0].name).toBe('STIG Checklist Scan');
    expect(hdf.baselines[0].title).toBe(
      'Mozilla Firefox Security Technical Implementation Guide'
    );
    expect(hdf.baselines[0].requirements).toHaveLength(6);
  });

  it('maps the host target_data to a Host component', async () => {
    const hdf = JSON.parse(await convertCklbToHdf(loadFixture('firefox-stig.cklb'))) as HDFResults;
    expect(hdf.components).toHaveLength(1);
    const c = hdf.components![0];
    expect(c.name).toBe('EXAMPLE-HOST');
    expect(c.type).toBe('host');
    expect(c.ipAddress).toBe('192.0.2.10');
    expect(c.fqdn).toBe('host.example.com');
    expect(c.macAddress).toBe('00:00:00:00:00:00');
  });

  it('maps CKLB status values to HDF result statuses', async () => {
    const hdf = JSON.parse(await convertCklbToHdf(loadFixture('firefox-stig.cklb'))) as HDFResults;
    const reqs = hdf.baselines[0].requirements;
    expect(findReq(reqs, 'V-251545').results[0].status).toBe('failed'); // open
    expect(findReq(reqs, 'V-251546').results[0].status).toBe('passed'); // not_a_finding
    expect(findReq(reqs, 'V-251547').results[0].status).toBe('notApplicable'); // not_applicable
    expect(findReq(reqs, 'V-251559').results[0].status).toBe('notReviewed'); // not_reviewed
  });

  it('derives controlType from CCI->NIST and omits verificationMethod/applicability', async () => {
    const hdf = JSON.parse(await convertCklbToHdf(loadFixture('firefox-stig.cklb'))) as HDFResults;
    const r = findReq(hdf.baselines[0].requirements, 'V-251545');

    expect(r.title).toBe('The installed version of Firefox must be supported.');
    expect(r.impact).toBeCloseTo(0.7, 3); // high
    expect((r.tags as Record<string, unknown>)['nist']).toContain('SI-2 c');
    expect((r.tags as Record<string, unknown>)['cci']).toContain('CCI-002605');
    expect(r.controlType).toBe('technical');
    expect(r.verificationMethod).toBeUndefined();
    expect(r.applicability).toBeUndefined();
  });

  it('omits verificationMethod for every requirement', async () => {
    const hdf = JSON.parse(await convertCklbToHdf(loadFixture('firefox-stig.cklb'))) as HDFResults;
    for (const r of hdf.baselines[0].requirements) {
      expect(r.verificationMethod).toBeUndefined();
    }
  });

  it('tracks impact from severity regardless of status', async () => {
    const hdf = JSON.parse(await convertCklbToHdf(loadFixture('firefox-stig.cklb'))) as HDFResults;
    const reqs = hdf.baselines[0].requirements;
    // medium + not_applicable -> impact 0.5, status notApplicable
    expect(findReq(reqs, 'V-251547').impact).toBeCloseTo(0.5, 3);
    expect(findReq(reqs, 'V-251547').results[0].status).toBe('notApplicable');
    expect(findReq(reqs, 'V-251559').impact).toBeCloseTo(0.3, 3); // low
  });

  // Pins safe behavior: an all-passing CKLB must emit one requirement per rule, never requirements:[].
  it('emits one passed requirement per rule for an all-passing CKLB', async () => {
    const hdf = JSON.parse(await convertCklbToHdf(loadFixture('all-passing.cklb'))) as HDFResults;
    expect(hdf.baselines).toHaveLength(1);

    const reqs = hdf.baselines[0].requirements;
    expect(reqs).toHaveLength(6);
    expect(reqs.length).toBeGreaterThan(0);

    for (const r of reqs) {
      expect(r.results).toHaveLength(1);
      expect(r.results[0].status).toBe('passed');
    }
  });

  // finding_details and comments are separate fields in CKLB; message carries
  // finding_details alone and comments round-trips through a tag.
  it('keeps comments out of message and round-trips it through tags', async () => {
    const hdf = JSON.parse(await convertCklbToHdf(loadFixture('firefox-stig.cklb'))) as HDFResults;
    const req = hdf.baselines[0]!.requirements[0]! as EvaluatedRequirement;

    expect(req.results[0]!.message).toBe('Installed Firefox version is end-of-life and unsupported.');
    expect(req.results[0]!.message).not.toContain('Synthetic checklist');
    // toBe, not a truthy/contains check: a non-string tag value must fail here.
    expect(req.tags!['comments']).toBe(
      'Synthetic checklist for hdf-libs converter test fixture - not a real assessment.',
    );
  });
});
