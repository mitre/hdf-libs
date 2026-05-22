import { readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { describe, it, expect } from 'vitest';
import { convertCklbToHdf } from './converter.js';
import type { HdfResults, EvaluatedRequirement } from '@mitre/hdf-schema';

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

describe('cklb-to-hdf converter', () => {
  it('throws on empty input', async () => {
    await expect(convertCklbToHdf('')).rejects.toThrow();
  });

  it('throws on non-CKLB JSON', async () => {
    await expect(convertCklbToHdf('not valid json at all')).rejects.toThrow();
  });

  it('produces the expected top-level HDF structure', async () => {
    const hdf = JSON.parse(await convertCklbToHdf(loadFixture('firefox-stig.cklb'))) as HdfResults;

    expect(hdf.timestamp).toBeTruthy();
    expect(hdf.generator?.name).toBe('hdf-converters');
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
    const hdf = JSON.parse(await convertCklbToHdf(loadFixture('firefox-stig.cklb'))) as HdfResults;
    expect(hdf.components).toHaveLength(1);
    const c = hdf.components![0];
    expect(c.name).toBe('EXAMPLE-HOST');
    expect(c.type).toBe('host');
    expect(c.ipAddress).toBe('192.0.2.10');
    expect(c.fqdn).toBe('host.example.com');
    expect(c.macAddress).toBe('00:00:00:00:00:00');
  });

  it('maps CKLB status values to HDF result statuses', async () => {
    const hdf = JSON.parse(await convertCklbToHdf(loadFixture('firefox-stig.cklb'))) as HdfResults;
    const reqs = hdf.baselines[0].requirements;
    expect(findReq(reqs, 'V-251545').results[0].status).toBe('failed'); // open
    expect(findReq(reqs, 'V-251546').results[0].status).toBe('passed'); // not_a_finding
    expect(findReq(reqs, 'V-251547').results[0].status).toBe('notApplicable'); // not_applicable
    expect(findReq(reqs, 'V-251559').results[0].status).toBe('notReviewed'); // not_reviewed
  });

  it('derives controlType from CCI->NIST and omits verificationMethod/applicability', async () => {
    const hdf = JSON.parse(await convertCklbToHdf(loadFixture('firefox-stig.cklb'))) as HdfResults;
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
    const hdf = JSON.parse(await convertCklbToHdf(loadFixture('firefox-stig.cklb'))) as HdfResults;
    for (const r of hdf.baselines[0].requirements) {
      expect(r.verificationMethod).toBeUndefined();
    }
  });

  it('tracks impact from severity regardless of status', async () => {
    const hdf = JSON.parse(await convertCklbToHdf(loadFixture('firefox-stig.cklb'))) as HdfResults;
    const reqs = hdf.baselines[0].requirements;
    // medium + not_applicable -> impact 0.5, status notApplicable
    expect(findReq(reqs, 'V-251547').impact).toBeCloseTo(0.5, 3);
    expect(findReq(reqs, 'V-251547').results[0].status).toBe('notApplicable');
    expect(findReq(reqs, 'V-251559').impact).toBeCloseTo(0.3, 3); // low
  });
});
