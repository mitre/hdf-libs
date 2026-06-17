import { readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { describe, it, expect } from 'vitest';
import { convertCklToHdf } from './converter.js';
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

const MINIMAL_CKL = `<?xml version="1.0" encoding="UTF-8"?>
<CHECKLIST>
  <ASSET>
    <HOST_NAME></HOST_NAME>
    <HOST_IP></HOST_IP>
    <HOST_FQDN></HOST_FQDN>
  </ASSET>
  <STIGS>
    <iSTIG>
      <STIG_INFO>
        <SI_DATA><SID_NAME>title</SID_NAME><SID_DATA>Bare STIG</SID_DATA></SI_DATA>
      </STIG_INFO>
      <VULN>
        <STIG_DATA><VULN_ATTRIBUTE>Vuln_Num</VULN_ATTRIBUTE><ATTRIBUTE_DATA>V-1</ATTRIBUTE_DATA></STIG_DATA>
        <STIG_DATA><VULN_ATTRIBUTE>Severity</VULN_ATTRIBUTE><ATTRIBUTE_DATA>low</ATTRIBUTE_DATA></STIG_DATA>
        <STIG_DATA><VULN_ATTRIBUTE>Rule_Title</VULN_ATTRIBUTE><ATTRIBUTE_DATA>Bare rule</ATTRIBUTE_DATA></STIG_DATA>
        <STATUS>Open</STATUS>
        <FINDING_DETAILS></FINDING_DETAILS>
        <COMMENTS></COMMENTS>
      </VULN>
    </iSTIG>
  </STIGS>
</CHECKLIST>`;

describe('ckl-to-hdf converter', () => {
  it('throws on empty input', async () => {
    await expect(convertCklToHdf('')).rejects.toThrow();
  });

  it('throws on non-CKL XML', async () => {
    await expect(
      convertCklToHdf('<?xml version="1.0"?><Benchmark></Benchmark>')
    ).rejects.toThrow();
  });

  it('produces the expected top-level HDF structure', async () => {
    const hdf = JSON.parse(await convertCklToHdf(loadFixture('firefox-stig.ckl'))) as HDFResults;

    expect(hdf.timestamp).toBeTruthy();
    expect(hdf.generator?.name).toBe('ckl-to-hdf');
    expect(hdf.tool?.name).toBe('DISA STIG Viewer');
    expect(hdf.tool?.format).toBe('CKL');
    expect(hdf.baselines).toHaveLength(1);
    expect(hdf.baselines[0].name).toBe('STIG Checklist Scan');
    expect(hdf.baselines[0].title).toBe(
      'Mozilla Firefox Security Technical Implementation Guide'
    );
    expect(hdf.baselines[0].requirements).toHaveLength(6);
  });

  it('maps the host ASSET to a Host component', async () => {
    const hdf = JSON.parse(await convertCklToHdf(loadFixture('firefox-stig.ckl'))) as HDFResults;
    expect(hdf.components).toHaveLength(1);
    const c = hdf.components![0];
    expect(c.name).toBe('EXAMPLE-HOST');
    expect(c.type).toBe('host');
    expect(c.ipAddress).toBe('192.0.2.10');
    expect(c.fqdn).toBe('host.example.com');
    expect(c.macAddress).toBe('00:00:00:00:00:00');
  });

  it('maps CKL STATUS values to HDF result statuses', async () => {
    const hdf = JSON.parse(await convertCklToHdf(loadFixture('firefox-stig.ckl'))) as HDFResults;
    const reqs = hdf.baselines[0].requirements;
    expect(findReq(reqs, 'V-251545').results[0].status).toBe('failed'); // Open
    expect(findReq(reqs, 'V-251546').results[0].status).toBe('passed'); // NotAFinding
    expect(findReq(reqs, 'V-251547').results[0].status).toBe('notApplicable'); // Not_Applicable
    expect(findReq(reqs, 'V-251559').results[0].status).toBe('notReviewed'); // Not_Reviewed
  });

  it('derives controlType from CCI->NIST and omits verificationMethod/applicability', async () => {
    const hdf = JSON.parse(await convertCklToHdf(loadFixture('firefox-stig.ckl'))) as HDFResults;
    const r = findReq(hdf.baselines[0].requirements, 'V-251545');

    expect(r.title).toBe('The installed version of Firefox must be supported.');
    expect(r.impact).toBeCloseTo(0.7, 3); // high
    expect((r.tags as Record<string, unknown>)['nist']).toContain('SI-2 c');
    expect((r.tags as Record<string, unknown>)['cci']).toContain('CCI-002605');
    expect(r.controlType).toBe('technical');
    expect(r.verificationMethod).toBeUndefined();
    expect(r.applicability).toBeUndefined();
    expect(r.results[0].message).toContain('end-of-life');
  });

  it('omits verificationMethod for every requirement', async () => {
    const hdf = JSON.parse(await convertCklToHdf(loadFixture('firefox-stig.ckl'))) as HDFResults;
    for (const r of hdf.baselines[0].requirements) {
      expect(r.verificationMethod).toBeUndefined();
    }
  });

  it('tracks impact from severity regardless of status', async () => {
    const hdf = JSON.parse(await convertCklToHdf(loadFixture('firefox-stig.ckl'))) as HDFResults;
    const reqs = hdf.baselines[0].requirements;
    // medium + Not_Applicable -> impact 0.5, status notApplicable
    expect(findReq(reqs, 'V-251547').impact).toBeCloseTo(0.5, 3);
    expect(findReq(reqs, 'V-251547').results[0].status).toBe('notApplicable');
    expect(findReq(reqs, 'V-251559').impact).toBeCloseTo(0.3, 3); // low
  });

  it('omits the component and controlType when no host / no CCI', async () => {
    const hdf = JSON.parse(await convertCklToHdf(MINIMAL_CKL)) as HDFResults;
    expect(hdf.components).toBeUndefined();
    const r = hdf.baselines[0].requirements[0];
    expect((r.tags as Record<string, unknown>)['nist']).toEqual([]);
    expect(r.controlType).toBeUndefined();
    expect(r.verificationMethod).toBeUndefined();
  });

  // Pins safe behavior: an all-passing CKL must produce one requirement per
  // VULN (never an empty requirements slice) so a future refactor cannot
  // silently introduce the "emit empty requirements" anti-pattern.
  it('emits one requirement per VULN for an all-passing CKL', async () => {
    const hdf = JSON.parse(await convertCklToHdf(loadFixture('all-passing.ckl'))) as HDFResults;
    expect(hdf.baselines).toHaveLength(1);
    const reqs = hdf.baselines[0].requirements;
    expect(reqs).toHaveLength(3);
    for (const r of reqs) {
      expect(r.results.length).toBeGreaterThan(0);
      expect(r.results[0].status).toBe('passed');
    }
  });
});
