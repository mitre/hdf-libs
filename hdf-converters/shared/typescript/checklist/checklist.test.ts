import { describe, it, expect } from 'vitest';
import type { HdfResults } from '@mitre/hdf-schema';
import { CheckStatus } from './model.js';
import {
  parseStatus,
  statusToCkl,
  statusToCklb,
  statusToHdf,
  statusFromHdf,
} from './status.js';
import { parseCkl, serializeCkl } from './ckl.js';
import { parseCklb, serializeCklb } from './cklb.js';
import { checklistToHdf } from './to-hdf.js';
import { hdfToChecklist } from './from-hdf.js';

const SAMPLE_CKL = `<?xml version="1.0" encoding="UTF-8"?>
<CHECKLIST>
  <ASSET>
    <ROLE>None</ROLE>
    <ASSET_TYPE>Computing</ASSET_TYPE>
    <HOST_NAME>EXAMPLE-HOST</HOST_NAME>
    <HOST_IP>192.0.2.10</HOST_IP>
    <HOST_MAC>00:00:00:00:00:00</HOST_MAC>
    <HOST_FQDN>host.example.com</HOST_FQDN>
    <WEB_OR_DATABASE>false</WEB_OR_DATABASE>
  </ASSET>
  <STIGS>
    <iSTIG>
      <STIG_INFO>
        <SI_DATA><SID_NAME>stigid</SID_NAME><SID_DATA>MOZ_Firefox_STIG</SID_DATA></SI_DATA>
        <SI_DATA><SID_NAME>title</SID_NAME><SID_DATA>Mozilla Firefox STIG</SID_DATA></SI_DATA>
        <SI_DATA><SID_NAME>version</SID_NAME><SID_DATA>1</SID_DATA></SI_DATA>
        <SI_DATA><SID_NAME>uuid</SID_NAME><SID_DATA>abc-123</SID_DATA></SI_DATA>
      </STIG_INFO>
      <VULN>
        <STIG_DATA><VULN_ATTRIBUTE>Vuln_Num</VULN_ATTRIBUTE><ATTRIBUTE_DATA>V-251545</ATTRIBUTE_DATA></STIG_DATA>
        <STIG_DATA><VULN_ATTRIBUTE>Severity</VULN_ATTRIBUTE><ATTRIBUTE_DATA>high</ATTRIBUTE_DATA></STIG_DATA>
        <STIG_DATA><VULN_ATTRIBUTE>Rule_ID</VULN_ATTRIBUTE><ATTRIBUTE_DATA>SV-251545r1_rule</ATTRIBUTE_DATA></STIG_DATA>
        <STIG_DATA><VULN_ATTRIBUTE>Rule_Ver</VULN_ATTRIBUTE><ATTRIBUTE_DATA>FFOX-00-000001</ATTRIBUTE_DATA></STIG_DATA>
        <STIG_DATA><VULN_ATTRIBUTE>Rule_Title</VULN_ATTRIBUTE><ATTRIBUTE_DATA>Firefox must be supported.</ATTRIBUTE_DATA></STIG_DATA>
        <STIG_DATA><VULN_ATTRIBUTE>Vuln_Discuss</VULN_ATTRIBUTE><ATTRIBUTE_DATA>Discussion.</ATTRIBUTE_DATA></STIG_DATA>
        <STIG_DATA><VULN_ATTRIBUTE>CCI_REF</VULN_ATTRIBUTE><ATTRIBUTE_DATA>CCI-002605</ATTRIBUTE_DATA></STIG_DATA>
        <STATUS>Open</STATUS>
        <FINDING_DETAILS>Out of date.</FINDING_DETAILS>
        <COMMENTS>Note.</COMMENTS>
      </VULN>
    </iSTIG>
  </STIGS>
</CHECKLIST>`;

const SAMPLE_CKLB = JSON.stringify({
  title: 'Mozilla Firefox STIG',
  cklb_version: '1.0',
  active: false,
  target_data: {
    target_type: 'Computing',
    host_name: 'EXAMPLE-HOST',
    ip_address: '192.0.2.10',
    fqdn: 'host.example.com',
    role: 'None',
  },
  stigs: [
    {
      stig_name: 'Mozilla Firefox STIG',
      stig_id: 'MOZ_Firefox_STIG',
      version: '1',
      uuid: 'abc-123',
      rules: [
        {
          group_id: 'V-251545',
          rule_id: 'SV-251545r1_rule',
          rule_version: 'FFOX-00-000001',
          rule_title: 'Firefox must be supported.',
          severity: 'high',
          discussion: 'Discussion.',
          ccis: ['CCI-002605'],
          status: 'open',
          finding_details: 'Out of date.',
          comments: 'Note.',
        },
      ],
    },
  ],
});

const CHECKSUM = { algorithm: 'sha256' as never, value: 'abc' };

describe('checklist shared model', () => {
  it('status translations round-trip', () => {
    for (const s of [
      CheckStatus.Open,
      CheckStatus.NotAFinding,
      CheckStatus.NotReviewed,
      CheckStatus.NotApplicable,
    ]) {
      expect(parseStatus(statusToCkl(s))).toBe(s);
      expect(parseStatus(statusToCklb(s))).toBe(s);
      expect(statusFromHdf(statusToHdf(s))).toBe(s);
    }
    expect(parseStatus('bogus')).toBe(CheckStatus.NotReviewed);
    expect(parseStatus(undefined)).toBe(CheckStatus.NotReviewed);
  });

  it('parses CKL and CKLB to equivalent models', () => {
    const ckl = parseCkl(SAMPLE_CKL);
    const cklb = parseCklb(SAMPLE_CKLB);
    expect(ckl.format).toBe('ckl');
    expect(cklb.format).toBe('cklb');
    expect(ckl.asset.hostName).toBe(cklb.asset.hostName);
    expect(ckl.stigs[0].stigID).toBe(cklb.stigs[0].stigID);
    const cv = ckl.stigs[0].vulns[0];
    const bv = cklb.stigs[0].vulns[0];
    expect(cv.vulnNum).toBe(bv.vulnNum);
    expect(cv.severity).toBe(bv.severity);
    expect(cv.ccis).toEqual(bv.ccis);
    expect(cv.status).toBe(bv.status);
    expect(cv.ruleTitle).toBe(bv.ruleTitle);
  });

  it('maps checklist to HDF with controlType and no verificationMethod', () => {
    const hdf = checklistToHdf(parseCkl(SAMPLE_CKL), CHECKSUM);
    expect(hdf.baselines).toHaveLength(1);
    const bl = hdf.baselines[0];
    expect(bl.name).toBe('STIG Checklist Scan');
    expect(bl.title).toBe('Mozilla Firefox STIG');
    expect((bl.extensions as Record<string, unknown>)['stigid']).toBe('MOZ_Firefox_STIG');
    const r = bl.requirements[0];
    expect(r.id).toBe('V-251545');
    expect(r.impact).toBeCloseTo(0.7, 3);
    expect(r.results[0].status).toBe('failed');
    expect(r.controlType).toBe('technical');
    expect(r.verificationMethod).toBeUndefined();
    expect(r.applicability).toBeUndefined();
    expect(hdf.components?.[0].name).toBe('EXAMPLE-HOST');
    expect((hdf.extensions as Record<string, unknown>)['checklistFormat']).toBe('ckl');
  });

  it('round-trips CKL -> HDF -> model -> CKL', () => {
    const cl = parseCkl(SAMPLE_CKL);
    const hdf = checklistToHdf(cl, CHECKSUM);
    const rt = hdfToChecklist(JSON.stringify(hdf));
    expect(rt.asset.hostName).toBe(cl.asset.hostName);
    expect(rt.stigs[0].stigID).toBe(cl.stigs[0].stigID);
    const o = cl.stigs[0].vulns[0];
    const n = rt.stigs[0].vulns[0];
    expect(n.vulnNum).toBe(o.vulnNum);
    expect(n.ruleID).toBe(o.ruleID);
    expect(n.severity).toBe(o.severity);
    expect(n.ccis).toEqual(o.ccis);
    expect(n.status).toBe(o.status);

    const reparsed = parseCkl(serializeCkl(rt));
    expect(reparsed.stigs[0].vulns[0].vulnNum).toBe(o.vulnNum);
    expect(reparsed.stigs[0].vulns[0].status).toBe(o.status);
  });

  it('round-trips CKLB -> HDF -> model -> CKLB with snake_case status', () => {
    const cl = parseCklb(SAMPLE_CKLB);
    const hdf = checklistToHdf(cl, CHECKSUM);
    const rt = hdfToChecklist(JSON.stringify(hdf));
    expect(rt.format).toBe('cklb');
    const out = serializeCklb(rt);
    expect(out).toContain('"status": "open"');
    expect(out).toContain('"ccis"');
    const reparsed = parseCklb(out);
    expect(reparsed.stigs[0].vulns[0].vulnNum).toBe('V-251545');
    expect(reparsed.stigs[0].vulns[0].ccis).toEqual(['CCI-002605']);
  });

  it('synthesizes a valid checklist from arbitrary HDF (nist->cci, defaults)', () => {
    const hdf: HdfResults = {
      baselines: [
        {
          name: 'Some Scan',
          title: 'Some Tool Scan',
          requirements: [
            {
              id: 'GEN-001',
              title: 'A finding',
              impact: 0.5,
              tags: { nist: ['SI-2 c'] },
              descriptions: [],
              results: [{ status: 'failed' as never, codeDesc: '' }],
            },
          ],
        },
      ],
    } as unknown as HdfResults;
    const cl = hdfToChecklist(JSON.stringify(hdf));
    const v = cl.stigs[0].vulns[0];
    expect(v.vulnNum).toBe('GEN-001');
    expect(v.severity).toBe('medium');
    expect(v.status).toBe(CheckStatus.Open);
    expect(v.ccis.length).toBeGreaterThan(0);
    // serializes to valid CKL that re-parses
    expect(() => parseCkl(serializeCkl(cl))).not.toThrow();
  });

  it('throws on malformed input', () => {
    expect(() => parseCkl('not xml')).toThrow();
    expect(() => parseCklb('not json')).toThrow();
    expect(() => parseCklb('{"stigs":[]}')).toThrow();
    expect(() => hdfToChecklist('{"baselines":[]}')).toThrow();
  });
});
