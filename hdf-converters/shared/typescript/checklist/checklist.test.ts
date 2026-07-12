import { describe, it, expect } from 'vitest';
import type { HDFResults } from '@mitre/hdf-schema';
import { CheckStatus, Checklist } from './model.js';
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

  it('statusToCkl falls back to Not_Reviewed for falsy input', () => {
    expect(statusToCkl('' as CheckStatus)).toBe(CheckStatus.NotReviewed);
    expect(statusToCkl(undefined as unknown as CheckStatus)).toBe(CheckStatus.NotReviewed);
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

  it('strips HTML from descriptions (parity with the Go mapping)', () => {
    const ckl = `<?xml version="1.0"?><CHECKLIST><ASSET><HOST_NAME>H</HOST_NAME></ASSET><STIGS><iSTIG><STIG_INFO><SI_DATA><SID_NAME>stigid</SID_NAME><SID_DATA>S</SID_DATA></SI_DATA></STIG_INFO><VULN><STIG_DATA><VULN_ATTRIBUTE>Vuln_Num</VULN_ATTRIBUTE><ATTRIBUTE_DATA>V-1</ATTRIBUTE_DATA></STIG_DATA><STIG_DATA><VULN_ATTRIBUTE>Vuln_Discuss</VULN_ATTRIBUTE><ATTRIBUTE_DATA>Use &lt;b&gt;bold&lt;/b&gt; markup.</ATTRIBUTE_DATA></STIG_DATA><STATUS>Open</STATUS></VULN></iSTIG></STIGS></CHECKLIST>`;
    const hdf = checklistToHdf(parseCkl(ckl), CHECKSUM, 'test-converter');
    const data = hdf.baselines[0].requirements[0].descriptions[0].data;
    expect(data).toBe('Use bold markup.');
    expect(data).not.toContain('<b>');
  });

  it('stamps a conversion-time startTime on every result (schema requires it)', () => {
    const hdf = checklistToHdf(parseCkl(SAMPLE_CKL), CHECKSUM, 'test-converter');
    const startTime = hdf.baselines[0].requirements[0].results[0].startTime;
    expect(startTime).toBeDefined();
    expect(new Date(startTime as string | Date).getTime()).toBeGreaterThan(0);
  });

  it('maps checklist to HDF with controlType and no verificationMethod', () => {
    const hdf = checklistToHdf(parseCkl(SAMPLE_CKL), CHECKSUM, 'test-converter');
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
    const hdf = checklistToHdf(cl, CHECKSUM, 'test-converter');
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

    const xml = serializeCkl(rt);
    const reparsed = parseCkl(xml);
    expect(reparsed.stigs[0].vulns[0].vulnNum).toBe(o.vulnNum);
    expect(reparsed.stigs[0].vulns[0].status).toBe(o.status);
    // Fields must serialize as child ELEMENTS, not VULN/ASSET attributes —
    // STIG Viewer rejects the attribute form. (Regression guard: with the
    // hdf-utilities default empty attribute prefix, fast-xml-parser would emit
    // scalar leaves as attributes.)
    expect(xml).toContain('<STATUS>Open</STATUS>');
    expect(xml).toContain('<HOST_NAME>EXAMPLE-HOST</HOST_NAME>');
    expect(xml).not.toMatch(/STATUS="/);
  });

  it('round-trips CKLB -> HDF -> model -> CKLB with snake_case status', () => {
    const cl = parseCklb(SAMPLE_CKLB);
    const hdf = checklistToHdf(cl, CHECKSUM, 'test-converter');
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
    const hdf: HDFResults = {
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
    } as unknown as HDFResults;
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

  // An iSTIG/stig with zero rules would yield requirements: [] downstream,
  // violating the HDF schema's minItems=1; both are rejected as malformed.
  it('rejects an iSTIG with no VULN rules', () => {
    const xml = '<?xml version="1.0" encoding="UTF-8"?><CHECKLIST><STIGS><iSTIG><STIG_INFO></STIG_INFO></iSTIG></STIGS></CHECKLIST>';
    expect(() => parseCkl(xml)).toThrow(/no <VULN> rules/);
  });

  it('rejects a CKLB stig with empty rules[]', () => {
    expect(() => parseCklb('{"cklb_version":"1.0","stigs":[{"stig_id":"x","rules":[]}]}')).toThrow(/no rules\[\]/);
  });

  // --- field/branch variations -------------------------------------------

  it('component name falls back to FQDN then IP when host name is absent', () => {
    const fqdnOnly = checklistToHdf(
      { format: 'ckl', asset: { hostFQDN: 'h.example.com' }, stigs: [{ vulns: [] }] },
      CHECKSUM,
      'test-converter',
    );
    expect(fqdnOnly.components?.[0].name).toBe('h.example.com');

    const ipOnly = checklistToHdf(
      { format: 'ckl', asset: { hostIP: '192.0.2.10' }, stigs: [{ vulns: [] }] },
      CHECKSUM,
      'test-converter',
    );
    expect(ipOnly.components?.[0].name).toBe('192.0.2.10');
  });

  it('omits the component when the asset has no host identity', () => {
    const hdf = checklistToHdf({ format: 'ckl', asset: {}, stigs: [{ vulns: [] }] }, CHECKSUM, 'test-converter');
    expect(hdf.components).toBeUndefined();
  });

  it('stores HOST_NAME in a dedicated hostname field, distinct from the Name fallback', () => {
    const both = checklistToHdf(
      { format: 'ckl', asset: { hostName: 'web01', hostFQDN: 'web01.prod.example.com', hostIP: '10.0.1.5' }, stigs: [{ vulns: [] }] },
      CHECKSUM,
      'test-converter',
    );
    expect(both.components?.[0].hostname).toBe('web01');
    expect(both.components?.[0].fqdn).toBe('web01.prod.example.com');

    // No HOST_NAME: hostname is not fabricated from the FQDN fallback.
    const fqdnOnly = checklistToHdf(
      { format: 'ckl', asset: { hostFQDN: 'web01.prod.example.com', hostIP: '10.0.1.5' }, stigs: [{ vulns: [] }] },
      CHECKSUM,
      'test-converter',
    );
    expect(fqdnOnly.components?.[0].hostname).toBeUndefined();
    expect(fqdnOnly.components?.[0].name).toBe('web01.prod.example.com');
  });

  it('preserves both HOST_NAME and HOST_FQDN through a round-trip without fabricating a short name', () => {
    const rt = (asset: Record<string, unknown>) => {
      const hdf = checklistToHdf({ format: 'ckl', asset, stigs: [{ stigId: 'S', title: 'T', version: '1', vulns: [{ vulnNum: 'V-1', ruleId: 'SV-1_rule', severity: 'low', ccis: [], status: CheckStatus.Open }] }] }, CHECKSUM, 'test-converter');
      return hdfToChecklist(JSON.stringify(hdf)).asset;
    };

    const both = rt({ hostName: 'web01', hostFQDN: 'web01.prod.example.com', hostIP: '10.0.1.5' });
    expect(both.hostName).toBe('web01');
    expect(both.hostFQDN).toBe('web01.prod.example.com');

    const fqdnOnly = rt({ hostFQDN: 'web01.prod.example.com', hostIP: '10.0.1.5' });
    expect(fqdnOnly.hostName).toBeFalsy();
    expect(fqdnOnly.hostFQDN).toBe('web01.prod.example.com');
  });

  it('recovers a legacy short HOST_NAME from Name without fabricating one from the fqdn/ip fallback', () => {
    const build = (component: Record<string, unknown>) => {
      const hdf = {
        components: [{ type: 'host', ...component }],
        baselines: [{ name: 'b', requirements: [{ id: 'V-1', impact: 0, tags: {}, descriptions: [], results: [{ status: 'passed', codeDesc: '' }] }] }],
      };
      return hdfToChecklist(JSON.stringify(hdf)).asset;
    };

    // Legacy HDF (no hostname field): real short name in name alongside fqdn -> preserved.
    const legacy = build({ name: 'web01', fqdn: 'web01.prod.example.com' });
    expect(legacy.hostName).toBe('web01');
    expect(legacy.hostFQDN).toBe('web01.prod.example.com');

    // Legacy HDF where name merely mirrors the fqdn/ip fallback -> not fabricated.
    expect(build({ name: 'web01.prod.example.com', fqdn: 'web01.prod.example.com' }).hostName).toBeFalsy();
    expect(build({ name: '10.0.1.5', ipAddress: '10.0.1.5' }).hostName).toBeFalsy();
  });

  it('coerces CKLB null fields to undefined (e.g. classification: null)', () => {
    const cklb = JSON.stringify({
      cklb_version: '1.0',
      target_data: { host_name: 'H', classification: null, role: null },
      stigs: [{ stig_id: 'S', rules: [{ group_id: 'V-1', status: 'open', ccis: null, classification: null }] }],
    });
    const cl = parseCklb(cklb);
    expect(cl.asset.classification).toBeUndefined();
    expect(cl.asset.role).toBeUndefined();
    expect(cl.stigs[0].vulns[0].ccis).toEqual([]);
    expect(cl.stigs[0].vulns[0].classification).toBeUndefined();
  });

  it('serializeCklb emits has_path and snake_case scaffolding', () => {
    const out = serializeCklb({ format: 'cklb', asset: {}, stigs: [{ vulns: [] }] });
    const doc = JSON.parse(out);
    expect(doc.has_path).toBe(false);
    expect(doc.active).toBe(false);
    expect(doc.cklb_version).toBe('1.0');
    expect(doc.target_data.role).toBe('None');
    expect(doc.target_data.target_type).toBe('Computing');
  });

  it('serializeCkl applies safe defaults and emits core attrs for sparse vulns', () => {
    const cl: Checklist = {
      format: 'ckl',
      asset: {},
      stigs: [{ vulns: [{ vulnNum: 'V-1', ccis: [], status: CheckStatus.NotReviewed }] }],
    };
    const xml = serializeCkl(cl);
    expect(xml).toContain('<ROLE>None</ROLE>');
    expect(xml).toContain('<ASSET_TYPE>Computing</ASSET_TYPE>');
    // Weight/Class are STIG_DATA attribute pairs with safe defaults.
    expect(xml).toMatch(/<VULN_ATTRIBUTE>Weight<\/VULN_ATTRIBUTE>\s*<ATTRIBUTE_DATA>10\.0<\/ATTRIBUTE_DATA>/);
    expect(xml).toMatch(/<VULN_ATTRIBUTE>Class<\/VULN_ATTRIBUTE>\s*<ATTRIBUTE_DATA>Unclass<\/ATTRIBUTE_DATA>/);
    expect(xml).toContain('<STATUS>Not_Reviewed</STATUS>');
  });

  it('round-trips extra fields and legacy IDs through ckl + cklb', () => {
    const cl: Checklist = {
      format: 'cklb',
      asset: { hostName: 'H', webOrDatabase: true },
      stigs: [{
        stigID: 'S',
        vulns: [{
          vulnNum: 'V-1', ruleID: 'SV-1', ccis: ['CCI-000366'], legacyIDs: ['V-9'],
          status: CheckStatus.NotAFinding, extra: { Third_Party_Tools: 'blob', Responsibility: 'admin' },
        }],
      }],
    };
    const cklbDoc = JSON.parse(serializeCklb(cl));
    expect(cklbDoc.stigs[0].rules[0].legacy_ids).toEqual(['V-9']);
    expect(cklbDoc.stigs[0].rules[0].third_party_tools).toBe('blob');
    expect(cklbDoc.target_data.is_web_database).toBe(true);
    // extras survive into CKL XML as STIG_DATA attributes
    expect(serializeCkl(cl)).toContain('<ATTRIBUTE_DATA>admin</ATTRIBUTE_DATA>');
  });

  it('hdfToChecklist derives severity from impact tiers when no severity tag', () => {
    const mk = (impact: number) =>
      hdfToChecklist(JSON.stringify({
        baselines: [{ name: 'b', requirements: [{ id: 'V-1', impact, tags: {}, descriptions: [], results: [{ status: 'failed', codeDesc: '' }] }] }],
      })).stigs[0].vulns[0].severity;
    expect(mk(0.7)).toBe('high');
    expect(mk(0.5)).toBe('medium');
    expect(mk(0.3)).toBe('low');
    expect(mk(0)).toBe('');
  });

  it('stashes all asset extras + STIG metadata in extensions and round-trips them', () => {
    const cl: Checklist = {
      format: 'cklb',
      cklbVersion: '1.0',
      asset: {
        hostName: 'H', role: 'Member Server', assetType: 'Computing', marking: 'CUI',
        targetKey: '2350', techArea: 'area', targetComment: 'tc',
        webDBSite: 'site', webDBInstance: 'inst', classification: 'UNCLASSIFIED',
        webOrDatabase: true,
      },
      stigs: [{
        stigID: 'S', title: 'T', version: '2', uuid: 'u-1', releaseInfo: 'R: 3',
        displayName: 'disp', referenceIdentifier: 'ref', classification: 'UNCLASSIFIED',
        vulns: [{ vulnNum: 'V-1', ccis: [], status: CheckStatus.Open }],
      }],
    };
    const hdf = checklistToHdf(cl, CHECKSUM, 'test-converter');
    const ext = hdf.extensions as Record<string, unknown>;
    expect((ext.assetExtras as Record<string, unknown>).marking).toBe('CUI');
    expect((ext.assetExtras as Record<string, unknown>).webOrDatabase).toBe(true);
    expect(ext.cklbVersion).toBe('1.0');
    const blExt = hdf.baselines[0].extensions as Record<string, unknown>;
    expect(blExt.stigid).toBe('S');
    expect(blExt.referenceIdentifier).toBe('ref');

    // survives the reverse trip
    const rt = hdfToChecklist(JSON.stringify(hdf));
    expect(rt.asset.marking).toBe('CUI');
    expect(rt.asset.webOrDatabase).toBe(true);
    expect(rt.cklbVersion).toBe('1.0');
    expect(rt.stigs[0].uuid).toBe('u-1');
    expect(rt.stigs[0].referenceIdentifier).toBe('ref');
  });

  it('hdfToChecklist prefers explicit cci tags over nist reverse, and omits both when absent', () => {
    const withCci = hdfToChecklist(JSON.stringify({
      baselines: [{ name: 'b', requirements: [{ id: 'V-1', impact: 0.5, tags: { cci: ['CCI-000001'], nist: ['SI-2'] }, descriptions: [], results: [{ status: 'failed', codeDesc: '' }] }] }],
    }));
    expect(withCci.stigs[0].vulns[0].ccis).toEqual(['CCI-000001']);

    const noTags = hdfToChecklist(JSON.stringify({
      baselines: [{ name: 'b', requirements: [{ id: 'V-1', impact: 0.5, tags: {}, descriptions: [], results: [{ status: 'failed', codeDesc: '' }] }] }],
    }));
    expect(noTags.stigs[0].vulns[0].ccis).toEqual([]);
  });
});
