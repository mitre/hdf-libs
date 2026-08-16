import { parseXmlWithArrays, buildXml } from '@mitre/hdf-utilities';
import { Asset, Checklist, Stig, Vuln } from './model.js';
import { parseStatus, statusToCkl } from './status.js';

const ARRAY_TAGS = ['iSTIG', 'VULN', 'STIG_DATA', 'SI_DATA'];

// attributeNamePrefix is set to a token none of our element keys use, so every
// plain key renders as a child ELEMENT (with the hdf-utilities default of '',
// fast-xml-parser would emit scalar leaves like STATUS/HOST_NAME as attributes,
// producing malformed CKL).
const BUILD_OPTIONS = {
  attributeNamePrefix: '@_',
  textNodeName: '#text',
  ignoreAttributes: false,
  format: true,
  indentBy: '\t',
  suppressEmptyNode: false,
};

interface CklParsed {
  CHECKLIST?: {
    ASSET?: Record<string, unknown>;
    STIGS?: { iSTIG?: IStigEl[] };
  };
}
interface IStigEl {
  STIG_INFO?: { SI_DATA?: { SID_NAME?: string; SID_DATA?: unknown }[] };
  VULN?: VulnEl[];
}
interface VulnEl {
  STIG_DATA?: { VULN_ATTRIBUTE?: string; ATTRIBUTE_DATA?: unknown }[];
  STATUS?: string;
  FINDING_DETAILS?: unknown;
  COMMENTS?: unknown;
  SEVERITY_OVERRIDE?: unknown;
  SEVERITY_JUSTIFICATION?: unknown;
}

function str(v: unknown): string {
  return v === undefined || v === null ? '' : String(v);
}

const VULN_ATTR_ORDER = [
  'Vuln_Num', 'Severity', 'Group_Title', 'Rule_ID', 'Rule_Ver', 'Rule_Title',
  'Vuln_Discuss', 'IA_Controls', 'Check_Content', 'Fix_Text', 'False_Positives',
  'False_Negatives', 'Documentable', 'Mitigations', 'Potential_Impact',
  'Third_Party_Tools', 'Mitigation_Control', 'Responsibility',
  'Security_Override_Guidance', 'Check_Content_Ref', 'Weight', 'Class', 'STIG_UUID',
];
const CORE_VULN_ATTR = new Set([
  'Vuln_Num', 'Severity', 'Group_Title', 'Rule_ID', 'Rule_Ver', 'Rule_Title',
  'Vuln_Discuss', 'Check_Content', 'Fix_Text', 'Weight', 'Class',
]);

/** Parse CKL XML into the format-neutral Checklist model. */
export function parseCkl(input: string): Checklist {
  // processEntities decodes XML entities (&lt; &gt; &amp; …) so CKL text matches
  // Go's encoding/xml (which decodes by default); without it, entity-encoded
  // markup like "&lt;b&gt;" survives and stripHTML in checklistToHdf can't act
  // on it — diverging from the Go output.
  const parsed = parseXmlWithArrays(input, ARRAY_TAGS, {
    processEntities: true,
  }) as CklParsed;
  const checklist = parsed.CHECKLIST;
  const istigs = checklist?.STIGS?.iSTIG;
  if (!checklist || !istigs || istigs.length === 0) {
    throw new Error('parse ckl: no <iSTIG> blocks found (not a CKL document?)');
  }

  const a = checklist.ASSET ?? {};
  const asset: Asset = {
    role: str(a['ROLE']),
    assetType: str(a['ASSET_TYPE']),
    marking: str(a['MARKING']),
    hostName: str(a['HOST_NAME']),
    hostIP: str(a['HOST_IP']),
    hostMAC: str(a['HOST_MAC']),
    hostFQDN: str(a['HOST_FQDN']),
    targetComment: str(a['TARGET_COMMENT']),
    techArea: str(a['TECH_AREA']),
    targetKey: str(a['TARGET_KEY']),
    webOrDatabase: str(a['WEB_OR_DATABASE']) === 'true',
    webDBSite: str(a['WEB_DB_SITE']),
    webDBInstance: str(a['WEB_DB_INSTANCE']),
  };

  const stigs: Stig[] = istigs.map((is, i) => {
    // An iSTIG with no rules would yield requirements: [] downstream, which
    // violates the HDF schema's requirements.minItems=1. Reject as malformed,
    // consistent with the no-<iSTIG> guard above.
    const vulns = is.VULN ?? [];
    if (vulns.length === 0) {
      throw new Error(`parse ckl: <iSTIG> block ${i + 1} contains no <VULN> rules`);
    }
    const si = is.STIG_INFO?.SI_DATA ?? [];
    const siVal = (name: string): string =>
      str(si.find((d) => d.SID_NAME === name)?.SID_DATA);
    return {
      stigID: siVal('stigid'),
      title: siVal('title'),
      version: siVal('version'),
      releaseInfo: siVal('releaseinfo'),
      uuid: siVal('uuid'),
      classification: siVal('classification'),
      vulns: vulns.map(cklVulnToModel),
    };
  });

  return { format: 'ckl', asset, stigs };
}

function cklVulnToModel(v: VulnEl): Vuln {
  const data = v.STIG_DATA ?? [];
  const attr = (name: string): string =>
    str(data.find((sd) => sd.VULN_ATTRIBUTE === name)?.ATTRIBUTE_DATA);
  const ccis: string[] = [];
  const legacyIDs: string[] = [];
  const extra: Record<string, string> = {};
  const promoted = new Set([
    'CCI_REF', 'LEGACY_ID', 'Vuln_Num', 'Severity', 'Group_Title', 'Rule_ID', 'Rule_Ver',
    'Rule_Title', 'Vuln_Discuss', 'Check_Content', 'Fix_Text', 'Weight', 'Class',
  ]);
  for (const sd of data) {
    const name = sd.VULN_ATTRIBUTE ?? '';
    const val = str(sd.ATTRIBUTE_DATA);
    if (name === 'CCI_REF') {
      if (val) ccis.push(val);
    } else if (name === 'LEGACY_ID') {
      if (val) legacyIDs.push(val);
    } else if (!promoted.has(name) && val) {
      extra[name] = val;
    }
  }
  return {
    vulnNum: attr('Vuln_Num'),
    ruleID: attr('Rule_ID'),
    ruleVer: attr('Rule_Ver'),
    groupTitle: attr('Group_Title'),
    severity: attr('Severity'),
    ruleTitle: attr('Rule_Title'),
    vulnDiscuss: attr('Vuln_Discuss'),
    checkContent: attr('Check_Content'),
    fixText: attr('Fix_Text'),
    weight: attr('Weight'),
    classification: attr('Class'),
    ccis,
    legacyIDs,
    status: parseStatus(v.STATUS),
    findingDetails: str(v.FINDING_DETAILS),
    comments: str(v.COMMENTS),
    severityOverride: str(v.SEVERITY_OVERRIDE),
    severityJustification: str(v.SEVERITY_JUSTIFICATION),
    extra,
  };
}

/** Serialize the Checklist model to CKL XML (with declaration). */
export function serializeCkl(cl: Checklist): string {
  const xmlObj = {
    CHECKLIST: {
      ASSET: {
        ROLE: cl.asset.role || 'None',
        ASSET_TYPE: cl.asset.assetType || 'Computing',
        HOST_NAME: cl.asset.hostName ?? '',
        HOST_IP: cl.asset.hostIP ?? '',
        HOST_MAC: cl.asset.hostMAC ?? '',
        HOST_FQDN: cl.asset.hostFQDN ?? '',
        TARGET_COMMENT: cl.asset.targetComment ?? '',
        TECH_AREA: cl.asset.techArea ?? '',
        TARGET_KEY: cl.asset.targetKey ?? '',
        WEB_OR_DATABASE: cl.asset.webOrDatabase ? 'true' : 'false',
        WEB_DB_SITE: cl.asset.webDBSite ?? '',
        WEB_DB_INSTANCE: cl.asset.webDBInstance ?? '',
      },
      STIGS: {
        iSTIG: cl.stigs.map((s) => ({
          STIG_INFO: { SI_DATA: stigInfoSiData(s) },
          VULN: s.vulns.map(modelVulnToCkl),
        })),
      },
    },
  };
  const body = buildXml(xmlObj, BUILD_OPTIONS);
  return `<?xml version="1.0" encoding="UTF-8"?>\n${body}`;
}

function stigInfoSiData(s: Stig): { SID_NAME: string; SID_DATA: string }[] {
  return [
    { name: 'version', data: s.version },
    { name: 'classification', data: s.classification },
    { name: 'stigid', data: s.stigID },
    { name: 'releaseinfo', data: s.releaseInfo },
    { name: 'title', data: s.title },
    { name: 'uuid', data: s.uuid },
  ]
    .filter((p) => p.data)
    .map((p) => ({ SID_NAME: p.name, SID_DATA: p.data as string }));
}

function modelVulnToCkl(v: Vuln): {
  STIG_DATA: { VULN_ATTRIBUTE: string; ATTRIBUTE_DATA: string }[];
  STATUS: string;
  FINDING_DETAILS: string;
  COMMENTS: string;
  SEVERITY_OVERRIDE: string;
  SEVERITY_JUSTIFICATION: string;
} {
  const typed: Record<string, string> = {
    Vuln_Num: v.vulnNum,
    Severity: v.severity ?? '',
    Group_Title: v.groupTitle ?? '',
    Rule_ID: v.ruleID ?? '',
    Rule_Ver: v.ruleVer ?? '',
    Rule_Title: v.ruleTitle ?? '',
    Vuln_Discuss: v.vulnDiscuss ?? '',
    Check_Content: v.checkContent ?? '',
    Fix_Text: v.fixText ?? '',
    Weight: v.weight || '10.0',
    Class: v.classification || 'Unclass',
  };
  const stigData: { VULN_ATTRIBUTE: string; ATTRIBUTE_DATA: string }[] = [];
  for (const name of VULN_ATTR_ORDER) {
    const val = typed[name] ?? v.extra?.[name] ?? '';
    if (!val && !CORE_VULN_ATTR.has(name)) continue;
    stigData.push({ VULN_ATTRIBUTE: name, ATTRIBUTE_DATA: val });
  }
  // LEGACY_ID entries (one per id) precede CCI_REF, matching STIG Viewer.
  for (const lid of v.legacyIDs ?? []) {
    if (lid) stigData.push({ VULN_ATTRIBUTE: 'LEGACY_ID', ATTRIBUTE_DATA: lid });
  }
  for (const cci of v.ccis) {
    stigData.push({ VULN_ATTRIBUTE: 'CCI_REF', ATTRIBUTE_DATA: cci });
  }
  return {
    STIG_DATA: stigData,
    STATUS: statusToCkl(v.status),
    FINDING_DETAILS: v.findingDetails ?? '',
    COMMENTS: v.comments ?? '',
    // STIG Viewer always writes these two, even empty; the Go serializer does too.
    SEVERITY_OVERRIDE: v.severityOverride ?? '',
    SEVERITY_JUSTIFICATION: v.severityJustification ?? '',
  };
}
