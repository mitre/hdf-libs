import { parseJSON } from '@mitre/hdf-utilities';
import { Asset, Checklist, Stig, Vuln } from './model.js';
import { parseStatus, statusToCklb } from './status.js';

interface CklbDoc {
  title?: string;
  cklb_version?: string;
  active?: boolean;
  mode?: number;
  has_path?: boolean;
  target_data?: CklbTarget;
  stigs?: CklbStig[];
}
interface CklbTarget {
  target_type?: string;
  host_name?: string;
  ip_address?: string;
  mac_address?: string;
  fqdn?: string;
  comments?: string;
  role?: string;
  is_web_database?: boolean;
  technology_area?: string;
  web_db_site?: string;
  web_db_instance?: string;
  classification?: string;
}
interface CklbStig {
  stig_name?: string;
  display_name?: string;
  stig_id?: string;
  release_info?: string;
  version?: string;
  uuid?: string;
  reference_identifier?: string;
  rules?: CklbRule[];
}
interface CklbRule {
  group_id?: string;
  group_title?: string;
  rule_id?: string;
  rule_version?: string;
  rule_title?: string;
  severity?: string;
  weight?: string;
  check_content?: string;
  fix_text?: string;
  discussion?: string;
  classification?: string;
  ccis?: string[];
  legacy_ids?: string[];
  srg_id?: string;
  status?: string;
  overrides?: CklbOverrides;
  comments?: string;
  finding_details?: string;
  third_party_tools?: string;
}
interface CklbOverrides {
  severity?: { severity?: string; justification?: string };
}

/** Parse CKLB JSON into the format-neutral Checklist model. */
export function parseCklb(input: string): Checklist {
  const doc = parseJSON<CklbDoc>(input);
  if (!doc || !Array.isArray(doc.stigs) || doc.stigs.length === 0) {
    throw new Error('parse cklb: no stigs[] found (not a CKLB document?)');
  }
  const t = doc.target_data ?? {};
  const asset: Asset = {
    role: nz(t.role),
    assetType: nz(t.target_type),
    hostName: nz(t.host_name),
    hostIP: nz(t.ip_address),
    hostMAC: nz(t.mac_address),
    hostFQDN: nz(t.fqdn),
    targetComment: nz(t.comments),
    webOrDatabase: t.is_web_database === true,
    webDBSite: nz(t.web_db_site),
    webDBInstance: nz(t.web_db_instance),
    techArea: nz(t.technology_area),
    classification: nz(t.classification),
  };

  const stigs: Stig[] = doc.stigs.map((s, i) => {
    // A stig with no rules would yield requirements: [] downstream, which
    // violates the HDF schema's requirements.minItems=1. Reject as malformed,
    // consistent with the empty-stigs[] guard above.
    const rules = s.rules ?? [];
    if (rules.length === 0) {
      throw new Error(`parse cklb: stigs[${i}] contains no rules[]`);
    }
    return {
      stigID: nz(s.stig_id),
      title: nz(s.stig_name) || nz(s.display_name),
      displayName: nz(s.display_name),
      version: nz(s.version),
      releaseInfo: nz(s.release_info),
      uuid: nz(s.uuid),
      referenceIdentifier: nz(s.reference_identifier),
      vulns: rules.map(cklbRuleToModel),
    };
  });

  return {
    format: 'cklb',
    cklbVersion: nz(doc.cklb_version),
    active: doc.active ?? false,
    hasPath: doc.has_path ?? false,
    mode: doc.mode ?? 0,
    asset,
    stigs,
  };
}

/** Coerce a possibly-null/non-string JSON value to string | undefined.
 * Real STIG Viewer CKLB output uses null for unset fields (e.g.
 * target_data.classification: null); the model expects string | undefined. */
function nz(v: unknown): string | undefined {
  return typeof v === 'string' ? v : undefined;
}

function cklbRuleToModel(r: CklbRule): Vuln {
  const extra: Record<string, string> = {};
  if (r.third_party_tools) extra['Third_Party_Tools'] = r.third_party_tools;
  if (r.srg_id) extra['SRG_ID'] = r.srg_id;
  return {
    vulnNum: nz(r.group_id) ?? '',
    ruleID: nz(r.rule_id),
    ruleVer: nz(r.rule_version),
    groupID: nz(r.group_id),
    groupTitle: nz(r.group_title),
    severity: nz(r.severity),
    ruleTitle: nz(r.rule_title),
    vulnDiscuss: nz(r.discussion),
    checkContent: nz(r.check_content),
    fixText: nz(r.fix_text),
    weight: nz(r.weight),
    classification: nz(r.classification),
    ccis: Array.isArray(r.ccis) ? r.ccis.filter((c): c is string => typeof c === 'string') : [],
    legacyIDs: r.legacy_ids,
    status: parseStatus(r.status),
    findingDetails: nz(r.finding_details),
    comments: nz(r.comments),
    severityOverride: nz(r.overrides?.severity?.severity),
    severityJustification: nz(r.overrides?.severity?.justification),
    extra,
  };
}

/** Serialize the Checklist model to CKLB JSON. */
export function serializeCklb(cl: Checklist): string {
  const doc: CklbDoc & { active: boolean; has_path: boolean } = {
    title: cklbTitle(cl),
    cklb_version: cl.cklbVersion || '1.0',
    active: cl.active ?? false,
    // mode is omitempty in the Go struct — emit only when non-zero, in the same
    // key position (between active and has_path) for byte-for-byte parity.
    ...(cl.mode ? { mode: cl.mode } : {}),
    // has_path is a required top-level key in real STIG Viewer CKLB output;
    // the Go serializer always emits it, so emit it here for parity.
    has_path: cl.hasPath ?? false,
    target_data: {
      target_type: cl.asset.assetType || 'Computing',
      host_name: cl.asset.hostName ?? '',
      ip_address: cl.asset.hostIP ?? '',
      mac_address: cl.asset.hostMAC ?? '',
      fqdn: cl.asset.hostFQDN ?? '',
      comments: cl.asset.targetComment ?? '',
      role: cl.asset.role || 'None',
      is_web_database: cl.asset.webOrDatabase ?? false,
      technology_area: cl.asset.techArea ?? '',
      web_db_site: cl.asset.webDBSite ?? '',
      web_db_instance: cl.asset.webDBInstance ?? '',
      ...(cl.asset.classification ? { classification: cl.asset.classification } : {}),
    },
    stigs: cl.stigs.map((s) => ({
      stig_name: s.title ?? '',
      display_name: s.displayName || s.title || '',
      stig_id: s.stigID ?? '',
      release_info: s.releaseInfo ?? '',
      version: s.version ?? '',
      uuid: s.uuid ?? '',
      ...(s.referenceIdentifier ? { reference_identifier: s.referenceIdentifier } : {}),
      rules: s.vulns.map((v) => ({
        group_id: v.groupID || v.vulnNum,
        group_title: v.groupTitle ?? '',
        rule_id: v.ruleID ?? '',
        rule_version: v.ruleVer ?? '',
        rule_title: v.ruleTitle ?? '',
        severity: v.severity ?? '',
        weight: v.weight || '10.0',
        check_content: v.checkContent ?? '',
        fix_text: v.fixText ?? '',
        discussion: v.vulnDiscuss ?? '',
        ccis: v.ccis,
        ...(v.legacyIDs && v.legacyIDs.length ? { legacy_ids: v.legacyIDs } : {}),
        status: statusToCklb(v.status),
        // overrides is always emitted ({} when empty), matching real STIG Viewer 3
        // and the Go serializer's non-omitempty overrides field.
        overrides: v.severityOverride
          ? { severity: { severity: v.severityOverride, justification: v.severityJustification ?? '' } }
          : {},
        comments: v.comments ?? '',
        finding_details: v.findingDetails ?? '',
        ...(v.extra?.['Third_Party_Tools'] ? { third_party_tools: v.extra['Third_Party_Tools'] } : {}),
      })),
    })),
  };
  return JSON.stringify(doc, null, 2);
}

function cklbTitle(cl: Checklist): string {
  return cl.stigs[0]?.title || 'STIG Checklist';
}
