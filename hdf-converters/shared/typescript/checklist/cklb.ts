import { parseJSON } from '@mitre/hdf-utilities';
import { Asset, Checklist, Stig, Vuln } from './model.js';
import { parseStatus, statusToCklb } from './status.js';

interface CklbDoc {
  title?: string;
  cklb_version?: string;
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
  comments?: string;
  finding_details?: string;
  third_party_tools?: string;
}

/** Parse CKLB JSON into the format-neutral Checklist model. */
export function parseCklb(input: string): Checklist {
  const doc = parseJSON<CklbDoc>(input);
  if (!doc || !Array.isArray(doc.stigs) || doc.stigs.length === 0) {
    throw new Error('parse cklb: no stigs[] found (not a CKLB document?)');
  }
  const t = doc.target_data ?? {};
  const asset: Asset = {
    role: t.role,
    assetType: t.target_type,
    hostName: t.host_name,
    hostIP: t.ip_address,
    hostMAC: t.mac_address,
    hostFQDN: t.fqdn,
    targetComment: t.comments,
    webOrDatabase: t.is_web_database,
    webDBSite: t.web_db_site,
    webDBInstance: t.web_db_instance,
    techArea: t.technology_area,
    classification: t.classification,
  };

  const stigs: Stig[] = doc.stigs.map((s) => ({
    stigID: s.stig_id,
    title: s.stig_name || s.display_name,
    displayName: s.display_name,
    version: s.version,
    releaseInfo: s.release_info,
    uuid: s.uuid,
    referenceIdentifier: s.reference_identifier,
    vulns: (s.rules ?? []).map(cklbRuleToModel),
  }));

  return { format: 'cklb', cklbVersion: doc.cklb_version, asset, stigs };
}

function cklbRuleToModel(r: CklbRule): Vuln {
  const extra: Record<string, string> = {};
  if (r.third_party_tools) extra['Third_Party_Tools'] = r.third_party_tools;
  if (r.srg_id) extra['SRG_ID'] = r.srg_id;
  return {
    vulnNum: r.group_id ?? '',
    ruleID: r.rule_id,
    ruleVer: r.rule_version,
    groupID: r.group_id,
    groupTitle: r.group_title,
    severity: r.severity,
    ruleTitle: r.rule_title,
    vulnDiscuss: r.discussion,
    checkContent: r.check_content,
    fixText: r.fix_text,
    weight: r.weight,
    classification: r.classification,
    ccis: r.ccis ?? [],
    legacyIDs: r.legacy_ids,
    status: parseStatus(r.status),
    findingDetails: r.finding_details,
    comments: r.comments,
    extra,
  };
}

/** Serialize the Checklist model to CKLB JSON. */
export function serializeCklb(cl: Checklist): string {
  const doc: CklbDoc & { active: boolean } = {
    title: cklbTitle(cl),
    cklb_version: cl.cklbVersion || '1.0',
    active: false,
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
