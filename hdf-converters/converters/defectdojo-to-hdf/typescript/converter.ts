import {
  type Checksum,
  type Cvss,
  type Description,
  type Epss,
  type EvaluatedBaseline,
  type EvaluatedRequirement,
  type Identity,
  IdentityType,
  OverrideType,
  type RequirementResult,
  ResultStatus,
  type StatusOverride,
  Version as CvssVersion,
  createMinimalBaseline,
} from '@mitre/hdf-schema';
import {nistToCci, DEFAULT_STATIC_ANALYSIS_NIST_TAGS} from '@mitre/hdf-mappings';
import {severityToImpact, parseJSON, parseTimestamp} from '@mitre/hdf-utilities';
import {inputChecksum, buildNistCciTags, buildNoFindingsRequirement, deriveControlTypeFromTags, validateInputSize, buildHdfResults, mapCWEToNIST} from '../../../shared/typescript/converterutil.js';
import {buildCvss as buildSharedCvss} from '../../../shared/typescript/cvss.js';

// DefectDojo /api/v2/findings/ input model (subset). The live fetcher produces
// the same bytes; see converter.go for the design rationale (risk-acceptance
// provenance is what lets this emit a real waiver override).

interface DDResponse {
  results?: DDFinding[];
}

interface DDFinding {
  id: number;
  title: string;
  severity: string;
  description?: string;
  mitigation?: string;
  impact?: string;
  references?: string;
  cwe?: number | null;
  vulnerability_ids?: {vulnerability_id: string}[];
  cvssv3?: string | null;
  cvssv3_score?: number | null;
  cvssv4?: string | null;
  cvssv4_score?: number | null;
  epss_score?: number | null;
  epss_percentile?: number | null;
  unique_id_from_tool?: string | null;
  vuln_id_from_tool?: string | null;
  file_path?: string | null;
  line?: number | null;
  component_name?: string | null;
  component_version?: string | null;
  service?: string | null;
  date?: string;
  active?: boolean;
  verified?: boolean;
  false_p?: boolean;
  is_mitigated?: boolean;
  risk_accepted?: boolean;
  out_of_scope?: boolean;
  under_review?: boolean;
  accepted_risks?: DDAcceptedRisk[];
  related_fields?: {test?: {test_type?: {name?: string}}};
}

interface DDAcceptedRisk {
  owner?: number | string | null;
  owner_username?: string | null; // optional fetcher enrichment
  owner_email?: string | null; // optional fetcher enrichment
  created?: string;
  expiration_date?: string | null;
  decision?: string;
  decision_details?: string | null;
  name?: string;
}

// Raw-primary: what the tool reported is preserved; triage decisions ride in
// tags (and, for risk acceptance, an override). Explicit dispositions take
// precedence over the derived is_mitigated.
function deriveStatus(f: DDFinding): ResultStatus {
  if (f.out_of_scope) return ResultStatus.NotApplicable;
  if (f.false_p) return ResultStatus.Failed;
  if (f.risk_accepted) return ResultStatus.Failed;
  if (f.is_mitigated) return ResultStatus.Passed;
  if (f.under_review) return ResultStatus.NotReviewed;
  return ResultStatus.Failed;
}

function triageTags(f: DDFinding): Record<string, unknown> {
  return {
    'defectdojo/active': f.active ?? false,
    'defectdojo/verified': f.verified ?? false,
    'defectdojo/false_p': f.false_p ?? false,
    'defectdojo/is_mitigated': f.is_mitigated ?? false,
    'defectdojo/risk_accepted': f.risk_accepted ?? false,
    'defectdojo/out_of_scope': f.out_of_scope ?? false,
    'defectdojo/under_review': f.under_review ?? false,
  };
}

function riskAcceptanceOwner(ar: DDAcceptedRisk): Identity {
  if (ar.owner_email) return {type: IdentityType.Email, identifier: ar.owner_email};
  if (ar.owner_username) return {type: IdentityType.Username, identifier: ar.owner_username};
  if (ar.owner !== undefined && ar.owner !== null && `${ar.owner}` !== '') {
    return {type: IdentityType.Simple, identifier: `defectdojo-user-${ar.owner}`};
  }
  return {type: IdentityType.Simple, identifier: 'defectdojo-risk-acceptance-owner'};
}

// The HDF schema documents `waiver` as "risk accepted by Authorizing Official"
// (FedRAMP-aligned) — exactly a DefectDojo decision=Accept. Raw status stays
// failed; effectiveStatus becomes passed with the full attributed, expiring
// override present — not laundering.
function buildWaiverOverride(ar: DDAcceptedRisk): StatusOverride {
  let reason = ar.decision_details || ar.name || '';
  if (!reason) reason = 'Risk accepted in DefectDojo';
  const appliedAt = (ar.created ? parseTimestamp(ar.created) : null) ?? new Date();
  // expiresAt is REQUIRED; DefectDojo acceptances usually carry an expiration.
  // Default to one year out when absent so the waiver is reviewed, not permanent.
  const oneYearOut = new Date();
  oneYearOut.setTime(appliedAt.getTime());
  oneYearOut.setFullYear(oneYearOut.getFullYear() + 1);
  const parsedExpiry = ar.expiration_date ? parseTimestamp(ar.expiration_date) : null;
  const expiresAt = parsedExpiry ?? oneYearOut;
  return {
    type: OverrideType.Waiver,
    status: ResultStatus.Passed,
    reason,
    appliedBy: riskAcceptanceOwner(ar),
    appliedAt,
    expiresAt,
  };
}

const DATE_ONLY = /^\d{4}-\d{2}-\d{2}$/;

// Parse a DefectDojo finding `date`. That field is date-only (YYYY-MM-DD); a bare
// date is promoted to UTC midnight before canonical parsing so Go and TS agree
// (Go's ParseTimestamp has no date-only layout). parseTimestamp then reads it as
// UTC. Returns null when absent/unparseable.
function parseFindingDate(s: string | undefined): Date | null {
  if (!s) return null;
  return parseTimestamp(DATE_ONLY.test(s) ? `${s}T00:00:00Z` : s);
}

// The most recent finding `date`. DefectDojo carries no single top-level scan
// time, so the newest finding date is the defensible report time for the
// top-level HDF timestamp. Returns undefined when no finding carries a parseable
// date — the caller then omits the optional timestamp rather than fabricating a
// wall-clock value (keeping the mapping source-derived and deterministic).
function latestFindingDate(findings: DDFinding[]): Date | undefined {
  let latest: Date | undefined;
  for (const f of findings) {
    const d = parseFindingDate(f.date);
    if (d && (!latest || d.getTime() > latest.getTime())) latest = d;
  }
  return latest;
}

function findingId(f: DDFinding): string {
  return f.unique_id_from_tool || f.vuln_id_from_tool || `DefectDojo-Finding-${f.id}`;
}

function cveList(f: DDFinding): string[] {
  return (f.vulnerability_ids ?? []).map(v => v.vulnerability_id).filter(Boolean);
}

function buildCvss(f: DDFinding): Cvss[] {
  const out: Cvss[] = [];
  const add = (version: CvssVersion, vector?: string | null, score?: number | null): void => {
    if ((score === undefined || score === null) && !vector) return;
    out.push(buildSharedCvss({version, baseScore: score, baseVector: vector}));
  };
  add(CvssVersion.The31, f.cvssv3, f.cvssv3_score);
  add(CvssVersion.The40, f.cvssv4, f.cvssv4_score);
  return out;
}

function buildEpss(f: DDFinding): Epss | undefined {
  if (f.epss_score === undefined || f.epss_score === null || !f.date) return undefined;
  // format: date (YYYY-MM-DD) string; quicktype types it as Date.
  return {score: f.epss_score, percentile: f.epss_percentile ?? 0, date: f.date as unknown as Date};
}

function nistTags(f: DDFinding): string[] {
  return f.cwe && f.cwe > 0
    ? mapCWEToNIST([`CWE-${f.cwe}`], DEFAULT_STATIC_ANALYSIS_NIST_TAGS)
    : DEFAULT_STATIC_ANALYSIS_NIST_TAGS;
}

function buildDescriptions(f: DDFinding): Description[] {
  const descs: Description[] = [{label: 'default', data: f.description || f.title || 'No description provided.'}];
  if (f.mitigation) descs.push({label: 'fix', data: f.mitigation});
  if (f.impact) descs.push({label: 'impact', data: f.impact});
  return descs;
}

function codeDesc(f: DDFinding): string {
  const parts = [f.title];
  if (f.component_name) {
    parts.push(`Component: ${f.component_name}${f.component_version ? '@' + f.component_version : ''}`);
  }
  if (f.file_path) {
    parts.push(`Location: ${f.file_path}${f.line !== undefined && f.line !== null ? ':' + f.line : ''}`);
  }
  const cves = cveList(f);
  if (cves.length > 0) parts.push(`CVE: ${cves.join(', ')}`);
  return parts.join(' | ');
}

function convertFinding(f: DDFinding): EvaluatedRequirement {
  const nist = nistTags(f);
  const tags = buildNistCciTags(nist, nistToCci(nist), triageTags(f));

  // CVE → tags.cve (interim, pending a first-class identifiers[] field). The
  // requirement.id is a native DefectDojo finding id (DefectDojo-Finding-<n> or a
  // tool id), never the CVE, so the CVE list is not a duplicate of the id.
  const cves = cveList(f);
  if (cves.length > 0) tags.cve = cves;

  const result: RequirementResult = {
    status: deriveStatus(f),
    codeDesc: codeDesc(f),
    startTime: parseFindingDate(f.date) ?? new Date(),
  };

  const req: EvaluatedRequirement = {
    id: findingId(f),
    impact: severityToImpact(f.severity),
    results: [result],
    tags,
    descriptions: buildDescriptions(f),
  };

  const controlType = deriveControlTypeFromTags(nist);
  if (controlType !== undefined) req.controlType = controlType;

  const cvss = buildCvss(f);
  if (cvss.length > 0) req.cvss = cvss;
  const epss = buildEpss(f);
  if (epss) req.epss = epss;
  if (f.cwe && f.cwe > 0) req.cwe = [`CWE-${f.cwe}`];

  // KEV is NOT-IN-SOURCE: DefectDojo findings carry known_exploited/kev_date/
  // ransomware_used but no CISA remediation due date. hdf Kev requires both
  // dateAdded AND dueDate when inKev is true, so a schema-valid requirement.kev
  // cannot be produced from source alone — synthesizing a dueDate DefectDojo
  // never sent would be fabrication. The KEV signal is preserved verbatim in
  // requirement.code (the raw finding JSON).

  // DefectDojo carries no literal source snippet, so requirement.code (Heimdall's
  // CODE tab) holds the whole finding as indented JSON — every field the typed
  // interface does not model, byte-identical to the Go twin's json.Indent output.
  req.code = JSON.stringify(f, null, 2);

  // The novel part: a risk-accepted finding carries a real waiver override built
  // from accepted_risks provenance.
  const firstRisk = f.accepted_risks?.[0];
  if (f.risk_accepted && firstRisk) {
    req.statusOverrides = [buildWaiverOverride(firstRisk)];
    req.effectiveStatus = ResultStatus.Passed;
    req.disposition = OverrideType.Waiver;
    tags['defectdojo/decision'] = firstRisk.decision ?? '';
  }

  return req;
}

function scannerName(f: DDFinding): string {
  return f.related_fields?.test?.test_type?.name || 'DefectDojo';
}

export async function convertDefectDojoToHdf(input: string, converterVersion = '0.1.0'): Promise<string> {
  validateInputSize(input, 'defectdojo');
  const resultsChecksum: Checksum = await inputChecksum(input);

  const parsed = parseJSON<DDResponse | DDFinding[]>(input);
  const findings: DDFinding[] = Array.isArray(parsed) ? parsed : (parsed.results ?? []);

  // Group findings into per-scanner baselines, preserving encounter order.
  const order: string[] = [];
  const byScanner = new Map<string, EvaluatedRequirement[]>();
  for (const f of findings) {
    const name = scannerName(f);
    if (!byScanner.has(name)) {
      order.push(name);
      byScanner.set(name, []);
    }
    byScanner.get(name)!.push(convertFinding(f));
  }

  const baselines: EvaluatedBaseline[] = order.map(name => {
    const baseline = createMinimalBaseline(`DefectDojo: ${name}`, byScanner.get(name)!, {
      resultsChecksum,
    }) as EvaluatedBaseline;
    baseline.title = name;
    return baseline;
  });

  if (baselines.length === 0) {
    baselines.push(
      createMinimalBaseline(
        'DefectDojo',
        [buildNoFindingsRequirement('defectdojo-no-findings', 'DefectDojo reported zero findings.', new Date())],
        {resultsChecksum},
      ) as EvaluatedBaseline,
    );
  }

  return buildHdfResults({
    generatorName: 'defectdojo-to-hdf',
    converterVersion,
    toolName: 'DefectDojo',
    baselines,
    // Top-level timestamp: the newest finding date, source-derived and
    // deterministic. Omitted when no finding carries a parseable date.
    timestamp: latestFindingDate(findings),
  });
}
