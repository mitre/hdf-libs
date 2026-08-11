/**
 * AWS Security Finding Format (ASFF) to HDF converter.
 *
 * A single ASFF envelope can carry findings from many products, and Security Hub
 * findings span multiple compliance standards (CIS, AFSBP, PCI, ...). Because
 * hdf-results supports multiple baselines in one document, each product — and
 * each Security Hub standard — becomes its own baseline entry, mirroring the
 * per-file split the predecessor SAF CLI produced.
 */

import { parseJSON, parseTimestamp, roundImpact } from '@mitre/hdf-utilities';
import {
  nistToCci,
  getAwsConfigNistControlsBySubstring,
  DEFAULT_STATIC_ANALYSIS_NIST_TAGS,
  DEFAULT_CONFIG_MANAGEMENT_NIST_TAGS,
} from '@mitre/hdf-mappings';
import {
  buildNoFindingsRequirement,
  deriveControlTypeFromTags,
  inputChecksum,
  buildNistCciTags,
  serializeHdf,
  validateInputSize,
  DEFAULT_REMEDIATION_NIST_TAGS,
} from '../../../shared/typescript/converterutil.js';
import { buildCvss, cvssVersionFromString } from '../../../shared/typescript/cvss.js';
import type {
  HDFResults,
  EvaluatedBaseline,
  EvaluatedRequirement,
  RequirementResult,
  Description,
  Component,
  Cvss,
} from '@mitre/hdf-schema';
import {
  ResultStatus,
  TargetType,
  createMinimalBaseline,
  createRequirement,
  createResult,
} from '@mitre/hdf-schema';

interface AsffSeverity {
  Label?: string;
  Normalized?: number;
}

export interface AsffFinding {
  Id?: string;
  GeneratorId?: string;
  ProductArn?: string;
  AwsAccountId?: string;
  Title?: string;
  Description?: string;
  Types?: string[];
  SourceUrl?: string;
  LastObservedAt?: string;
  UpdatedAt?: string;
  Severity?: AsffSeverity;
  Remediation?: { Recommendation?: { Text?: string; Url?: string } };
  ProductFields?: Record<string, string>;
  Resources?: { Type?: string; Id?: string; Partition?: string; Region?: string; Details?: { Other?: Record<string, string> } }[];
  Compliance?: { Status?: string; StatusReasons?: { ReasonCode?: string; Description?: string }[] };
  Workflow?: { Status?: string };
  // Standard ASFF field any producer may populate (Inspector, third-party
  // scanners); mapped generically so CVE/CVSS/fix data survives.
  Vulnerabilities?: AsffVulnerability[];
  // The finding provider's authoritative severity, preferred over the top-level
  // Severity that Security Hub may overwrite on ingest.
  FindingProviderFields?: { Severity?: AsffSeverity };
}

export interface AsffVulnerability {
  Id?: string;
  Cvss?: { Version?: string; BaseScore?: number; Source?: string }[];
  VulnerablePackages?: { Name?: string; Version?: string; FixedInVersion?: string }[];
  ReferenceUrls?: string[];
  FixAvailable?: string;
  ExploitAvailable?: string;
  EpssScore?: number;
}

export type Product = 'securityHub' | 'prowler' | 'trivy' | 'default';

export function productOf(f: AsffFinding): Product {
  const [company, prod] = productArnParts(f.ProductArn);
  if (prod === 'securityhub') return 'securityHub';
  if (company === 'prowler' && prod === 'prowler') return 'prowler';
  if (company === 'aquasecurity' && prod === 'aquasecurity') return 'trivy';
  return 'default';
}

/** The CVE id Trivy stashes under Resources[0].Details.Other. */
export function trivyCVE(f: AsffFinding): string {
  return f.Resources?.[0]?.Details?.Other?.['CVE ID'] ?? '';
}

/** Accepts the `{ "Findings": [...] }` envelope, a bare array, a single finding, or NDJSON (Prowler). */
function parseFindings(input: string): AsffFinding[] {
  try {
    const parsed = parseJSON<unknown>(input);
    if (parsed !== null && typeof parsed === 'object' && 'Findings' in parsed) {
      const findings = (parsed as { Findings: unknown }).Findings;
      return Array.isArray(findings) ? (findings as AsffFinding[]) : [];
    }
    if (Array.isArray(parsed)) {
      return parsed as AsffFinding[];
    }
    if (parsed !== null && typeof parsed === 'object') {
      return [parsed as AsffFinding];
    }
  } catch {
    // fall through to NDJSON
  }
  const lines = input.trim().split('\n').filter((l) => l.trim().length > 0);
  // Keep only object-shaped lines: valid-but-scalar JSON (e.g. `42`, `null`,
  // `"x"`) parses without throwing and must NOT be accepted as a finding — Go
  // rejects it too, so filtering to objects keeps the two languages in parity.
  const out = lines
    .map((l) => parseJSON<unknown>(l.trim()))
    .filter((x): x is AsffFinding => x !== null && typeof x === 'object' && !Array.isArray(x));
  if (out.length > 0) {
    return out;
  }
  throw new Error('invalid ASFF JSON');
}

/**
 * mapComplianceStatus maps ASFF Compliance.Status to an HDF result status.
 * hdf-results has no "skipped": WARNING and NOT_AVAILABLE (no clean pass/fail
 * verdict) map to notReviewed; an absent status defaults to failed.
 */
export function mapComplianceStatus(status: string | undefined): ResultStatus {
  switch (status) {
    case 'PASSED':
      return ResultStatus.Passed;
    case 'FAILED':
      return ResultStatus.Failed;
    case 'WARNING':
    case 'NOT_AVAILABLE':
      return ResultStatus.NotReviewed;
    case undefined:
    case '':
      return ResultStatus.Failed;
    default:
      return ResultStatus.Error;
  }
}

export function severityLabelToImpact(label: string | undefined): number {
  switch ((label ?? '').toUpperCase()) {
    case 'CRITICAL':
      return 0.9;
    case 'HIGH':
      return 0.7;
    case 'MEDIUM':
      return 0.5;
    case 'LOW':
      return 0.3;
    default:
      return 0.0;
  }
}

/**
 * findingImpact derives a 0.0–1.0 impact. Suppressed findings are forced to 0.
 * Security Hub's INFORMATIONAL is up-graded to MEDIUM (Security Hub over-marks
 * findings INFORMATIONAL without context). FindingProviderFields.Severity — the
 * provider's own rating — is preferred over the top-level Severity, which
 * Security Hub may overwrite on ingest.
 */
export function findingImpact(f: AsffFinding): number {
  if (f.Workflow?.Status === 'SUPPRESSED') {
    return 0.0;
  }
  const sev = f.FindingProviderFields?.Severity?.Label ? f.FindingProviderFields.Severity : f.Severity;
  let label = sev?.Label;
  if (isSecurityHub(f) && (label ?? '').toUpperCase() === 'INFORMATIONAL') {
    label = 'MEDIUM';
  }
  if (label) {
    return severityLabelToImpact(label);
  }
  if (typeof sev?.Normalized === 'number') {
    return roundImpact(sev.Normalized / 100.0);
  }
  return 0.0;
}

function productArnParts(arn: string | undefined): [string, string] {
  if (!arn) return ['', ''];
  const tail = arn.split(':').pop() ?? '';
  const segs = tail.split('/');
  if (segs.length >= 3) return [segs[1]!, segs[2]!];
  return ['', ''];
}

function isSecurityHub(f: AsffFinding): boolean {
  return productOf(f) === 'securityHub';
}

const normalizeStd = (s: string): string => s.toLowerCase().replace(/-/g, ' ');

function titleCaseWords(s: string): string {
  return s
    .split(/\s+/)
    .filter(Boolean)
    .map((w) => w.charAt(0).toUpperCase() + w.slice(1))
    .join(' ');
}

/**
 * securityHubStandardName derives "CIS AWS Foundations Benchmark v1.2.0" from a
 * finding's StandardsControlArn, preferring the nicer Types[0] casing when it
 * matches the ARN's standard slug (mirrors the SAF CLI grouping key).
 */
function securityHubStandardName(f: AsffFinding): string {
  const arn = f.ProductFields?.StandardsControlArn ?? '';
  if (!arn) return '';
  const segs = arn.split('/');
  if (segs.length < 4) return '';
  const slug = segs[segs.length - 4]!;
  const version = segs[segs.length - 2]!;

  let typesLast = '';
  if (f.Types && f.Types.length > 0) {
    const ts = f.Types[0]!.split('/');
    typesLast = ts[ts.length - 1]!;
  }

  const standard =
    typesLast && normalizeStd(typesLast) === normalizeStd(slug)
      ? typesLast.replace(/-/g, ' ')
      : titleCaseWords(slug.replace(/-/g, ' '));
  return `${standard} v${version}`;
}

/** Level-1 grouping key, per product. */
function baselineName(f: AsffFinding): string {
  switch (productOf(f)) {
    case 'securityHub': {
      const name = securityHubStandardName(f);
      if (name) return name;
      break;
    }
    case 'prowler':
      if (f.ProductFields?.ProviderName) return f.ProductFields.ProviderName;
      break;
    case 'trivy':
      return 'Aqua Security - Trivy';
  }
  const [company, prod] = productArnParts(f.ProductArn);
  if (!company && !prod) return 'AWS Security Finding Format';
  return `${company} - ${prod}`;
}

/** Level-2 grouping key within a baseline, per product. */
function controlId(f: AsffFinding): string {
  switch (productOf(f)) {
    case 'securityHub':
      if (f.ProductFields?.ControlId) return f.ProductFields.ControlId;
      if (f.ProductFields?.RuleId) return f.ProductFields.RuleId;
      break;
    case 'prowler': {
      const i = (f.GeneratorId ?? '').indexOf('-');
      if (i >= 0) return (f.GeneratorId ?? '').slice(i + 1);
      break;
    }
    case 'trivy':
      return `${f.GeneratorId ?? ''}/${trivyCVE(f) || f.Id || ''}`;
  }
  // Unrecognized producer. A compliance/control finding aggregates per-resource
  // under one requirement, so group it by its generator-derived control ref.
  // A per-instance finding (a vulnerability, a threat) has no such aggregation —
  // key it by the ASFF-unique finding Id so distinct findings never collapse.
  // GeneratorId is NOT guaranteed unique per finding: every Inspector finding
  // shares "AWSInspector", so keying on it lumped every CVE into one requirement.
  if (f.Compliance?.Status && f.GeneratorId) {
    const segs = f.GeneratorId.split('/');
    if (segs[segs.length - 1]) return segs[segs.length - 1]!;
  }
  return f.Id ?? '';
}

/**
 * nistTags derives NIST controls for a finding group: AWS Config rule → NIST via
 * the shared awsconfig mapping, falling back to the static analysis default
 * bundle (matching the SAF CLI) when no config rule applies.
 */
function nistTags(group: AsffFinding[]): string[] {
  // Trivy CVE findings map to the update/remediation NIST bundle.
  if (group.length > 0 && productOf(group[0]!) === 'trivy' && trivyCVE(group[0]!)) {
    return DEFAULT_REMEDIATION_NIST_TAGS;
  }
  const out: string[] = [];
  const seen = new Set<string>();
  for (const f of group) {
    for (const tag of configRuleNist(f)) {
      if (!seen.has(tag)) {
        seen.add(tag);
        out.push(tag);
      }
    }
  }
  if (out.length > 0) return out;
  // A Config-rule-backed finding whose rule we can't map is still a configuration-settings
  // check → CM-6, matching the aws-config-to-hdf floor so the same Security Hub signal tags
  // consistently across both converters. Generic ASFF scanner findings keep the default.
  if (group.length > 0 && isConfigRuleFinding(group[0]!)) {
    return DEFAULT_CONFIG_MANAGEMENT_NIST_TAGS;
  }
  return DEFAULT_STATIC_ANALYSIS_NIST_TAGS;
}

function isConfigRuleFinding(f: AsffFinding): boolean {
  return f.ProductFields?.['RelatedAWSResources:0/type'] === 'AWS::Config::ConfigRule';
}

function configRuleNist(f: AsffFinding): string[] {
  if (!isConfigRuleFinding(f)) {
    return [];
  }
  const name = f.ProductFields?.['RelatedAWSResources:0/name'];
  if (!name) return [];
  return getAwsConfigNistControlsBySubstring(name);
}

function remediationText(f: AsffFinding): string {
  const parts: string[] = [];
  const rec = f.Remediation?.Recommendation;
  if (rec?.Text) parts.push(rec.Text);
  if (rec?.Url) parts.push(rec.Url);
  return parts.join('\n');
}

function resourceCodeDesc(f: AsffFinding): string {
  const parts = (f.Resources ?? []).map((r) => {
    let seg = `Type: ${r.Type ?? ''}, Id: ${r.Id ?? ''}`;
    if (r.Partition) seg += `, Partition: ${r.Partition}`;
    if (r.Region) seg += `, Region: ${r.Region}`;
    return seg;
  });
  return `Resources: [${parts.join('; ')}]`;
}

function statusReason(f: AsffFinding): string {
  const lines: string[] = [];
  for (const r of f.Compliance?.StatusReasons ?? []) {
    if (r.ReasonCode) lines.push(`ReasonCode: ${r.ReasonCode}`);
    if (r.Description) lines.push(`Description: ${r.Description}`);
  }
  return lines.join('\n');
}

function buildResult(f: AsffFinding): RequirementResult {
  const start = parseTimestamp(f.LastObservedAt ?? f.UpdatedAt ?? '') ?? new Date();
  let status = mapComplianceStatus(f.Compliance?.Status);
  let codeDesc = resourceCodeDesc(f);
  let message = statusReason(f);
  switch (productOf(f)) {
    case 'prowler':
      codeDesc = f.Description ?? '';
      break;
    case 'trivy': {
      status = ResultStatus.Failed;
      const m = trivyMessage(f);
      if (m) message = m;
      break;
    }
  }
  // A finding may carry structured vulnerability data (Inspector and other
  // scanners). Fold a summary into the message so CVE/CVSS/fix data survives —
  // it is otherwise dropped entirely.
  const vuln = vulnerabilitySummary(f);
  if (vuln) message = message ? `${message}\n${vuln}` : vuln;
  return createResult(status, message || undefined, { codeDesc, startTime: start });
}

/**
 * Renders a finding's ASFF Vulnerabilities[] as a compact text block: CVE id,
 * CVSS base score, EPSS, exploit/fix availability, and affected packages.
 * Generic — applies to any producer that emits the field.
 */
function vulnerabilitySummary(f: AsffFinding): string {
  return (f.Vulnerabilities ?? [])
    .map((v) => {
      const parts: string[] = [v.Id ?? ''];
      const cvss = v.Cvss?.[0];
      if (cvss && typeof cvss.BaseScore === 'number') parts.push(`CVSS ${cvss.Version ?? ''} ${cvss.BaseScore.toFixed(1)}`);
      if (typeof v.EpssScore === 'number') parts.push(`EPSS ${v.EpssScore.toFixed(4)}`);
      if (v.ExploitAvailable) parts.push(`exploit ${v.ExploitAvailable.toLowerCase()}`);
      if (v.FixAvailable) parts.push(`fix ${v.FixAvailable.toLowerCase()}`);
      for (const p of v.VulnerablePackages ?? []) {
        let pkg = `${p.Name ?? ''}@${p.Version ?? ''}`;
        if (p.FixedInVersion) pkg += ` (fixed in ${p.FixedInVersion})`;
        parts.push(pkg);
      }
      return parts.join('; ');
    })
    .join('\n');
}

/**
 * Assembles requirement.cvss[] from a finding's ASFF Vulnerabilities[]. Each Cvss
 * entry carrying a BaseScore becomes one structured Cvss via the shared builder.
 * ASFF's Cvss shape has no vector string, so only version, score, and source map;
 * an entry without a BaseScore contributes nothing.
 */
function vulnCvss(f: AsffFinding): Cvss[] {
  const out: Cvss[] = [];
  for (const v of f.Vulnerabilities ?? []) {
    for (const c of v.Cvss ?? []) {
      if (typeof c.BaseScore !== 'number') continue;
      out.push(buildCvss({version: cvssVersionFromString(c.Version), baseScore: c.BaseScore, source: c.Source}));
    }
  }
  return out;
}

/**
 * Collects the CVE ids a finding's Vulnerabilities[] carry (dedup, first-seen
 * order) for tags.cve. ASFF stores the CVE in Vulnerabilities[].Id.
 */
function vulnCves(f: AsffFinding): string[] {
  const out: string[] = [];
  const seen = new Set<string>();
  for (const v of f.Vulnerabilities ?? []) {
    if (v.Id && !seen.has(v.Id)) {
      seen.add(v.Id);
      out.push(v.Id);
    }
  }
  return out;
}

/**
 * Collects the distinct ASFF Types[] taxonomy strings across a requirement's
 * finding group (dedup, first-appearance order) for tags.types.
 */
function groupTypes(group: AsffFinding[]): string[] {
  const out: string[] = [];
  const seen = new Set<string>();
  for (const f of group) {
    for (const t of f.Types ?? []) {
      if (t && !seen.has(t)) {
        seen.add(t);
        out.push(t);
      }
    }
  }
  return out;
}

// trivyMessage summarizes a Trivy finding's product-specific detail for the
// result message, dispatching on the finding shape Trivy's ASFF template emits:
// a CVE reports the installed vs patched package, a misconfiguration reports the
// remediation message and file location, and a secret reports the file it was
// found in. Details.Other keys are the discriminator — 'CVE ID' for
// vulnerabilities, 'Message' for misconfigurations, a lone 'Filename' for secrets.
function trivyMessage(f: AsffFinding): string {
  const o = f.Resources?.[0]?.Details?.Other;
  if (!o) return '';
  if (o['CVE ID']) {
    const patched = o['Patched Package'];
    const patchMsg = patched
      ? `The package has been patched since version(s): ${patched}.`
      : 'There is no patched version of the package.';
    // Coalesce to '' so a missing key renders empty (matching Go), not "undefined".
    const pkg = o['PkgName'] ?? '';
    const installed = o['Installed Package'] ?? '';
    return `For package ${pkg}, the current version that is installed is ${installed}.  ${patchMsg}`;
  }
  if (o['Message']) {
    const loc = trivyLocation(o);
    return loc ? `${o['Message']} (${loc})` : o['Message'];
  }
  if (o['Filename']) {
    return `Secret detected in ${o['Filename']}.`;
  }
  return '';
}

// trivyLocation renders 'file:startLine-endLine' from a misconfiguration
// finding, omitting line numbers Trivy reports as 0 (whole-file findings).
export function trivyLocation(o: Record<string, string>): string {
  const file = o['Filename'] ?? '';
  if (!file) return '';
  const sl = o['StartLine'];
  if (!sl || sl === '0') return file;
  let loc = `${file}:${sl}`;
  const el = o['EndLine'];
  if (el && el !== '0' && el !== sl) loc += `-${el}`;
  return loc;
}

function buildRequirement(id: string, group: AsffFinding[]): EvaluatedRequirement {
  const primary = group[0]!;
  const impact = Math.max(...group.map(findingImpact));

  const descData = productOf(primary) === 'prowler' ? ' ' : (primary.Description ?? primary.Title ?? '');
  const descriptions: Description[] = [{ label: 'default', data: descData }];
  const fix = remediationText(primary);
  if (fix) descriptions.push({ label: 'fix', data: fix });

  const nist = nistTags(group);
  const tags: Record<string, unknown> = nist.length > 0 ? buildNistCciTags(nist, nistToCci(nist)) : {};
  // The CVE lives in ASFF's Vulnerabilities[].Id, while requirement.id is the
  // finding id — so the CVE is not otherwise represented. Surface it in tags.cve
  // (interim, pending a first-class identifiers[] schema field).
  const cves = vulnCves(primary);
  if (cves.length > 0) tags.cve = cves;
  // ASFF's Types[] finding-type taxonomy is otherwise dropped; surface the
  // distinct values across the aggregated group (first-appearance order) in
  // tags.types so the source categorization survives.
  const types = groupTypes(group);
  if (types.length > 0) tags.types = types;

  const results = group.map(buildResult);

  const req = createRequirement(id, primary.Title ?? '', descriptions, impact, results, {
    tags,
  }) as EvaluatedRequirement;

  const controlType = deriveControlTypeFromTags(nist);
  if (controlType !== undefined) {
    req.controlType = controlType;
  }
  const cvss = vulnCvss(primary);
  if (cvss.length > 0) req.cvss = cvss;
  // ASFF carries no literal source snippet, so code holds the whole finding
  // serialized as indented JSON (byte-identical to the Go twin's json.Indent of
  // the source bytes).
  req.code = JSON.stringify(primary, null, 2);
  const refs: { url: string }[] = [];
  if (primary.SourceUrl) refs.push({ url: primary.SourceUrl });
  const seen = new Set<string>();
  for (const v of primary.Vulnerabilities ?? []) {
    for (const u of v.ReferenceUrls ?? []) {
      if (u && !seen.has(u)) {
        seen.add(u);
        refs.push({ url: u });
      }
    }
  }
  if (refs.length > 0) req.refs = refs;
  return req;
}

function buildBaseline(
  name: string,
  findings: AsffFinding[],
  resultsChecksum: HDFResults['baselines'][number]['resultsChecksum']
): EvaluatedBaseline {
  const order: string[] = [];
  const groups = new Map<string, AsffFinding[]>();
  for (const f of findings) {
    const id = controlId(f);
    const existing = groups.get(id);
    if (existing) {
      existing.push(f);
    } else {
      order.push(id);
      groups.set(id, [f]);
    }
  }

  const requirements = order.map((id) => buildRequirement(id, groups.get(id)!));
  return createMinimalBaseline(name, requirements, { resultsChecksum }) as EvaluatedBaseline;
}

/** Converts an ASFF document to HDF Results JSON. */
export async function convertAsffToHdf(input: string, converterVersion = '1.0.0'): Promise<string> {
  if (!input || input.trim().length === 0) {
    throw new Error('asff: empty input');
  }
  validateInputSize(input, 'asff');

  const findings = parseFindings(input);
  const resultsChecksum = await inputChecksum(input);

  const order: string[] = [];
  const byBaseline = new Map<string, AsffFinding[]>();
  const accounts: string[] = [];
  const seenAccount = new Set<string>();
  for (const f of findings) {
    const name = baselineName(f);
    const existing = byBaseline.get(name);
    if (existing) {
      existing.push(f);
    } else {
      order.push(name);
      byBaseline.set(name, [f]);
    }
    if (f.AwsAccountId && !seenAccount.has(f.AwsAccountId)) {
      seenAccount.add(f.AwsAccountId);
      accounts.push(f.AwsAccountId);
    }
  }

  let baselines = order.map((name) => buildBaseline(name, byBaseline.get(name)!, resultsChecksum));

  if (baselines.length === 0) {
    baselines = [
      createMinimalBaseline(
        'AWS Security Finding Format',
        [
          buildNoFindingsRequirement(
            'asff-no-findings',
            'AWS Security Finding Format input contained zero findings.',
            new Date()
          ),
        ],
        { resultsChecksum }
      ) as EvaluatedBaseline,
    ];
  }

  const hdf: HDFResults = {
    baselines,
    generator: { name: 'asff-to-hdf', version: converterVersion },
    tool: { name: 'AWS Security Finding Format' },
    timestamp: new Date(),
  };

  if (accounts.length > 0) {
    const refs = baselines.map((b) => b.name);
    hdf.components = accounts.map(
      (acct): Component => ({ name: acct, type: TargetType.CloudAccount, baselineRefs: refs })
    );
  }

  return serializeHdf(hdf);
}
