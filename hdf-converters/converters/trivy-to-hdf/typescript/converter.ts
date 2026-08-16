import {
  type AffectedPackage,
  type Checksum,
  type Component,
  type Cvss,
  type Description,
  Ecosystem,
  type EvaluatedBaseline,
  type EvaluatedRequirement,
  type Reference,
  type RequirementResult,
  ResultStatus,
  type SourceLocation,
  TargetType,
  Version,
  VerificationMethodEnum,
  createMinimalBaseline,
} from '@mitre/hdf-schema';
import {nistToCci, DEFAULT_STATIC_ANALYSIS_NIST_TAGS} from '@mitre/hdf-mappings';
import {parseJSON, parseTimestamp} from '@mitre/hdf-utilities';
import {
  inputChecksum,
  buildNistCciTags,
  buildNoFindingsRequirement,
  deriveControlTypeFromTags,
  validateInputSize,
  buildHdfResults,
} from '../../../shared/typescript/converterutil.js';
import {buildCvss as buildSharedCvss, cvssVersionFromVector} from '../../../shared/typescript/cvss.js';
import {convertSarifToHdf} from '../../sarif-to-hdf/typescript/converter.js';
import {convertCyclonedxToHdf} from '../../cyclonedx-to-hdf/typescript/converter.js';
import {convertAsffToHdf} from '../../asff-to-hdf/typescript/converter.js';
import {convertGitlabToHdf} from '../../gitlab-to-hdf/typescript/converter.js';

const BASELINE_NAME = 'Trivy Scan';
const STATIC_CCI = nistToCci(DEFAULT_STATIC_ANALYSIS_NIST_TAGS);
const CWE_ID_PATTERN = /^CWE-[1-9]\d*$/;

// Mirrors the Go peer's SeverityToImpactWithAliases({critical:0.9}, 0.5).
const IMPACT_MAP: Record<string, number> = {
  critical: 0.9,
  high: 0.7,
  medium: 0.5,
  low: 0.3,
  unknown: 0.5,
  none: 0.0,
  info: 0.0,
};
function severityToImpact(severity: string): number {
  return IMPACT_MAP[(severity || '').toLowerCase()] ?? 0.5;
}

// --- native model -----------------------------------------------------------

interface TrivyCvss {
  V2Vector?: string;
  V3Vector?: string;
  V40Vector?: string;
  V2Score?: number;
  V3Score?: number;
  V40Score?: number;
}
interface TrivyVuln {
  VulnerabilityID?: string;
  PkgName?: string;
  PkgPath?: string;
  InstalledVersion?: string;
  FixedVersion?: string;
  Severity?: string;
  SeveritySource?: string;
  PrimaryURL?: string;
  Title?: string;
  Description?: string;
  PublishedDate?: string;
  CweIDs?: string[];
  References?: string[];
  PkgIdentifier?: {PURL?: string};
  DataSource?: {Name?: string};
  VendorSeverity?: Record<string, number>;
  CVSS?: Record<string, TrivyCvss>;
}
interface TrivyMisconf {
  ID?: string;
  AVDID?: string;
  Type?: string;
  Title?: string;
  Description?: string;
  Message?: string;
  Resolution?: string;
  Severity?: string;
  Status?: string;
  PrimaryURL?: string;
  References?: string[];
  CauseMetadata?: {StartLine?: number};
}
interface TrivySecret {
  RuleID?: string;
  Category?: string;
  Severity?: string;
  Title?: string;
  StartLine?: number;
  Match?: string;
}
interface TrivyLicense {
  Severity?: string;
  Category?: string;
  PkgName?: string;
  FilePath?: string;
  Name?: string;
  Confidence?: number;
  Link?: string;
}
interface TrivyResult {
  Target?: string;
  Class?: string;
  Type?: string;
  Vulnerabilities?: TrivyVuln[];
  Misconfigurations?: TrivyMisconf[];
  Secrets?: TrivySecret[];
  Licenses?: TrivyLicense[];
}
interface TrivyReport {
  SchemaVersion?: number;
  ArtifactName?: string;
  ArtifactType?: string;
  CreatedAt?: string;
  Trivy?: {Version?: string};
  Metadata?: {
    OS?: {Family?: string; Name?: string};
    ImageID?: string;
    RepoDigests?: string[];
    ImageConfig?: {architecture?: string};
  };
  Results?: TrivyResult[];
}

/**
 * Route Trivy output to HDF Results: native Trivy JSON (SchemaVersion 2) is
 * parsed here; SARIF / CycloneDX / ASFF / GitLab are delegated to their
 * converters. TypeScript peer of shared/go/../trivy-to-hdf converter.go.
 */
export async function convertTrivyToHdf(input: string, converterVersion = '1.0.0'): Promise<string> {
  validateInputSize(input, 'trivy');
  if (!input?.trim()) {
    throw new Error('trivy: empty input');
  }
  const probe = parseJSON<Record<string, unknown>>(input);
  if (typeof probe !== 'object' || probe === null || Array.isArray(probe)) {
    throw new Error('trivy: input is not a JSON object');
  }

  if (isNativeTrivy(probe)) {
    return convertNative(input, converterVersion);
  }
  if (probe.bomFormat === 'CycloneDX') {
    return convertCyclonedxToHdf(input, converterVersion);
  }
  if ('runs' in probe && 'version' in probe) {
    return convertSarifToHdf(input, converterVersion);
  }
  if ('Findings' in probe || 'ProductArn' in probe) {
    return convertAsffToHdf(input, converterVersion);
  }
  if ('vulnerabilities' in probe) {
    return convertGitlabToHdf(input, converterVersion);
  }
  throw new Error('trivy: not a recognized Trivy output format (native JSON, SARIF, CycloneDX, ASFF, or GitLab)');
}

function isNativeTrivy(m: Record<string, unknown>): boolean {
  return 'SchemaVersion' in m && 'ArtifactName' in m && 'ArtifactType' in m;
}

// --- native conversion ------------------------------------------------------

async function convertNative(input: string, converterVersion: string): Promise<string> {
  const report = parseJSON<TrivyReport>(input);
  const resultsChecksum: Checksum = await inputChecksum(input);
  const scanTime = report.CreatedAt ? parseTimestamp(report.CreatedAt) : null;
  // Match the Go peer's zero-time sentinel (0001-01-01) rather than epoch, so an
  // unknown scan time doesn't imply a real 1970 date and TS/Go output aligns.
  const startTime = scanTime ?? new Date('0001-01-01T00:00:00Z');

  const requirements: EvaluatedRequirement[] = [];
  for (const res of report.Results ?? []) {
    for (const v of res.Vulnerabilities ?? []) requirements.push(convertVuln(v, res, startTime));
    for (const m of res.Misconfigurations ?? []) requirements.push(convertMisconf(m, res, startTime));
    for (const s of res.Secrets ?? []) requirements.push(convertSecret(s, res, startTime));
    for (const l of res.Licenses ?? []) requirements.push(convertLicense(l, res, startTime));
  }

  if (requirements.length === 0) {
    requirements.push(
      buildNoFindingsRequirement(
        'trivy-no-findings',
        `Trivy scanned ${report.ArtifactName ?? 'the target'} and reported zero findings.`,
        startTime,
      ),
    );
  }

  const baseline = createMinimalBaseline(BASELINE_NAME, requirements, {resultsChecksum}) as EvaluatedBaseline;
  if (report.ArtifactName) baseline.title = report.ArtifactName;

  const component = buildComponent(report);
  return buildHdfResults({
    generatorName: 'trivy-to-hdf',
    converterVersion,
    toolName: 'Trivy',
    toolVersion: report.Trivy?.Version,
    baselines: [baseline],
    components: component ? [component] : undefined,
    timestamp: scanTime ?? undefined,
  });
}

function convertVuln(v: TrivyVuln, res: TrivyResult, startTime: Date): EvaluatedRequirement {
  const descriptions: Description[] = [
    {label: 'default', data: firstNonEmpty(v.Description, v.Title, v.VulnerabilityID)},
  ];
  if (v.FixedVersion) descriptions.push({label: 'fix', data: `Fixed in version ${v.FixedVersion}.`});

  const extras: Record<string, unknown> = {class: res.Class};
  putIf(extras, 'trivy_type', res.Type);
  putIf(extras, 'severity_source', v.SeveritySource);
  putIf(extras, 'data_source', v.DataSource?.Name);
  putIf(extras, 'published_date', v.PublishedDate);
  if (v.VendorSeverity && Object.keys(v.VendorSeverity).length > 0) extras.vendor_severity = v.VendorSeverity;
  const tags = buildTags(extras);

  const req: EvaluatedRequirement = {
    id: `Trivy/${v.VulnerabilityID ?? ''}`,
    title: `Trivy found ${v.VulnerabilityID ?? ''} in ${pkgLabel(v.PkgName, v.InstalledVersion)}`,
    descriptions,
    impact: severityToImpact(v.Severity ?? ''),
    tags,
    cwe: filterCwes(v.CweIDs),
    cvss: buildCvssEntries(v.CVSS),
    refs: buildRefs([v.PrimaryURL, ...(v.References ?? [])]),
    code: JSON.stringify(v, null, 2),
    controlType: deriveControlTypeFromTags(DEFAULT_STATIC_ANALYSIS_NIST_TAGS),
    verificationMethod: VerificationMethodEnum.Automated,
    results: [
      {
        status: ResultStatus.Failed,
        codeDesc: buildVulnCodeDesc(v, res),
        startTime,
        message: `Severity: ${v.Severity ?? 'UNKNOWN'}`,
      } as RequirementResult,
    ],
  };
  // Emit affectedPackages only when it satisfies the schema anyOf. Package
  // identity comes from the PURL (which also yields the ecosystem); a
  // name/version without a PURL lacks the required ecosystem and would be
  // schema-invalid, so gate on the PURL.
  const ap = buildAffectedPackage(v);
  if (ap.purl) req.affectedPackages = [ap];
  if (v.PkgPath) req.sourceLocation = {ref: v.PkgPath} as SourceLocation;
  return req;
}

function convertMisconf(m: TrivyMisconf, res: TrivyResult, startTime: Date): EvaluatedRequirement {
  const descriptions: Description[] = [
    {label: 'default', data: firstNonEmpty(m.Description, m.Message, m.Title)},
  ];
  if (m.Resolution) descriptions.push({label: 'fix', data: m.Resolution});

  const tags = buildTags({class: res.Class, ...(m.Type ? {misconfig_type: m.Type} : {})});
  const req: EvaluatedRequirement = {
    id: `Trivy/${firstNonEmpty(m.ID, m.AVDID)}`,
    title: m.Title,
    descriptions,
    impact: severityToImpact(m.Severity ?? ''),
    tags,
    refs: buildRefs([m.PrimaryURL, ...(m.References ?? [])]),
    code: JSON.stringify(m, null, 2),
    controlType: deriveControlTypeFromTags(DEFAULT_STATIC_ANALYSIS_NIST_TAGS),
    verificationMethod: VerificationMethodEnum.Automated,
    results: [
      {
        status: misconfStatus(m.Status),
        codeDesc: firstNonEmpty(m.Message, m.Title),
        startTime,
      } as RequirementResult,
    ],
  };
  if (res.Target) {
    const sl: SourceLocation = {ref: res.Target};
    if (m.CauseMetadata?.StartLine && m.CauseMetadata.StartLine > 0) sl.line = m.CauseMetadata.StartLine;
    req.sourceLocation = sl;
  }
  return req;
}

function convertSecret(s: TrivySecret, res: TrivyResult, startTime: Date): EvaluatedRequirement {
  const tags = buildTags({class: res.Class, ...(s.Category ? {secret_category: s.Category} : {})});
  const req: EvaluatedRequirement = {
    id: `Trivy/secret/${s.RuleID ?? ''}@${res.Target ?? ''}:${s.StartLine ?? 0}`,
    title: s.Title,
    descriptions: [
      {
        label: 'default',
        data: `${firstNonEmpty(s.Title, s.RuleID)} detected in ${res.Target ?? ''} (value redacted by Trivy).`,
      },
    ],
    impact: severityToImpact(s.Severity ?? ''),
    tags,
    code: JSON.stringify(s, null, 2),
    controlType: deriveControlTypeFromTags(DEFAULT_STATIC_ANALYSIS_NIST_TAGS),
    verificationMethod: VerificationMethodEnum.Automated,
    results: [{status: ResultStatus.Failed, codeDesc: s.Match ?? '', startTime} as RequirementResult],
  };
  if (res.Target) {
    const sl: SourceLocation = {ref: res.Target};
    if (s.StartLine && s.StartLine > 0) sl.line = s.StartLine;
    req.sourceLocation = sl;
  }
  return req;
}

function convertLicense(l: TrivyLicense, res: TrivyResult, startTime: Date): EvaluatedRequirement {
  const extras: Record<string, unknown> = {class: res.Class};
  putIf(extras, 'license_category', l.Category);
  putIf(extras, 'package', l.PkgName);
  if (l.Confidence && l.Confidence > 0) extras.confidence = l.Confidence;
  const tags = buildTags(extras);

  // No affectedPackages: a license finding carries only the package name, and
  // AffectedPackage requires name+version+ecosystem, a purl, or a cpe.
  const req: EvaluatedRequirement = {
    id: `Trivy/license/${l.PkgName ?? ''}/${l.Name ?? ''}`,
    title: `${l.Name ?? ''} (${l.Category ?? ''})`,
    descriptions: [
      {label: 'default', data: `Package ${l.PkgName ?? ''} uses the ${l.Name ?? ''} license (category: ${l.Category ?? ''}).`},
    ],
    impact: severityToImpact(l.Severity ?? ''),
    tags,
    refs: buildRefs([l.Link]),
    code: JSON.stringify(l, null, 2),
    controlType: deriveControlTypeFromTags(DEFAULT_STATIC_ANALYSIS_NIST_TAGS),
    verificationMethod: VerificationMethodEnum.Automated,
    results: [
      {status: ResultStatus.Failed, codeDesc: `${l.PkgName ?? ''}: ${l.Name ?? ''} license`, startTime} as RequirementResult,
    ],
  };
  if (l.FilePath) req.sourceLocation = {ref: l.FilePath} as SourceLocation;
  return req;
}

// --- component --------------------------------------------------------------

function buildComponent(report: TrivyReport): Component | undefined {
  if (!report.ArtifactName) return undefined;
  if (report.ArtifactType !== 'container_image') {
    return {name: report.ArtifactName, type: TargetType.Artifact} as Component;
  }
  const c: Component = {name: report.ArtifactName, type: TargetType.ContainerImage} as Component;
  const md = report.Metadata;
  if (!md) return c;
  if (md.ImageID) c.imageId = md.ImageID;
  if (md.OS?.Family) c.osName = md.OS.Family;
  if (md.OS?.Name) c.osVersion = md.OS.Name;
  const repoDigest = md.RepoDigests?.[0];
  if (repoDigest) {
    c.image = repoDigest;
    const dig = sha256Digest(repoDigest);
    if (dig) c.integrity = [{algorithm: 'sha256', value: dig} as Checksum];
  }
  if (md.ImageConfig?.architecture) c.labels = {architecture: md.ImageConfig.architecture};
  return c;
}

// --- helpers ----------------------------------------------------------------

function buildTags(extras: Record<string, unknown>): Record<string, unknown> {
  return buildNistCciTags(DEFAULT_STATIC_ANALYSIS_NIST_TAGS, STATIC_CCI, extras);
}

function misconfStatus(status?: string): ResultStatus {
  switch ((status ?? '').toUpperCase()) {
    case 'PASS':
      return ResultStatus.Passed;
    case 'EXCEPTION':
      return ResultStatus.NotApplicable;
    default:
      return ResultStatus.Failed;
  }
}

function filterCwes(cwes?: string[]): string[] | undefined {
  if (!cwes) return undefined;
  const out = cwes.filter((c) => CWE_ID_PATTERN.test(c));
  return out.length > 0 ? out : undefined;
}

function buildCvssEntries(m?: Record<string, TrivyCvss>): Cvss[] | undefined {
  if (!m || Object.keys(m).length === 0) return undefined;
  const entries: Cvss[] = [];
  for (const src of Object.keys(m).sort()) {
    const c = m[src];
    if (!c) continue;
    if (c.V2Vector || c.V2Score !== undefined) {
      entries.push(buildSharedCvss({version: Version.The20, baseVector: c.V2Vector, baseScore: c.V2Score, source: src}));
    }
    if (c.V3Vector || c.V3Score !== undefined) {
      entries.push(
        buildSharedCvss({version: cvssVersionFromVector(c.V3Vector, Version.The31), baseVector: c.V3Vector, baseScore: c.V3Score, source: src}),
      );
    }
    if (c.V40Vector || c.V40Score !== undefined) {
      entries.push(buildSharedCvss({version: Version.The40, baseVector: c.V40Vector, baseScore: c.V40Score, source: src}));
    }
  }
  return entries.length > 0 ? entries : undefined;
}

const PURL_ECOSYSTEMS: Record<string, Ecosystem> = {
  deb: Ecosystem.Deb,
  rpm: Ecosystem.RPM,
  maven: Ecosystem.Maven,
  npm: Ecosystem.Npm,
  pypi: Ecosystem.Pypi,
  gem: Ecosystem.Gem,
  cargo: Ecosystem.Cargo,
  golang: Ecosystem.Go,
  nuget: Ecosystem.Nuget,
};

function buildAffectedPackage(v: TrivyVuln): AffectedPackage {
  const ap: AffectedPackage = {};
  if (v.PkgName) ap.name = v.PkgName;
  if (v.InstalledVersion) ap.version = v.InstalledVersion;
  if (v.FixedVersion) ap.fixedInVersion = v.FixedVersion;
  const purl = v.PkgIdentifier?.PURL;
  if (purl) {
    ap.purl = purl;
    const eco = ecosystemFromPurl(purl);
    if (eco) ap.ecosystem = eco;
  }
  return ap;
}

function ecosystemFromPurl(purl: string): Ecosystem | undefined {
  const rest = purl.replace(/^pkg:/, '');
  const type = (rest.split(/[/@?]/)[0] ?? '').toLowerCase();
  return PURL_ECOSYSTEMS[type];
}

function buildRefs(urls: (string | undefined)[]): Reference[] | undefined {
  const seen = new Set<string>();
  const refs: Reference[] = [];
  for (const u of urls) {
    if (!u || seen.has(u)) continue;
    seen.add(u);
    refs.push({url: u});
  }
  return refs.length > 0 ? refs : undefined;
}

function buildVulnCodeDesc(v: TrivyVuln, res: TrivyResult): string {
  const parts = [`Package: ${v.PkgName ?? ''}@${v.InstalledVersion ?? ''}`];
  if (res.Type) parts.push(`Type: ${res.Type}`);
  if (v.PkgPath) parts.push(`Location: ${v.PkgPath}`);
  if (v.FixedVersion) parts.push(`Fixed: ${v.FixedVersion}`);
  return parts.join(' | ');
}

function pkgLabel(name?: string, version?: string): string {
  if (!version) return name ?? '';
  return `${name ?? ''}@${version}`;
}

function sha256Digest(ref: string): string {
  const i = ref.indexOf('sha256:');
  return i >= 0 ? ref.slice(i + 'sha256:'.length) : '';
}

function firstNonEmpty(...vals: (string | undefined)[]): string {
  for (const v of vals) if (v) return v;
  return '';
}

function putIf(m: Record<string, unknown>, key: string, val?: string): void {
  if (val) m[key] = val;
}
