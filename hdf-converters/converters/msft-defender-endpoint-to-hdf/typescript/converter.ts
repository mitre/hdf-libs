import { parseJSON, parseTimestamp, severityToImpact } from '@mitre/hdf-utilities';
import { buildNoFindingsRequirement, deriveControlTypeFromTags, inputChecksum, limitArray, validateInputSize, buildHdfResults } from '../../../shared/typescript/converterutil.js';
import type {
  EvaluatedBaseline,
  EvaluatedRequirement,
  RequirementResult,
  Checksum,
  Component,
  Identity,
  Reference,
  StatusOverride,
} from '@mitre/hdf-schema';
import {
  IdentityType,
  OverrideType,
  ResultStatus,
  TargetType,
  VerificationMethodEnum,
  createMinimalBaseline,
  createRequirement,
  createResult,
  type Description,
} from '@mitre/hdf-schema';

/**
 * Microsoft Graph Security API v2 alert response structure.
 * Derived from official Microsoft documentation:
 * https://learn.microsoft.com/en-us/graph/api/resources/security-alert
 */
interface MdeAlertResponse {
  '@odata.context'?: string;
  value: MdeAlert[];
}

interface MdeAlert {
  id: string;
  incidentId?: string;
  status: string;
  severity?: string;
  classification?: string | null;
  determination?: string | null;
  serviceSource?: string;
  detectionSource?: string;
  category: string;
  title: string;
  description: string;
  alertWebUrl?: string;
  createdDateTime?: string;
  firstActivityDateTime?: string;
  lastActivityDateTime?: string;
  lastUpdateDateTime?: string;
  resolvedDateTime?: string | null;
  assignedTo?: string | null;
  tenantId?: string;
  actorDisplayName?: string | null;
  threatDisplayName?: string | null;
  threatFamilyName?: string | null;
  mitreTechniques?: string[];
  recommendedActions?: string;
  comments?: unknown[];
  evidence?: MdeEvidence[];
}

interface MdeEvidence {
  '@odata.type'?: string;
  deviceDnsName?: string;
  osPlatform?: string;
  mdeDeviceId?: string;
  healthStatus?: string;
  onboardingStatus?: string;
  rbacGroupName?: string;
  processId?: number;
  processCommandLine?: string;
  imageFile?: MdeImageFile;
  detectionStatus?: string;
  parentProcess?: MdeParentProcess;
  fileName?: string;
  filePath?: string;
  sha256?: string;
}

interface MdeImageFile {
  fileName?: string;
  filePath?: string;
  sha256?: string;
}

interface MdeParentProcess {
  processId?: number;
  imageFile?: MdeImageFile;
}

/**
 * An MDE alert is a detection that fired, so every alert is a raw Failed result.
 * Consumer triage (falsePositive, expected-activity) never flips the raw status —
 * it rides in a structured Status_Override that carries effectiveStatus + full
 * provenance (see buildTriageOverride). The raw failure and the attributed,
 * expiring override are both present.
 */
const RAW_ALERT_STATUS = ResultStatus.Failed;

/**
 * Resolves the alert's human triager (assignedTo) to an HDF Identity, typed as
 * email when the value looks like an address. When no owner is recorded, falls
 * back to an honest system identity rather than inventing a person.
 */
function triageIdentity(assignedTo?: string | null): Identity {
  if (assignedTo) {
    if (assignedTo.includes('@')) {
      return { type: IdentityType.Email, identifier: assignedTo };
    }
    return { type: IdentityType.Username, identifier: assignedTo };
  }
  return { type: IdentityType.System, identifier: 'Microsoft Defender for Endpoint (automated triage)' };
}

/**
 * Renders the override justification from the alert's determination and
 * classification (e.g. "notMalicious (falsePositive)").
 */
function triageReason(alert: MdeAlert): string {
  const det = alert.determination ?? '';
  const cls = alert.classification ?? '';
  if (det && cls) {
    return `${det} (${cls})`;
  }
  return det || cls || 'Triaged in Microsoft Defender for Endpoint';
}

interface TriageOverride {
  override: StatusOverride;
  effectiveStatus: ResultStatus;
  disposition: OverrideType;
}

/**
 * Turns an MDE alert's classification triage into a structured HDF
 * Status_Override with full provenance (assignedTo owner, resolvedDateTime applied
 * time). Returns null when the classification carries no override-worthy decision
 * (truePositive or untriaged → raw stays failed).
 * - falsePositive → falsePositive override, effectiveStatus notApplicable (the
 *   detection was wrong; disposition distinguishes it from a genuine N/A).
 * - informationalExpectedActivity → waiver override, effectiveStatus passed (the
 *   activity is real but expected/authorized, i.e. an accepted risk).
 */
function buildTriageOverride(alert: MdeAlert, startTime: Date): TriageOverride | null {
  if (!alert.classification) {
    return null;
  }
  let disposition: OverrideType;
  let effectiveStatus: ResultStatus;
  switch (alert.classification.toLowerCase()) {
    case 'falsepositive':
      disposition = OverrideType.FalsePositive;
      effectiveStatus = ResultStatus.NotApplicable;
      break;
    case 'informationalexpectedactivity':
      disposition = OverrideType.Waiver;
      effectiveStatus = ResultStatus.Passed;
      break;
    default: // truePositive, unknownFutureValue, … → no override
      return null;
  }

  const appliedAt =
    (alert.resolvedDateTime ? parseTimestamp(alert.resolvedDateTime) : null) ??
    (alert.lastUpdateDateTime ? parseTimestamp(alert.lastUpdateDateTime) : null) ??
    startTime;
  const expiresAt = new Date();
  expiresAt.setTime(appliedAt.getTime());
  expiresAt.setUTCFullYear(expiresAt.getUTCFullYear() + 1);

  const override: StatusOverride = {
    type: disposition,
    status: effectiveStatus,
    reason: triageReason(alert),
    appliedBy: triageIdentity(alert.assignedTo),
    appliedAt,
    expiresAt,
  };
  return { override, effectiveStatus, disposition };
}

/**
 * Formats evidence items into a human-readable code_desc string.
 */
function formatEvidence(evidence: MdeEvidence[]): string {
  if (!evidence || evidence.length === 0) {
    return 'No evidence available';
  }

  const parts: string[] = [];
  for (const ev of evidence) {
    const odataType = ev['@odata.type'] ?? '';
    if (odataType.includes('deviceEvidence')) {
      parts.push(`Device: ${ev.deviceDnsName ?? 'unknown'} (OS: ${ev.osPlatform ?? 'unknown'})`);
    } else if (odataType.includes('processEvidence')) {
      if (ev.imageFile) {
        parts.push(`Process: ${ev.imageFile.filePath ?? ''}\\${ev.imageFile.fileName ?? ''} (Command: ${ev.processCommandLine ?? ''})`);
      } else {
        parts.push(`Process: (Command: ${ev.processCommandLine ?? ''})`);
      }
    } else if (odataType.includes('fileEvidence')) {
      parts.push(`File: ${ev.filePath ?? ''}\\${ev.fileName ?? ''}`);
    } else {
      parts.push(`Evidence type: ${odataType}`);
    }
  }

  return parts.join('\n');
}

/**
 * Formats the message string for a result.
 */
function formatMessage(alert: MdeAlert): string {
  const parts: string[] = [];
  parts.push(`Alert: ${alert.title}`);
  parts.push(`Status: ${alert.status}`);
  parts.push(`Severity: ${alert.severity ?? ''}`);
  if (alert.threatDisplayName) {
    parts.push(`Threat: ${alert.threatDisplayName}`);
  }
  if (alert.alertWebUrl) {
    parts.push(`URL: ${alert.alertWebUrl}`);
  }
  return parts.join('\n');
}

/**
 * Extracts a Host target from device evidence, carrying the MDE device id
 * (externalIds.mde) plus rbac/health/onboarding labels. Falls back to tenant as
 * a cloud account when no device evidence exists.
 */
function extractDeviceTarget(alert: MdeAlert): Component {
  if (alert.evidence) {
    for (const ev of alert.evidence) {
      const odataType = ev['@odata.type'] ?? '';
      if (!odataType.includes('deviceEvidence')) {
        continue;
      }
      const deviceName = ev.deviceDnsName ?? '';
      const mdeDeviceId = ev.mdeDeviceId ?? '';
      // A device with neither a name nor an id carries no usable identity.
      if (!deviceName && !mdeDeviceId) {
        continue;
      }
      const labels: Record<string, string> = { provider: 'azure' };
      if (ev.rbacGroupName) {
        labels['rbacGroupName'] = ev.rbacGroupName;
      }
      if (ev.healthStatus) {
        labels['healthStatus'] = ev.healthStatus;
      }
      if (ev.onboardingStatus) {
        labels['onboardingStatus'] = ev.onboardingStatus;
      }
      const target: Component = {
        name: deviceName || mdeDeviceId,
        type: TargetType.Host,
        labels,
      };
      if (deviceName) {
        target.fqdn = deviceName;
      }
      if (ev.osPlatform) {
        target.osName = ev.osPlatform;
      }
      if (mdeDeviceId) {
        target.externalIds = { mde: mdeDeviceId };
      }
      return target;
    }
  }
  // No device evidence — use tenant as cloud account
  return {
    name: alert.tenantId ?? 'unknown',
    type: TargetType.CloudAccount,
    accountId: alert.tenantId,
    labels: { account: alert.tenantId ?? '', provider: 'azure' },
  };
}

/**
 * Returns the identity used to deduplicate scan-target components: the MDE device
 * id when present, else the component name.
 */
function targetDedupKey(target: Component): string {
  const mde = target.externalIds?.['mde'];
  return mde ? `mde:${mde}` : target.name;
}

/**
 * Builds tags map for a requirement.
 */
function buildTags(alert: MdeAlert): Record<string, unknown> {
  const tags: Record<string, unknown> = {
    nist: ['SA-11', 'RA-5'],
  };

  if (alert.category) {
    tags['category'] = alert.category;
  }

  if (alert.mitreTechniques && alert.mitreTechniques.length > 0) {
    tags['mitre'] = alert.mitreTechniques;
  }

  if (alert.incidentId) {
    // Emit as a number when the id is a canonical base-10 integer (round-trips
    // cleanly); otherwise preserve the source string verbatim. The round-trip
    // guard keeps Go/TS byte-parity for edge cases like leading zeros.
    const n = Number(alert.incidentId);
    tags['incident_id'] = Number.isInteger(n) && String(n) === alert.incidentId ? n : alert.incidentId;
  }
  if (alert.detectionSource) {
    tags['detection_source'] = alert.detectionSource;
  }
  if (alert.serviceSource) {
    tags['service_source'] = alert.serviceSource;
  }
  if (alert.threatFamilyName) {
    tags['threat_family_name'] = alert.threatFamilyName;
  }

  return tags;
}

/**
 * Resolves a clean per-finding source timestamp, falling back to the conversion time.
 */
function resolveStartTime(alert: MdeAlert, scanTime: Date): Date {
  // Resolve each candidate independently (matching the Go converter): a
  // present-but-unparseable firstActivityDateTime must still fall through to
  // createdDateTime, not skip straight to the conversion time.
  const first = alert.firstActivityDateTime ? parseTimestamp(alert.firstActivityDateTime) : null;
  if (first) {
    return first;
  }
  const created = alert.createdDateTime ? parseTimestamp(alert.createdDateTime) : null;
  if (created) {
    return created;
  }
  return scanTime;
}

/**
 * Derives the top-level report timestamp from the latest source alert time: the
 * freshest lastUpdateDateTime across alerts, falling back per alert to
 * lastActivityDateTime then createdDateTime. Source-derived so the conversion is
 * deterministic. Returns null when no alert carries a parseable time (caller
 * falls back to the conversion time). The skip-null logic mirrors the Go
 * converter's time.IsZero() fallthrough for byte-parity.
 */
function deriveScanTimestamp(alerts: MdeAlert[]): Date | null {
  let latest: Date | null = null;
  for (const alert of alerts) {
    const t =
      (alert.lastUpdateDateTime ? parseTimestamp(alert.lastUpdateDateTime) : null) ??
      (alert.lastActivityDateTime ? parseTimestamp(alert.lastActivityDateTime) : null) ??
      (alert.createdDateTime ? parseTimestamp(alert.createdDateTime) : null);
    if (!t) {
      continue;
    }
    if (!latest || t.getTime() > latest.getTime()) {
      latest = t;
    }
  }
  return latest;
}

/**
 * Converts a single MDE alert to an HDF EvaluatedRequirement.
 */
function alertToRequirement(alert: MdeAlert, scanTime: Date): EvaluatedRequirement {
  // Shared standard map, default 0.5 — mirrors the Go twin's SeverityToImpact.
  const impact = severityToImpact(alert.severity);

  const codeDesc = formatEvidence(alert.evidence ?? []);
  const message = formatMessage(alert);
  const startTime = resolveStartTime(alert, scanTime);

  const results: RequirementResult[] = [
    createResult(RAW_ALERT_STATUS, message, { codeDesc, startTime }),
  ];

  const descriptions: Description[] = [
    { label: 'default', data: alert.description },
  ];
  if (alert.recommendedActions) {
    descriptions.push({ label: 'fix', data: alert.recommendedActions });
  }

  const tags = buildTags(alert);

  const req = createRequirement(alert.id, alert.title, descriptions, impact, results, { tags }) as EvaluatedRequirement;
  const nistTags = tags.nist as string[];
  const controlType = deriveControlTypeFromTags(nistTags);
  if (controlType !== undefined) {
    req.controlType = controlType;
  }
  req.verificationMethod = VerificationMethodEnum.Automated;
  if (alert.alertWebUrl) {
    const refs: Reference[] = [{ url: alert.alertWebUrl }];
    req.refs = refs;
  }

  // Consumer triage becomes a structured override (raw failure + attributed,
  // expiring override both present). When the classification carries no
  // override-worthy decision (truePositive / untriaged), preserve the raw
  // classification + determination as loose tags instead.
  const triage = buildTriageOverride(alert, startTime);
  if (triage) {
    req.statusOverrides = [triage.override];
    req.effectiveStatus = triage.effectiveStatus;
    req.disposition = triage.disposition;
  } else {
    if (alert.classification) {
      tags['classification'] = alert.classification;
    }
    if (alert.determination) {
      tags['determination'] = alert.determination;
    }
  }
  return req;
}

/**
 * Converts Microsoft Defender for Endpoint alerts (Microsoft Graph Security API v2 format) to HDF.
 * Each alert becomes one requirement with one result.
 *
 * @param input - JSON string of MDE alert response
 * @returns HDF JSON string
 */
export async function convertMsftDefenderEndpointToHdf(input: string, converterVersion = '1.0.0'): Promise<string> {
  validateInputSize(input, 'msft-defender-endpoint');

  const resultsChecksum: Checksum = await inputChecksum(input);

  const response = parseJSON<MdeAlertResponse>(input);

  if (!response || typeof response !== 'object') {
    throw new Error('Invalid Microsoft Defender for Endpoint structure: not a valid JSON object');
  }

  if (!Array.isArray(response.value)) {
    throw new Error('Invalid Microsoft Defender for Endpoint structure: missing or invalid value array');
  }

  const scanTime = new Date();

  const { items: limitedAlerts, truncated } = limitArray(response.value);

  // Top-level timestamp is source-derived (latest alert time), not now(), so the
  // conversion is deterministic. Fall back to the conversion time only when the
  // input carries no parseable alert time (e.g. an empty tenant window).
  const derivedTimestamp = deriveScanTimestamp(limitedAlerts) ?? scanTime;
  /* v8 ignore next -- truncation only triggers with >100K items */
  if (truncated) {
    // eslint-disable-next-line no-console
    console.warn(`WARNING: Input truncated at ${limitedAlerts.length} alert items (original: ${response.value.length})`);
  }

  const requirements: EvaluatedRequirement[] = limitedAlerts.map((alert) => alertToRequirement(alert, scanTime));

  const seenTargets = new Set<string>();
  const components: Component[] = [];
  for (const alert of limitedAlerts) {
    const target = extractDeviceTarget(alert);
    const key = targetDedupKey(target);
    if (!seenTargets.has(key)) {
      seenTargets.add(key);
      components.push(target);
    }
  }

  if (requirements.length === 0) {
    requirements.push(buildNoFindingsRequirement(
      'msft-defender-endpoint-no-findings',
      'Microsoft Defender for Endpoint scanned the tenant and reported zero findings.',
      scanTime,
    ));
  }

  const baseline: EvaluatedBaseline = createMinimalBaseline(
    'Microsoft Defender for Endpoint Scan',
    requirements,
    { resultsChecksum },
  ) as EvaluatedBaseline;

  return buildHdfResults({
    generatorName: 'msft-defender-endpoint-to-hdf',
    converterVersion,
    toolName: 'Microsoft Defender for Endpoint',
    baselines: [baseline],
    components,
    timestamp: derivedTimestamp,
  });
}
