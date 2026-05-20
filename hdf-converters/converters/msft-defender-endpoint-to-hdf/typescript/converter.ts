import { parseJSON } from '@mitre/hdf-utilities';
import { deriveControlTypeFromTags, inputChecksum, limitArray, validateInputSize, buildHdfResults } from '../../../shared/typescript/converterutil.js';
import type {
  EvaluatedBaseline,
  EvaluatedRequirement,
  RequirementResult,
  Checksum,
  Component,
} from '@mitre/hdf-schema';
import {
  ResultStatus,
  Copyright,
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
  severity: string;
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
 * Severity to HDF impact mapping.
 */
const IMPACT_MAPPING: Record<string, number> = {
  high: 0.7,
  medium: 0.5,
  low: 0.3,
  informational: 0.0,
};

/**
 * Maps MDE severity to HDF impact value.
 */
function severityToImpact(severity: string): number {
  return IMPACT_MAPPING[severity.toLowerCase()] ?? 0.5;
}

/**
 * Maps MDE alert status + classification to HDF result status.
 * new/inProgress → Failed, resolved with falsePositive → Passed, otherwise → Failed.
 */
function statusToResultStatus(status: string, classification?: string | null): ResultStatus {
  if (status.toLowerCase() === 'resolved') {
    if (classification && classification.toLowerCase() === 'falsepositive') {
      return ResultStatus.Passed;
    }
    return ResultStatus.Failed;
  }
  return ResultStatus.Failed;
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
  parts.push(`Severity: ${alert.severity}`);
  if (alert.threatDisplayName) {
    parts.push(`Threat: ${alert.threatDisplayName}`);
  }
  if (alert.alertWebUrl) {
    parts.push(`URL: ${alert.alertWebUrl}`);
  }
  return parts.join('\n');
}

/**
 * Extracts a Host target from device evidence, or falls back to tenant as cloud account.
 */
function extractDeviceTarget(alert: MdeAlert): Component {
  if (alert.evidence) {
    for (const ev of alert.evidence) {
      const odataType = ev['@odata.type'] ?? '';
      if (odataType.includes('deviceEvidence') && ev.deviceDnsName) {
        const target: Component = {
          name: ev.deviceDnsName,
          type: Copyright.Host,
          labels: { provider: 'azure' },
        };
        if (ev.deviceDnsName) {
          target.fqdn = ev.deviceDnsName;
        }
        if (ev.osPlatform) {
          target.osName = ev.osPlatform;
        }
        return target;
      }
    }
  }
  // No device evidence — use tenant as cloud account
  return {
    name: alert.tenantId ?? 'unknown',
    type: Copyright.CloudAccount,
    accountId: alert.tenantId,
    labels: { account: alert.tenantId ?? '', provider: 'azure' },
  };
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

  if (alert.classification) {
    tags['classification'] = alert.classification;
  }
  if (alert.determination) {
    tags['determination'] = alert.determination;
  }

  return tags;
}

/**
 * Converts a single MDE alert to an HDF EvaluatedRequirement.
 */
function alertToRequirement(alert: MdeAlert): EvaluatedRequirement {
  const impact = severityToImpact(alert.severity);
  const status = statusToResultStatus(alert.status, alert.classification);

  const codeDesc = formatEvidence(alert.evidence ?? []);
  const message = formatMessage(alert);

  const results: RequirementResult[] = [
    createResult(status, message, { codeDesc }),
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
  return req;
}

/**
 * Converts Microsoft Defender for Endpoint alerts (Microsoft Graph Security API v2 format) to HDF.
 * Each alert becomes one requirement with one result.
 *
 * @param input - JSON string of MDE alert response
 * @returns HDF JSON string
 */
export async function convertMsftDefenderEndpointToHdf(input: string): Promise<string> {
  validateInputSize(input, 'msft-defender-endpoint');

  const resultsChecksum: Checksum = await inputChecksum(input);

  const response = parseJSON<MdeAlertResponse>(input);

  if (!response || typeof response !== 'object') {
    throw new Error('Invalid Microsoft Defender for Endpoint structure: not a valid JSON object');
  }

  if (!Array.isArray(response.value)) {
    throw new Error('Invalid Microsoft Defender for Endpoint structure: missing or invalid value array');
  }

  const { items: limitedAlerts, truncated } = limitArray(response.value);
  /* v8 ignore next -- truncation only triggers with >100K items */
  if (truncated) {
    // eslint-disable-next-line no-console
    console.warn(`WARNING: Input truncated at ${limitedAlerts.length} alert items (original: ${response.value.length})`);
  }

  const requirements: EvaluatedRequirement[] = limitedAlerts.map(alertToRequirement);

  // Build components — deduplicate by device name
  const seenTargets = new Set<string>();
  const components: Component[] = [];
  for (const alert of limitedAlerts) {
    const target = extractDeviceTarget(alert);
    if (!seenTargets.has(target.name)) {
      seenTargets.add(target.name);
      components.push(target);
    }
  }

  const baseline: EvaluatedBaseline = createMinimalBaseline(
    'Microsoft Defender for Endpoint Scan',
    requirements,
    { resultsChecksum },
  ) as EvaluatedBaseline;

  return buildHdfResults({
    generatorName: 'msft-defender-endpoint-to-hdf',
    converterVersion: '1.0.0',
    toolName: 'Microsoft Defender for Endpoint',
    baselines: [baseline],
    components,
    timestamp: new Date(),
  });
}
