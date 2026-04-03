import { parseJSON } from '@mitre/hdf-utilities';
import {
  DEFAULT_STATIC_ANALYSIS_NIST_TAGS,
} from '@mitre/hdf-mappings';
import { inputChecksum, limitArray, stripHTML, buildNistCciTags, validateInputSize, buildHdfResults } from '../../../shared/typescript/converterutil.js';
import type {
  EvaluatedBaseline,
  EvaluatedRequirement,
  Checksum,
} from '@mitre/hdf-schema';
import {
  ResultStatus,
  Copyright,
  createMinimalBaseline,
  createRequirement,
  createResult,
  type Description,
} from '@mitre/hdf-schema';

/**
 * Microsoft Graph Secure Score structures.
 * Defined locally to avoid external dependency on @microsoft/microsoft-graph-types.
 */
interface CombinedResponse {
  secureScore: SecureScoreResponse;
  profiles: ProfileResponse;
}

interface SecureScoreResponse {
  '@odata.context'?: string;
  value: SecureScore[];
}

interface SecureScore {
  id: string;
  azureTenantId: string;
  activeUserCount?: number;
  createdDateTime: string;
  currentScore?: number;
  enabledServices?: string[];
  licensedUserCount?: number;
  maxScore?: number;
  controlScores: ControlScore[];
  averageComparativeScores?: unknown[];
}

interface ControlScore {
  controlCategory: string;
  controlName: string;
  description: string;
  score: number;
  lastSynced?: string;
  implementationStatus: string;
  on?: string;
  scoreInPercentage: number;
}

interface ProfileResponse {
  '@odata.context'?: string;
  '@odata.nextLink'?: string;
  value: SecureScoreControlProfile[];
}

interface SecureScoreControlProfile {
  id: string;
  azureTenantId?: string;
  controlCategory?: string;
  title?: string;
  maxScore?: number;
  rank?: unknown;
  remediation?: string;
  remediationImpact?: string;
  service?: string;
  threats?: unknown;
  tier?: string;
  userImpact?: string;
}

/**
 * Returns all profiles matching a given control name.
 */
function getMatchingProfiles(
  profiles: SecureScoreControlProfile[],
  controlName: string,
): SecureScoreControlProfile[] {
  return profiles.filter(p => p.id === controlName);
}

/**
 * Gets the title from matching profiles, or falls back to category:name.
 */
function getTitle(
  profiles: SecureScoreControlProfile[],
  cs: ControlScore,
): string {
  const matched = getMatchingProfiles(profiles, cs.controlName);
  const titles = matched
    .map(p => p.title)
    .filter((t): t is string => t !== undefined && t !== '');

  if (titles.length > 0) {
    return titles[0]!;
  }

  // Fallback
  return [cs.controlCategory, cs.controlName].filter(Boolean).join(':');
}

/**
 * Computes impact from profile maxScore (maxScore / 10.0).
 * Falls back to 0.5 when no matching profile exists.
 * Capped at 1.0.
 */
function getImpact(
  profiles: SecureScoreControlProfile[],
  cs: ControlScore,
): number {
  const matched = getMatchingProfiles(profiles, cs.controlName);
  if (matched.length === 0) {
    return 0.5;
  }

  const maxScore = Math.max(...matched.map(p => p.maxScore ?? 0));
  const impact = maxScore / 10.0;
  return Math.min(Math.round(impact * 100) / 100, 1.0);
}

/**
 * Determines the result status based on scoreInPercentage and profile maxScore.
 */
function getStatus(
  profiles: SecureScoreControlProfile[],
  cs: ControlScore,
): ResultStatus {
  if (cs.scoreInPercentage === 100) {
    return ResultStatus.Passed;
  }

  const matched = getMatchingProfiles(profiles, cs.controlName);
  if (matched.length === 0) {
    return ResultStatus.Failed;
  }

  const maxScore = Math.max(...matched.map(p => p.maxScore ?? 0));
  if (cs.score === maxScore) {
    return ResultStatus.Passed;
  }

  return ResultStatus.Failed;
}

/**
 * Builds an EvaluatedRequirement from a ControlScore.
 */
function buildRequirement(
  cs: ControlScore,
  profiles: SecureScoreControlProfile[],
  createdDateTime: string,
): EvaluatedRequirement {
  const id = `${cs.controlCategory}:${cs.controlName}`;
  const title = getTitle(profiles, cs);
  const impact = getImpact(profiles, cs);
  const status = getStatus(profiles, cs);

  // NIST tags: use default static analysis tags
  const nist = [...DEFAULT_STATIC_ANALYSIS_NIST_TAGS];
  const tags = buildNistCciTags(nist, []);

  // Descriptions
  const descriptions: Description[] = [
    { label: 'default', data: stripHTML(cs.description) },
  ];

  // Add fix description from profile remediation
  const matched = getMatchingProfiles(profiles, cs.controlName);
  if (matched.length > 0) {
    const remediations = matched
      .map(p => p.remediation)
      .filter((r): r is string => r !== undefined && r !== '');
    if (remediations.length > 0) {
      descriptions.push({ label: 'fix', data: stripHTML(remediations[0]!) });
    }

    const impacts = matched
      .map(p => p.remediationImpact)
      .filter((r): r is string => r !== undefined && r !== '');
    if (impacts.length > 0) {
      descriptions.push({ label: 'rationale', data: stripHTML(impacts[0]!) });
    }
  }

  // CodeDesc from implementationStatus
  const codeDesc = cs.implementationStatus || 'No implementation status provided';

  // StartTime from createdDateTime
  const startTime = createdDateTime ? new Date(createdDateTime) : undefined;

  const results = [
    createResult(status, undefined, {
      codeDesc,
      ...(startTime ? { startTime } : {}),
    }),
  ];

  return createRequirement(
    id,
    title,
    descriptions,
    impact,
    results,
    { tags },
  );
}

/**
 * Converts Microsoft Secure Score combined JSON to HDF format.
 *
 * Input is the combined JSON containing both secureScore and profiles data
 * from the Microsoft Graph API.
 *
 * @param input - Combined JSON string with secureScore and profiles
 * @returns HDF JSON string
 */
export async function convertMsftSecureScoreToHdf(input: string): Promise<string> {
  if (!input || input.trim().length === 0) {
    throw new Error('msft-secure-score: empty input');
  }
  validateInputSize(input, 'msft-secure-score');

  const combined = parseJSON<CombinedResponse>(input);

  if (!combined || typeof combined !== 'object') {
    throw new Error('msft-secure-score: invalid JSON');
  }

  if (!combined.secureScore?.value) {
    throw new Error('msft-secure-score: missing secureScore.value');
  }
  if (!combined.profiles?.value) {
    throw new Error('msft-secure-score: missing profiles.value');
  }
  if (combined.secureScore.value.length === 0) {
    throw new Error('msft-secure-score: secureScore.value is empty');
  }

  const resultsChecksum: Checksum = await inputChecksum(input);

  const profiles = combined.profiles.value;
  let tenantId = '';

  const baselines: EvaluatedBaseline[] = combined.secureScore.value.map(ss => {
    if (!tenantId) {
      tenantId = ss.azureTenantId;
    }

    const { items: limitedControlScores, truncated } = limitArray(ss.controlScores);
    /* v8 ignore next -- truncation only triggers with >100K items */
    if (truncated) {
      // eslint-disable-next-line no-console
      console.warn(`WARNING: Input truncated at ${limitedControlScores.length} controlScore items (original: ${ss.controlScores.length})`);
    }

    const requirements = limitedControlScores.map(cs =>
      buildRequirement(cs, profiles, ss.createdDateTime),
    );

    const title = `Azure Secure Score report - Tenant ID: ${ss.azureTenantId} - Run ID: ${ss.id}`;

    return createMinimalBaseline(
      'Microsoft Secure Score',
      requirements,
      {
        resultsChecksum,
        title,
      },
    ) as EvaluatedBaseline;
  });

  return buildHdfResults({
    generatorName: 'msft-secure-score-to-hdf',
    converterVersion: '1.0.0',
    toolName: 'Microsoft Secure Score',
    toolFormat: 'JSON',
    baselines,
    components: [{
      name: `Azure Tenant: ${tenantId}`,
      type: Copyright.CloudAccount,
      labels: { account: tenantId, provider: 'azure' },
    }],
    timestamp: new Date(),
  });
}
