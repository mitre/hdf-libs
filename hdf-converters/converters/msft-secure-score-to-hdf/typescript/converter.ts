import { parseJSON, parseTimestamp } from '@mitre/hdf-utilities';
import {
  DEFAULT_STATIC_ANALYSIS_NIST_TAGS,
} from '@mitre/hdf-mappings';
import { deriveControlTypeFromTags, inputChecksum, limitArray, stripHTML, buildNistCciTags, validateInputSize, buildHdfResults } from '../../../shared/typescript/converterutil.js';
import type {
  Component,
  EvaluatedBaseline,
  EvaluatedRequirement,
  Reference,
  RequirementResult,
  Checksum,
} from '@mitre/hdf-schema';
import {
  ResultStatus,
  TargetType,
  VerificationMethodEnum,
  createMinimalBaseline,
  createRequirement,
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
  actionType?: string;
  actionUrl?: string;
  controlCategory?: string;
  title?: string;
  implementationCost?: string;
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
  const refs: Reference[] = [];
  if (matched.length > 0) {
    for (const url of matched
      .map(p => p.actionUrl)
      .filter((u): u is string => u !== undefined && u !== '')) {
      refs.push({ url });
    }

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

    // Source categorization/metadata from the matched profile(s). Emit each tag
    // only when a matched profile actually carries the value; preserve the
    // source's natural JSON type (threats array, numeric rank, strings).
    const threats = matched
      .map(p => p.threats)
      .find(t => Array.isArray(t) && t.length > 0);
    if (threats !== undefined) {
      tags.threats = threats;
    }
    const rank = matched
      .map(p => p.rank)
      .find(r => r !== undefined && r !== null);
    if (rank !== undefined) {
      tags.rank = rank;
    }
    const service = matched.map(p => p.service).find((s): s is string => !!s);
    if (service !== undefined) {
      tags.service = service;
    }
    const tier = matched.map(p => p.tier).find((s): s is string => !!s);
    if (tier !== undefined) {
      tags.tier = tier;
    }
    const userImpact = matched.map(p => p.userImpact).find((s): s is string => !!s);
    if (userImpact !== undefined) {
      tags.user_impact = userImpact;
    }
    const actionType = matched.map(p => p.actionType).find((s): s is string => !!s);
    if (actionType !== undefined) {
      tags.action_type = actionType;
    }
    const implementationCost = matched.map(p => p.implementationCost).find((s): s is string => !!s);
    if (implementationCost !== undefined) {
      tags.implementation_cost = implementationCost;
    }
  }

  // `on` is carried on the control score itself as a "true"/"false" string
  // (null/absent when Microsoft reports no enablement state). Map to a boolean;
  // omit when neither literal is present.
  if (cs.on === 'true') {
    tags.on = true;
  } else if (cs.on === 'false') {
    tags.on = false;
  }

  // CodeDesc from implementationStatus
  const codeDesc = cs.implementationStatus || 'No implementation status provided';

  // StartTime: the control's own lastSynced (when Microsoft last evaluated it).
  // Fall back to the score snapshot's createdDateTime when a control carries no
  // sync time (startTime is schema-required). Mirrors Go's IsZero fallback chain.
  const startTime =
    parseTimestamp(cs.lastSynced ?? '') ??
    parseTimestamp(createdDateTime ?? '') ??
    new Date('0001-01-01T00:00:00Z');

  // Secure Score has no per-result explanation beyond codeDesc, so `message`
  // stays absent rather than an empty string (createResult would default it to '').
  const results: RequirementResult[] = [
    { status, codeDesc, startTime },
  ];

  const req = createRequirement(
    id,
    title,
    descriptions,
    impact,
    results,
    { tags, ...(refs.length > 0 ? { refs } : {}) },
  ) as EvaluatedRequirement;
  const controlType = deriveControlTypeFromTags(nist);
  if (controlType !== undefined) {
    req.controlType = controlType;
  }
  req.verificationMethod = VerificationMethodEnum.Automated;
  return req;
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
export async function convertMsftSecureScoreToHdf(input: string, converterVersion = '1.0.0'): Promise<string> {
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

  // Top-level timestamp: the score snapshot's createdDateTime (when Microsoft
  // generated this Secure Score), not wall-clock now — keeps conversion
  // deterministic. Fall back to now only when the snapshot carries no time.
  const timestamp =
    parseTimestamp(combined.secureScore.value[0]?.createdDateTime ?? '') ?? new Date();

  return buildHdfResults({
    generatorName: 'msft-secure-score-to-hdf',
    converterVersion,
    toolName: 'Microsoft Secure Score',
    baselines,
    components: [{
      name: `Azure Tenant: ${tenantId}`,
      type: TargetType.CloudAccount,
      provider: 'azure' as Component['provider'],
      labels: { account: tenantId, provider: 'azure' },
    }],
    timestamp,
  });
}
