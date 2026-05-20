import { parseJSON } from '@mitre/hdf-utilities';
import { deriveControlTypeFromTags, inputChecksum, validateInputSize } from '../../../shared/typescript/converterutil.js';
import type {
  HdfResults,
  EvaluatedBaseline,
  EvaluatedRequirement,
  RequirementResult,
  Checksum,
  Description,
  RequirementGroup,
} from '@mitre/hdf-schema';
import {
  ResultStatus,
  Copyright,
  VerificationMethodEnum,
  createMinimalBaseline,
  createRequirement,
  createDescription,
  createResult,
} from '@mitre/hdf-schema';

/**
 * Splunk event metadata. Each event emitted by the HDF-to-Splunk pipeline
 * carries a `meta` object that describes the event's role.
 */
interface SplunkMeta {
  guid: string;
  subtype: 'header' | 'profile' | 'control';
  hdf_splunk_schema: string;
  filetype: string;
  filename: string;
  profile_sha256?: string;
  status?: string;
  is_baseline?: boolean;
  is_waived?: boolean;
  overlay_depth?: number;
}

interface SplunkEvent {
  meta: SplunkMeta;
  [key: string]: unknown;
}

interface SplunkHeader extends SplunkEvent {
  profiles: unknown[];
  platform: { name: string; release: string };
  statistics: Record<string, unknown>;
  version: string;
}

interface SplunkProfile extends SplunkEvent {
  name: string;
  title: string;
  sha256: string;
  version: string;
  summary?: string;
  copyright?: string;
  maintainer?: string;
  license?: string;
  supports: unknown[];
  groups: Array<{ id: string; controls: string[] }>;
  attributes: unknown[];
  controls: unknown[];
}

interface SplunkControl extends SplunkEvent {
  id: string;
  title: string;
  desc: string;
  descriptions: Record<string, string>;
  impact: number;
  code: string;
  tags: Record<string, unknown>;
  results: SplunkResult[];
  refs: unknown[];
  source_location?: { ref: string; line: number };
}

interface SplunkResult {
  status: string;
  code_desc: string;
  message?: string;
  start_time: string;
  run_time?: number;
  skip_message?: string;
  exception?: string;
  backtrace?: string[];
  resource?: string;
}

/**
 * Map a Splunk result status string to the HDF ResultStatus enum.
 */
function mapStatus(status: string): ResultStatus {
  switch (status.toLowerCase()) {
    case 'passed':
      return ResultStatus.Passed;
    case 'failed':
      return ResultStatus.Failed;
    case 'skipped':
      return ResultStatus.NotReviewed;
    case 'error':
      return ResultStatus.Error;
    default:
      return ResultStatus.NotReviewed;
  }
}

/**
 * Convert a Splunk descriptions object (`{ key: value }`) to an array of
 * HDF Description objects.
 */
function convertDescriptions(
  descriptions: Record<string, string> | undefined,
): Description[] {
  if (!descriptions || typeof descriptions !== 'object') {
    return [];
  }
  return Object.entries(descriptions).map(([label, data]) =>
    createDescription(label, data),
  );
}

/**
 * Convert Splunk profile groups (which use `controls`) to HDF
 * RequirementGroups (which use `requirements`).
 */
function convertGroups(
  groups: Array<{ id: string; controls: string[] }> | undefined,
): RequirementGroup[] {
  if (!groups || !Array.isArray(groups)) {
    return [];
  }
  return groups.map((g) => ({
    id: g.id,
    requirements: g.controls,
  }));
}

/**
 * Convert a Splunk JSON event array back into an HDF Results document.
 *
 * Input is a JSON string containing an array of Splunk events previously
 * produced by the HDF-to-Splunk pipeline. Each event carries a `meta.subtype`
 * of "header", "profile", or "control" and a shared `meta.guid` that ties
 * them together.
 *
 * @param input - JSON string of a SplunkEvent array
 * @returns HDF Results JSON string
 */
export async function convertSplunkToHdf(input: string): Promise<string> {
  validateInputSize(input, 'splunk');
  const resultsChecksum: Checksum = await inputChecksum(input);

  const events = parseJSON<SplunkEvent[]>(input);

  if (!Array.isArray(events) || events.length === 0) {
    throw new Error('No Splunk events found in input');
  }

  // Group events by GUID (each GUID represents one original HDF execution)
  const eventsByGuid = new Map<string, SplunkEvent[]>();
  for (const event of events) {
    const guid = event.meta.guid;
    if (!eventsByGuid.has(guid)) {
      eventsByGuid.set(guid, []);
    }
    eventsByGuid.get(guid)!.push(event);
  }

  // Process each GUID group into baselines + components
  const allBaselines: EvaluatedBaseline[] = [];
  let targetName = 'unknown';
  let targetRelease = '';

  for (const [, guidEvents] of eventsByGuid) {
    const headers: SplunkHeader[] = [];
    const profiles: SplunkProfile[] = [];
    const controls: SplunkControl[] = [];

    for (const event of guidEvents) {
      switch (event.meta.subtype) {
        case 'header':
          headers.push(event as SplunkHeader);
          break;
        case 'profile':
          profiles.push(event as SplunkProfile);
          break;
        case 'control':
          controls.push(event as SplunkControl);
          break;
      }
    }

    if (headers.length !== 1) {
      throw new Error(
        `Expected 1 header event, got ${headers.length}`,
      );
    }

    const header = headers[0]!;
    targetName = header.platform.name;
    targetRelease = header.platform.release;

    // Group controls by their profile_sha256
    const controlsByProfile = new Map<string, SplunkControl[]>();
    for (const control of controls) {
      const sha = control.meta.profile_sha256 ?? '';
      if (!controlsByProfile.has(sha)) {
        controlsByProfile.set(sha, []);
      }
      controlsByProfile.get(sha)!.push(control);
    }

    // Build a baseline for each profile event
    for (const profile of profiles) {
      const profileControls = controlsByProfile.get(profile.sha256) ?? [];

      const requirements: EvaluatedRequirement[] = profileControls.map(
        (control) => {
          const descriptions = convertDescriptions(control.descriptions);

          const results: RequirementResult[] = Array.isArray(control.results)
            ? control.results.map((result) =>
                createResult(mapStatus(result.status), result.message, {
                  codeDesc: result.code_desc,
                  startTime: new Date(result.start_time),
                  runTime: result.run_time,
                  exception: result.exception,
                  backtrace: result.backtrace,
                }),
              )
            : [];

          const options: {
            tags: Record<string, unknown>;
            sourceLocation?: { ref: string; line: number };
          } = {
            tags: control.tags ?? {},
          };

          if (control.source_location) {
            options.sourceLocation = control.source_location;
          }

          const req = createRequirement(
            control.id,
            control.title,
            descriptions,
            control.impact,
            results,
            options,
          ) as EvaluatedRequirement;

          const nistTagsRaw = (control.tags as Record<string, unknown> | undefined)?.['nist'];
          const nistTags = Array.isArray(nistTagsRaw)
            ? nistTagsRaw.filter((t): t is string => typeof t === 'string')
            : [];
          const controlType = deriveControlTypeFromTags(nistTags);
          if (controlType !== undefined) {
            req.controlType = controlType;
          }
          req.verificationMethod = VerificationMethodEnum.Automated;

          return req;
        },
      );

      const groups = convertGroups(profile.groups);

      const baselineOptions: {
        title?: string;
        version?: string;
        summary?: string;
        groups?: RequirementGroup[];
        resultsChecksum: Checksum;
      } = {
        resultsChecksum,
      };

      if (profile.title) {
        baselineOptions.title = profile.title;
      }
      if (profile.version) {
        baselineOptions.version = profile.version;
      }
      if (profile.summary) {
        baselineOptions.summary = profile.summary;
      }
      if (groups.length > 0) {
        baselineOptions.groups = groups;
      }

      allBaselines.push(
        createMinimalBaseline(profile.name, requirements, baselineOptions),
      );
    }
  }

  const hdf: HdfResults = {
    baselines: allBaselines,
    components: [
      {
        name: targetName,
        type: Copyright.Host,
        osName: targetRelease || undefined,
        labels: {},
      },
    ],
    generator: {
      name: 'splunk-to-hdf',
      version: '1.0.0',
    },
  };

  return JSON.stringify(hdf, null, 2);
}
