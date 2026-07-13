import { parseJSON, parseTimestamp } from '@mitre/hdf-utilities';
import { buildHdfResults, deriveControlTypeFromTags, inputChecksum, validateInputSize } from '../../../shared/typescript/converterutil.js';
import type {
  Component,
  EvaluatedBaseline,
  EvaluatedRequirement,
  RequirementResult,
  Checksum,
  Description,
  Integrity,
  RequirementGroup,
  Statistics,
} from '@mitre/hdf-schema';
import {
  HashAlgorithm,
  ResultStatus,
  TargetType,
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
 * HDF Description objects. Labels are sorted: Go decodes the same object into
 * a map, so sorting is the only ordering both languages can agree on.
 */
function convertDescriptions(
  descriptions: Record<string, string> | undefined,
): Description[] {
  if (!descriptions || typeof descriptions !== 'object') {
    return [];
  }
  return Object.entries(descriptions)
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
    .map(([label, data]) => createDescription(label, data));
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
export async function convertSplunkToHdf(input: string, converterVersion = '1.0.0'): Promise<string> {
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

  // Process each GUID group into baselines + components. GUIDs are visited in
  // sorted order because Go groups them in a map and can only agree on that.
  const allBaselines: EvaluatedBaseline[] = [];
  const components: Component[] = [];
  let statistics: Statistics | undefined;

  for (const guid of [...eventsByGuid.keys()].sort()) {
    const guidEvents = eventsByGuid.get(guid)!;
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
    const component: Component = {
      name: header.platform.name,
      type: TargetType.Host,
    };
    if (header.platform.release) {
      component.osVersion = header.platform.release;
    }
    components.push(component);
    statistics = convertStatistics(header.statistics);

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
          if (descriptions.length === 0) {
            descriptions.push(createDescription('default', control.desc ?? ''));
          }

          const results: RequirementResult[] = Array.isArray(control.results)
            ? control.results.map((result) => {
                const res = createResult(
                  mapStatus(result.status),
                  result.skip_message || result.message,
                  {
                    codeDesc: result.code_desc,
                    startTime: parseTimestamp(result.start_time) ?? new Date('0001-01-01T00:00:00Z'),
                    runTime: result.run_time,
                    exception: result.exception,
                    backtrace: result.backtrace,
                  },
                );
                if (!res.message) delete res.message;
                if (result.resource) res.resource = result.resource;
                return res;
              })
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

          if (!req.title) delete req.title;
          if (control.code) req.code = control.code;

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
        integrity?: Integrity;
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
      if (profile.sha256) {
        baselineOptions.integrity = {
          algorithm: HashAlgorithm.Sha256,
          checksum: profile.sha256,
        };
      }

      const baseline = createMinimalBaseline(profile.name, requirements, baselineOptions);
      if (profile.copyright) baseline.copyright = profile.copyright;
      if (profile.maintainer) baseline.maintainer = profile.maintainer;
      if (profile.license) baseline.license = profile.license;

      allBaselines.push(baseline);
    }
  }

  return buildHdfResults({
    generatorName: 'splunk-to-hdf',
    converterVersion,
    toolName: 'Splunk',
    baselines: allBaselines,
    components,
    statistics,
    timestamp: new Date(),
  });
}

/** Extract the assessment duration from a Splunk header's statistics blob. */
function convertStatistics(stats: Record<string, unknown> | undefined): Statistics | undefined {
  if (!stats || typeof stats !== 'object') return undefined;
  const out: Statistics = {};
  if (typeof stats['duration'] === 'number') {
    out.duration = stats['duration'];
  }
  return out;
}
