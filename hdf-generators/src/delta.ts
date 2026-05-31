import type { HDFBaseline, BaselineRequirement } from '@mitre/hdf-schema';
import type { UpgradeResult, UpgradeOptions, DeltaResult, DeltaOptions, LinkRecord, DeltaStatistics } from './delta-types.js';
import type { InSpecProfile } from './types.js';
import { mergeRequirement } from './merge.js';
import { generateControlStub } from './control-stub.js';
import { generateInSpecYml } from './inspec-yml.js';

/**
 * Generate an upgraded HDF Baseline by smart-merging current and upstream requirements.
 *
 * For each upstream requirement:
 * - If matched: smart-merge current + upstream fields per mergeRequirement semantics
 * - If unmatched: include upstream requirement as-is (new control)
 *
 * Current requirements with no upstream match are dropped by default
 * (a control removed from upstream should not survive the upgrade).
 * Set opts.keepUnmatched to retain them instead.
 */
export function generateUpgrade(
  currentBaseline: HDFBaseline,
  upstreamBaseline: HDFBaseline,
  linkRecords: LinkRecord[],
  opts?: UpgradeOptions,
): UpgradeResult {
  const prefer = opts?.prefer;

  // Build lookup: newId -> LinkRecord (prefer primary over related)
  const linkByNewId = new Map<string, LinkRecord>();
  for (const lr of linkRecords) {
    const existing = linkByNewId.get(lr.newId);
    if (!existing || lr.relationship === 'primary') {
      linkByNewId.set(lr.newId, lr);
    }
  }

  // Build lookup: oldId -> current requirement
  const currentById = new Map<string, BaselineRequirement>();
  for (const req of currentBaseline.requirements) {
    currentById.set(req.id, req);
  }

  // Track which current IDs got matched
  const matchedCurrentIds = new Set<string>();

  // Merge upstream requirements
  const mergedReqs: BaselineRequirement[] = [];
  for (const upReq of upstreamBaseline.requirements) {
    const link = linkByNewId.get(upReq.id);
    if (link && link.oldId) {
      const curReq = currentById.get(link.oldId);
      if (curReq) {
        matchedCurrentIds.add(link.oldId);

        // Handle --noCode
        const effectiveCurrent = opts?.noCode
          ? { ...curReq, code: undefined }
          : curReq;

        mergedReqs.push(mergeRequirement(effectiveCurrent, upReq, prefer));
        continue;
      }
    }
    // Unmatched upstream: include as-is
    mergedReqs.push(upReq);
  }

  // Include unmatched current requirements only when explicitly opted in.
  // By default they're dropped — a control removed from upstream should
  // not survive the upgrade, matching SAF CLI delta semantics.
  if (opts?.keepUnmatched) {
    for (const curReq of currentBaseline.requirements) {
      if (!matchedCurrentIds.has(curReq.id)) {
        mergedReqs.push(curReq);
      }
    }
  }

  // Build upgraded baseline (use upstream metadata)
  const upgradedBaseline: HDFBaseline = {
    ...upstreamBaseline,
    requirements: mergedReqs,
  };

  // Compute statistics
  const statistics = computeStatistics(linkRecords, currentBaseline.requirements.length, upstreamBaseline.requirements.length);

  const result: UpgradeResult = {
    baseline: upgradedBaseline,
    linkRecords,
    statistics,
  };

  // Generate InSpec profile if requested
  const outputFormat = opts?.outputFormat ?? '';
  if (outputFormat === 'inspec' || outputFormat === 'both' || outputFormat === '') {
    result.profile = generateProfileFromBaseline(upgradedBaseline, opts);
  }

  return result;
}

/**
 * Legacy entry point. Wraps generateUpgrade for backward compatibility.
 *
 * @deprecated Use generateUpgrade instead.
 */
export function generateDelta(
  newBaseline: HDFBaseline,
  linkRecords: LinkRecord[],
  oldCodeMap: Map<string, string>,
  opts?: DeltaOptions,
  oldControlCount?: number,
): DeltaResult {
  // Build synthetic current baseline from code map
  const currentReqs = buildCurrentReqsFromCodeMap(linkRecords, oldCodeMap);
  const currentBaseline: HDFBaseline = {
    name: 'current',
    requirements: currentReqs,
    groups: [],
    supports: [],
  };

  const result = generateUpgrade(currentBaseline, newBaseline, linkRecords, opts);

  // Patch statistics to use provided old control count
  result.statistics.oldControlsLength = oldControlCount ?? 0;

  return result;
}

function buildCurrentReqsFromCodeMap(
  linkRecords: LinkRecord[],
  oldCodeMap: Map<string, string>,
): BaselineRequirement[] {
  const seen = new Set<string>();
  const reqs: BaselineRequirement[] = [];

  for (const lr of linkRecords) {
    if (!lr.oldId || seen.has(lr.oldId)) continue;
    seen.add(lr.oldId);

    const req: BaselineRequirement = {
      id: lr.oldId,
      impact: 0,
      tags: {},
      descriptions: [{ label: 'default', data: '' }],
    };
    const code = oldCodeMap.get(lr.oldId);
    if (code) {
      req.code = code;
    }
    reqs.push(req);
  }
  return reqs;
}

function generateProfileFromBaseline(baseline: HDFBaseline, opts?: UpgradeOptions): InSpecProfile {
  const controls = new Map<string, string>();
  const allStubs: string[] = [];

  for (const req of baseline.requirements) {
    const ruby = generateControlStub(req);

    if (opts?.singleFile) {
      allStubs.push(ruby);
    } else {
      const safeId = req.id.replace(/\.\./g, '').replace(/[/\\]/g, '') || 'unknown';
      controls.set(`controls/${safeId}.rb`, ruby);
    }
  }

  if (opts?.singleFile && allStubs.length > 0) {
    controls.set('controls/controls.rb', allStubs.join('\n'));
  }

  const inspecYml = generateInSpecYml(baseline, {
    singleFile: opts?.singleFile,
    metadata: opts?.metadata,
    inspecVersion: opts?.inspecVersion,
  });

  return { inspecYml, controls };
}

function computeStatistics(linkRecords: LinkRecord[], oldControlCount: number, newControlCount: number): DeltaStatistics {
  let match = 0;
  let posMisMatch = 0;
  let dupMatch = 0;
  let noMatch = 0;

  for (const lr of linkRecords) {
    if (lr.relationship === 'related') {
      dupMatch++;
    } else if (lr.relationship === 'no-match') {
      noMatch++;
    } else if (lr.potentialMismatch) {
      posMisMatch++;
    } else {
      match++;
    }
  }

  return {
    oldControlsLength: oldControlCount,
    newControlsLength: newControlCount,
    totalMappedControls: match + posMisMatch + dupMatch,
    match,
    posMisMatch,
    dupMatch,
    noMatch,
  };
}
