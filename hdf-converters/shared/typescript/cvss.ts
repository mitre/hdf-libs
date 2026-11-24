import { computeCvssScore, cvssSeverityForVersion, parseCvssVector } from '@mitre/hdf-utilities';
import type { Cvss } from '@mitre/hdf-schema';
import { CVSSSeverity, Version as CvssVersion } from '@mitre/hdf-schema';

/** The CVSS version strings hdf-utilities reports, mapped to the schema Version enum. */
const CVSS_SCHEMA_VERSIONS: ReadonlyMap<string, CvssVersion> = new Map([
  ['2.0', CvssVersion.The20],
  ['3.0', CvssVersion.The30],
  ['3.1', CvssVersion.The31],
  ['4.0', CvssVersion.The40],
]);

/**
 * Returns the schema CVSS Version enum for a vector string, read through
 * parseCvssVector: the version a CVSS: prefix names, CVSS 2.0 for a prefix-less
 * vector carrying the 2.0-only Au metric, and otherwise `defaultVersion` (3.1
 * when omitted; historical Nessus output with no prefix passes 3.0).
 */
export function cvssVersionFromVector(
  vector: string | undefined,
  defaultVersion: CvssVersion = CvssVersion.The31
): CvssVersion {
  if (!vector) return defaultVersion;
  const { version, metrics } = parseCvssVector(vector);
  if (!vector.replace(/^\/+/, '').startsWith('CVSS:')) {
    return metrics.has('Au') ? CvssVersion.The20 : defaultVersion;
  }
  return CVSS_SCHEMA_VERSIONS.get(version) ?? defaultVersion;
}

/**
 * Maps a bare CVSS version number ("2.0"/"3.0"/"3.1"/"4.0") — as emitted in a
 * structured version field rather than a vector prefix — to the schema Version
 * enum. Unrecognized values default to 3.1.
 */
export function cvssVersionFromString(v: string | undefined): CvssVersion {
  return (v === undefined ? undefined : CVSS_SCHEMA_VERSIONS.get(v)) ?? CvssVersion.The31;
}

/**
 * Maps a CVSS score of the given version to the schema CVSSSeverity enum through
 * cvssSeverityForVersion, the one place the per-version scales live (NVD's v2
 * ranges for 2.0, the specification scale for 3.x and 4.0). A score with no
 * rating maps to "none".
 */
export function cvssSeverityFromScore(version: CvssVersion, score: number): CVSSSeverity {
  switch (cvssSeverityForVersion(version, score)) {
    case 'critical': return CVSSSeverity.Critical;
    case 'high': return CVSSSeverity.High;
    case 'medium': return CVSSSeverity.Medium;
    case 'low': return CVSSSeverity.Low;
    default: return CVSSSeverity.None;
  }
}

/**
 * Base-metric fields a converter provides for a single Cvss entry. Empty/undefined
 * fields are omitted from the assembled entry, so each converter can produce
 * exactly the shape it produces today (some set a baseVector and source, some do not).
 */
export interface CvssInput {
  version: CvssVersion;
  baseScore?: number | null;
  baseVector?: string | null;
  source?: string | null;
}

/**
 * Assembles a Cvss from the base-metric fields a converter provides. version is
 * always set. baseScore is the source's finite score; without one it is computed
 * from baseVector through computeCvssScore when the vector scores and its version
 * is the entry's version, and is otherwise absent. baseSeverity follows baseScore
 * on the entry's version's scale. baseVector and source are set only when
 * non-empty. Consumers needing threat/environmental/computed enrichment set those
 * fields on the result.
 */
export function buildCvss(input: CvssInput): Cvss {
  const cv: Cvss = {version: input.version};
  const score =
    typeof input.baseScore === 'number' && Number.isFinite(input.baseScore)
      ? input.baseScore
      : scoreFromVector(input.version, input.baseVector);
  if (score !== undefined) {
    cv.baseScore = score;
    cv.baseSeverity = cvssSeverityFromScore(input.version, score);
  }
  if (input.baseVector) cv.baseVector = input.baseVector;
  if (input.source) cv.source = input.source;
  return cv;
}

/** The vector's base score when it is of the entry's version, else undefined. */
function scoreFromVector(version: CvssVersion, vector: string | null | undefined): number | undefined {
  if (!vector) return undefined;
  try {
    const s = computeCvssScore(vector);
    return s.version === version ? s.baseScore : undefined;
  } catch {
    return undefined;
  }
}
