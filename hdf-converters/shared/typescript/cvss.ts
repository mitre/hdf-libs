import { cvssScoreToSeverity } from '@mitre/hdf-utilities';
import type { Cvss } from '@mitre/hdf-schema';
import { CVSSSeverity, Version as CvssVersion } from '@mitre/hdf-schema';

/**
 * Returns the schema CVSS Version enum for a vector-string prefix (CVSS:2.0/,
 * CVSS:3.0/, CVSS:3.1/, CVSS:4.0/). `defaultVersion` sets the version returned
 * when the vector is absent or carries no recognized prefix (e.g. historical
 * Nessus output with no prefix passes 3.0); it defaults to 3.1, the version
 * modern scanners emit most often.
 */
export function cvssVersionFromVector(
  vector: string | undefined,
  defaultVersion: CvssVersion = CvssVersion.The31
): CvssVersion {
  if (!vector) return defaultVersion;
  if (vector.startsWith('CVSS:2.0/')) return CvssVersion.The20;
  if (vector.startsWith('CVSS:3.0/')) return CvssVersion.The30;
  if (vector.startsWith('CVSS:3.1/')) return CvssVersion.The31;
  if (vector.startsWith('CVSS:4.0/')) return CvssVersion.The40;
  return defaultVersion;
}

/**
 * Maps a bare CVSS version number ("2.0"/"3.0"/"3.1"/"4.0") — as emitted in a
 * structured version field rather than a vector prefix — to the schema Version
 * enum. Unrecognized values default to 3.1.
 */
export function cvssVersionFromString(v: string | undefined): CvssVersion {
  switch (v) {
    case '2.0': return CvssVersion.The20;
    case '3.0': return CvssVersion.The30;
    case '4.0': return CvssVersion.The40;
    default: return CvssVersion.The31;
  }
}

/**
 * Maps a CVSS base/computed score to the schema CVSSSeverity enum via the shared
 * band thresholds in cvssScoreToSeverity. Scores below the low threshold (and
 * non-finite inputs, per cvssScoreToSeverity) map to the "none" band.
 */
export function cvssSeverityFromScore(score: number): CVSSSeverity {
  switch (cvssScoreToSeverity(score)) {
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
 * always set. baseScore (and its derived baseSeverity) is set only when a finite
 * number is supplied; baseVector and source are set only when non-empty. Consumers
 * needing threat/environmental/computed enrichment set those fields on the result.
 */
export function buildCvss(input: CvssInput): Cvss {
  const cv: Cvss = {version: input.version};
  if (typeof input.baseScore === 'number' && Number.isFinite(input.baseScore)) {
    cv.baseScore = input.baseScore;
    cv.baseSeverity = cvssSeverityFromScore(input.baseScore);
  }
  if (input.baseVector) cv.baseVector = input.baseVector;
  if (input.source) cv.source = input.source;
  return cv;
}
