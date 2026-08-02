/**
 * Helper functions for creating valid HDF objects with sensible defaults
 * Use these in converters to ensure type safety and schema compliance
 */

/**
 * Create a minimal valid EvaluatedBaseline with required fields
 * @param {string} name - Unique baseline identifier
 * @param {import('../dist/ts/hdf-results.js').EvaluatedRequirement[]} requirements - Array of evaluated requirements
 * @param {Object} [options] - Optional fields to override defaults
 * @returns {import('../dist/ts/hdf-results.js').EvaluatedBaseline}
 */
export function createMinimalBaseline(name, requirements, options = {}) {
  const baseline = {
    name,
    requirements,
  };

  // Include optional fields only if provided
  if (options.title) {
    baseline.title = options.title;
  }
  if (options.version) {
    baseline.version = options.version;
  }
  if (options.attributes) {
    baseline.attributes = options.attributes;
  }
  if (options.groups) {
    baseline.groups = options.groups;
  }
  if (options.supports) {
    baseline.supports = options.supports;
  }
  if (options.integrity) {
    baseline.integrity = options.integrity;
  }
  if (options.resultsChecksum) {
    baseline.resultsChecksum = options.resultsChecksum;
  }
  if (options.originalChecksum) {
    baseline.originalChecksum = options.originalChecksum;
  }
  if (options.status) {
    baseline.status = options.status;
  }
  if (options.summary) {
    baseline.summary = options.summary;
  }

  return baseline;
}

/**
 * Create a minimal valid EvaluatedRequirement
 * @param {string} id - Unique requirement identifier
 * @param {string} title - Human-readable title
 * @param {import('../dist/ts/hdf-results.js').Description[]} descriptions - Array of descriptions
 * @param {number} impact - Impact score (0.0 to 1.0)
 * @param {import('../dist/ts/hdf-results.js').RequirementResult[]} results - Array of test results
 * @param {Object} [options] - Optional fields
 * @returns {import('../dist/ts/hdf-results.js').EvaluatedRequirement}
 */
export function createRequirement(id, title, descriptions, impact, results, options = {}) {
  const req = {
    id,
    title,
    descriptions,
    impact,
    results,
    tags: options.tags || {},
  };

  // Only include sourceLocation if it's provided
  if (options.sourceLocation) {
    req.sourceLocation = options.sourceLocation;
  }

  return req;
}

/**
 * Create a description object
 * @param {string} label - Description label ('default', 'check', 'fix', 'rationale', etc.)
 * @param {string} data - Description text
 * @returns {import('../dist/ts/hdf-results.js').Description}
 */
export function createDescription(label, data) {
  return { label, data };
}

/**
 * Create a RequirementResult
 * @param {import('../dist/ts/hdf-results.js').ResultStatus} status - Test result status
 * @param {string} [message] - Optional message explaining the result. Omitted from
 *   the result entirely when empty/undefined, so converters no longer emit a spurious
 *   `"message": ""` that the Go side (omitempty) drops — keeping TS/Go output aligned.
 * @param {Object} [options] - Optional fields
 * @returns {import('../dist/ts/hdf-results.js').RequirementResult}
 */
export function createResult(status, message, options = {}) {
  return {
    status,
    ...(message ? { message } : {}),
    codeDesc: options.codeDesc || '',
    startTime: options.startTime,
    runTime: options.runTime,
    backtrace: options.backtrace,
    exception: options.exception,
  };
}

/**
 * Create an empty checksum (for when checksum data is unavailable)
 * @returns {import('../dist/ts/hdf-results.js').Checksum}
 */
export function createEmptyChecksum() {
  return {
    algorithm: 'sha256',
    value: '',
  };
}

/**
 * Create a supported platform object
 * @param {string} platform - Platform name (e.g., 'linux', 'windows', 'aws')
 * @param {string} [release] - Optional release version
 * @returns {import('../dist/ts/hdf-results.js').SupportedPlatform}
 */
export function createSupportedPlatform(platform, release) {
  return {
    platform,
    release,
  };
}

/**
 * Create a source location reference
 * @param {string} ref - File or resource reference
 * @param {number} line - Line number
 * @returns {import('../dist/ts/hdf-results.js').SourceLocation}
 */
export function createSourceLocation(ref, line) {
  return { ref, line };
}

// Re-export severity mapping from @mitre/hdf-utilities (canonical location).
// Kept here for backwards compatibility — consumers importing from
// @mitre/hdf-schema/helpers still get these functions.
export { severityToImpact, impactToSeverity } from '@mitre/hdf-utilities';

import { worstStatus } from '@mitre/hdf-utilities';

/**
 * Compute the effective status of a requirement from its results and impact.
 *
 * When effectiveStatus is already set on the requirement, returns it directly.
 * Otherwise derives status using standard HDF/InSpec precedence:
 *   1. effectiveStatus already set → return it
 *   2. impact === 0 → notApplicable
 *   3. No results → notReviewed
 *   4. Worst-wins roll-up of results via the canonical shared ordering
 *      (error > failed > passed > notApplicable > notReviewed)
 *
 * @param {import('../dist/ts/hdf-results.js').EvaluatedRequirement} requirement
 * @returns {import('../dist/ts/hdf-results.js').ResultStatus}
 */
export function computeEffectiveStatus(requirement) {
  if (requirement.effectiveStatus) {
    return requirement.effectiveStatus;
  }

  if (requirement.impact === 0) {
    return 'notApplicable';
  }

  // Worst-wins roll-up via the canonical shared ordering (error > failed >
  // passed > notApplicable > notReviewed); empty results -> notReviewed.
  // NOTE: unlike the full effective-status computation in @mitre/hdf-utilities,
  // this helper deliberately honors an already-set effectiveStatus first (its
  // documented back-compat contract) and does not consult statusOverrides.
  const results = requirement.results ?? [];
  return worstStatus(results.map((result) => result.status));
}
