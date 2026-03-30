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
  if (options.checksum) {
    baseline.checksum = options.checksum;
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
 * @param {string} [message] - Optional message explaining the result
 * @param {Object} [options] - Optional fields
 * @returns {import('../dist/ts/hdf-results.js').RequirementResult}
 */
export function createResult(status, message = '', options = {}) {
  return {
    status,
    message,
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

/**
 * Map a severity string to an impact score.
 *
 * Impact bands align with CVSS 3.x severity ratings normalized to 0-1:
 *   critical=0.9 (CVSS 9.0), high=0.7 (CVSS 7.0), medium=0.5 (CVSS 5.0),
 *   low=0.3 (CVSS 3.0), informational=0.0 (CVSS 0.0)
 *
 * Each value is the floor of its band, preserving sub-band precision:
 *   0.9-1.0=critical, 0.7-0.8=high, 0.4-0.6=medium, 0.1-0.3=low, 0.0=informational
 *
 * @param {string} severity - Severity level
 * @returns {number} Impact score between 0.0 and 1.0
 */
export function severityToImpact(severity) {
  const normalized = severity.toLowerCase();
  switch (normalized) {
    case 'critical':
      return 0.9;
    case 'high':
      return 0.7;
    case 'medium':
      return 0.5;
    case 'low':
      return 0.3;
    case 'informational':
    case 'info':
      return 0.0;
    default:
      return 0.5;
  }
}

/**
 * Map an impact score to a severity string
 * @param {number} impact - Impact score (0.0 to 1.0)
 * @returns {string} Severity level
 */
export function impactToSeverity(impact) {
  if (impact >= 0.9) return 'critical';
  if (impact >= 0.7) return 'high';
  if (impact >= 0.4) return 'medium';
  if (impact > 0.0) return 'low';
  return 'informational';
}

/**
 * Compute the effective status of a requirement from its results and impact.
 *
 * When effectiveStatus is already set on the requirement, returns it directly.
 * Otherwise derives status using standard HDF/InSpec precedence:
 *   1. effectiveStatus already set → return it
 *   2. impact === 0 → notApplicable
 *   3. No results → notReviewed
 *   4. Any "error" result → error
 *   5. Any "failed" result → failed
 *   6. All "passed" → passed
 *   7. Otherwise → notReviewed
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

  const results = requirement.results;
  if (!results || results.length === 0) {
    return 'notReviewed';
  }

  let hasError = false;
  let hasFailed = false;
  let hasPassed = false;

  for (const result of results) {
    switch (result.status) {
      case 'error':
        hasError = true;
        break;
      case 'failed':
        hasFailed = true;
        break;
      case 'passed':
        hasPassed = true;
        break;
    }
  }

  if (hasError) return 'error';
  if (hasFailed) return 'failed';
  if (hasPassed) return 'passed';
  return 'notReviewed';
}
