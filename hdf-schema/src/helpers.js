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
  return {
    name,
    requirements,
    attributes: options.attributes || [],
    groups: options.groups || [],
    supports: options.supports || [],
    checksum: options.checksum || createEmptyChecksum(),
    title: options.title,
    version: options.version,
  };
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
 * Map a severity string to an impact score
 * @param {string} severity - Severity level
 * @returns {number} Impact score between 0.0 and 1.0
 */
export function severityToImpact(severity) {
  const normalized = severity.toLowerCase();
  switch (normalized) {
    case 'critical':
      return 1.0;
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
