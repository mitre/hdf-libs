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
 * @param {string|null|undefined} title - Human-readable title. Pass null/undefined
 *   to omit it (some controls legitimately have no title).
 * @param {import('../dist/ts/hdf-results.js').Description[]} descriptions - Array of descriptions
 * @param {number} impact - Impact score (0.0 to 1.0)
 * @param {import('../dist/ts/hdf-results.js').RequirementResult[]} results - Array of test results
 * @param {Object} [options] - Optional fields: sourceLocation, code, tags;
 *   amendment fields (effectiveStatus, effectiveImpact, disposition, statusOverrides, poams);
 *   vulnerability fields (cwe, cvss, refs, affectedPackages, epss, kev).
 * @returns {import('../dist/ts/hdf-results.js').EvaluatedRequirement}
 */
export function createRequirement(id, title, descriptions, impact, results, options = {}) {
  const req = {
    id,
    descriptions,
    impact,
    results,
    tags: options.tags || {},
  };

  if (title != null) req.title = title;
  if (options.sourceLocation) req.sourceLocation = options.sourceLocation;
  if (options.code != null) req.code = options.code;

  // Amendment fields
  if (options.effectiveStatus) req.effectiveStatus = options.effectiveStatus;
  if (options.effectiveImpact != null) req.effectiveImpact = options.effectiveImpact;
  if (options.disposition) req.disposition = options.disposition;
  if (options.statusOverrides) req.statusOverrides = options.statusOverrides;
  if (options.poams) req.poams = options.poams;

  // Vulnerability fields
  if (options.cwe) req.cwe = options.cwe;
  if (options.cvss) req.cvss = options.cvss;
  if (options.refs) req.refs = options.refs;
  if (options.affectedPackages) req.affectedPackages = options.affectedPackages;
  if (options.epss) req.epss = options.epss;
  if (options.kev) req.kev = options.kev;

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
    ...(options.resource ? { resource: options.resource } : {}),
    ...(options.resourceId ? { resourceId: options.resourceId } : {}),
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
 * Create a minimal valid inline Status_Override (requirement.statusOverrides[]).
 * The schema requires one of status/impact; when neither is supplied this
 * defaults status to 'notApplicable' so the built override stays valid.
 * @param {string} type - Override_Type (waiver, attestation, falsePositive, riskAdjustment, ...)
 * @param {Object} [options] - reason, appliedBy, appliedAt, expiresAt, status, impact
 * @returns {Object}
 */
export function createStatusOverride(type, options = {}) {
  const override = {
    type,
    reason: options.reason || 'Test override',
    appliedBy: options.appliedBy || { type: 'simple', identifier: 'test' },
    appliedAt: options.appliedAt || '2025-01-01T00:00:00Z',
    expiresAt: options.expiresAt || '2099-12-31T00:00:00Z',
  };
  if (options.status) override.status = options.status;
  if (options.impact) override.impact = options.impact;
  if (!override.status && !override.impact) override.status = 'notApplicable';
  return override;
}

/**
 * Create a minimal valid POA&M (requirement.poams[]). expiresAt is schema-
 * required (a POA&M is time-boxed) and defaults to a far-future constant.
 * @param {string} type - remediation | mitigation | riskAcceptance | vendorDependency
 * @param {Object} [options] - explanation, appliedBy, appliedAt, expiresAt, milestones
 * @returns {Object}
 */
export function createPoam(type, options = {}) {
  const poam = {
    type,
    explanation: options.explanation || 'Remediation planned',
    appliedBy: options.appliedBy || { type: 'simple', identifier: 'test' },
    appliedAt: options.appliedAt || '2025-01-01T00:00:00Z',
    expiresAt: options.expiresAt || '2099-12-31T00:00:00Z',
  };
  if (options.milestones) poam.milestones = options.milestones;
  return poam;
}

/**
 * Create a Cvss primitive. Only `version` is schema-required; every other CVSS
 * field is passed through from options when present.
 * @param {string} version - CVSS version (e.g. '3.1', '4.0')
 * @param {Object} [options] - source, baseVector, baseScore, baseSeverity, threatVector,
 *   threatScore, environmentalVector, environmentalScore, supplementalVector, computedScore, computedSeverity
 * @returns {Object}
 */
export function createCvss(version, options = {}) {
  const cvss = { version };
  const fields = [
    'source', 'baseVector', 'baseScore', 'baseSeverity',
    'threatVector', 'threatScore', 'environmentalVector', 'environmentalScore',
    'supplementalVector', 'computedScore', 'computedSeverity',
  ];
  for (const f of fields) {
    if (options[f] != null) cvss[f] = options[f];
  }
  return cvss;
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
