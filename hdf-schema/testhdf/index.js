/**
 * Test-only builders for minimal, schema-valid HDF Results documents.
 *
 * The TS peer of hdf-schema/testhdf/go — same defaults, same shape. Shipped as
 * the '@mitre/hdf-schema/testhdf' subpath export (a package export must be in
 * the published tarball, so it ships alongside the create* helpers; it is
 * intended for tests but harmless to consumers). Use results(req(...)) for the
 * common single-requirement case; reach for doc/baseline for multiple baselines.
 */

const DEFAULT_START_TIME = '2020-01-01T00:00:00Z';

/**
 * Build an EvaluatedRequirement with defaults: impact 0, empty tags, a single
 * "default" description (data = id), and one notReviewed result.
 *
 * @param {string} id
 * @param {Object} [opts]
 * @param {string} [opts.severity]
 * @param {number} [opts.impact]
 * @param {string} [opts.status] - status of the (default) result
 * @param {Object<string, unknown>} [opts.tags]
 * @param {string} [opts.code]
 * @param {string[]} [opts.cwe]
 * @param {string} [opts.desc] - data for the default description
 * @param {Array<[string, string]>} [opts.addDesc] - extra [label, data] descriptions
 * @param {object[]} [opts.results] - replace results wholesale
 * @returns {import('../dist/ts/hdf.js').EvaluatedRequirement}
 */
export function req(id, opts = {}) {
  const r = {
    id,
    impact: opts.impact ?? 0,
    tags: opts.tags ?? {},
    descriptions: [{ label: 'default', data: opts.desc ?? id }],
    results: opts.results ?? [
      { status: opts.status ?? 'notReviewed', codeDesc: id, startTime: DEFAULT_START_TIME },
    ],
  };
  if (opts.severity !== undefined) r.severity = opts.severity;
  if (opts.code !== undefined) r.code = opts.code;
  if (opts.cwe !== undefined) r.cwe = opts.cwe;
  if (opts.title !== undefined) r.title = opts.title;
  if (opts.codeDesc !== undefined && r.results[0]) r.results[0].codeDesc = opts.codeDesc;
  if (opts.startTime !== undefined && r.results[0]) r.results[0].startTime = opts.startTime;
  for (const [label, data] of opts.addDesc ?? []) {
    r.descriptions.push({ label, data });
  }
  return /** @type {import('../dist/ts/hdf.js').EvaluatedRequirement} */ (r);
}

/**
 * Build an EvaluatedBaseline with the given name and requirements.
 * @param {string} name
 * @param {...import('../dist/ts/hdf.js').EvaluatedRequirement} reqs
 * @returns {import('../dist/ts/hdf.js').EvaluatedBaseline}
 */
export function baseline(name, ...reqs) {
  return /** @type {import('../dist/ts/hdf.js').EvaluatedBaseline} */ ({ name, requirements: reqs });
}

/**
 * Build an HDFResults from the given baselines, filling the required generator.
 * @param {...import('../dist/ts/hdf.js').EvaluatedBaseline} baselines
 * @returns {import('../dist/ts/hdf.js').HDFResults}
 */
export function doc(...baselines) {
  return /** @type {import('../dist/ts/hdf.js').HDFResults} */ ({
    baselines,
    generator: { name: 'testhdf', version: '0.0.0' },
  });
}

/**
 * Common shortcut: wrap the requirements in one "test" baseline.
 * @param {...import('../dist/ts/hdf.js').EvaluatedRequirement} reqs
 * @returns {import('../dist/ts/hdf.js').HDFResults}
 */
export function results(...reqs) {
  return doc(baseline('test', ...reqs));
}

const DEFAULT_EXPIRY = '2099-12-31T00:00:00Z';

// ===== HDF Baseline (requirements without results) =====

/**
 * @param {string} id
 * @param {{impact?:number, tags?:Object<string,unknown>, desc?:string}} [opts]
 * @returns {import('../dist/ts/hdf.js').BaselineRequirement}
 */
export function baselineReq(id, opts = {}) {
  return /** @type {any} */ ({
    id,
    impact: opts.impact ?? 0,
    tags: opts.tags ?? {},
    descriptions: [{ label: 'default', data: opts.desc ?? id }],
  });
}

/**
 * @param {string} name
 * @param {...import('../dist/ts/hdf.js').BaselineRequirement} reqs
 * @returns {import('../dist/ts/hdf.js').HDFBaseline}
 */
export function baselineDoc(name, ...reqs) {
  return /** @type {any} */ ({ name, requirements: reqs });
}

// ===== HDF Amendments =====

/**
 * @param {string} type - override type (waiver, falsePositive, poam, ...)
 * @param {string} reqId
 * @param {{status?:string, reason?:string, appliedBy?:object, milestones?:object[]}} [opts]
 * @returns {import('../dist/ts/hdf.js').StandaloneOverride}
 */
export function override(type, reqId, opts = {}) {
  const o = {
    type,
    requirementId: reqId,
    appliedAt: DEFAULT_START_TIME,
    expiresAt: DEFAULT_EXPIRY,
    appliedBy: opts.appliedBy ?? { type: 'simple', identifier: 'test' },
    reason: opts.reason ?? 'test override',
  };
  if (opts.status !== undefined) o.status = opts.status;
  if (opts.milestones !== undefined) o.milestones = opts.milestones;
  return /** @type {any} */ (o);
}

/**
 * @param {string} name
 * @param {...import('../dist/ts/hdf.js').StandaloneOverride} overrides
 * @returns {import('../dist/ts/hdf.js').HDFAmendments}
 */
export function amendments(name, ...overrides) {
  return /** @type {any} */ ({ name, overrides });
}

// ===== HDF System =====

/**
 * @param {string} name
 * @param {string} type - component type (host, application, cloudResource, ...)
 * @param {object} [opts] - extra component fields (componentId, osName, ...)
 * @returns {import('../dist/ts/hdf.js').Component}
 */
export function component(name, type, opts = {}) {
  return /** @type {any} */ ({ name, type, ...opts });
}

/**
 * @param {string} name
 * @param {...import('../dist/ts/hdf.js').Component} components
 * @returns {import('../dist/ts/hdf.js').HDFSystem}
 */
export function system(name, ...components) {
  return /** @type {any} */ ({ name, components });
}

// ===== HDF Plan =====

/** @param {string} baselineRef @returns {import('../dist/ts/hdf.js').Assessment} */
export function assessment(baselineRef) {
  return /** @type {any} */ ({ baselineRef });
}

/**
 * @param {string} name
 * @param {...import('../dist/ts/hdf.js').Assessment} assessments
 * @returns {import('../dist/ts/hdf.js').HDFPlan}
 */
export function plan(name, ...assessments) {
  return /** @type {any} */ ({ name, assessments });
}

// ===== HDF Evidence Package =====

/** @param {string} uri @param {string} type @returns {import('../dist/ts/hdf.js').ContentReference} */
export function content(uri, type) {
  return /** @type {any} */ ({ uri, type });
}

/**
 * @param {string} name
 * @param {...import('../dist/ts/hdf.js').ContentReference} contents
 * @returns {import('../dist/ts/hdf.js').HDFEvidencePackage}
 */
export function evidencePackage(name, ...contents) {
  return /** @type {any} */ ({ name, contents });
}

// ===== HDF Requirement Change Event =====

/**
 * @param {string} reqId
 * @param {{state?:string, before?:unknown, after?:unknown, priorChecksum?:unknown}} [opts]
 * @returns {import('../dist/ts/hdf.js').HDFRequirementChangeEvent}
 */
export function changeEvent(reqId, opts = {}) {
  return /** @type {any} */ ({
    requirementId: reqId,
    eventId: '00000000-0000-4000-8000-000000000001',
    componentId: '00000000-0000-4000-8000-000000000002',
    systemRef: 'test-system',
    source: 'test',
    sequence: 1,
    timestamp: DEFAULT_START_TIME,
    state: opts.state ?? 'new',
    before: opts.before ?? null,
    after: opts.after ?? req(reqId),
    priorChecksum: opts.priorChecksum ?? null,
  });
}

// ===== HDF Comparison =====

/** @param {string} mode @returns {import('../dist/ts/hdf.js').HDFComparison} */
export function comparison(mode) {
  return /** @type {any} */ ({
    comparisonMode: mode,
    formatVersion: '1.0.0',
    sources: [{ label: 'old', role: 'old' }, { label: 'new', role: 'new' }],
    requirementDiffs: [],
    summary: { total: 0, matchedCount: 0, unmatchedNewCount: 0, unmatchedOldCount: 0 },
  });
}
