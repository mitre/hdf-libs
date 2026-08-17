/**
 * Test-only builders for minimal, schema-valid HDF Results documents.
 *
 * The TS peer of hdf-schema/testhdf/go — same defaults, same shape. Lives
 * outside dist/ so it is never published (package.json files: ["dist"]);
 * imported in-workspace via '@mitre/hdf-schema/testhdf'. Use results(req(...))
 * for the common single-requirement case; reach for doc/baseline for multiple
 * baselines.
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
