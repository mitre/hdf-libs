// Build-time only, so deliberately NOT exported: buildComponentsDocument, loadBundles and
// EMBED_DIR read the HDF schema bundles, which belong to @mitre/hdf-schema and are not in
// this package — no `files` entry can make them work for a consumer, and before this they
// threw. The built documents are the published surface; import them from the subpaths.
export { EXPECTED_DEFINITIONS, MAIN_SCHEMAS, ROOT_COMPONENT_NAMES } from './components.js';
export type { ComponentsDocument, JsonSchema } from './components.js';
export { extractStandaloneSchema } from './extract.js';
// The problem-type table: ADR-0010 §6's one code-to-status mapping, the prose each type
// dereferences to, and the codes §6 marks as never reaching HTTP.
export {
  PROBLEM_BASE,
  UNMAPPED_CODES,
  loadProblemDocs,
  problemTypes,
} from './problems.js';
export type { ProblemDoc, ProblemOwner } from './problems.js';
export { validateExample } from './validate-example.js';
export type { ExampleFault } from './validate-example.js';
