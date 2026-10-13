export {
  EXPECTED_DEFINITIONS,
  MAIN_SCHEMAS,
  ROOT_COMPONENT_NAMES,
  buildComponentsDocument,
} from './components.js';
export type { BuildOptions, ComponentsDocument, JsonSchema } from './components.js';
export { EMBED_DIR, loadBundles } from './embed.js';
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
