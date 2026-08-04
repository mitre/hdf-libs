// @mitre/hdf-engine — shared, schema-typed read-side engines for HDF documents
// (detect, query, compliance, and future read-side engines). Consumed as a
// library by the CLI and the MCP; sibling to @mitre/hdf-diff. See ADR-0007.

/** Library version, kept on the workspace lockstep. */
export const engineVersion = '3.5.0';

// Detection engine (peer of hdf-engine/go/detect.go).
export { detect, type HdfDocType } from './detect.js';
