import { runSnapshotTests } from '../../../shared/typescript/snapshot.js';
import { convertXccdfToHdf } from './converter.js';

// Asserts the SAME fixtures/expected/*.hdf.json goldens the Go snapshot test
// asserts, under the same normalization — this is the TS<->Go parity guarantee.
// The Go side snapshots ConvertXccdfToHDF's raw bytes; mirror that entry point
// (auto-detect benchmark-vs-results) and hand the harness the JSON payload.
runSnapshotTests('xccdf-results-to-hdf', async (input) => (await convertXccdfToHdf(input)).json);
