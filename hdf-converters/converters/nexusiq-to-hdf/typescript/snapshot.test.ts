import { runSnapshotTests } from '../../../shared/typescript/snapshot.js';
import { convertNexusIQToHdf } from './converter.js';

// Asserts the SAME fixtures/expected/*.hdf.json goldens the Go snapshot test
// asserts, under the same normalization — the TS<->Go parity guarantee.
//
// startTime is masked for every fixture ('*'): the result file carries no
// evaluation time, so there is no input-derived time to assert against.
runSnapshotTests('nexusiq-to-hdf', convertNexusIQToHdf, ['*']);
