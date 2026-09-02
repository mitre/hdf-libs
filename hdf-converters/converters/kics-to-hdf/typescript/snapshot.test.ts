import { runSnapshotTests } from '../../../shared/typescript/snapshot.js';
import { convertKicsToHdf } from './converter.js';

// Asserts the SAME fixtures/expected/*.hdf.json goldens the Go snapshot test
// asserts, under the same normalization — the TS<->Go parity guarantee.
//
// startTime is masked for every fixture ('*'): KICS emits no scan timestamp
// anywhere in its output, so there is no input-derived time to assert against.
runSnapshotTests('kics-to-hdf', convertKicsToHdf, ['*']);
