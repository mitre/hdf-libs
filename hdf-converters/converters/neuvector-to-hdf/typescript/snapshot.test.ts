import { runSnapshotTests } from '../../../shared/typescript/snapshot.js';
import { convertNeuvectorToHdf } from './converter.js';

// Asserts the SAME fixtures/expected/*.hdf.json goldens the Go snapshot test
// asserts, under the same normalization — this is the TS<->Go parity guarantee.
// NeuVector scan JSON carries no scan time.
runSnapshotTests('neuvector-to-hdf', convertNeuvectorToHdf, ['*']);
