import { runSnapshotTests } from '../../../shared/typescript/snapshot.js';
import { convertJunitToHdf } from './converter.js';

// Asserts the SAME fixtures/expected/*.hdf.json goldens the Go snapshot test
// asserts, under the same normalization — this is the TS<->Go parity guarantee.
runSnapshotTests('junit-to-hdf', convertJunitToHdf);
