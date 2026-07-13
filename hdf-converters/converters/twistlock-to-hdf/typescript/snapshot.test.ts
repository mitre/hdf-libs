import { runSnapshotTests } from '../../../shared/typescript/snapshot.js';
import { convertTwistlockToHdf } from './converter.js';

// Asserts the SAME fixtures/expected/*.hdf.json goldens the Go snapshot test
// asserts, under the same normalization — this is the TS<->Go parity guarantee.
runSnapshotTests('twistlock-to-hdf', convertTwistlockToHdf);
