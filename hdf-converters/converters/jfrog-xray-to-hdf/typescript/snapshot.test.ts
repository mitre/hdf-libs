import { runSnapshotTests } from '../../../shared/typescript/snapshot.js';
import { convertJfrogXrayToHdf } from './converter.js';

// Asserts the SAME fixtures/expected/*.hdf.json goldens the Go snapshot test
// asserts, under the same normalization — this is the TS<->Go parity guarantee.
runSnapshotTests('jfrog-xray-to-hdf', convertJfrogXrayToHdf);
