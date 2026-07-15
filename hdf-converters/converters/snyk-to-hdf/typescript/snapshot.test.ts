import { runSnapshotTests } from '../../../shared/typescript/snapshot.js';
import { convertSnykToHdf } from './converter.js';

// Asserts the SAME fixtures/expected/*.hdf.json goldens the Go snapshot test
// asserts, under the same normalization — this is the TS<->Go parity guarantee.
// Snyk output carries no scan time.
runSnapshotTests('snyk-to-hdf', convertSnykToHdf, ['*']);
