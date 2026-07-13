import { runSnapshotTests } from '../../../shared/typescript/snapshot.js';
import { convertGrypeToHdf } from './converter.js';

// Asserts the SAME fixtures/expected/*.hdf.json goldens the Go snapshot test
// asserts, under the same normalization — this is the TS<->Go parity guarantee.
runSnapshotTests('grype-to-hdf', convertGrypeToHdf);
