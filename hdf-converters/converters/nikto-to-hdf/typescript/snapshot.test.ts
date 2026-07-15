import { runSnapshotTests } from '../../../shared/typescript/snapshot.js';
import { convertNiktoToHdf } from './converter.js';

// Asserts the SAME fixtures/expected/*.hdf.json goldens the Go snapshot test
// asserts, under the same normalization — this is the TS<->Go parity guarantee.
// Nikto JSON carries no scan time (zero-time).
runSnapshotTests('nikto-to-hdf', convertNiktoToHdf, ['*']);
