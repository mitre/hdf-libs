import { runSnapshotTests } from '../../../shared/typescript/snapshot.js';
import { convertCheckovToHdf } from './converter.js';

// Asserts the SAME fixtures/expected/*.hdf.json goldens the Go snapshot test
// asserts, under the same normalization — this is the TS<->Go parity guarantee.
// Checkov JSON carries no per-finding scan time; startTime is the conversion-time fallback.
runSnapshotTests('checkov-to-hdf', convertCheckovToHdf, ['*']);
