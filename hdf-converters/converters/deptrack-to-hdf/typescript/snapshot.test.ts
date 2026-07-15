import { runSnapshotTests } from '../../../shared/typescript/snapshot.js';
import { convertDeptrackToHdf } from './converter.js';

// Asserts the SAME fixtures/expected/*.hdf.json goldens the Go snapshot test
// asserts, under the same normalization — this is the TS<->Go parity guarantee.
// fpf-no-vulnerabilities has zero findings -> synthesized no-findings placeholder
// startTime; mask only it. The findings fixtures derive startTime and are asserted.
runSnapshotTests('deptrack-to-hdf', convertDeptrackToHdf, ['fpf-no-vulnerabilities.json']);
