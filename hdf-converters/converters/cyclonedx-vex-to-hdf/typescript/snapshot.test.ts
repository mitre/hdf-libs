import { runSnapshotTests } from '../../../shared/typescript/snapshot.js';
import { convertCyclonedxVexToHdf } from './converter.js';

// Asserts the SAME fixtures/expected/<input>.hdf.json goldens the Go snapshot test
// asserts, under the same normalization — the TS<->Go parity guarantee.
runSnapshotTests('cyclonedx-vex-to-hdf', convertCyclonedxVexToHdf);
