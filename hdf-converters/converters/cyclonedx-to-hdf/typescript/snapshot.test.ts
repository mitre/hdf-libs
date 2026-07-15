import { runSnapshotTests } from '../../../shared/typescript/snapshot.js';
import { convertCyclonedxToHdf } from './converter.js';

// Asserts the SAME fixtures/expected/*.hdf.json goldens the Go snapshot test
// asserts, under the same normalization — this is the TS<->Go parity guarantee.
// vex.json carries no metadata.timestamp -> synthesized startTime; mask only it.
// The SBOM fixtures derive startTime from metadata.timestamp and are asserted.
runSnapshotTests('cyclonedx-to-hdf', convertCyclonedxToHdf, ['vex.json']);
