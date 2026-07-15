import { runSnapshotTests } from '../../../shared/typescript/snapshot.js';
import { convertTrufflehogToHdf } from './converter.js';

// Asserts the SAME fixtures/expected/*.hdf.json goldens the Go snapshot test
// asserts, under the same normalization — this is the TS<->Go parity guarantee.
// ndjson-input carries no git commit timestamp -> synthesized startTime; mask only
// it. The JSON fixtures derive startTime from the commit time and are asserted.
runSnapshotTests('trufflehog-to-hdf', convertTrufflehogToHdf, ['ndjson-input.ndjson']);
