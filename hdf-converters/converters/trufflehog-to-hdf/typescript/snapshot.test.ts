import { runSnapshotTests } from '../../../shared/typescript/snapshot.js';
import { convertTrufflehogToHdf } from './converter.js';

// Asserts the SAME fixtures/expected/*.hdf.json goldens the Go snapshot test
// asserts, under the same normalization — this is the TS<->Go parity guarantee.
// ndjson-input carries no git commit timestamp -> synthesized startTime; mask only
// it. empty-stdout.json is a clean-scan (zero-findings) input whose placeholder
// requirement carries a synthesized startTime; mask it too. The other JSON
// fixtures derive startTime from the commit time and are asserted.
runSnapshotTests('trufflehog-to-hdf', convertTrufflehogToHdf, ['ndjson-input.ndjson', 'empty-stdout.json']);
