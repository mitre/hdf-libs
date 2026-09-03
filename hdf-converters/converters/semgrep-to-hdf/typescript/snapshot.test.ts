import { runSnapshotTests } from '../../../shared/typescript/snapshot.js';
import { convertSemgrepToHdf } from './converter.js';

// Asserts the SAME fixtures/expected/*.hdf.json goldens the Go snapshot test
// asserts, under the same normalization — the TS<->Go parity guarantee.
//
// startTime is masked for every fixture ('*'): semgrep's JSON output carries no
// scan timestamp anywhere, so there is no input-derived time to assert against
// and the converter necessarily stamps conversion time.
runSnapshotTests('semgrep-to-hdf', convertSemgrepToHdf, ['*']);
