import { runSnapshotTests } from '../../../shared/typescript/snapshot.js';
import { convertHipcheckToHdf } from './converter.js';

// Asserts the SAME fixtures/expected/*.hdf.json goldens the Go snapshot test
// asserts, under the same normalization — the TS<->Go parity guarantee. Every
// fixture derives result startTime from the report's analyzed_at (and the
// empty-fixture placeholder reuses it too), so no startTime masking is needed;
// only the volatile top-level `timestamp` is masked by the harness.
runSnapshotTests('hipcheck-to-hdf', convertHipcheckToHdf);
