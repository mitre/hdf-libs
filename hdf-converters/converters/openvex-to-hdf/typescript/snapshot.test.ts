import { runSnapshotTests } from '../../../shared/typescript/snapshot.js';
import { convertOpenVexToHdf } from './converter.js';

// Asserts the SAME fixtures/expected/<input>.hdf.json goldens the Go snapshot test
// asserts, under the same normalization — the TS<->Go parity guarantee. openvex
// emits an amendment document whose only volatile field is the doc-level timestamp
// (always masked); no per-result startTime.
runSnapshotTests('openvex-to-hdf', convertOpenVexToHdf);
