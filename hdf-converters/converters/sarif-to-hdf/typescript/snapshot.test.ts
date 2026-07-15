import { runSnapshotTests } from '../../../shared/typescript/snapshot.js';
import { convertSarifToHdf } from './converter.js';

// Asserts the SAME fixtures/expected/*.hdf.json goldens the Go snapshot test
// asserts, under the same normalization — this is the TS<->Go parity guarantee.
// SARIF fixtures carry no run start time; conversion-time fallback.
runSnapshotTests('sarif-to-hdf', convertSarifToHdf, ['*']);
