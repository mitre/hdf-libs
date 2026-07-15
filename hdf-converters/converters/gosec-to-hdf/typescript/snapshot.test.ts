import { runSnapshotTests } from '../../../shared/typescript/snapshot.js';
import { convertGosecToHdf } from './converter.js';

// Asserts the SAME fixtures/expected/*.hdf.json goldens the Go snapshot test
// asserts, under the same normalization — this is the TS<->Go parity guarantee.
// gosec output carries no per-finding timestamp.
runSnapshotTests('gosec-to-hdf', convertGosecToHdf, ['*']);
