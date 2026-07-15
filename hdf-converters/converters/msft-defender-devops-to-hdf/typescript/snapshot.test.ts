import { runSnapshotTests } from '../../../shared/typescript/snapshot.js';
import { convertMsftDefenderDevopsToHdf } from './converter.js';

// Asserts the SAME fixtures/expected/*.hdf.json goldens the Go snapshot test
// asserts, under the same normalization — this is the TS<->Go parity guarantee.
// delegates to the SARIF path, which carries no scan time.
runSnapshotTests('msft-defender-devops-to-hdf', convertMsftDefenderDevopsToHdf, ['*']);
