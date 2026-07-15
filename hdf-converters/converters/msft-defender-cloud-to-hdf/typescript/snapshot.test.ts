import { runSnapshotTests } from '../../../shared/typescript/snapshot.js';
import { convertMsftDefenderCloudToHdf } from './converter.js';

// Asserts the SAME fixtures/expected/*.hdf.json goldens the Go snapshot test
// asserts, under the same normalization — this is the TS<->Go parity guarantee.
// Defender for Cloud export carries no scan time.
runSnapshotTests('msft-defender-cloud-to-hdf', convertMsftDefenderCloudToHdf, ['*']);
