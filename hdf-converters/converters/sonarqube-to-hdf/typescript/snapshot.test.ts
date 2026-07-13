import { runSnapshotTests } from '../../../shared/typescript/snapshot.js';
import { convertSonarqubeToHdf } from './converter.js';

// Asserts the SAME fixtures/expected/*.hdf.json goldens the Go snapshot test
// asserts, under the same normalization — this is the TS<->Go parity guarantee.
runSnapshotTests('sonarqube-to-hdf', convertSonarqubeToHdf);
