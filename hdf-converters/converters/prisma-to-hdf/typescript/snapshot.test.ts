import { runSnapshotTests } from '../../../shared/typescript/snapshot.js';
import { convertPrismaToHdf } from './converter.js';

// Asserts the SAME fixtures/expected/*.hdf.json goldens the Go snapshot test
// asserts, under the same normalization — this is the TS<->Go parity guarantee.
// Prisma Cloud export carries no scan time.
runSnapshotTests('prisma-to-hdf', convertPrismaToHdf, ['*']);
