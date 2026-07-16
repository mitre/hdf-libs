import { runSnapshotTests } from '../../../shared/typescript/snapshot.js';
import { convertAsffToHdf } from './converter.js';

// Asserts the SAME fixtures/expected/*.hdf.json goldens the Go snapshot test
// asserts, under the same normalization — this is the TS<->Go parity guarantee.
// empty.json has zero findings, so the converter synthesizes a placeholder
// result whose startTime is the conversion time (non-deterministic) — mask it.
// Every real-finding fixture asserts startTime against its input-derived value.
runSnapshotTests('asff-to-hdf', convertAsffToHdf, ['empty.json']);
