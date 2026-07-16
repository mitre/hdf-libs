import { runSnapshotTests } from '../../../shared/typescript/snapshot.js';
import { convertOscalToHdf } from './convert.js';

// Asserts the auto-detect entry point reproduces the SAME
// fixtures/expected/<input>.hdf.json goldens the Go snapshot test asserts, under
// the same normalization — the TS↔Go parity guarantee. All golden inputs are
// single-document (profiles, which need a separate catalog, carry no golden).
// Every emitted date is input-derived and deterministic, so nothing is masked
// beyond the always-masked document timestamp.
runSnapshotTests('oscal-to-hdf', convertOscalToHdf);
