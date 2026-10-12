import { runSnapshotTests } from '../../../shared/typescript/snapshot.js';
import { convertSarifToHdf } from './converter.js';

// Asserts the SAME fixtures/expected/*.hdf.json goldens the Go snapshot test
// asserts, under the same normalization — this is the TS<->Go parity guarantee.
// SARIF fixtures carry no run start time; conversion-time fallback. Suppression
// overrides likewise carry no owner/date, so appliedAt/expiresAt are conversion-
// time — masked alongside startTime.
// WHAT THIS GUARANTEE DOES NOT COVER. A golden-based parity test can only discriminate
// shapes the corpus actually contains, so it is silent on every conformant construct no
// fixture carries. Four Go/TypeScript divergences were found by reading the two
// implementations against the spec, not by this test, and it stayed green through all of
// them: an empty runs array, a SARIF 2.0 resources.rules block, an artifactLocation with
// no uri, and a host-zone timestamp. Two of them now have fixtures; the 2.0 shape
// cannot have one, because the only vendored schema admits 2.1.0 alone, so it is
// covered by inline documents in both languages instead. The conformance
// surface is much larger than the corpus (SARIF defines 30 result properties alone), so a
// divergence in an uncovered construct will not be caught here. Add a fixture when a
// conformant shape matters, rather than trusting this to find it.
runSnapshotTests('sarif-to-hdf', convertSarifToHdf, ['*'], undefined, ['appliedAt', 'expiresAt']);
