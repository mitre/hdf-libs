import { inspec } from '@mitre/hdf-fixtures';
import { runSnapshotTests } from '../../../shared/typescript/snapshot.js';
import { convertLegacyHdf, type LegacyHDFResults } from './converter.js';

// Asserts the SAME fixtures/expected/<input>.hdf.json goldens the Go snapshot
// test asserts, under the same normalization — the TS<->Go parity guarantee
// that legacyhdf previously lacked (Go ran structural checks, TS asserted its
// own goldens, so the two drifted). startTime is input-derived and
// deterministic, so nothing is masked beyond the always-masked timestamp.
//
// Four goldens' source fixtures live in @mitre/hdf-fixtures; the resolver
// supplies them by name. minimal.json is local and falls through to
// fixtures/input/.
const SHARED_INPUTS: Record<string, () => string> = {
  'ubi9-scan.json': () => inspec.ubi9Scan.read(),
  'container-scan.json': () => inspec.containerScan.read(),
  'three-layer-overlay.json': () => inspec.threeLayerOverlay.read(),
  'wrapper.json': () => inspec.wrapper.read(),
};

runSnapshotTests(
  'legacyhdf-to-hdf',
  (input: string) => convertLegacyHdf(JSON.parse(input) as LegacyHDFResults),
  [],
  (inputName) => SHARED_INPUTS[inputName]?.(),
);
