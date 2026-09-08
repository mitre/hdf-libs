import { canonicalJson, sha256 } from '@mitre/hdf-utilities';
import { HashAlgorithm } from '@mitre/hdf-schema';
import type { StandaloneOverride } from '@mitre/hdf-schema';
import { serializeHdf } from './converterutil.js';

/**
 * Stamps `previousChecksum` across amendment overrides in document order,
 * linking each to the one before it and leaving the first unlinked.
 *
 * Every route that authors amendments calls this, so whether a document carries
 * tamper-evidence does not depend on which one wrote it. The checksum is the
 * canonical JSON form shared with the Go converters and with `hdf amend verify`,
 * so a chain written here verifies everywhere.
 *
 * The override is put through serializeHdf first, so what gets hashed is the
 * shape the document will actually carry. The TS converters hold
 * `appliedAt`/`expiresAt` as `Date` objects, which stringify with a `.000`
 * fraction that trimmed-UTC HDF output never carries; hashing them raw would
 * make every TS-written chain disagree with its own serialized document, and
 * with Go.
 *
 * Mutates the array in place, mirroring the Go helper.
 */
export async function chainOverrides(overrides: StandaloneOverride[]): Promise<void> {
  let previous: { algorithm: HashAlgorithm; value: string } | undefined;
  for (const override of overrides) {
    if (previous === undefined) {
      delete override.previousChecksum;
    } else {
      override.previousChecksum = previous;
    }
    previous = {
      algorithm: HashAlgorithm.Sha256,
      value: await sha256(canonicalJson(JSON.parse(serializeHdf(override, 0)))),
    };
  }
}
