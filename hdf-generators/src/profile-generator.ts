import type { HdfBaseline } from '@mitre/hdf-schema';
import type { GeneratorOptions, InSpecProfile } from './types.js';
import { generateControlStub } from './control-stub.js';
import { generateInSpecYml } from './inspec-yml.js';

/**
 * Generate an in-memory InSpec profile from an HDF Baseline.
 *
 * Returns an InSpecProfile with inspec.yml content and a Map of
 * control filenames to Ruby source code. No file I/O — the CLI
 * is responsible for writing files to disk.
 */
export function generateInSpecProfile(
  baseline: HdfBaseline,
  options?: GeneratorOptions,
): InSpecProfile {
  const inspecYml = generateInSpecYml(baseline, options);
  const controls = new Map<string, string>();

  if (baseline.requirements.length === 0) {
    return { inspecYml, controls };
  }

  if (options?.singleFile) {
    // All controls in a single file
    const stubs = baseline.requirements.map((req) => generateControlStub(req));
    controls.set('controls/controls.rb', stubs.join('\n'));
  } else {
    // One file per control
    for (const req of baseline.requirements) {
      const filename = `controls/${req.id}.rb`;
      controls.set(filename, generateControlStub(req));
    }
  }

  return { inspecYml, controls };
}
