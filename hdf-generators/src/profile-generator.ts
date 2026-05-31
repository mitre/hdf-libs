import type { BaselineRequirement, HDFBaseline } from '@mitre/hdf-schema';
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
  baseline: HDFBaseline,
  options?: GeneratorOptions,
): InSpecProfile {
  const inspecYml = generateInSpecYml(baseline, options);
  const controls = new Map<string, string>();

  if (baseline.requirements.length === 0) {
    return { inspecYml, controls };
  }

  if (options?.singleFile) {
    // All controls in a single file
    const stubs = baseline.requirements.map((req: BaselineRequirement) => generateControlStub(req));
    controls.set('controls/controls.rb', stubs.join('\n'));
  } else {
    // One file per control — sanitize ID for safe filenames
    for (const req of baseline.requirements) {
      const safeId = req.id.replace(/\.\./g, '').replace(/[/\\]/g, '') || 'unknown';
      const filename = `controls/${safeId}.rb`;
      controls.set(filename, generateControlStub(req));
    }
  }

  return { inspecYml, controls };
}
