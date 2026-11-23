import type { BaselineRequirement, HDFBaseline } from '@mitre/hdf-schema';
import type { GeneratorOptions, InSpecProfile } from './types.js';
import { generateControlStub } from './control-stub.js';
import { generateInSpecYml } from './inspec-yml.js';
import { controlFilename, keyRequirements } from './id-type.js';

/**
 * Generate an in-memory InSpec profile from an HDF Baseline.
 *
 * Returns an InSpecProfile with inspec.yml content and a Map of
 * control filenames to Ruby source code. No file I/O — the CLI
 * is responsible for writing files to disk. Throws when a requirement lacks
 * the identifier `options.idType` selects, or when two requirements would
 * share a control id or a control file.
 */
export function generateInSpecProfile(
  baseline: HDFBaseline,
  options?: GeneratorOptions,
): InSpecProfile {
  const inspecYml = generateInSpecYml(baseline, options);
  const controls = new Map<string, string>();
  const reqs = keyRequirements(baseline.requirements, options?.idType, !options?.singleFile);

  if (reqs.length === 0) {
    return { inspecYml, controls };
  }

  if (options?.singleFile) {
    controls.set('controls/controls.rb', reqs.map((req: BaselineRequirement) => generateControlStub(req)).join('\n'));
  } else {
    for (const req of reqs) {
      controls.set(controlFilename(req.id), generateControlStub(req));
    }
  }

  return { inspecYml, controls };
}
