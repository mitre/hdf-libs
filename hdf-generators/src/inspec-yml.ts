import type { HDFBaseline } from '@mitre/hdf-schema';
import type { GeneratorOptions } from './types.js';

/**
 * Generate an inspec.yml YAML string from an HDF Baseline and options.
 *
 * Uses string interpolation — no YAML library needed since the structure
 * is fixed and shallow.
 */
export function generateInSpecYml(
  baseline: HDFBaseline,
  options?: GeneratorOptions,
): string {
  const lines: string[] = [];
  const meta = options?.metadata;

  // Required: name
  lines.push(`name: ${yamlScalar(baseline.name)}`);

  // Optional metadata fields
  if (baseline.title) {
    lines.push(`title: ${yamlScalar(baseline.title)}`);
  }

  const maintainer = meta?.maintainer ?? baseline.maintainer;
  if (maintainer) {
    lines.push(`maintainer: ${yamlScalar(maintainer)}`);
  }

  const copyright = meta?.copyright ?? baseline.copyright;
  if (copyright) {
    lines.push(`copyright: ${yamlScalar(copyright)}`);
  }

  const license = meta?.license ?? baseline.license;
  if (license) {
    lines.push(`license: ${yamlScalar(license)}`);
  }

  if (baseline.summary) {
    lines.push(`summary: ${yamlScalar(baseline.summary)}`);
  }

  // Version: metadata override takes priority; otherwise <version>.<release>.0,
  // the profileVersion shape SAF CLI writes, so profiles from both tools agree.
  const release = benchmarkRelease(baseline);
  const versionWithRelease =
    baseline.version && release ? `${baseline.version}.${release}.0` : baseline.version;
  const version = meta?.version ?? versionWithRelease;
  if (version) {
    lines.push(`version: '${version}'`);
  }

  // InSpec version constraint
  const inspecVersion = options?.inspecVersion ?? '>= 7.0';
  lines.push(`inspec_version: '${inspecVersion}'`);

  // Supports array
  if (baseline.supports && baseline.supports.length > 0) {
    lines.push('supports:');
    for (const support of baseline.supports) {
      const entries: string[] = [];
      if (support.platformName) {
        entries.push(`  platform-name: ${yamlScalar(support.platformName)}`);
      }
      if (support.platformFamily) {
        entries.push(`  platform-family: ${yamlScalar(support.platformFamily)}`);
      }
      if (support.platform) {
        entries.push(`  platform: ${yamlScalar(support.platform)}`);
      }
      if (support.release) {
        entries.push(`  release: ${yamlScalar(support.release)}`);
      }
      if (entries.length > 0) {
        lines.push(`- ${entries[0]!.trimStart()}`);
        for (let i = 1; i < entries.length; i++) {
          lines.push(entries[i]!);
        }
      }
    }
  }

  // Depends array
  if (baseline.depends && baseline.depends.length > 0) {
    lines.push('depends:');
    for (const dep of baseline.depends) {
      const entries: string[] = [];
      if (dep.name) entries.push(`name: ${yamlScalar(dep.name)}`);
      if (dep.git) entries.push(`git: ${yamlScalar(dep.git)}`);
      if (dep.url) entries.push(`url: ${yamlScalar(dep.url)}`);
      if (dep.path) entries.push(`path: ${yamlScalar(dep.path)}`);
      if (dep.branch) entries.push(`branch: ${yamlScalar(dep.branch)}`);
      if (dep.compliance) entries.push(`compliance: ${yamlScalar(dep.compliance)}`);
      if (dep.supermarket) entries.push(`supermarket: ${yamlScalar(dep.supermarket)}`);
      if (entries.length > 0) {
        lines.push(`- ${entries[0]}`);
        for (let i = 1; i < entries.length; i++) {
          lines.push(`  ${entries[i]}`);
        }
      }
    }
  }

  // Inputs array
  if (baseline.inputs && baseline.inputs.length > 0) {
    lines.push('inputs:');
    for (const input of baseline.inputs) {
      for (const [key, value] of Object.entries(input)) {
        lines.push(`- ${key}: ${formatYamlValue(value)}`);
      }
    }
  }

  lines.push(''); // trailing newline
  return lines.join('\n');
}

/**
 * extensions.passthrough.benchmarkRelease when it is an unsigned integer, else '': DISA
 * releases are integers, and anything else joined into <version>.<release>.0 fails
 * InSpec's semver check.
 */
function benchmarkRelease(baseline: HDFBaseline): string {
  const release = baseline.extensions?.passthrough?.['benchmarkRelease'];
  return typeof release === 'string' && /^\d+$/.test(release) ? release : '';
}

/**
 * Quote a scalar YAML would otherwise misread (": " in DISA prose); the trigger set
 * matches Go's yamlScalar so both generators emit identical bytes.
 */
function yamlScalar(s: string): string {
  if (/[:#{}&*!|>'"`@,\[\]]/.test(s) || s.startsWith('- ')) {
    return `'${s.replace(/'/g, "''")}'`;
  }
  return s;
}

/** Format a value for inline YAML output. */
function formatYamlValue(value: unknown): string {
  if (typeof value === 'boolean') return String(value);
  if (typeof value === 'number') return String(value);
  if (typeof value === 'string') return value;
  return JSON.stringify(value);
}
