import type { HdfBaseline } from '@mitre/hdf-schema';
import type { GeneratorOptions } from './types.js';

/**
 * Generate an inspec.yml YAML string from an HDF Baseline and options.
 *
 * Uses string interpolation — no YAML library needed since the structure
 * is fixed and shallow.
 */
export function generateInSpecYml(
  baseline: HdfBaseline,
  options?: GeneratorOptions,
): string {
  const lines: string[] = [];
  const meta = options?.metadata;

  // Required: name
  lines.push(`name: ${baseline.name}`);

  // Optional metadata fields
  if (baseline.title) {
    lines.push(`title: ${baseline.title}`);
  }

  const maintainer = meta?.maintainer ?? baseline.maintainer;
  if (maintainer) {
    lines.push(`maintainer: ${maintainer}`);
  }

  const copyright = meta?.copyright ?? baseline.copyright;
  if (copyright) {
    lines.push(`copyright: ${copyright}`);
  }

  const license = meta?.license ?? baseline.license;
  if (license) {
    lines.push(`license: ${license}`);
  }

  if (baseline.summary) {
    lines.push(`summary: ${baseline.summary}`);
  }

  // Version: metadata override takes priority
  const version = meta?.version ?? baseline.version;
  if (version) {
    lines.push(`version: '${version}'`);
  }

  // InSpec version constraint
  const inspecVersion = options?.inspecVersion ?? '~>6.0';
  lines.push(`inspec_version: '${inspecVersion}'`);

  // Supports array
  if (baseline.supports && baseline.supports.length > 0) {
    lines.push('supports:');
    for (const support of baseline.supports) {
      const entries: string[] = [];
      if (support.platformName) {
        entries.push(`  platform-name: ${support.platformName}`);
      }
      if (support.platformFamily) {
        entries.push(`  platform-family: ${support.platformFamily}`);
      }
      if (support.platform) {
        entries.push(`  platform: ${support.platform}`);
      }
      if (support.release) {
        entries.push(`  release: ${support.release}`);
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
      if (dep.name) entries.push(`name: ${dep.name}`);
      if (dep.git) entries.push(`git: ${dep.git}`);
      if (dep.url) entries.push(`url: ${dep.url}`);
      if (dep.path) entries.push(`path: ${dep.path}`);
      if (dep.branch) entries.push(`branch: ${dep.branch}`);
      if (dep.compliance) entries.push(`compliance: ${dep.compliance}`);
      if (dep.supermarket) entries.push(`supermarket: ${dep.supermarket}`);
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

/** Format a value for inline YAML output. */
function formatYamlValue(value: unknown): string {
  if (typeof value === 'boolean') return String(value);
  if (typeof value === 'number') return String(value);
  if (typeof value === 'string') return value;
  return JSON.stringify(value);
}
