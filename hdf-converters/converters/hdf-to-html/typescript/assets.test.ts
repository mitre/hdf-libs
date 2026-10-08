import { describe, it, expect } from 'vitest';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { BLADES_CSS, REPORT_CSS, SCRIPT, SCRIPT_HASH, STYLESHEET } from './assets.js';
import { renderModule, scriptHash } from '../../../scripts/generate-html-assets.mjs';

const __dirname = dirname(fileURLToPath(import.meta.url));
const assetsDir = join(__dirname, '..', 'go', 'assets');
const moduleFile = join(__dirname, 'assets.ts');

function asset(name: string): string {
  return readFileSync(join(assetsDir, name), 'utf8');
}

describe('the generated assets module', () => {
  const blades = asset('blades.min.css');
  const report = asset('report.css');
  const script = asset('report.js');

  it('carries the asset files verbatim', () => {
    expect(BLADES_CSS).toBe(blades);
    expect(REPORT_CSS).toBe(report);
    expect(SCRIPT).toBe(script);
    expect(STYLESHEET).toBe(`${blades}\n${report}`);
  });

  // The drift gate: an asset edited without regenerating fails here rather than
  // reaching only one of the two languages.
  it('is exactly what the generator writes from those files', () => {
    expect(readFileSync(moduleFile, 'utf8'), 'regenerate with: pnpm --filter @mitre/hdf-converters run generate').toBe(
      renderModule(blades, report, script),
    );
  });

  it('pins the content security policy hash to the script file', () => {
    expect(SCRIPT_HASH).toBe(`sha256-${createHash('sha256').update(`\n${script}`, 'utf8').digest('base64')}`);
    expect(SCRIPT_HASH).toBe(scriptHash(script));
  });

  it('names only system fonts and fetches nothing', () => {
    for (const css of [BLADES_CSS, REPORT_CSS]) {
      expect(css).not.toContain('@import');
      expect(css).not.toContain('image-set(');
      for (const m of css.matchAll(/url\(\s*["']?([^"')]*)/g)) {
        expect(m[1]!.startsWith('data:'), `url(${m[1]}) must be a data URI`).toBe(true);
      }
      expect(css).not.toContain('@font-face');
    }
    expect(REPORT_CSS).toContain('--pico-font-family-sans-serif: system-ui');
  });

  it('pins the original type density and equal-height dashboard panels', () => {
    expect(REPORT_CSS).toContain('--pico-font-size: 100%');
    expect(REPORT_CSS).toMatch(/\.dashboard \{[^}]*align-items: stretch/);
  });
});
