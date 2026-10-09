// Lint a generated document with the tracked Spectral ruleset.
//
// Uses the library rather than the CLI: the CLI carries an unpatchable advisory, and the
// library packages carry neither braces nor fast-glob. `setRuleset` is the documented API,
// so nothing here hand-rolls ruleset loading.
//
// Run: node scripts/spectral-lint.mjs dist/hdf-api.oas.json

import { Document, Ruleset, Spectral } from '@stoplight/spectral-core';
import Parsers from '@stoplight/spectral-parsers';
import { readFileSync } from 'fs';
import { dirname, join, resolve } from 'path';
import { fileURLToPath } from 'url';

const HERE = dirname(fileURLToPath(import.meta.url));

export async function lintDocument(path) {
  const rulesetPath = join(HERE, '..', '.spectral.mjs');
  const { default: definition } = await import(rulesetPath);
  const spectral = new Spectral();
  // The source is required because the ruleset carries `overrides`, whose file globs are
  // resolved relative to where the ruleset lives.
  spectral.setRuleset(new Ruleset(definition, { source: rulesetPath }));
  const absolute = resolve(path);
  const document = new Document(readFileSync(absolute, 'utf-8'), Parsers.Json, absolute);
  const results = await spectral.run(document);
  return {
    errors: results.filter((r) => r.severity === 0),
    warnings: results.filter((r) => r.severity === 1),
  };
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const target = process.argv[2] ?? 'dist/hdf-api.oas.json';
  const { errors, warnings } = await lintDocument(target);
  for (const e of errors) {
    process.stderr.write(`  ${e.code} at ${e.path.join('/')}: ${e.message}\n`);
  }
  process.stdout.write(
    `spectral: ${target} — ${errors.length} error(s), ${warnings.length} warning(s)\n`,
  );
  if (errors.length > 0) process.exit(1);
}
