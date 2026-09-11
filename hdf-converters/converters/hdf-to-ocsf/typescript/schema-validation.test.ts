import { readdirSync, readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, it, expect } from 'vitest';
import { loadSchemaValidator } from '../../../shared/typescript/schema-validation.js';
import { convertHdfToOcsf } from './converter.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const schemas = join(__dirname, '..', 'schemas');
const inputs = join(__dirname, '..', 'fixtures', 'input');
const VERSION = '0.1.0';

// The vendored OCSF schema for each class this converter emits. See
// ../schemas/provenance.txt for the source and the version note.
const validators: Record<number, ReturnType<typeof loadSchemaValidator>> = {
  2002: loadSchemaValidator(join(schemas, 'ocsf-vulnerability_finding-2002.schema.json')),
  2003: loadSchemaValidator(join(schemas, 'ocsf-compliance_finding-2003.schema.json')),
};

// The EXACT set of schema violations this converter still produces, tracked as
// hdf-libs-5gri.42 and mirrored one-for-one by the Go peer. Pinned rather than
// tolerated: a new violation fails, and so does fixing one, so it cannot drift
// either way.
//
// The key includes params.additionalProperty so an additionalProperties error
// names the offending member, matching gojsonschema. Keying on the message alone
// collapses every extra member into one entry and hides a newly added one.
const KNOWN_VIOLATIONS = [
  '2002|additionalProperties|evidences',
  '2002|additionalProperties|remediation',
  '2002|required|cloud',
  '2002|required|osint',
  '2003|required|cloud',
  '2003|required|osint',
].sort();

function violations(out: string): Set<string> {
  const seen = new Set<string>();
  for (const line of out.trim().split('\n')) {
    if (line === '') continue;
    const doc = JSON.parse(line) as { class_uid?: number };
    const uid = doc.class_uid;
    expect(uid, 'every finding must carry a class_uid').toBeDefined();
    const validate = validators[uid as number];
    expect(validate, `converter emitted class_uid ${String(uid)} with no vendored schema`).toBeDefined();
    if (validate(doc)) continue;
    for (const e of validate.errors ?? []) {
      const p = e.params as { additionalProperty?: string; missingProperty?: string };
      const member = p.additionalProperty ?? p.missingProperty ?? (e.message ?? '');
      seen.add(`${String(uid)}|${e.keyword}|${member}`);
    }
  }
  return seen;
}

describe('hdf-to-ocsf output against the vendored OCSF schemas', () => {
  it('produces exactly the carded violation set, no more and no less', () => {
    const files = readdirSync(inputs);
    expect(files.length, 'no fixtures — the run would prove nothing').toBeGreaterThan(0);

    const all = new Set<string>();
    for (const f of files) {
      let out: string;
      try {
        out = convertHdfToOcsf(readFileSync(join(inputs, f), 'utf-8'), VERSION);
      } catch {
        continue; // rejection is a separate contract
      }
      for (const v of violations(out)) all.add(v);
    }
    expect(
      [...all].sort(),
      'OCSF violation set changed. A NEW entry is a regression; a MISSING one means ' +
        'hdf-libs-5gri.42 was fixed and this pin should be reduced to plain validation.',
    ).toEqual(KNOWN_VIOLATIONS);
  });
});
