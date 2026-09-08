/**
 * XML-against-XSD validation for converter output tests, for formats whose
 * authoritative schema is an XSD rather than JSON Schema (e.g. XCCDF).
 *
 * The TypeScript peer of shared/go/xsdvalidate. Both wrap libxml2 — Go through
 * cgo, this side through the WASM build — so the two languages gate output on
 * the same engine and report the same violations.
 *
 * It lives here, in the converters' shared test-support tree, rather than in
 * @mitre/hdf-utilities: that package is published and consumed at runtime,
 * while this is a test gate. Adding a WASM libxml2 to it would put a validator
 * no consumer executes into every consumer's dependency tree. The Go peer
 * isolates its cgo dependency in its own package for the same reason.
 */
import { readFileSync } from 'node:fs';
import { basename, dirname, join } from 'node:path';
import { validateXML } from 'xmllint-wasm';
import type { DocumentValidator } from './schema-corpus.js';

/** A file the main XSD reaches through a relative <xsd:import> schemaLocation. */
interface Companion {
  fileName: string;
  contents: string;
}

/**
 * Compile an XSD and return a validator over XML documents.
 *
 * `companions` names the files the schema <xsd:import>s by relative
 * schemaLocation; each is preloaded under exactly that name so the import
 * resolves offline. They are NOT optional in practice — a missing companion
 * makes the schema fail to load rather than silently validating less, which is
 * why loadXsdValidator surfaces that as a thrown error on first use.
 */
export function loadXsdValidator(xsdPath: string, companions: string[] = []): DocumentValidator {
  const dir = dirname(xsdPath);
  const schema = [{ fileName: basename(xsdPath), contents: readFileSync(xsdPath, 'utf-8') }];
  const preload: Companion[] = companions.map((fileName) => ({
    fileName,
    contents: readFileSync(join(dir, fileName), 'utf-8'),
  }));

  return async (doc: unknown): Promise<string | null> => {
    const xml = typeof doc === 'string' ? doc : String(doc);
    const result = await validateXML({
      xml: [{ fileName: 'output.xml', contents: xml }],
      schema,
      preload,
    });
    if (result.valid) return null;
    return (result.errors ?? [])
      .map((e) => `  ${typeof e === 'string' ? e : (e.message ?? JSON.stringify(e))}`)
      .join('\n');
  };
}

/**
 * Assert that an XML document satisfies the XSD, reporting every violation on
 * failure so a red run pinpoints exactly what is wrong.
 */
export async function assertXsdValid(
  validate: DocumentValidator,
  label: string,
  doc: string,
): Promise<void> {
  const errors = await validate(doc);
  if (errors === null) return;
  throw new Error(`${label}: XML does not satisfy the XSD:\n${errors}`);
}
