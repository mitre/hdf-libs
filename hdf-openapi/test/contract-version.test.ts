import { describe, expect, it } from 'vitest';
import { readFileSync } from 'fs';
import { join } from 'path';
import { API_VERSION, contractDigest, generateApiDocument } from '../src/generate-api.js';

const BASELINE = join(new URL('.', import.meta.url).pathname, 'baseline', 'contract.json');
const recorded = JSON.parse(readFileSync(BASELINE, 'utf-8')) as { version: string; digest: string };
const doc = generateApiDocument();

/**
 * ADR-0008 §4 says what moves this document's version and §6 gives it a semver of its own.
 * Neither was implemented: `info.version` was a literal, so the published build and this
 * one both reported 1.0.0 with materially different contracts — fifteen of eighteen
 * operationIds renamed between them — and a consumer had nothing in the document to tell
 * them apart. The archive is keyed on that version too, so the second overwrote the first.
 *
 * A digest cannot say whether a change is BREAKING, which is the question semver answers.
 * So it detects, and the version stays a reviewed value this refuses to let drift.
 */
describe("the contract's identity moves when the contract does", () => {
  it('the document carries the digest of itself', () => {
    expect((doc.info as Record<string, string>)['x-hdf-contract-digest']).toBe(contractDigest(doc));
  });

  it('the recorded baseline is for the version the generator emits', () => {
    expect(recorded.version).toBe(API_VERSION);
    expect(doc.info.version).toBe(API_VERSION);
  });

  it('a changed contract has a changed version', () => {
    expect(
      contractDigest(doc),
      `The contract changed under version ${API_VERSION}. Bump API_VERSION in ` +
        'src/generate-api.ts — §4 says which digit — then run `pnpm run contract:update`.',
    ).toBe(recorded.digest);
  });

  it('the digest ignores key order, so a reordering is not a contract change', () => {
    const reordered = JSON.parse(JSON.stringify(doc)) as typeof doc;
    reordered.components = Object.fromEntries(
      Object.entries(reordered.components).reverse(),
    ) as typeof reordered.components;
    expect(contractDigest(reordered)).toBe(contractDigest(doc));
  });

  it('the digest moves for a change anywhere outside info', () => {
    const altered = JSON.parse(JSON.stringify(doc)) as typeof doc;
    (altered.paths['/documents/{id}']!.delete as { summary: string }).summary = 'changed';
    expect(contractDigest(altered)).not.toBe(contractDigest(doc));
  });

  it('the digest ignores info, which carries it', () => {
    const altered = JSON.parse(JSON.stringify(doc)) as typeof doc;
    (altered.info as Record<string, string>).title = 'Something else';
    expect(contractDigest(altered)).toBe(contractDigest(doc));
  });
});
