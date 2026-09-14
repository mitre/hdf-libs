import { readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { describe, it, expect } from 'vitest';
import { convertAsffToHdf } from './converter.js';

const __dirname = dirname(fileURLToPath(import.meta.url));

// Derived from the committed unknown-producer fixture with only the two numbers
// under test overridden, so the document keeps its real shape and no new fixture
// claims to be sample data it is not. The Go peer does the same and asserts the
// same two strings. toFixed rounds a tie away from zero; Go's fmt rounds it to
// even, which is why Go routes through hdfutil.FormatFixed. If someone ever
// "fixes" this side to match fmt, this fails.
function tieRoundingInput(): string {
  const doc = JSON.parse(
    readFileSync(join(__dirname, '..', 'fixtures', 'input', 'unknown-producer.json'), 'utf-8'),
  ) as { Findings: Array<Record<string, unknown>> };

  for (const f of doc.Findings) {
    const vulns = f.Vulnerabilities as Array<Record<string, unknown>> | undefined;
    if (!vulns?.length) continue;
    vulns[0].EpssScore = 0.03125;
    const cvss = vulns[0].Cvss as Array<Record<string, unknown>> | undefined;
    if (cvss?.length) cvss[0].BaseScore = 7.25;
    return JSON.stringify(doc);
  }
  throw new Error('no finding with Vulnerabilities[] to override');
}

describe('asff-to-hdf renders exact ties the way Go now does', () => {
  it('rounds 7.25 to 7.3 at one decimal and 0.03125 to 0.0313 at four', async () => {
    const hdf = JSON.parse(await convertAsffToHdf(tieRoundingInput(), '0.1.0'));
    const messages = (hdf.baselines[0].requirements as Array<Record<string, unknown>>)
      .flatMap((r) => (r.results as Array<Record<string, unknown>>) ?? [])
      .map((r) => String(r.message ?? ''))
      .join('\n');

    expect(messages).not.toBe('');
    expect(messages).toContain('CVSS 3.1 7.3');
    expect(messages).toContain('EPSS 0.0313');
    expect(messages).not.toContain('CVSS 3.1 7.2');
    expect(messages).not.toContain('EPSS 0.0312');
  });
});
