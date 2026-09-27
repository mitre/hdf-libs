import { describe, expect, it } from 'vitest';
import { maskVolatileJson } from './golden-mask.js';

const mask = (doc: string, volatile: string[] = []): unknown =>
  maskVolatileJson(JSON.parse(doc), volatile);

describe('maskVolatileJson', () => {
  it('replaces uuids with first-occurrence ordinals', () => {
    expect(
      mask('{"a":"11111111-1111-1111-1111-111111111111","b":"22222222-2222-2222-2222-222222222222"}'),
    ).toEqual({ a: 'uuid-1', b: 'uuid-2' });
  });

  it('gives the same uuid the same ordinal, so references survive masking', () => {
    // The party uuid reappears under responsible-parties.
    expect(
      mask(`{"parties":[{"uuid":"11111111-1111-1111-1111-111111111111"}],
             "responsible":{"party-uuids":["11111111-1111-1111-1111-111111111111"]}}`),
    ).toEqual({
      parties: [{ uuid: 'uuid-1' }],
      responsible: { 'party-uuids': ['uuid-1'] },
    });
  });

  // The property that makes ordinal masking worth the complexity: two documents whose
  // uuids are wired up DIFFERENTLY must not compare equal. A single-constant mask would
  // flatten both to the same thing and let a broken reference graph pass.
  it('does not flatten a different reference graph to the same value', () => {
    const linked = mask(`{"a":{"uuid":"11111111-1111-1111-1111-111111111111"},
                          "b":{"ref":"11111111-1111-1111-1111-111111111111"}}`);
    const unlinked = mask(`{"a":{"uuid":"11111111-1111-1111-1111-111111111111"},
                            "b":{"ref":"22222222-2222-2222-2222-222222222222"}}`);
    expect(linked).not.toEqual(unlinked);
  });

  it('gives a "#<uuid>" fragment reference the ordinal of the uuid it names', () => {
    expect(
      mask(
        '{"a":{"href":"#11111111-1111-1111-1111-111111111111"},"b":{"uuid":"11111111-1111-1111-1111-111111111111"},"c":"#SV-1"}',
      ),
    ).toEqual({ a: { href: '#uuid-1' }, b: { uuid: 'uuid-1' }, c: '#SV-1' });
  });

  it('blanks the volatile keys it is given', () => {
    expect(mask('{"last-modified":"2026-07-12T00:00:00Z","title":"keep me"}', ['last-modified'])).toEqual({
      'last-modified': '(normalized)',
      title: 'keep me',
    });
  });

  it('leaves input-derived dates alone', () => {
    // A milestone deadline comes from the input and must still be asserted.
    expect(mask('{"deadline":"2026-02-01T00:00:00Z"}', ['last-modified'])).toEqual({
      deadline: '2026-02-01T00:00:00Z',
    });
  });

  it('leaves non-uuid strings untouched', () => {
    expect(mask('{"id":"SV-204393","near":"1111-11-11-1111"}')).toEqual({
      id: 'SV-204393',
      near: '1111-11-11-1111',
    });
  });
});
