import { describe, it, expect } from 'vitest';
import { parseXml } from '../src/xml/index.js';

/**
 * A canary, not a feature test.
 *
 * The prologue detectors exist to gate DTD constructs at the boundary. How strict that
 * gate needs to be depends entirely on whether the parser behind it would DO anything
 * with a DTD — and fast-xml-parser 5.x does not: it neither expands DTD-declared
 * entities nor fetches an external DTD. So the gate is defence in depth today.
 *
 * If a parser upgrade changes that, these assertions fail, and the gate stops being
 * belt-and-braces and becomes the only thing standing between a converter and an XXE or
 * a billion-laughs expansion. That is worth being told about loudly rather than
 * discovering from a report.
 */
describe('XML parser DTD canary', () => {
  it('does not expand DTD-declared entities (billion laughs is inert)', () => {
    const doc =
      '<!DOCTYPE l [<!ENTITY a "aaaaaaaaaa"><!ENTITY b "&a;&a;&a;&a;&a;">]><l>&b;</l>';
    const text = JSON.stringify(parseXml(doc));
    // The payload would be 50 'a's if expansion happened at one level of nesting.
    expect(text).not.toContain('aaaaaaaaaa');
  });

  it('refuses an external entity outright rather than resolving it', () => {
    const doc = '<!DOCTYPE l [<!ENTITY x SYSTEM "file:///etc/hosts">]><l>&x;</l>';
    expect(() => parseXml(doc)).toThrow(/external entities are not supported/i);
  });

  // An unreachable port: a parser that fetched the external DTD would hang or throw a
  // connection error rather than returning the document's own content.
  it('does not fetch an external DTD', () => {
    const doc = '<!DOCTYPE l SYSTEM "http://127.0.0.1:1/evil.dtd"><l>x</l>';
    expect(() => parseXml(doc)).not.toThrow();
  });

  it('does not apply an ATTLIST default value', () => {
    const doc = '<!DOCTYPE l [<!ATTLIST l v CDATA "dflt">]><l>ok</l>';
    expect(JSON.stringify(parseXml(doc))).not.toContain('dflt');
  });
});
