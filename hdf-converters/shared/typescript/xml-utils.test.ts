import { describe, it, expect } from 'vitest';
import { extractXmlRootElement } from './xml-utils.js';

describe('extractXmlRootElement', () => {
  it('extracts root from simple XML', () => {
    expect(extractXmlRootElement('<root/>')).toBe('root');
  });

  it('extracts root after XML declaration', () => {
    expect(extractXmlRootElement('<?xml version="1.0"?><Benchmark/>')).toBe('Benchmark');
  });

  it('strips namespace prefix', () => {
    expect(extractXmlRootElement('<xccdf:Benchmark/>')).toBe('Benchmark');
  });

  it('extracts root after simple DOCTYPE declaration', () => {
    expect(extractXmlRootElement('<?xml?>\n<!DOCTYPE root>\n<root/>')).toBe('root');
  });

  it('extracts root after DOCTYPE with internal subset', () => {
    const input = `<?xml version="1.0"?>
<!DOCTYPE issues [
<!ELEMENT issues (issue*)>
<!ATTLIST issues burpVersion CDATA "">
<!ELEMENT issue (name, severity)>
]>
<issues burpVersion="2024.1"><issue/></issues>`;
    expect(extractXmlRootElement(input)).toBe('issues');
  });

  it('extracts root after comments', () => {
    expect(extractXmlRootElement('<!-- comment --><root/>')).toBe('root');
  });

  it('returns null for plain text', () => {
    expect(extractXmlRootElement('plain text')).toBeNull();
  });

  it('returns null for empty string', () => {
    expect(extractXmlRootElement('')).toBeNull();
  });

  it('handles large input with many declarations without ReDoS', () => {
    // Build a string with many XML declarations to test ReDoS resistance
    const declarations = '<?xml version="1.0"?>'.repeat(100);
    const input = declarations + '<realRoot/>';
    const start = performance.now();
    const result = extractXmlRootElement(input);
    const elapsed = performance.now() - start;
    // Should complete in under 100ms (ReDoS would take seconds)
    expect(elapsed).toBeLessThan(100);
    expect(result).toBe('realRoot');
  });
});
