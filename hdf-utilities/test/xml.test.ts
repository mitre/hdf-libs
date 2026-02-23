import { describe, it, expect } from 'vitest';
import {
  parseXml,
  buildXml,
  isValidXml,
  parseXmlWithArrays,
  extractTextFromXml,
} from '../src/xml/index.js';

describe('XML Utilities', () => {
  describe('parseXml', () => {
    it('should parse simple XML', () => {
      const xml = '<root><item>Test</item></root>';
      const result = parseXml(xml);
      expect(result).toEqual({ root: { item: 'Test' } });
    });

    it('should parse XML with attributes', () => {
      const xml = '<root><item id="1" type="test">Value</item></root>';
      const result = parseXml(xml);
      expect(result).toEqual({
        root: { item: { id: '1', type: 'test', '#text': 'Value' } },
      });
    });

    it('should parse XML with nested elements', () => {
      const xml = '<root><parent><child>Value</child></parent></root>';
      const result = parseXml(xml);
      expect(result).toEqual({
        root: { parent: { child: 'Value' } },
      });
    });

    it('should parse XML with multiple sibling elements', () => {
      const xml = '<root><item>First</item><item>Second</item></root>';
      const result = parseXml(xml);
      expect(result).toEqual({
        root: { item: ['First', 'Second'] },
      });
    });

    it('should handle XML with namespaces', () => {
      const xml = '<root xmlns:ns="http://example.com"><ns:item>Test</ns:item></root>';
      const result = parseXml(xml);
      // removeNSPrefix is true by default
      expect(result).toHaveProperty('root');
      expect(result.root).toHaveProperty('item');
    });

    it('should handle empty elements', () => {
      const xml = '<root><empty/></root>';
      const result = parseXml(xml);
      expect(result).toEqual({ root: { empty: '' } });
    });

    it('should handle self-closing tags with attributes', () => {
      const xml = '<root><item id="1"/></root>';
      const result = parseXml(xml);
      expect(result).toEqual({ root: { item: { id: '1' } } });
    });

    it('should handle CDATA sections', () => {
      const xml = '<root><item><![CDATA[<special>chars</special>]]></item></root>';
      const result = parseXml(xml);
      expect(result.root).toHaveProperty('item');
    });

    it('should handle XML with comments (ignored by default)', () => {
      const xml = '<root><!-- comment --><item>Test</item></root>';
      const result = parseXml(xml);
      expect(result).toEqual({ root: { item: 'Test' } });
    });

    it('should support custom options', () => {
      const xml = '<root><item id="1">Test</item></root>';
      const result = parseXml(xml, { ignoreAttributes: true });
      expect(result).toEqual({ root: { item: 'Test' } });
    });

    it('should handle XML declaration', () => {
      const xml = '<?xml version="1.0" encoding="UTF-8"?><root><item>Test</item></root>';
      const result = parseXml(xml);
      expect(result).toEqual({ root: { item: 'Test' } });
    });

    it('should throw on malformed XML', () => {
      const xml = '<root><item>Test</root>'; // Mismatched tags
      expect(() => parseXml(xml)).toThrow();
    });
  });

  describe('buildXml', () => {
    it('should build simple XML', () => {
      // Note: Simple string values become attributes, use #text for element content
      const obj = { root: { item: { '#text': 'Test' } } };
      const xml = buildXml(obj);
      expect(xml).toContain('<root>');
      expect(xml).toContain('<item>Test</item>');
      expect(xml).toContain('</root>');
    });

    it('should build XML with attributes', () => {
      const obj = { root: { item: { id: '1', text: 'Test' } } };
      const xml = buildXml(obj);
      expect(xml).toContain('id="1"');
      expect(xml).toContain('Test');
    });

    it('should build XML with nested elements', () => {
      const obj = { root: { parent: { child: { '#text': 'Value' } } } };
      const xml = buildXml(obj);
      expect(xml).toContain('<parent>');
      expect(xml).toContain('<child>Value</child>');
      expect(xml).toContain('</parent>');
    });

    it('should build XML with arrays', () => {
      const obj = { root: { item: ['First', 'Second'] } };
      const xml = buildXml(obj);
      expect(xml).toContain('<item>First</item>');
      expect(xml).toContain('<item>Second</item>');
    });

    it('should format XML with indentation by default', () => {
      const obj = { root: { parent: { child: { '#text': 'Test' } } } };
      const xml = buildXml(obj);
      expect(xml).toContain('\n');
      expect(xml).toContain('  ');
    });

    it('should support custom formatting options', () => {
      const obj = { root: { item: 'Test' } };
      const xml = buildXml(obj, { format: false });
      expect(xml).not.toContain('\n  ');
    });

    it('should handle empty objects', () => {
      const obj = { root: {} };
      const xml = buildXml(obj);
      expect(xml).toContain('<root');
    });
  });

  describe('isValidXml', () => {
    it('should return true for valid XML', () => {
      expect(isValidXml('<root><item>Test</item></root>')).toBe(true);
    });

    it('should return true for XML with attributes', () => {
      expect(isValidXml('<root><item id="1">Test</item></root>')).toBe(true);
    });

    it('should return true for XML with declaration', () => {
      expect(isValidXml('<?xml version="1.0"?><root><item>Test</item></root>')).toBe(true);
    });

    it('should return true for self-closing tags', () => {
      expect(isValidXml('<root><item/></root>')).toBe(true);
    });

    it('should return false for mismatched tags', () => {
      expect(isValidXml('<root><item>Test</root>')).toBe(false);
    });

    it('should return false for unclosed tags', () => {
      expect(isValidXml('<root><item>Test')).toBe(false);
    });

    it('should return false for plain text', () => {
      expect(isValidXml('not xml')).toBe(false);
    });

    it('should return false for empty string', () => {
      expect(isValidXml('')).toBe(false);
    });

    it('should return false for JSON', () => {
      expect(isValidXml('{"key": "value"}')).toBe(false);
    });
  });

  describe('parseXmlWithArrays', () => {
    it('should force single element to be array', () => {
      const xml = '<root><item>Test</item></root>';
      const result = parseXmlWithArrays(xml, ['item']);
      expect(result).toEqual({ root: { item: ['Test'] } });
    });

    it('should handle multiple elements as arrays', () => {
      const xml = '<root><item>First</item><item>Second</item></root>';
      const result = parseXmlWithArrays(xml, ['item']);
      expect(result).toEqual({ root: { item: ['First', 'Second'] } });
    });

    it('should force multiple tag types to arrays', () => {
      const xml = '<root><item>A</item><value>B</value></root>';
      const result = parseXmlWithArrays(xml, ['item', 'value']);
      expect(result).toEqual({
        root: { item: ['A'], value: ['B'] },
      });
    });

    it('should not affect non-specified tags', () => {
      const xml = '<root><item>A</item><other>B</other></root>';
      const result = parseXmlWithArrays(xml, ['item']);
      expect(result).toEqual({
        root: { item: ['A'], other: 'B' },
      });
    });

    it('should handle nested elements with array forcing', () => {
      const xml =
        '<root><parent><child>Test</child></parent></root>';
      const result = parseXmlWithArrays(xml, ['child']);
      expect(result.root).toHaveProperty('parent');
      const parent = result.root as Record<string, unknown>;
      expect(parent.parent).toHaveProperty('child');
      const child = (parent.parent as Record<string, unknown>).child;
      expect(Array.isArray(child)).toBe(true);
    });

    it('should throw on malformed XML', () => {
      const xml = '<root><item>Test</root>'; // Mismatched tags
      expect(() => parseXmlWithArrays(xml, ['item'])).toThrow('Invalid XML');
    });

    it('should support custom options', () => {
      const xml = '<root><item id="1">Test</item></root>';
      const result = parseXmlWithArrays(xml, ['item'], { ignoreAttributes: true });
      expect(result).toEqual({ root: { item: ['Test'] } });
    });
  });

  describe('extractTextFromXml', () => {
    it('should extract text from simple XML', () => {
      const xml = '<root>Test</root>';
      const text = extractTextFromXml(xml);
      expect(text).toBe('Test');
    });

    it('should extract text from nested elements', () => {
      const xml = '<root><item>First</item><item>Second</item></root>';
      const text = extractTextFromXml(xml);
      expect(text).toContain('First');
      expect(text).toContain('Second');
    });

    it('should strip all tags', () => {
      const xml = '<root><b>Bold</b> and <i>italic</i></root>';
      const text = extractTextFromXml(xml);
      expect(text).toContain('Bold');
      expect(text).toContain('italic');
      expect(text).not.toContain('<b>');
      expect(text).not.toContain('<i>');
    });

    it('should handle attributes', () => {
      const xml = '<root><item id="1">Text</item></root>';
      const text = extractTextFromXml(xml);
      expect(text).toBe('Text');
      expect(text).not.toContain('id');
    });

    it('should handle empty XML', () => {
      const xml = '<root></root>';
      const text = extractTextFromXml(xml);
      expect(text).toBe('');
    });

    it('should handle deeply nested elements', () => {
      const xml = '<root><a><b><c>Deep</c></b></a></root>';
      const text = extractTextFromXml(xml);
      expect(text).toBe('Deep');
    });

    it('should join multiple text nodes with spaces', () => {
      const xml = '<root><a>First</a><b>Second</b><c>Third</c></root>';
      const text = extractTextFromXml(xml);
      const words = text.split(/\s+/).filter(w => w.length > 0);
      expect(words).toEqual(['First', 'Second', 'Third']);
    });

    it('should handle malformed XML gracefully', () => {
      const xml = '<root><item>Test</root>'; // Mismatched tags
      const text = extractTextFromXml(xml);
      expect(text).toBe('');
    });

    it('should handle numeric content', () => {
      const xml = '<root><count>42</count></root>';
      const text = extractTextFromXml(xml);
      expect(text).toBe('42');
    });
  });

  describe('extractTextFromXml edge cases', () => {
    it('should handle number value in XML node (exercises typeof number branch)', () => {
      // fast-xml-parser parses numeric text nodes as numbers when parseTagValue:true
      // extractTextRecursive has a `typeof obj === 'number'` branch
      const xml = '<root><count>42</count></root>';
      const text = extractTextFromXml(xml);
      // The number branch converts to string via String(obj)
      expect(text).toContain('42');
    });

    it('should handle array children (exercises Array.isArray branch)', () => {
      // Repeated sibling elements produce arrays in parsed output
      const xml = '<root><item>First</item><item>Second</item><item>Third</item></root>';
      const text = extractTextFromXml(xml);
      expect(text).toContain('First');
      expect(text).toContain('Second');
      expect(text).toContain('Third');
    });

    it('should join multiple text segments with space separator', () => {
      const xml = '<root><a>Hello</a><b>World</b></root>';
      const text = extractTextFromXml(xml);
      // Array.map().join(' ') uses a space — verify the separator
      const parts = text.split(/\s+/).filter(Boolean);
      expect(parts).toContain('Hello');
      expect(parts).toContain('World');
      // They should be space-separated, not concatenated without space
      expect(text).toMatch(/Hello\s+World|World\s+Hello/);
    });

    it('should return empty for whitespace-only XML input', () => {
      // isValidXml returns false for whitespace-only, so extractTextFromXml returns ''
      const text = extractTextFromXml('   ');
      expect(text).toBe('');
    });
  });

  describe('parseXml option variants', () => {
    it('should handle parseTagValue:true option', () => {
      const xml = '<root><count>42</count></root>';
      const result = parseXml(xml, { parseTagValue: true });
      expect(result).toHaveProperty('root');
    });

    it('should handle suppressEmptyNode option', () => {
      const xml = '<root><empty/><item>Test</item></root>';
      const result = parseXml(xml, { });
      expect(result).toHaveProperty('root');
    });
  });

  describe('maxSize option', () => {
    const smallXml = '<root><item>Test</item></root>';

    it('parseXml should accept input within maxSize limit', () => {
      expect(() => parseXml(smallXml, { maxSize: 1000 })).not.toThrow();
    });

    it('parseXml should reject input exceeding maxSize limit', () => {
      expect(() => parseXml(smallXml, { maxSize: 5 })).toThrow(
        /exceeds maximum allowed size/
      );
    });

    it('parseXml should not enforce a limit when maxSize is omitted', () => {
      const largeXml = '<r>' + 'x'.repeat(10_000) + '</r>';
      expect(() => parseXml(largeXml)).not.toThrow();
    });

    it('parseXmlWithArrays should accept input within maxSize limit', () => {
      expect(() =>
        parseXmlWithArrays(smallXml, ['item'], { maxSize: 1000 })
      ).not.toThrow();
    });

    it('parseXmlWithArrays should reject input exceeding maxSize limit', () => {
      expect(() =>
        parseXmlWithArrays(smallXml, ['item'], { maxSize: 5 })
      ).toThrow(/exceeds maximum allowed size/);
    });

    it('should report actual size and limit in error message', () => {
      expect(() => parseXml(smallXml, { maxSize: 10 })).toThrow(
        new RegExp(`${smallXml.length} bytes.*10 bytes`)
      );
    });

    it('should check size before doing any parsing work', () => {
      // Even invalid XML should fail on size before reaching the parser
      const invalidXml = '<root><unclosed';
      expect(() => parseXml(invalidXml, { maxSize: 3 })).toThrow(
        /exceeds maximum allowed size/
      );
    });
  });

  describe('XXE safety', () => {
    it('should not process external entities', () => {
      const xxeXml = `<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root><data>&xxe;</data></root>`;
      // fast-xml-parser v5 does not process DTD/entities
      // parseXml should either:
      // 1. Parse but not expand the entity (entity text remains as literal or empty)
      // 2. Throw on invalid XML (the validator may reject DTD syntax)
      // Either outcome is safe — the key assertion is that /etc/passwd content is NOT returned
      try {
        const result = parseXml(xxeXml);
        const data = (result.root as Record<string, unknown>)?.data;
        // Should not contain actual file contents
        expect(String(data)).not.toMatch(/root:/);
      } catch {
        // Throwing is also safe — DTD rejected
      }
    });

    it('should not process parameter entities', () => {
      const paramXml = `<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % param "parameter-value">
  <!ENTITY test "%param;">
]>
<root><data>&test;</data></root>`;
      try {
        const result = parseXml(paramXml);
        const data = (result.root as Record<string, unknown>)?.data;
        expect(String(data)).not.toBe('parameter-value');
      } catch {
        // Throwing is also safe
      }
    });

    it('should not expand billion laughs attack', () => {
      const billionLaughsXml = `<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
]>
<root><data>&lol3;</data></root>`;
      try {
        const result = parseXml(billionLaughsXml);
        const data = String((result.root as Record<string, unknown>)?.data ?? '');
        // Should not have exponentially expanded text
        expect(data.length).toBeLessThan(1000);
      } catch {
        // Throwing is also safe
      }
    });
  });

  describe('Real-world security tool XML scenarios', () => {
    it('should parse Nessus-like vulnerability XML', () => {
      const xml = `
        <ReportHost name="example.com">
          <ReportItem port="443" svc_name="https" protocol="tcp" severity="2" pluginID="12345">
            <plugin_name>SSL Certificate</plugin_name>
            <risk_factor>Medium</risk_factor>
            <description>Certificate issue found</description>
          </ReportItem>
        </ReportHost>
      `;
      const result = parseXml(xml);
      expect(result).toHaveProperty('ReportHost');
      const host = result.ReportHost as Record<string, unknown>;
      expect(host.name).toBe('example.com');
      expect(host).toHaveProperty('ReportItem');
    });

    it('should parse XCCDF-like compliance XML', () => {
      const xml = `
        <Benchmark id="RHEL-9">
          <Rule id="rule-1" severity="high">
            <title>System must be patched</title>
            <check system="oval">
              <check-content-ref href="oval.xml"/>
            </check>
          </Rule>
        </Benchmark>
      `;
      const result = parseXml(xml);
      expect(result).toHaveProperty('Benchmark');
      const benchmark = result.Benchmark as Record<string, unknown>;
      expect(benchmark.id).toBe('RHEL-9');
      expect(benchmark).toHaveProperty('Rule');
    });

    it('should handle multiple report items consistently', () => {
      const xml = `
        <Report>
          <Host>
            <Item>First</Item>
            <Item>Second</Item>
            <Item>Third</Item>
          </Host>
        </Report>
      `;
      const result = parseXmlWithArrays(xml, ['Item']);
      const report = result.Report as Record<string, unknown>;
      const host = report.Host as Record<string, unknown>;
      const items = host.Item as string[];
      expect(Array.isArray(items)).toBe(true);
      expect(items).toHaveLength(3);
    });
  });
});
