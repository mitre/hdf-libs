import { describe, it, expect } from 'vitest';
import {
  countXmlElements,
  countJsonItemsUnderKey,
  assertRequirementCount,
  assertOverrideCount,
} from './anchor.js';

describe('anchor: countXmlElements', () => {
  it('counts opening tags, ignoring closing, namespaced, and substring tags', () => {
    const xml =
      '<Benchmark><Group><Rule id="1"/><Rule id="2"></Rule></Group>' +
      '<xccdf:Rule id="3"/><RuleResult/></Benchmark>';
    // 2 plain + 1 namespaced <Rule>; <RuleResult> and </Rule> excluded.
    expect(countXmlElements(xml, 'Rule')).toBe(3);
  });

  it('counts hyphenated element names', () => {
    expect(countXmlElements('<a><rule-result/><rule-result/></a>', 'rule-result')).toBe(2);
  });

  it('returns 0 when the element is absent', () => {
    expect(countXmlElements('<a><b/></a>', 'Rule')).toBe(0);
  });
});

describe('anchor: countJsonItemsUnderKey', () => {
  it('counts array items under a key at any depth, including nested', () => {
    const json = JSON.stringify({
      groups: [{ controls: [{ id: 'a', controls: [{ id: 'a.1' }] }, { id: 'b' }] }],
    });
    expect(countJsonItemsUnderKey(json, 'controls')).toBe(3); // a, b, a.1
  });

  it('returns 0 when the key is absent', () => {
    expect(countJsonItemsUnderKey('{"x":1}', 'controls')).toBe(0);
  });
});

describe('anchor: assertRequirementCount', () => {
  it('passes on the HDFResults shape (baselines[].requirements)', () => {
    assertRequirementCount(
      JSON.stringify({ baselines: [{ requirements: [{}, {}] }] }),
      2,
      'results shape',
    );
  });

  it('passes on the HDFBaseline shape (top-level requirements)', () => {
    assertRequirementCount({ requirements: [{}, {}, {}] }, 3, 'baseline shape');
  });

  it('throws when want is 0 (an anchor with want=0 proves nothing)', () => {
    expect(() => assertRequirementCount({ requirements: [] }, 0, 'x')).toThrow();
  });

  it('throws on a count mismatch', () => {
    expect(() => assertRequirementCount({ requirements: [{}] }, 2, 'x')).toThrow();
  });
});

describe('anchor: assertOverrideCount', () => {
  it('passes on matching overrides[] count (string or object)', () => {
    assertOverrideCount(JSON.stringify({ overrides: [{}, {}, {}] }), 3, 'string input');
    assertOverrideCount({ overrides: [{}, {}] }, 2, 'object input');
  });

  it('throws on a count mismatch', () => {
    expect(() => assertOverrideCount({ overrides: [{}] }, 2, 'x')).toThrow();
  });
});
