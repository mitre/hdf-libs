import { describe, expect, it } from 'vitest';
import { convertHdfToSarif } from './converter.js';
import { PASSTHROUGH_SCHEMA_VERSION } from './passthrough.js';

const TEST_VERSION = '0.0.0';

type Json = Record<string, any>;

/**
 * Builds a document carrying the given addressed bags. Built here rather than
 * committed as a fixture: no importer writes this block yet, so a committed file
 * would assert about data no tool has produced.
 */
function carriedDoc(...bags: Json[]): Json {
  const input = JSON.stringify({
    baselines: [
      {
        name: 'run-one',
        requirements: [
          {
            id: 'V-1',
            impact: 0.5,
            tags: {},
            descriptions: [{ label: 'default', data: 'd' }],
            sourceLocation: { ref: 'a.c', line: 7 },
            results: [
              { status: 'failed', codeDesc: 'first', startTime: '2020-01-01T00:00:00Z' },
              { status: 'failed', codeDesc: 'second', startTime: '2020-01-01T00:00:00Z' },
            ],
          },
        ],
      },
    ],
    extensions: { passthrough: { sarif: { schemaVersion: PASSTHROUGH_SCHEMA_VERSION, propertyBags: bags } } },
  });
  return JSON.parse(convertHdfToSarif(input, TEST_VERSION)) as Json;
}

const run0 = (log: Json): Json => log.runs[0] as Json;
const rule0 = (log: Json): Json => run0(log).tool.driver.rules[0] as Json;
const results0 = (log: Json): Json[] => (run0(log).results ?? []) as Json[];

describe('hdf-to-sarif carried property bags', () => {
  // Each addressed bag reaches the one object its address names. The address is
  // built from the HDF identities that survive conversion — never array
  // position, which HDF reorders and deduplicates.
  it('reaches the object its address names', () => {
    const log = carriedDoc(
      { on: 'log', properties: { logKey: 'logValue' } },
      { on: 'run', baseline: 'run-one', properties: { columnKind: 'utf16CodeUnits' } },
      { on: 'driver', baseline: 'run-one', properties: { driverKey: 1 } },
      { on: 'conversion', baseline: 'run-one', properties: { convKey: true } },
      { on: 'rule', baseline: 'run-one', ruleId: 'V-1', properties: { ruleKey: 'r' } },
      { on: 'result', baseline: 'run-one', ruleId: 'V-1', ordinal: 1, properties: { rank: 3 } },
      { on: 'location', baseline: 'run-one', ruleId: 'V-1', properties: { locKey: 'l' } },
    );

    expect(log.properties.logKey).toBe('logValue');
    expect(run0(log).properties.columnKind).toBe('utf16CodeUnits');
    expect(run0(log).tool.driver.properties.driverKey).toBe(1);
    expect(run0(log).conversion.properties.convKey).toBe(true);
    expect(rule0(log).properties.ruleKey).toBe('r');

    const res = results0(log);
    expect(res).toHaveLength(2);
    expect(res[0]?.properties).not.toHaveProperty('rank');
    expect(res[1]?.properties.rank).toBe(3);
    expect(res[0]?.locations[0].properties.locKey).toBe('l');
  });

  // Verbatim carriage buys bookkeeping fidelity; mapping buys semantic fidelity.
  // A carried key never overwrites one this converter derived from an HDF field.
  it('never overwrites a mapped value', () => {
    const log = carriedDoc({
      on: 'rule',
      baseline: 'run-one',
      ruleId: 'V-1',
      properties: { hdf: 'hijacked', 'security-severity': '0.0', ownKey: 'kept' },
    });
    const props = rule0(log).properties as Json;
    expect(props.hdf.control_id).toBe('V-1');
    expect(props.ownKey).toBe('kept');
    // This requirement carries no CVSS, so the exporter sets nothing there and
    // the carried value stands.
    expect(props['security-severity']).toBe('0.0');
  });

  // propertyBag tags carries uniqueItems, so the two sides union rather than
  // append, and both languages must agree on the order.
  it('unions the tags arrays', () => {
    const log = carriedDoc({
      on: 'rule',
      baseline: 'run-one',
      ruleId: 'V-1',
      properties: { tags: ['security', 'external/cwe/cwe-79', 'security'] },
    });
    expect(rule0(log).properties.tags).toEqual(['external/cwe/cwe-79', 'security']);
  });

  // An entry addressing an object this exporter does not emit is not re-emitted
  // anywhere, and never lands on the wrong object (ADR-0014 §3.4's rule).
  it('does not re-emit an unmatched address', () => {
    const log = carriedDoc(
      { on: 'rule', baseline: 'other-baseline', ruleId: 'V-1', properties: { stray: 1 } },
      { on: 'rule', baseline: 'run-one', ruleId: 'V-999', properties: { stray: 2 } },
      { on: 'taxonomy', baseline: 'run-one', properties: { stray: 3 } },
    );
    expect(JSON.stringify(log)).not.toContain('stray');
  });

  // Carriage is bookkeeping: a malformed entry must not cost the document its
  // findings.
  it('skips malformed entries', () => {
    const log = carriedDoc(
      { on: 'rule' },
      { on: 'rule', properties: {} },
      { properties: { x: 1 } },
    );
    expect(results0(log)).toHaveLength(2);
    expect(rule0(log).properties).not.toHaveProperty('x');
  });

  it('carries only the passthrough it did not consume', () => {
    const input = JSON.stringify({
      baselines: [
        {
          name: 'b',
          requirements: [
            {
              id: 'V-1',
              impact: 0.5,
              tags: {},
              descriptions: [{ label: 'default', data: 'd' }],
              results: [{ status: 'failed', codeDesc: 'c', startTime: '2020-01-01T00:00:00Z' }],
            },
          ],
          extensions: { passthrough: { baselineVendor: { b: 1 } } },
        },
      ],
      extensions: { passthrough: { sarif: { propertyBags: [] }, docVendor: { d: 2 } } },
    });
    const log = JSON.parse(convertHdfToSarif(input, TEST_VERSION)) as Json;

    const docPassthrough = log.properties.hdf.extensions.passthrough as Json;
    expect(docPassthrough).toHaveProperty('docVendor');
    expect(docPassthrough).not.toHaveProperty('sarif');

    expect(run0(log).properties.hdf.extensions.passthrough).toHaveProperty('baselineVendor');
  });
});
