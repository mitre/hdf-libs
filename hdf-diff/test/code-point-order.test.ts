import { describe, it, expect } from 'vitest';
import { diffHdf, diffBaselines, diffSystems } from '../src/diff.js';
import { diffSboms } from '../src/sbom.js';
import { groupEventChains } from '../src/event-stream-common.js';
import { ORDER_VECTORS, orderResultsDoc as resultsDoc } from './order-vectors.js';

const { ids, codePointOrder } = ORDER_VECTORS;

describe('identifier order matches Go byte order (shared vectors)', () => {
  it('has ids to check, and they are not already in the expected order', () => {
    expect(ids.length).toBeGreaterThan(0);
    expect([...ids].sort()).toEqual([...codePointOrder].sort());
    expect(ids).not.toEqual(codePointOrder);
  });

  it('orders temporal requirementDiffs by code point', () => {
    const diff = diffHdf(resultsDoc('passed', ids), resultsDoc('failed', [...ids].reverse()));
    expect(diff.requirementDiffs.map((d) => d.id)).toEqual(codePointOrder);
  });

  it('orders fleet requirementDiffs by code point, then by source', () => {
    const diff = diffHdf(resultsDoc('passed', ids), [resultsDoc('failed', ids), resultsDoc('passed', ids)], {
      comparisonMode: 'fleet',
    });
    expect(diff.requirementDiffs.map((d) => [d.id, d.sourceIndex])).toEqual(
      codePointOrder.flatMap((id) => [[id, 1], [id, 2]]),
    );
  });

  it('orders baseline-evolution requirementDiffs by code point', () => {
    const baseline = (title: string) => ({
      name: 'order-stig', version: '1.0',
      requirements: ids.map((id) => ({ id, title, impact: 0.5, descriptions: [], tags: {} })),
    });
    const diff = diffBaselines(baseline('Old'), baseline('New'));
    expect(diff.requirementDiffs.map((d) => d.id)).toEqual(codePointOrder);
  });

  it('orders system componentDiffs by code point', () => {
    const system = { name: 'Order-Prod', components: ids.map((name) => ({ name, type: 'application' })) };
    const diff = diffSystems({ name: 'Order-Prod', components: [] }, system);
    expect((diff.componentDiffs ?? []).map((d) => d.name)).toEqual(codePointOrder);
  });

  it('orders SBOM packageDiffs by code point', () => {
    const bom = (names: string[]) => JSON.stringify({
      bomFormat: 'CycloneDX', specVersion: '1.5', version: 1,
      components: names.map((name) => ({ type: 'library', name, version: '1.0.0' })),
    });
    const result = diffSboms(bom([]), bom(ids));
    expect(result.packageDiffs.map((d) => d.name)).toEqual(codePointOrder);
  });

  it('orders event keys, and same-sequence events by eventId, by code point', () => {
    const byRequirement = groupEventChains(ids.map((requirementId) => ({ requirementId, sequence: 1, eventId: 'e' })));
    expect(byRequirement.keys).toEqual(codePointOrder);

    const oneChain = groupEventChains(ids.map((eventId) => ({ requirementId: 'SV-1', sequence: 1, eventId })));
    expect((oneChain.byKey.get('SV-1') ?? []).map((ev) => ev['eventId'])).toEqual(codePointOrder);
  });
});
