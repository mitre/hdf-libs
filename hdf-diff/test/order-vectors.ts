import { readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

/** The identifier-order table; Go reads it in go/code_point_order_test.go. */
export const ORDER_VECTORS = JSON.parse(
  readFileSync(join(dirname(fileURLToPath(import.meta.url)), '..', 'testdata', 'code-point-order-vectors.json'), 'utf-8'),
) as { ids: string[]; codePointOrder: string[] };

/** A results document with one requirement per id, in order, all of one status. */
export function orderResultsDoc(status: string, order: string[]): Record<string, unknown> {
  return {
    timestamp: '2024-01-01T00:00:00Z',
    baselines: [{
      name: 'order-baseline', version: '1.0.0', groups: [], supports: [],
      requirements: order.map((id) => ({
        id, title: `Check ${id}`, impact: 0.5, tags: {},
        descriptions: [{ label: 'default', data: 'test' }],
        results: [{ status, codeDesc: 'test', startTime: '2024-01-01T00:00:00Z' }],
      })),
    }],
  };
}
