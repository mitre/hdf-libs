import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, it, expect } from 'vitest';
import { applyChangeEvents } from '../src/apply-events.js';
import { foldChangeEventsIntoComparison } from '../src/fold-events.js';
import { changeEventFromPrevious, type KeyState } from '../src/change-event.js';
import { computeEffectiveChecksum, foldEffectiveState, type FoldedState } from '../src/effective-checksum.js';

/**
 * The table read here is also read by go/shared_event_cases_test.go, so both kernels are
 * asserted against ONE definition of what a requirement id's entries fold to, what event
 * that produces, and what applying it back leaves in the document.
 */

type Doc = Record<string, unknown>;

interface SharedFold {
  effectiveStatus: string;
  effectiveImpact: number;
  checksum: string;
}

interface SharedEventCase {
  name: string;
  why: string;
  prev: Doc[][];
  next: Doc[];
  prevFold: SharedFold | null;
  nextFold: SharedFold | null;
  singleEntryChecksum?: boolean;
  event: {
    state: string;
    afterCount: number;
    changeReasons: string[];
    before: { effectiveStatus: string; effectiveImpact: number } | null;
  } | null;
  applied: { baselines: string[][]; warnings: string[] };
  foldedDiff: {
    state: string;
    oldEffectiveStatus: string | null;
    newEffectiveStatus: string | null;
    oldImpact: number | null;
    newImpact: number | null;
  } | null;
}

const table = JSON.parse(
  readFileSync(resolve(import.meta.dirname, '..', 'testdata', 'duplicate-id-event-cases.json'), 'utf-8'),
) as {
  inputs: {
    eventId: string;
    source: string;
    sequence: number;
    systemRef: string;
    componentId: string;
    requirementId: string;
    timestamp: string;
    referenceTimestamp: string;
  };
  seedTimestamp: string;
  cases: SharedEventCase[];
};

function expectFold(want: SharedFold | null, got: FoldedState | null, why: string): void {
  if (want === null) {
    expect(got, why).toBeNull();
    return;
  }
  expect(got, why).not.toBeNull();
  expect(got!.effectiveStatus, why).toBe(want.effectiveStatus);
  expect(got!.effectiveImpact, why).toBeCloseTo(want.effectiveImpact, 9);
  expect(got!.checksum.value, why).toBe(want.checksum);
}

function appliedTitles(doc: Doc): string[][] {
  const baselines = (doc['baselines'] as Doc[] | undefined) ?? [];
  return baselines.map((baseline) =>
    ((baseline['requirements'] as Doc[] | undefined) ?? []).flatMap((req) =>
      typeof req['title'] === 'string' ? [req['title']] : [],
    ),
  );
}

describe('shared duplicate-id event cases', () => {
  for (const tc of table.cases) {
    it(tc.name, async () => {
      const prevEntries = tc.prev.flat();
      const ref = table.inputs.referenceTimestamp;

      const prevState = await foldEffectiveState(prevEntries, ref);
      expectFold(tc.prevFold, prevState, `prev fold: ${tc.why}`);
      expectFold(tc.nextFold, await foldEffectiveState(tc.next, ref), `next fold: ${tc.why}`);

      if (tc.singleEntryChecksum === true) {
        expect(prevEntries).toHaveLength(1);
        const own = await computeEffectiveChecksum(prevEntries[0]!, ref);
        expect(prevState!.checksum.value, `one entry must keep exactly its own effective checksum: ${tc.why}`).toBe(
          own.value,
        );
      }

      const event = await changeEventFromPrevious(
        prevState as KeyState | null,
        tc.next,
        prevEntries,
        { ...table.inputs },
      );

      if (tc.event === null) {
        expect(event, `no event expected: ${tc.why}`).toBeNull();
      } else {
        expect(event, tc.why).not.toBeNull();
        expect(event!['state'], tc.why).toBe(tc.event.state);
        expect((event!['after'] as Doc[] | null) ?? [], `after[] carries every entry: ${tc.why}`).toHaveLength(
          tc.event.afterCount,
        );
        expect((event!['changeReasons'] as string[] | undefined) ?? [], tc.why).toEqual(tc.event.changeReasons);
        if (tc.event.before === null) {
          expect(event!['before'], `before is null exactly at chain start: ${tc.why}`).toBeNull();
          expect(event!['priorChecksum'], tc.why).toBeNull();
        } else {
          expect(event!['before'], tc.why).toEqual(tc.event.before);
          // The chain link is the prior FOLDED state, which the table pins literally.
          expect((event!['priorChecksum'] as { value: string })['value'], tc.why).toBe(tc.prevFold!.checksum);
        }
      }

      const seed = JSON.stringify({
        timestamp: table.seedTimestamp,
        baselines: tc.prev.map((requirements, i) => ({ name: `baseline-${i}`, requirements })),
      });
      const result = await applyChangeEvents(seed, event === null ? [] : [event], {
        generator: { name: 'shared-case-table', version: '0.0.0' },
        seedUri: 'memory://seed',
        source: table.inputs.source,
      });
      expect(appliedTitles(result.results), `applied: ${tc.why}`).toEqual(tc.applied.baselines);
      expect(
        result.warnings.map((w) => w.kind),
        `warnings: ${tc.why}`,
      ).toEqual(tc.applied.warnings);

      const folded = await foldChangeEventsIntoComparison(seed, event === null ? [] : [event]);
      const diffs = (folded.comparison['requirementDiffs'] as Doc[] | undefined) ?? [];
      if (tc.foldedDiff === null) {
        expect(diffs, `no event, so no requirementDiff: ${tc.why}`).toHaveLength(0);
      } else {
        // ONE diff per key however many entries the id carries, because the event key is
        // the requirement (ADR-0005 §1).
        expect(diffs, tc.why).toHaveLength(1);
        const got = diffs[0]!;
        expect(got['state'], tc.why).toBe(tc.foldedDiff.state);
        expect(got['oldEffectiveStatus'] ?? null, `old status: ${tc.why}`).toBe(
          tc.foldedDiff.oldEffectiveStatus,
        );
        expect(got['newEffectiveStatus'] ?? null, `new status: ${tc.why}`).toBe(
          tc.foldedDiff.newEffectiveStatus,
        );
        expect(got['oldImpact'] ?? null, `old impact: ${tc.why}`).toBe(tc.foldedDiff.oldImpact);
        expect(got['newImpact'] ?? null, `new impact: ${tc.why}`).toBe(tc.foldedDiff.newImpact);
      }
    });
  }
});
