// Merge engine — the TypeScript peer of hdf-engine/go/merge.go (ADR-0016).
// Combines several results documents into one multi-baseline results document:
// one baseline per input baseline renamed `<tool>/<original>`, per-baseline
// provenance in labels, each input's root provenance verbatim under
// extensions["hdf-merge"]. Union semantics — nothing deduplicated, re-keyed or
// dropped. Deterministic for the same inputs in the same order. Kept at
// behavioural parity with Go (see test/merge.test.ts / go/merge_test.go).

import type { HDFResults, EvaluatedBaseline, Component } from '@mitre/hdf-schema';
import { engineVersion } from './version.js';

/** One input to merge: a results document and the name it is recorded under. */
export interface MergeSource {
  name: string;
  doc: HDFResults;
}

export type MergeWarningKind = 'duplicate-baseline-name' | 'label-overwritten';

/** A non-fatal condition merge reports rather than silently resolving. */
export interface MergeWarning {
  kind: MergeWarningKind;
  /** Merged baseline name. */
  name: string;
  /** Merged baseline positions. */
  indices: number[];
  /** Set for label warnings only: the label key that was replaced or removed. */
  label?: string;
}

export interface MergeResult {
  results: HDFResults;
  warnings: MergeWarning[];
}

/** Provenance label keys written on every merged baseline (ADR-0016 §3). */
export const LABEL_TOOL = 'tool';
export const LABEL_TOOL_VERSION = 'toolVersion';
export const LABEL_SOURCE_DOCUMENT = 'sourceDocument';

const MERGE_GENERATOR_NAME = 'hdf-merge';
const MERGE_EXTENSION_KEY = 'hdf-merge';

/**
 * merge combines the sources, in order, into one results document. Returns the
 * document and any warnings (a collision or overwrite is never an error);
 * throws only when there is nothing to merge. Inputs are not mutated.
 */
export function merge(sources: MergeSource[]): MergeResult {
  if (sources.length === 0) {
    throw new Error('merge: no sources');
  }

  const baselines: EvaluatedBaseline[] = [];
  const components: Component[] = [];
  const warnings: MergeWarning[] = [];
  const seenComponent = new Set<string>();
  const provenance: Record<string, unknown>[] = [];
  const positionsByName = new Map<string, number[]>();
  let latest: HDFResults['timestamp'];

  sources.forEach((src, index) => {
    const prefix = toolPrefix(src.doc, index);
    const version = toolVersion(src.doc);

    for (const b of src.doc.baselines ?? []) {
      const name = `${prefix}/${b.name}`;
      const pos = baselines.length;
      const labels: Record<string, string> = { ...(b.labels ?? {}) };

      setLabel(warnings, labels, LABEL_TOOL, prefix, name, pos);
      if (version !== '') {
        setLabel(warnings, labels, LABEL_TOOL_VERSION, version, name, pos);
      } else if (LABEL_TOOL_VERSION in labels) {
        delete labels[LABEL_TOOL_VERSION];
        warnings.push({ kind: 'label-overwritten', name, indices: [pos], label: LABEL_TOOL_VERSION });
      }
      setLabel(warnings, labels, LABEL_SOURCE_DOCUMENT, src.name, name, pos);

      const positions = positionsByName.get(name);
      if (positions) positions.push(pos);
      else positionsByName.set(name, [pos]);

      baselines.push({ ...b, name, labels });
    }

    for (const c of src.doc.components ?? []) {
      if (c.componentId !== undefined) {
        if (seenComponent.has(c.componentId)) continue;
        seenComponent.add(c.componentId);
      }
      components.push(c);
    }

    if (src.doc.timestamp !== undefined && (latest === undefined || millis(src.doc.timestamp) > millis(latest))) {
      latest = src.doc.timestamp;
    }

    provenance.push(sourceProvenance(index, src));
  });

  for (const [name, positions] of positionsByName) {
    if (positions.length > 1) {
      warnings.push({ kind: 'duplicate-baseline-name', name, indices: positions });
    }
  }

  // Key order is fixed so the same inputs serialize identically on every run.
  const results: HDFResults = {
    baselines,
    ...(components.length > 0 ? { components } : {}),
    extensions: { [MERGE_EXTENSION_KEY]: { version: engineVersion, sources: provenance } },
    generator: { name: MERGE_GENERATOR_NAME, version: engineVersion },
    ...(latest !== undefined ? { timestamp: latest } : {}),
  };
  return { results, warnings };
}

function setLabel(
  warnings: MergeWarning[],
  labels: Record<string, string>,
  key: string,
  value: string,
  name: string,
  pos: number,
): void {
  if (key in labels) {
    warnings.push({ kind: 'label-overwritten', name, indices: [pos], label: key });
  }
  labels[key] = value;
}

/** `<tool>` of a merged baseline name: tool.name → generator.name → doc<N>, lower-cased and trimmed. */
function toolPrefix(doc: HDFResults, index: number): string {
  const tool = normalizeName(doc.tool?.name);
  if (tool !== '') return tool;
  const generator = normalizeName(doc.generator?.name);
  if (generator !== '') return generator;
  return `doc${index}`;
}

function normalizeName(s: string | undefined): string {
  return (s ?? '').trim().toLowerCase();
}

/**
 * millis reads a document timestamp for comparison. The schema type is Date,
 * but a document parsed from JSON carries the RFC 3339 string verbatim (the
 * loader does not revive dates), so both are accepted; the value itself is
 * carried through unchanged so output stays byte-faithful to the input.
 */
function millis(ts: Date | string): number {
  return ts instanceof Date ? ts.getTime() : Date.parse(ts);
}

function toolVersion(doc: HDFResults): string {
  return (doc.tool?.version ?? '').trim();
}

/** One input's root metadata, verbatim, for extensions["hdf-merge"].sources[]. */
function sourceProvenance(index: number, src: MergeSource): Record<string, unknown> {
  const entry: Record<string, unknown> = { index, name: src.name };
  if (src.doc.tool !== undefined) entry.tool = src.doc.tool;
  if (src.doc.generator !== undefined) entry.generator = src.doc.generator;
  if (src.doc.timestamp !== undefined) entry.timestamp = src.doc.timestamp;
  if (src.doc.runner !== undefined) entry.runner = src.doc.runner;
  return entry;
}
