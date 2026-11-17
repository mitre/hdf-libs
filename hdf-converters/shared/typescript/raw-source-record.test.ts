import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, it, expect } from 'vitest';
import type { RawSourceRecord } from '@mitre/hdf-schema';
import {
  buildJsonRawSourceRecord,
  buildJsonRawSourceRecordFromValue,
  parseJSONPreservingNumbers,
  type RecordLayout,
} from './exportmap.js';

// The Go peer reads the same ../testdata/json-raw-source-record-cases.json.
interface Case {
  name: string;
  raw: string;
  pointer: string;
  layout: RecordLayout;
  want: RawSourceRecord | null;
}

const { cases } = JSON.parse(
  readFileSync(
    join(dirname(fileURLToPath(import.meta.url)), '..', 'testdata', 'json-raw-source-record-cases.json'),
    'utf-8',
  ),
) as { cases: Case[] };

describe('buildJsonRawSourceRecord', () => {
  it('has vectors to run', () => {
    expect(cases.length).toBeGreaterThan(0);
  });

  it.each(cases.map((c) => [c.name, c] as const))('%s', (_name, c) => {
    const parsed = c.raw === '' ? undefined : parseJSONPreservingNumbers(c.raw);
    expect(buildJsonRawSourceRecord(parsed, c.pointer, c.layout) ?? null).toEqual(c.want);
  });
});

describe('buildJsonRawSourceRecordFromValue', () => {
  // A projection keeps its own key order, as a Go struct keeps its declaration order.
  it('keeps the value key order', () => {
    const got = buildJsonRawSourceRecordFromValue(
      { id: 'CVE-2024-0001', cvss: 9.8, description: 'a < b & c' },
      '/results/0/vulnerabilities/0',
      'indented',
    );
    expect(got).toEqual({
      content: '{\n  "id": "CVE-2024-0001",\n  "cvss": 9.8,\n  "description": "a < b & c"\n}',
      encoding: 'utf-8',
      mediaType: 'application/json',
      pointer: '/results/0/vulnerabilities/0',
    });
  });

  it('yields no record for an absent value', () => {
    expect(buildJsonRawSourceRecordFromValue(undefined, '/matches/0', 'compact')).toBeUndefined();
  });
});
