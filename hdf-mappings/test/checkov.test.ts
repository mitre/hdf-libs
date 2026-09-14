import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterEach, describe, it, expect } from 'vitest';
import {
  getCheckovCciNistMapping,
  checkovCheckExists,
  getAllCheckovCheckIds,
  getCheckovMappingProvenance,
} from '../src/checkov/index.js';
import * as mainIndex from '../src/index.js';
import { setCurrentNistRevision, resetNistRevision } from '../src/nist/index.js';

const GO_DATASET = join(dirname(fileURLToPath(import.meta.url)), '..', 'go', 'checkov', 'checkov-cci-nist-mappings.json');

describe('Checkov check_id to CCI/NIST mappings', () => {
  afterEach(() => {
    resetNistRevision();
  });

  it('returns the mapped CCI and NIST controls for a check', () => {
    expect(getCheckovCciNistMapping('CKV_AWS_18')).toEqual({
      cci: ['CCI-000130', 'CCI-000169'],
      nist: ['AU-2', 'AU-12'],
    });
  });

  it('preserves the source order of both lists', () => {
    expect(getCheckovCciNistMapping('CKV_AWS_145')).toEqual({
      cci: ['CCI-002476', 'CCI-002451'],
      nist: ['SC-28(1)', 'SC-12(1)'],
    });
  });

  it('returns undefined for an unmapped check', () => {
    expect(getCheckovCciNistMapping('CKV_DOES_NOT_EXIST')).toBeUndefined();
    expect(getCheckovCciNistMapping('')).toBeUndefined();
  });

  it('returns copies that callers cannot use to mutate the dataset', () => {
    const m = getCheckovCciNistMapping('CKV_AWS_18')!;
    m.cci[0] = 'mutated';
    m.nist[0] = 'mutated';
    expect(getCheckovCciNistMapping('CKV_AWS_18')).toEqual({
      cci: ['CCI-000130', 'CCI-000169'],
      nist: ['AU-2', 'AU-12'],
    });
  });

  it('translates NIST controls to the current revision and leaves CCIs unchanged', () => {
    expect(getCheckovCciNistMapping('CKV_TF_1')?.nist).toEqual(['SI-7(6)', 'SR-3']);
    // SR-3 is Rev 5 only; the crosswalk redirects it to its Rev 4 origins.
    setCurrentNistRevision(4);
    expect(getCheckovCciNistMapping('CKV_TF_1')).toEqual({
      cci: ['CCI-002705', 'CCI-003610'],
      nist: ['SI-7(6)', 'SA-12(3)', 'SA-12(15)'],
    });
  });

  it('reports whether a check is mapped', () => {
    expect(checkovCheckExists('CKV2_AWS_6')).toBe(true);
    expect(checkovCheckExists('CKV_DOES_NOT_EXIST')).toBe(false);
  });

  it('lists all 1341 mapped check ids, sorted', () => {
    const ids = getAllCheckovCheckIds();
    expect(ids).toHaveLength(1341);
    expect(ids).toEqual([...ids].sort());
    expect(ids[0]).toBe('CKV2_ADO_1');
  });

  it('records the dataset provenance', () => {
    const p = getCheckovMappingProvenance();
    expect(p.checkovVersion).toBe('3.2.506');
    expect(p.nistRevision).toBe(5);
    expect(p.source.package).toBe('@mitre/hdf-converters');
    expect(p.source.version).toBe('2.14.0');
  });

  it('reads the same dataset file the Go loader embeds', () => {
    const goDataset = JSON.parse(readFileSync(GO_DATASET, 'utf-8')) as { mappings: Record<string, unknown> };
    expect(getAllCheckovCheckIds()).toEqual(Object.keys(goDataset.mappings).sort());
    for (const id of Object.keys(goDataset.mappings)) {
      expect(getCheckovCciNistMapping(id, 5)).toEqual(goDataset.mappings[id]);
    }
  });

  it('is exported from the package entry point', () => {
    expect(mainIndex.getCheckovCciNistMapping('CKV_AWS_18')?.nist).toEqual(['AU-2', 'AU-12']);
    expect(mainIndex.checkovCheckExists('CKV_AWS_18')).toBe(true);
    expect(mainIndex.getAllCheckovCheckIds()).toHaveLength(1341);
    expect(mainIndex.getCheckovMappingProvenance().checkovVersion).toBe('3.2.506');
  });
});
