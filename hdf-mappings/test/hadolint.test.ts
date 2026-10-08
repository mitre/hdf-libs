import { describe, expect, it, vi } from 'vitest';
import {
  getAllHadolintRuleIds,
  getHadolintMappingProvenance,
  getHadolintNistMapping,
  hadolintRuleExists,
} from '../src/hadolint/index.js';

// Twin of go/hadolint/hadolint_test.go.
describe('hadolint NIST mappings', () => {
  it('maps a hadolint rule and a shellcheck rule from one table', () => {
    expect(getHadolintNistMapping('DL3002')?.nist).toEqual(['AC-6']);
    expect(getHadolintNistMapping('SC2154')?.nist).toEqual(['SA-11']);
  });

  it('returns undefined for an unmapped rule', () => {
    expect(getHadolintNistMapping('DL9999')).toBeUndefined();
    expect(getHadolintNistMapping('')).toBeUndefined();
    expect(getHadolintNistMapping('DL1000')).toBeUndefined();
  });

  it('never hands back a list aliasing the dataset', () => {
    const first = getHadolintNistMapping('DL3002')!;
    first.nist[0] = 'MUTATED';
    expect(getHadolintNistMapping('DL3002')?.nist).toEqual(['AC-6']);
  });

  it('reports rule existence', () => {
    expect(hadolintRuleExists('DL1001')).toBe(true);
    expect(hadolintRuleExists('SC1000')).toBe(true);
    expect(hadolintRuleExists('nope')).toBe(false);
  });

  it('lists every rule, sorted, as a copy', () => {
    const ids = getAllHadolintRuleIds();
    expect(ids).toHaveLength(105);
    expect([...ids].sort()).toEqual(ids);
    expect(ids).toContain('DL3002');
    expect(ids).toContain('SC2154');
    ids[0] = 'MUTATED';
    expect(getAllHadolintRuleIds()[0]).not.toBe('MUTATED');
  });

  it('exposes provenance', () => {
    const p = getHadolintMappingProvenance();
    expect(p.nistRevision).toBe(5);
    expect(p.source.commit).toBe('68b34a03b8746311925766da8bbb7a7490a39cb1');
    expect(p.source.sha256).toBeTruthy();
    expect(p.updated).toBeTruthy();
  });

  // The table is authored at Rev 5. SR-4 has no Rev 4 equivalent and drops to
  // an empty list; a caller seeing that must use its own fallback rather than
  // emit an empty nist tag.
  it('drops the Rev 5 supply-chain controls at Rev 4', () => {
    expect(getHadolintNistMapping('DL3026', 4)?.nist).toEqual(['SA-12(3)', 'SA-12(15)']);
    expect(getHadolintNistMapping('DL3055', 4)?.nist).toEqual([]);
    expect(getHadolintNistMapping('DL3002', 4)?.nist).toEqual(['AC-6']);
  });

  it('is reachable from the package barrel', async () => {
    const barrel = await import('../src/index.js');
    expect(barrel.getHadolintNistMapping('DL3002')?.nist).toEqual(['AC-6']);
    expect(barrel.hadolintRuleExists('DL3002')).toBe(true);
    expect(barrel.getAllHadolintRuleIds()).toHaveLength(105);
    expect(barrel.getHadolintMappingProvenance().nistRevision).toBe(5);
  });

  it('loads on first call after a module reset', async () => {
    vi.resetModules();
    const { getHadolintNistMapping: getFresh } = await import('../src/hadolint/index.js');
    expect(getFresh('DL3002')?.nist).toEqual(['AC-6']);
  });
});
