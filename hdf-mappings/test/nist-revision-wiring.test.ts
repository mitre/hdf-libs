import { describe, it, expect, afterEach } from 'vitest';
import {
  nistControlsAtRevision,
  setCurrentNistRevision,
  resetNistRevision,
  translateNistControl,
  getNessusNistControl,
  getHipcheckNistControls,
  getCCINistMappings,
  getAllNiktoMappings,
  getAllOwaspMappings,
  getAllScoutsuiteMappings,
} from '../src/index.js';

afterEach(() => resetNistRevision());

describe('nistControlsAtRevision', () => {
  it('is a no-op for same or unsupported revisions', () => {
    const input = ['AC-1', 'UM-1'];
    expect(nistControlsAtRevision(input, 4, 4)).toEqual(input);
    expect(nistControlsAtRevision(input, 3, 5)).toEqual(input);
  });

  it('follows redirects and passes identity through', () => {
    expect(nistControlsAtRevision(['AC-1', 'AU-8(1)'], 4, 5)).toEqual(['AC-1', 'SC-45(1)']);
  });

  it('keeps statement suffixes on identity, drops them on redirects', () => {
    expect(nistControlsAtRevision(['AC-1 a', 'TR-1 a', 'SC-19 a', 'SA-12.1 (i)'], 4, 5)).toEqual([
      'AC-1 a',
      'PT-5',
      'PT-5(1)',
    ]);
  });

  it('drops family/none outcomes and passes non-NIST placeholders through', () => {
    expect(nistControlsAtRevision(['SA-12', 'SC-19', 'UM-1'], 4, 5)).toEqual(['UM-1']);
  });

  it('dedups convergent redirects preserving first-seen order', () => {
    expect(nistControlsAtRevision(['IA-2(7)', 'IA-2(11)', 'IA-2(6)'], 4, 5)).toEqual(['IA-2(6)']);
  });
});

describe('revision-aware mapping lookups', () => {
  it('nessus translates AU-8(1) to SC-45(1) at the Rev 5 default', () => {
    expect(getNessusNistControl('Service detection', '10884')).toBe('SC-45(1)');
    setCurrentNistRevision(4);
    expect(getNessusNistControl('Service detection', '10884')).toBe('AU-8(1)');
  });

  it('nessus passes the UM-1 placeholder through untranslated', () => {
    expect(getNessusNistControl('Settings', '19506')).toBe('UM-1');
  });

  it('hipcheck drops SR-4 at Rev 4 (no Rev 4 equivalent)', () => {
    expect(getHipcheckNistControls('mitre/binary')).toEqual(['SI-7', 'SR-4']);
    setCurrentNistRevision(4);
    expect(getHipcheckNistControls('mitre/binary')).toEqual(['SI-7']);
  });

  it('cci follows Appendix J pointers at Rev 5 and stays raw at Rev 4', () => {
    expect(getCCINistMappings('CCI-003556')).toEqual(['PT-5', 'PT-5(1)']); // "TR-1 a"
    expect(getCCINistMappings('CCI-000722')).toEqual([]); // "SA-12" — family, no expansion
    setCurrentNistRevision(4);
    expect(getCCINistMappings('CCI-003556')).toEqual(['TR-1 a']);
  });
});

describe('revision-neutrality guards', () => {
  // These tables perform no useful translation only because every control they
  // carry is identical at Rev 4 and Rev 5. If one of these fails, a newly
  // added control diverges across revisions and the mapping's revision
  // handling must be revisited.
  const assertNeutral = (label: string, controls: string[]) => {
    for (const c of controls) {
      expect(
        translateNistControl(c.trim(), 4, 5).relation,
        `${label}: ${c} must be revision-neutral`
      ).toBe('identity');
    }
  };

  it('nikto table is revision-neutral', () => {
    assertNeutral('nikto', Object.values(getAllNiktoMappings()).flatMap((v) => v.split('|')));
  });

  it('owasp table is revision-neutral', () => {
    assertNeutral(
      'owasp',
      getAllOwaspMappings().flatMap((m) => m['NIST-ID'].split('|'))
    );
  });

  it('scoutsuite table is revision-neutral', () => {
    assertNeutral(
      'scoutsuite',
      getAllScoutsuiteMappings().flatMap((m) => m['NIST-ID'].split('|'))
    );
  });
});
