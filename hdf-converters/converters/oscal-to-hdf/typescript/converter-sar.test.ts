import type { Component, HDFResults } from '@mitre/hdf-schema';
import { validateResults } from '@mitre/hdf-validators';
import { describe, it, expect, vi } from 'vitest';
import { cloudProviderValues } from './component-props.js';
import { convertOscalSarToHdf } from './converter-sar.js';

const HDF_NS = 'https://mitre.github.io/hdf-libs/ns/oscal';

/** Builds a one-result SAR from raw findings and observations. Mirrors the Go sarWithProse. */
function sar(findings: unknown[], observations: unknown[]): string {
  return JSON.stringify({
    'assessment-results': {
      uuid: '11111111-1111-4111-8111-111111111111',
      metadata: { title: 't', 'last-modified': '2026-01-01T00:00:00Z', version: '1', 'oscal-version': '1.1.2' },
      'import-ap': { href: '#' },
      results: [
        {
          uuid: '22222222-2222-4222-8222-222222222222',
          title: 'r',
          description: 'd',
          start: '2026-01-01T00:00:00Z',
          'reviewed-controls': { 'control-selections': [{ 'include-all': {} }] },
          findings,
          observations,
          risks: [],
        },
      ],
    },
  });
}

const satisfiedFinding = (observationUuid: string) => ({
  uuid: 'f1',
  title: 't',
  description: 'd',
  target: { type: 'objective-id', 'target-id': 'ac-1', status: { state: 'satisfied' } },
  'related-observations': [{ 'observation-uuid': observationUuid }],
});

const observationWithSubjects = (subjects: unknown[]) => ({
  uuid: 'o1',
  description: 'd',
  methods: ['TEST'],
  collected: '2026-01-01T00:00:00Z',
  subjects,
});

const hdfProp = (name: string, value: string, extra: Record<string, unknown> = {}) => ({ name, ns: HDF_NS, value, ...extra });

/**
 * Imports the document and returns its sole component with everything the
 * converter warned. The result is schema-checked, because the point of the guards
 * is that a foreign subject cannot produce HDF the validator rejects.
 */
async function importComponentWithWarnings(input: string): Promise<{ component: Component; warnings: string[] }> {
  const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
  const doc = JSON.parse(await convertOscalSarToHdf(input)) as HDFResults;
  const warnings = warn.mock.calls.map((c) => String(c[0]));
  warn.mockRestore();

  const v = validateResults(doc);
  expect(v.valid, v.getErrorMessage()).toBe(true);
  expect(doc.components).toHaveLength(1);
  return { component: doc.components![0]!, warnings };
}

function sarWithComponentProp(subjectType: string, title: string, prop: string, value: string): string {
  return sar(
    [satisfiedFinding('o1')],
    [
      observationWithSubjects([
        { 'subject-uuid': 'a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d', type: subjectType, title, props: [hdfProp(prop, value)] },
      ]),
    ],
  );
}

describe('convertOscalSarToHdf component identity read-back', () => {
  // AC: a foreign component-port outside the decimal-integer grammar or the
  // schema's 1..65535 is dropped with a warning, and the document still validates.
  it.each(['80abc', '1e3', '0', '65536', ' 80'])('drops the invalid component-port %j with a warning', async (value) => {
    const { component, warnings } = await importComponentWithWarnings(
      sarWithComponentProp('database', 'db1', 'component-port', value),
    );
    expect(component.port, 'an out-of-domain port is not carried into HDF').toBeUndefined();
    expect(warnings).toContain(
      `WARNING: Dropping component-port ${JSON.stringify(value)} on component "db1": not a decimal integer in 1..65535`,
    );
  });

  it('keeps a valid component-port', async () => {
    const { component, warnings } = await importComponentWithWarnings(
      sarWithComponentProp('database', 'db1', 'component-port', '443'),
    );
    expect(component.port).toBe(443);
    expect(warnings.join('\n')).not.toContain('component-port');
  });

  // AC: a foreign component-provider outside the Cloud_Provider enum is dropped
  // with a warning instead of yielding HDF the validator rejects.
  it('drops a component-provider outside the Cloud_Provider enum with a warning', async () => {
    const { component, warnings } = await importComponentWithWarnings(
      sarWithComponentProp('cloudAccount', 'acct', 'component-provider', 'digitalocean'),
    );
    expect(component.provider, 'an out-of-enum provider is not carried into HDF').toBeUndefined();
    expect(warnings).toContain(
      `WARNING: Dropping component-provider "digitalocean" on component "acct": not one of ${cloudProviderValues().join(', ')}`,
    );
  });

  it('keeps a valid component-provider', async () => {
    const { component, warnings } = await importComponentWithWarnings(
      sarWithComponentProp('cloudAccount', 'acct', 'component-provider', 'aws'),
    );
    expect(component.provider).toBe('aws');
    expect(warnings.join('\n')).not.toContain('component-provider');
  });
});

// The Go peer is TestConvertAssessmentResultsToHDF_ReconstitutesAllComponents:
// cross-language importer equivalence rests on a mirrored test rather than only on
// the prop-table comparison.
describe('convertOscalSarToHdf component reconstitution', () => {
  it('reconstitutes every component from the SAR subjects', async () => {
    const input = sar(
      [satisfiedFinding('o1')],
      [
        observationWithSubjects([
          {
            'subject-uuid': 'a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d',
            type: 'host',
            title: 'web01',
            props: [
              hdfProp('component-os-name', 'Ubuntu'),
              hdfProp('component-os-version', '22.04 LTS'),
              hdfProp('component-label-key', 'environment', { group: 'component-label-1' }),
              hdfProp('component-label-value', 'production', { group: 'component-label-1' }),
            ],
          },
          {
            'subject-uuid': 'c1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d',
            type: 'cloudAccount',
            title: 'Prod AWS',
            props: [
              hdfProp('component-account-id', '123456789012'),
              hdfProp('component-region', 'us-east-1'),
              hdfProp('component-provider', 'aws'),
              hdfProp('component-label-key', 'boundary', { group: 'component-label-1' }),
              hdfProp('component-label-value', 'prod-authorization-boundary', { group: 'component-label-1' }),
            ],
          },
        ]),
      ],
    );

    const doc = JSON.parse(await convertOscalSarToHdf(input)) as HDFResults;
    expect(doc.components, 'importer must reconstitute every component from the SAR subjects').toHaveLength(2);
    const byName = new Map((doc.components ?? []).map((c) => [c.name, c]));

    const host = byName.get('web01');
    expect(host).toBeDefined();
    expect(host!.type).toBe('host');
    expect(host!.componentId).toBe('a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d');
    expect(host!.osName).toBe('Ubuntu');
    expect(host!.osVersion).toBe('22.04 LTS');
    expect(host!.labels?.environment).toBe('production');

    const acct = byName.get('Prod AWS');
    expect(acct).toBeDefined();
    expect(acct!.type).toBe('cloudAccount');
    expect(acct!.accountId).toBe('123456789012');
    expect(acct!.provider).toBe('aws');
    expect(acct!.labels?.boundary).toBe('prod-authorization-boundary');
  });

  // The Go peer is TestConvertAssessmentResultsToHDF_SkipsNonComponentSubjects.
  it('does not turn a non-HDF subject type into a component', async () => {
    const input = sar(
      [satisfiedFinding('o1')],
      [
        observationWithSubjects([
          { 'subject-uuid': 'a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d', type: 'inventory-item', title: 'asset' },
          { 'subject-uuid': 'b1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d', type: 'party', title: 'person' },
        ]),
      ],
    );
    const doc = JSON.parse(await convertOscalSarToHdf(input)) as HDFResults;
    expect(doc.components ?? []).toHaveLength(0);
  });
});
