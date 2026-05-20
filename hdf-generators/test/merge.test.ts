import { describe, it, expect } from 'vitest';
import { mergeRequirement, mergeTags, mergeDescriptions, mergeRefs } from '../src/merge.js';
import { makeRequirement } from './helpers.js';
import type { Reference } from '@mitre/hdf-schema';

describe('mergeRequirement', () => {
  it('should take scalars from upstream by default', () => {
    const current = makeRequirement({ id: 'V-001', title: 'Old title', impact: 0.5 });
    const upstream = makeRequirement({ id: 'SV-001', title: 'New title', impact: 0.7 });

    const merged = mergeRequirement(current, upstream);

    expect(merged.id).toBe('SV-001');
    expect(merged.title).toBe('New title');
    expect(merged.impact).toBe(0.7);
  });

  it('should preserve code from current by default', () => {
    const current = makeRequirement({
      id: 'V-001',
      code: "  describe command('test') do\n  end",
    });
    const upstream = makeRequirement({ id: 'SV-001' });

    const merged = mergeRequirement(current, upstream);

    expect(merged.code).toBe("  describe command('test') do\n  end");
  });

  it('should take scalars from current with prefer=current', () => {
    const current = makeRequirement({ id: 'V-001', title: 'Old title', impact: 0.5 });
    const upstream = makeRequirement({ id: 'SV-001', title: 'New title', impact: 0.7 });

    const merged = mergeRequirement(current, upstream, 'current');

    expect(merged.id).toBe('SV-001');
    expect(merged.title).toBe('Old title');
    expect(merged.impact).toBe(0.5);
  });

  it('should take code from upstream with prefer=upstream', () => {
    const current = makeRequirement({ id: 'V-001', code: '  # old test' });
    const upstream = makeRequirement({ id: 'SV-001', code: '  # new test' });

    const merged = mergeRequirement(current, upstream, 'upstream');

    expect(merged.code).toBe('  # new test');
  });

  it('should have nil code when neither side has code', () => {
    const current = makeRequirement({ id: 'V-001' });
    const upstream = makeRequirement({ id: 'SV-001' });

    const merged = mergeRequirement(current, upstream);

    expect(merged.code).toBeUndefined();
  });

  it('should take severity from upstream by default', () => {
    const current = makeRequirement({ id: 'V-001', severity: 'medium' });
    const upstream = makeRequirement({ id: 'SV-001', severity: 'high' });

    const merged = mergeRequirement(current, upstream);

    expect(merged.severity).toBe('high');
  });
});

describe('mergeTags', () => {
  it('should union with upstream winning key conflicts by default', () => {
    const current = { cci: ['CCI-000001'], custom: 'my-value', gtitle: 'Old SRG title' };
    const upstream = { cci: ['CCI-000001', 'CCI-000002'], gtitle: 'New SRG title', stig_id: 'RHEL-09-001234' };

    const merged = mergeTags(current, upstream);

    expect(merged.custom).toBe('my-value');
    expect(merged.gtitle).toBe('New SRG title');
    expect(merged.stig_id).toBe('RHEL-09-001234');
    expect(merged.cci).toEqual(['CCI-000001', 'CCI-000002']);
  });

  it('should let current win on conflict with prefer=current', () => {
    const current = { cci: ['CCI-000001'], custom: 'my-value', gtitle: 'Old SRG title' };
    const upstream = { cci: ['CCI-000001', 'CCI-000002'], gtitle: 'New SRG title', stig_id: 'RHEL-09-001234' };

    const merged = mergeTags(current, upstream, 'current');

    expect(merged.gtitle).toBe('Old SRG title');
    expect(merged.cci).toEqual(['CCI-000001']);
    expect(merged.stig_id).toBe('RHEL-09-001234');
  });

  it('should replace all with prefer=upstream', () => {
    const current = { custom: 'my-value', gtitle: 'Old SRG title' };
    const upstream = { gtitle: 'New SRG title', stig_id: 'RHEL-09-001234' };

    const merged = mergeTags(current, upstream, 'upstream');

    expect(merged.custom).toBeUndefined();
    expect(merged.gtitle).toBe('New SRG title');
    expect(merged.stig_id).toBe('RHEL-09-001234');
  });
});

describe('mergeDescriptions', () => {
  it('should union by label with upstream winning on conflict', () => {
    const current = [
      { label: 'default', data: 'Old default' },
      { label: 'check', data: 'Old check' },
      { label: 'custom', data: 'My custom desc' },
    ];
    const upstream = [
      { label: 'default', data: 'New default' },
      { label: 'check', data: 'New check' },
      { label: 'fix', data: 'New fix' },
    ];

    const merged = mergeDescriptions(current, upstream);

    const labels = Object.fromEntries(merged.map(d => [d.label, d.data]));
    expect(Object.keys(labels)).toHaveLength(4);
    expect(labels.default).toBe('New default');
    expect(labels.check).toBe('New check');
    expect(labels.custom).toBe('My custom desc');
    expect(labels.fix).toBe('New fix');
  });

  it('should let current win on conflict with prefer=current', () => {
    const current = [{ label: 'default', data: 'Old default' }];
    const upstream = [
      { label: 'default', data: 'New default' },
      { label: 'fix', data: 'New fix' },
    ];

    const merged = mergeDescriptions(current, upstream, 'current');

    const labels = Object.fromEntries(merged.map(d => [d.label, d.data]));
    expect(Object.keys(labels)).toHaveLength(2);
    expect(labels.default).toBe('Old default');
    expect(labels.fix).toBe('New fix');
  });

  it('should replace all with prefer=upstream', () => {
    const current = [
      { label: 'default', data: 'Old default' },
      { label: 'custom', data: 'My custom' },
    ];
    const upstream = [
      { label: 'default', data: 'New default' },
      { label: 'fix', data: 'New fix' },
    ];

    const merged = mergeDescriptions(current, upstream, 'upstream');

    const labels = Object.fromEntries(merged.map(d => [d.label, d.data]));
    expect(Object.keys(labels)).toHaveLength(2);
    expect(labels.default).toBe('New default');
    expect(labels.fix).toBe('New fix');
    expect(labels.custom).toBeUndefined();
  });
});

describe('mergeRefs', () => {
  it('should union and deduplicate by default', () => {
    const current: Reference[] = [{ url: 'https://example.com/ref1' }, { url: 'https://example.com/ref2' }];
    const upstream: Reference[] = [{ url: 'https://example.com/ref2' }, { url: 'https://example.com/ref3' }];

    const merged = mergeRefs(current, upstream);

    expect(merged).toHaveLength(3);
  });

  it('should keep only current with prefer=current', () => {
    const current: Reference[] = [{ url: 'https://example.com/ref1' }];
    const upstream: Reference[] = [{ url: 'https://example.com/ref2' }];

    const merged = mergeRefs(current, upstream, 'current');

    expect(merged).toHaveLength(1);
    expect(merged[0].url).toBe('https://example.com/ref1');
  });

  it('should keep only upstream with prefer=upstream', () => {
    const current: Reference[] = [{ url: 'https://example.com/ref1' }];
    const upstream: Reference[] = [{ url: 'https://example.com/ref2' }];

    const merged = mergeRefs(current, upstream, 'upstream');

    expect(merged).toHaveLength(1);
    expect(merged[0].url).toBe('https://example.com/ref2');
  });
});
