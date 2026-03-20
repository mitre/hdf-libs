import { describe, it, expect } from 'vitest';
import { diffSboms } from '../src/sbom.js';

const oldCycloneDX = JSON.stringify({
  bomFormat: 'CycloneDX',
  specVersion: '1.5',
  version: 1,
  components: [
    { type: 'library', name: 'lodash', version: '4.17.20', purl: 'pkg:npm/lodash@4.17.20' },
    { type: 'library', name: 'express', version: '4.18.0', purl: 'pkg:npm/express@4.18.0' },
    { type: 'library', name: 'old-lib', version: '1.0.0', purl: 'pkg:npm/old-lib@1.0.0' },
  ],
});

const newCycloneDX = JSON.stringify({
  bomFormat: 'CycloneDX',
  specVersion: '1.5',
  version: 1,
  components: [
    { type: 'library', name: 'lodash', version: '4.17.21', purl: 'pkg:npm/lodash@4.17.21' },
    { type: 'library', name: 'express', version: '4.18.0', purl: 'pkg:npm/express@4.18.0' },
    { type: 'library', name: 'new-lib', version: '2.0.0', purl: 'pkg:npm/new-lib@2.0.0' },
  ],
});

describe('diffSboms', () => {
  describe('CycloneDX comparison', () => {
    it('should detect updated packages (version change)', () => {
      const result = diffSboms(oldCycloneDX, newCycloneDX);
      const lodash = result.packageDiffs.find(d => d.name === 'lodash');
      expect(lodash).toBeDefined();
      expect(lodash!.state).toBe('updated');
      expect(lodash!.oldVersion).toBe('4.17.20');
      expect(lodash!.newVersion).toBe('4.17.21');
    });

    it('should detect unchanged packages', () => {
      const result = diffSboms(oldCycloneDX, newCycloneDX);
      const express = result.packageDiffs.find(d => d.name === 'express');
      expect(express).toBeDefined();
      expect(express!.state).toBe('unchanged');
    });

    it('should detect removed packages', () => {
      const result = diffSboms(oldCycloneDX, newCycloneDX);
      const oldLib = result.packageDiffs.find(d => d.name === 'old-lib');
      expect(oldLib).toBeDefined();
      expect(oldLib!.state).toBe('removed');
      expect(oldLib!.oldVersion).toBe('1.0.0');
    });

    it('should detect added packages', () => {
      const result = diffSboms(oldCycloneDX, newCycloneDX);
      const newLib = result.packageDiffs.find(d => d.name === 'new-lib');
      expect(newLib).toBeDefined();
      expect(newLib!.state).toBe('added');
      expect(newLib!.newVersion).toBe('2.0.0');
    });

    it('should produce correct counts', () => {
      const result = diffSboms(oldCycloneDX, newCycloneDX);
      expect(result.added).toBe(1);
      expect(result.removed).toBe(1);
      expect(result.updated).toBe(1);
      expect(result.unchanged).toBe(1);
    });

    it('should sort diffs by name', () => {
      const result = diffSboms(oldCycloneDX, newCycloneDX);
      for (let i = 1; i < result.packageDiffs.length; i++) {
        expect(result.packageDiffs[i - 1]!.name <= result.packageDiffs[i]!.name).toBe(true);
      }
    });
  });

  describe('identical SBOMs', () => {
    it('should report all packages as unchanged', () => {
      const result = diffSboms(oldCycloneDX, oldCycloneDX);
      expect(result.added).toBe(0);
      expect(result.removed).toBe(0);
      expect(result.updated).toBe(0);
      expect(result.unchanged).toBe(3);
    });
  });

  describe('empty SBOMs', () => {
    it('should produce empty result for two empty SBOMs', () => {
      const empty = JSON.stringify({
        bomFormat: 'CycloneDX',
        specVersion: '1.5',
        version: 1,
        components: [],
      });
      const result = diffSboms(empty, empty);
      expect(result.packageDiffs).toHaveLength(0);
      expect(result.added).toBe(0);
      expect(result.removed).toBe(0);
      expect(result.updated).toBe(0);
      expect(result.unchanged).toBe(0);
    });
  });

  describe('all removed', () => {
    it('should mark all packages as removed when new SBOM is empty', () => {
      const empty = JSON.stringify({
        bomFormat: 'CycloneDX',
        specVersion: '1.5',
        version: 1,
        components: [],
      });
      const result = diffSboms(oldCycloneDX, empty);
      expect(result.removed).toBe(3);
      expect(result.added).toBe(0);
    });
  });

  describe('all added', () => {
    it('should mark all packages as added when old SBOM is empty', () => {
      const empty = JSON.stringify({
        bomFormat: 'CycloneDX',
        specVersion: '1.5',
        version: 1,
        components: [],
      });
      const result = diffSboms(empty, newCycloneDX);
      expect(result.added).toBe(3);
      expect(result.removed).toBe(0);
    });
  });

  describe('SPDX format', () => {
    const oldSpdx = JSON.stringify({
      spdxVersion: 'SPDX-2.3',
      dataLicense: 'CC0-1.0',
      SPDXID: 'SPDXRef-DOCUMENT',
      packages: [
        {
          SPDXID: 'SPDXRef-lodash',
          name: 'lodash',
          versionInfo: '4.17.20',
          externalRefs: [
            { referenceCategory: 'PACKAGE-MANAGER', referenceType: 'purl', referenceLocator: 'pkg:npm/lodash@4.17.20' },
          ],
          licenseConcluded: 'MIT',
        },
        {
          SPDXID: 'SPDXRef-express',
          name: 'express',
          versionInfo: '4.18.0',
          externalRefs: [
            { referenceCategory: 'PACKAGE-MANAGER', referenceType: 'purl', referenceLocator: 'pkg:npm/express@4.18.0' },
          ],
          licenseConcluded: 'MIT',
        },
      ],
    });

    const newSpdx = JSON.stringify({
      spdxVersion: 'SPDX-2.3',
      dataLicense: 'CC0-1.0',
      SPDXID: 'SPDXRef-DOCUMENT',
      packages: [
        {
          SPDXID: 'SPDXRef-lodash',
          name: 'lodash',
          versionInfo: '4.17.21',
          externalRefs: [
            { referenceCategory: 'PACKAGE-MANAGER', referenceType: 'purl', referenceLocator: 'pkg:npm/lodash@4.17.21' },
          ],
          licenseConcluded: 'MIT',
        },
        {
          SPDXID: 'SPDXRef-axios',
          name: 'axios',
          versionInfo: '1.6.0',
          externalRefs: [
            { referenceCategory: 'PACKAGE-MANAGER', referenceType: 'purl', referenceLocator: 'pkg:npm/axios@1.6.0' },
          ],
          licenseConcluded: 'MIT',
        },
      ],
    });

    it('should parse and compare SPDX documents', () => {
      const result = diffSboms(oldSpdx, newSpdx);
      expect(result.updated).toBe(1);   // lodash
      expect(result.removed).toBe(1);   // express
      expect(result.added).toBe(1);     // axios
      expect(result.unchanged).toBe(0);
    });

    it('should extract PURL from SPDX externalRefs', () => {
      const result = diffSboms(oldSpdx, newSpdx);
      const lodash = result.packageDiffs.find(d => d.name === 'lodash');
      expect(lodash).toBeDefined();
      expect(lodash!.purl).toContain('pkg:npm/lodash');
    });

    it('should extract licenses from SPDX', () => {
      const result = diffSboms(oldSpdx, newSpdx);
      const axios = result.packageDiffs.find(d => d.name === 'axios');
      expect(axios).toBeDefined();
      expect(axios!.licenses).toContain('MIT');
    });
  });

  describe('CycloneDX licenses', () => {
    it('should extract licenses from CycloneDX components', () => {
      const withLicenses = JSON.stringify({
        bomFormat: 'CycloneDX',
        specVersion: '1.5',
        version: 1,
        components: [
          {
            type: 'library',
            name: 'pkg-a',
            version: '1.0.0',
            licenses: [{ license: { id: 'MIT' } }],
          },
        ],
      });
      const empty = JSON.stringify({
        bomFormat: 'CycloneDX',
        specVersion: '1.5',
        version: 1,
        components: [],
      });
      const result = diffSboms(empty, withLicenses);
      const pkgA = result.packageDiffs.find(d => d.name === 'pkg-a');
      expect(pkgA).toBeDefined();
      expect(pkgA!.licenses).toContain('MIT');
    });
  });

  describe('error handling', () => {
    it('should throw for invalid JSON', () => {
      expect(() => diffSboms('not json', newCycloneDX)).toThrow();
    });

    it('should throw for unrecognized SBOM format', () => {
      const badDoc = JSON.stringify({ someField: 'value' });
      expect(() => diffSboms(badDoc, badDoc)).toThrow('Unrecognized SBOM format');
    });
  });

  describe('PURL in output', () => {
    it('should include PURL strings when available', () => {
      const result = diffSboms(oldCycloneDX, newCycloneDX);
      const hasPurl = result.packageDiffs.some(d => d.purl.includes('pkg:'));
      expect(hasPurl).toBe(true);
    });
  });
});
