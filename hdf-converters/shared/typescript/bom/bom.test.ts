import { readFileSync } from 'fs';
import { dirname, join } from 'path';
import { fileURLToPath } from 'url';
import { describe, it, expect } from 'vitest';
import Ajv2020, { type ValidateFunction } from 'ajv/dist/2020.js';
import addFormats from 'ajv-formats';
import {
  BOMType,
  buildBom,
  detectCycloneDX,
  detectCycloneDXML,
  detectFormat,
  detectSPDX,
  enrichFromPurl,
  parseBom,
  parseCycloneDX,
  parseMLBOM,
  parseSPDX,
  type BillOfMaterials,
  type SBOMPackage,
} from './index.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const FIXTURES_DIR = join(__dirname, '..', '..', 'bom-fixtures');
const PRIMITIVES_DIR = join(__dirname, '..', '..', '..', '..', 'hdf-schema', 'src', 'schemas', 'primitives');

function loadFixture(name: string): string {
  return readFileSync(join(FIXTURES_DIR, name), 'utf-8');
}

function loadSchema(name: string): Record<string, unknown> {
  return JSON.parse(readFileSync(join(PRIMITIVES_DIR, name), 'utf-8')) as Record<string, unknown>;
}

/**
 * Compile a validator for the Bom definition against the shipped primitive
 * schemas (bom + common, which Bom $refs for Checksum). This is the round-trip
 * gate: buildBom output must validate against the real schema, including the
 * three-tier if/else discipline.
 */
const bomSchema = loadSchema('bom.schema.json');
const commonSchema = loadSchema('common.schema.json');
const ajv = new Ajv2020({ strict: false, allErrors: true, validateFormats: true });
addFormats(ajv);
ajv.addSchema(commonSchema);
ajv.addSchema(bomSchema);
const validateBomDef: ValidateFunction = ajv.compile({ $ref: `${bomSchema.$id as string}#/$defs/Bom` });

function expectValidBom(bom: BillOfMaterials): void {
  const roundTripped = JSON.parse(JSON.stringify(bom)) as unknown;
  const valid = validateBomDef(roundTripped);
  expect(valid, JSON.stringify(validateBomDef.errors)).toBe(true);
}

function pkgByName(packages: SBOMPackage[] | undefined, name: string): SBOMPackage {
  const found = (packages ?? []).find(p => p.name === name);
  expect(found, `expected package ${name}`).toBeDefined();
  return found!;
}

const CYCLONEDX = loadFixture('cyclonedx-sbom.json');
const SPDX = loadFixture('spdx-sbom.json');
const MLBOM = loadFixture('cyclonedx-mlbom.json');

// Guards that the round-trip gate is meaningful: the schema validator must
// REJECT invalid BOMs, else the expectValidBom(...) assertions prove nothing.
describe('round-trip validator rejects invalid BOMs', () => {
  it('rejects a BOM missing bomType', () => {
    expect(validateBomDef({ format: 'cyclonedx', ref: './x.json' })).toBe(false);
  });
  it('rejects an unknown bomType', () => {
    expect(validateBomDef({ bomType: 'vex', format: 'cyclonedx' })).toBe(false);
  });
  it('rejects a three-tier violation (model extension on an sbom BOM)', () => {
    expect(validateBomDef({ bomType: 'sbom', format: 'cyclonedx', model: { parameterCount: 1 } })).toBe(false);
  });
});

describe('detectFormat', () => {
  it('detects CycloneDX', () => {
    expect(detectCycloneDX(JSON.parse(CYCLONEDX))).toBe(1);
    expect(detectFormat(JSON.parse(CYCLONEDX))).toEqual({ format: 'cyclonedx', confidence: 1 });
  });

  it('detects SPDX', () => {
    expect(detectSPDX(JSON.parse(SPDX))).toBe(1);
    expect(detectFormat(JSON.parse(SPDX))).toEqual({ format: 'spdx', confidence: 1 });
  });

  it('detects an ML-BOM as cyclonedx-ml, not plain cyclonedx (precedence)', () => {
    const parsed = JSON.parse(MLBOM);
    expect(detectCycloneDX(parsed)).toBe(1);
    expect(detectCycloneDXML(parsed)).toBe(1);
    expect(detectFormat(parsed)).toEqual({ format: 'cyclonedx-ml', confidence: 1 });
  });

  it('returns 0 / undefined for non-BOM input', () => {
    expect(detectCycloneDX(null)).toBe(0);
    expect(detectCycloneDX([1, 2])).toBe(0);
    expect(detectCycloneDXML({ bomFormat: 'CycloneDX' })).toBe(0);
    expect(detectCycloneDXML({ bomFormat: 'CycloneDX', components: 'nope' })).toBe(0);
    expect(detectSPDX({ spdxVersion: '' })).toBe(0);
    expect(detectFormat({ foo: 'bar' })).toBeUndefined();
  });
});

describe('parseBom — CycloneDX SBOM', () => {
  const { format, normalized } = parseBom(CYCLONEDX);

  it('reports the format and sbom bomType', () => {
    expect(format).toBe('cyclonedx');
    expect(normalized.bomType).toBe(BOMType.Sbom);
    expect(normalized.format).toBe('cyclonedx');
  });

  it('maps every top-level component to a package', () => {
    expect(normalized.packages).toHaveLength(5);
    expect(normalized.model).toBeUndefined();
    expect(normalized.dataset).toBeUndefined();
  });

  it('pins body-parser@1.20.4 with purl and MIT license', () => {
    const bodyParser = pkgByName(normalized.packages, 'body-parser');
    expect(bodyParser.version).toBe('1.20.4');
    expect(bodyParser.purl).toBe('pkg:npm/body-parser@1.20.4');
    expect(bodyParser.licenses).toEqual(['MIT']);
  });

  it('has no uniqueId (fixture carries no serialNumber)', () => {
    expect(normalized.uniqueId).toBeUndefined();
  });

  it('produces schema-valid output', () => {
    expectValidBom(buildBom({ bomType: BOMType.Sbom, format: 'cyclonedx', packages: normalized.packages }));
  });
});

describe('parseBom — SPDX SBOM', () => {
  const { format, normalized } = parseBom(SPDX);

  it('reports the format and sbom bomType', () => {
    expect(format).toBe('spdx');
    expect(normalized.bomType).toBe(BOMType.Sbom);
  });

  it('uses documentNamespace as uniqueId', () => {
    expect(normalized.uniqueId).toBe(
      'http://spdx.org/spdxdocs/tools-java/v1.1.5-444504E0-4F89-41D3-9A0C-0305E82C3301',
    );
  });

  it('pins tools-java 1.5.1 with a github purl', () => {
    expect(normalized.packages).toHaveLength(2);
    const toolsJava = pkgByName(normalized.packages, 'tools-java');
    expect(toolsJava.version).toBe('1.5.1');
    expect(toolsJava.purl).toBe(
      'pkg:github/spdx/tools-java@2235d5d7f7fe46ce1e0d54b7831c5681633b25cc',
    );
  });

  it('pins xlsx 0.16.6 with a maven purl', () => {
    const xlsx = pkgByName(normalized.packages, 'xlsx');
    expect(xlsx.version).toBe('0.16.6');
    expect(xlsx.purl).toBe('pkg:maven/org.webjars.npm/xlsx@0.16.6');
  });

  it('omits licenses when the source has none', () => {
    expect(pkgByName(normalized.packages, 'tools-java').licenses).toBeUndefined();
  });

  it('produces schema-valid output', () => {
    expectValidBom(buildBom({ bomType: BOMType.Sbom, format: 'spdx', packages: normalized.packages, uniqueId: normalized.uniqueId }));
  });
});

describe('parseBom — CycloneDX ML-BOM', () => {
  const { format, normalized } = parseBom(MLBOM);

  it('reports cyclonedx-ml and ai-model bomType', () => {
    expect(format).toBe('cyclonedx-ml');
    expect(normalized.bomType).toBe(BOMType.AIModel);
    expect(normalized.format).toBe('cyclonedx-ml');
  });

  it('populates the model extension and carries NO packages', () => {
    expect(normalized.packages).toBeUndefined();
    expect(normalized.dataset).toBeUndefined();
    expect(normalized.model).toBeDefined();
    expect(normalized.model?.modelArchitecture).toBe('The architecture of the model.');
    expect(normalized.model?.intendedUse).toContain('Text-to-image generation for creative applications');
  });

  it('never fabricates parameterCount or serializationFormat', () => {
    expect(normalized.model?.parameterCount).toBeUndefined();
    expect(normalized.model?.serializationFormat).toBeUndefined();
  });

  it('carries the raw model component via document passthrough', () => {
    expect(normalized.document).toBeDefined();
    expect((normalized.document as Record<string, unknown>).type).toBe('machine-learning-model');
  });

  it('uses serialNumber as uniqueId', () => {
    expect(normalized.uniqueId).toBe('urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79');
  });

  it('produces schema-valid output', () => {
    expectValidBom(
      buildBom({
        bomType: BOMType.AIModel,
        format: 'cyclonedx-ml',
        model: normalized.model,
        document: normalized.document as Record<string, unknown>,
        uniqueId: normalized.uniqueId,
      }),
    );
  });
});

// Parametrized robustness sweep over the real CycloneDX-ML fixture set (spec
// versions 1.5/1.6/1.7, a considerations-only card, and a sparse trim). Every
// variant must detect as cyclonedx-ml and normalize to ai-model without ever
// fabricating parameterCount/serializationFormat/modelArchitecture.
interface MLFixtureCase {
  file: string;
  /** Expected modelArchitecture, or undefined when the source provides none. */
  modelArchitecture?: string;
  /** True when the normalized model extension must be exactly {} (partial-fidelity). */
  emptyModel: boolean;
}

const ML_FIXTURES: MLFixtureCase[] = [
  { file: 'cyclonedx-mlbom.json', modelArchitecture: 'The architecture of the model.', emptyModel: false },
  { file: 'cyclonedx-mlbom-1.5.json', modelArchitecture: 'The architecture of the model.', emptyModel: false },
  { file: 'cyclonedx-mlbom-1.7.json', modelArchitecture: 'The architecture of the model.', emptyModel: false },
  { file: 'cyclonedx-mlbom-considerations-1.6.json', emptyModel: true },
  { file: 'cyclonedx-mlbom-sparse.json', emptyModel: true },
];

describe.each(ML_FIXTURES)('parseBom — CycloneDX-ML fixture $file', fx => {
  const { format, normalized } = parseBom(loadFixture(fx.file));

  it('detects cyclonedx-ml and normalizes to ai-model', () => {
    expect(format).toBe('cyclonedx-ml');
    expect(normalized.bomType).toBe(BOMType.AIModel);
    expect(normalized.format).toBe('cyclonedx-ml');
  });

  it('never fabricates parameterCount, serializationFormat, or modelArchitecture', () => {
    expect(normalized.model?.parameterCount).toBeUndefined();
    expect(normalized.model?.serializationFormat).toBeUndefined();
    if (fx.modelArchitecture === undefined) {
      expect(normalized.model?.modelArchitecture).toBeUndefined();
    }
  });

  it('pins modelArchitecture when the source provides one', () => {
    if (fx.modelArchitecture !== undefined) {
      expect(normalized.model?.modelArchitecture).toBe(fx.modelArchitecture);
    }
  });

  it('carries a minimal/empty model extension for partial-fidelity sources', () => {
    if (fx.emptyModel) {
      expect(normalized.model).toEqual({});
    }
  });

  it('produces schema-valid output', () => {
    expectValidBom(
      buildBom({
        bomType: BOMType.AIModel,
        format: 'cyclonedx-ml',
        model: normalized.model,
        document: normalized.document as Record<string, unknown> | undefined,
        uniqueId: normalized.uniqueId,
      }),
    );
  });
});

describe('buildBom three-tier discipline', () => {
  it('drops a model extension on an sbom BOM', () => {
    const bom = buildBom({
      bomType: BOMType.Sbom,
      format: 'cyclonedx',
      packages: [{ name: 'x', version: '1.0.0' }],
      model: { modelArchitecture: 'transformer' },
    });
    expect(bom.model).toBeUndefined();
    expect(bom.packages).toHaveLength(1);
    expectValidBom(bom);
  });

  it('drops packages/dataset on an ai-model BOM', () => {
    const bom = buildBom({
      bomType: BOMType.AIModel,
      format: 'cyclonedx-ml',
      model: { modelArchitecture: 'diffusion' },
      packages: [{ name: 'x' }],
      dataset: { recordCount: 1 },
    });
    expect(bom.packages).toBeUndefined();
    expect(bom.dataset).toBeUndefined();
    expect(bom.model?.modelArchitecture).toBe('diffusion');
    expectValidBom(bom);
  });

  it('keeps a dataset extension only on a dataset BOM', () => {
    const bom = buildBom({
      bomType: BOMType.Dataset,
      format: 'croissant',
      dataset: { recordCount: 100, derivation: undefined },
      ref: 'https://example.com/ds.json',
      license: 'CC0-1.0',
    });
    expect(bom.dataset?.recordCount).toBe(100);
    expect(bom.ref).toBe('https://example.com/ds.json');
    expect(bom.license).toBe('CC0-1.0');
    expectValidBom(bom);
  });

  it('carries hashes when provided and non-empty', () => {
    const bom = buildBom({
      bomType: BOMType.Sbom,
      format: 'spdx',
      packages: [],
      hashes: [{ algorithm: 'sha256', value: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855' } as never],
    });
    expect(bom.hashes).toHaveLength(1);
    expectValidBom(bom);
  });
});

describe('parseBom errors and edge cases', () => {
  it('throws on undetectable input', () => {
    expect(() => parseBom('{"foo":"bar"}')).toThrow(/could not detect a supported BOM format/);
  });

  it('validates input size before parsing (rejects oversized input)', () => {
    const huge = `{"bomFormat":"CycloneDX","pad":"${'a'.repeat(60 * 1024 * 1024)}"}`;
    expect(() => parseBom(huge)).toThrow(/exceeds maximum allowed size/);
  });

  it('re-parsing is stable', () => {
    const a = parseBom(CYCLONEDX).normalized;
    const b = parseBom(CYCLONEDX).normalized;
    expect(a).toEqual(b);
  });

  it('tolerates a CycloneDX doc with no components', () => {
    const normalized = parseCycloneDX({ bomFormat: 'CycloneDX' });
    expect(normalized.packages).toEqual([]);
  });

  it('skips SPDX packages with no name', () => {
    const normalized = parseSPDX({ packages: [{ versionInfo: '1.0.0' }, { name: 'ok' }] });
    expect(normalized.packages).toHaveLength(1);
    expect(normalized.packages?.[0]?.name).toBe('ok');
  });

  it('handles an ML-BOM with no machine-learning-model component', () => {
    const normalized = parseMLBOM({ components: [{ type: 'library', name: 'x' }] });
    expect(normalized.bomType).toBe(BOMType.AIModel);
    expect(normalized.model).toEqual({});
    expect(normalized.document).toBeUndefined();
  });

  it('lifts dataset refs and falls back to architectureFamily', () => {
    const normalized = parseMLBOM({
      components: [
        {
          type: 'machine-learning-model',
          name: 'm',
          modelCard: {
            modelParameters: {
              architectureFamily: 'transformer',
              datasets: ['ds-ref-1', { ref: 'ds-ref-2' }, { name: 'inline-only' }],
            },
          },
        },
      ],
    });
    expect(normalized.model?.modelArchitecture).toBe('transformer');
    expect(normalized.model?.datasetRefs).toEqual(['ds-ref-1', 'ds-ref-2']);
    expect(normalized.model?.intendedUse).toBeUndefined();
  });
});

describe('CycloneDX license extraction variants', () => {
  it('reads license.name and expression, and skips malformed/entryless licenses', () => {
    const normalized = parseCycloneDX({
      bomFormat: 'CycloneDX',
      components: [
        { name: 'by-name', licenses: [{ license: { name: 'Apache-2.0' } }] },
        { name: 'by-expr', licenses: [{ expression: '(MIT OR Apache-2.0)' }] },
        { name: 'no-license-value', licenses: [{ license: {} }, 'not-an-object'] },
        { name: 'no-version-no-purl' },
        { version: '1.0.0' },
      ],
    });
    expect(pkgByName(normalized.packages, 'by-name').licenses).toEqual(['Apache-2.0']);
    expect(pkgByName(normalized.packages, 'by-expr').licenses).toEqual(['(MIT OR Apache-2.0)']);
    const empty = pkgByName(normalized.packages, 'no-license-value');
    expect(empty.licenses).toBeUndefined();
    const bare = pkgByName(normalized.packages, 'no-version-no-purl');
    expect(bare.version).toBeUndefined();
    expect(bare.purl).toBeUndefined();
    expect(normalized.packages).toHaveLength(4);
  });
});

describe('SPDX externalRefs / license variants', () => {
  it('ignores non-purl externalRefs and locator-less purl refs', () => {
    const normalized = parseSPDX({
      packages: [
        {
          name: 'no-purl',
          externalRefs: [
            { referenceType: 'cpe23Type', referenceLocator: 'cpe:2.3:a:x' },
            { referenceType: 'purl' },
            'not-an-object',
          ],
          licenseConcluded: 'NOASSERTION',
          licenseDeclared: 'MIT',
        },
      ],
    });
    const pkg = pkgByName(normalized.packages, 'no-purl');
    expect(pkg.purl).toBeUndefined();
    expect(pkg.licenses).toEqual(['MIT']);
  });
});

describe('enrichFromPurl', () => {
  it('fills a missing version from the purl', () => {
    const pkg: SBOMPackage = { name: 'lodash', purl: 'pkg:npm/lodash@4.17.21' };
    enrichFromPurl(pkg);
    expect(pkg.version).toBe('4.17.21');
  });

  it('does not overwrite an existing version', () => {
    const pkg: SBOMPackage = { name: 'x', version: '1.5.1', purl: 'pkg:github/spdx/tools-java@abc123' };
    enrichFromPurl(pkg);
    expect(pkg.version).toBe('1.5.1');
  });

  it('is a no-op without a purl', () => {
    const pkg: SBOMPackage = { name: 'x' };
    enrichFromPurl(pkg);
    expect(pkg.version).toBeUndefined();
  });
});
