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
  detectSPDX3,
  enrichFromPurl,
  parseBom,
  parseCycloneDX,
  parseMLBOM,
  parseSPDX,
  parseSPDX3,
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

  it('lifts learningApproach, task, performanceMetrics, and inputOutput.dataTypes from the model card', () => {
    expect(normalized.model?.learningApproach).toBe('supervised');
    expect(normalized.model?.task).toBe('task goes here');
    expect(normalized.model?.performanceMetrics).toEqual([
      { name: 'The type of performance metric', value: 'The value of the performance metric' },
    ]);
    expect(normalized.model?.inputOutput?.dataTypes).toEqual(['string', 'byte[]']);
  });

  it('never fabricates hyperparameters or the CycloneDX-less inputOutput fields', () => {
    expect(normalized.model?.hyperparameters).toBeUndefined();
    expect(normalized.model?.inputOutput?.modality).toBeUndefined();
    expect(normalized.model?.inputOutput?.contextLength).toBeUndefined();
    expect(normalized.model?.inputOutput?.tokenizer).toBeUndefined();
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

  it('never fabricates the kirq.8 fields when the source lacks them', () => {
    if (fx.emptyModel) {
      expect(normalized.model?.learningApproach).toBeUndefined();
      expect(normalized.model?.task).toBeUndefined();
      expect(normalized.model?.performanceMetrics).toBeUndefined();
      expect(normalized.model?.inputOutput).toBeUndefined();
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

const SPDX3_MODEL1 = loadFixture('spdx-ai-model-1.json');
const SPDX3_MODEL2 = loadFixture('spdx-ai-model-2.json');
const SPDX3_DATASET1 = loadFixture('spdx-ai-dataset-1.json');

function subjectsByKind(
  subjects: ReturnType<typeof parseSPDX3>['subjects'],
  kind: 'aiModel' | 'dataset',
) {
  return subjects.filter(s => s.kind === kind);
}

describe('detectSPDX3', () => {
  it('detects an SPDX-3 AI document as spdx-3-ai, not spdx', () => {
    const parsed = JSON.parse(SPDX3_MODEL1);
    expect(detectSPDX3(parsed)).toBe(1);
    expect(detectSPDX(parsed)).toBe(0);
    expect(detectFormat(parsed)).toEqual({ format: 'spdx-3-ai', confidence: 1 });
  });

  it('detects a dataset-only SPDX-3 document', () => {
    expect(detectSPDX3(JSON.parse(SPDX3_DATASET1))).toBe(1);
    expect(detectFormat(JSON.parse(SPDX3_DATASET1))).toEqual({ format: 'spdx-3-ai', confidence: 1 });
  });

  it('still classifies an SPDX 2.3 SBOM as spdx (no conflict)', () => {
    const parsed = JSON.parse(SPDX);
    expect(detectSPDX3(parsed)).toBe(0);
    expect(detectFormat(parsed)).toEqual({ format: 'spdx', confidence: 1 });
  });

  it('returns 0 for a graph without any AI/dataset element', () => {
    expect(detectSPDX3({ '@context': 'x', '@graph': [{ type: 'software_Package' }] })).toBe(0);
    expect(detectSPDX3({ '@graph': [{ type: 'ai_AIPackage' }] })).toBe(0); // no @context
    expect(detectSPDX3({ '@context': 'x', '@graph': 'nope' })).toBe(0);
  });
});

describe('parseSPDX3 — spdx-ai-model-1 (2 models + 1 dataset)', () => {
  const { subjects } = parseSPDX3(JSON.parse(SPDX3_MODEL1));
  const models = subjectsByKind(subjects, 'aiModel');
  const datasets = subjectsByKind(subjects, 'dataset');

  it('emits exactly 2 aiModel subjects and 1 dataset subject', () => {
    expect(models).toHaveLength(2);
    expect(datasets).toHaveLength(1);
  });

  it('every emitted BOM is spdx-3-ai and schema-valid', () => {
    for (const s of subjects) {
      expect(s.bom.format).toBe('spdx-3-ai');
      expectValidBom(s.bom);
    }
  });

  it('word-model: hyperparameters populated but parameterCount NEVER set (trap)', () => {
    const wordModel = models.find(m => m.name === 'word-model')!;
    expect(wordModel.bom.bomType).toBe(BOMType.AIModel);
    const model = wordModel.bom.model!;
    expect(model.hyperparameters?.length).toBeGreaterThan(0);
    expect(model.hyperparameters).toContainEqual({ name: 'optimizer', value: 'RMSprop' });
    expect(model.parameterCount).toBeUndefined();
  });

  it('word-model: performanceMetrics lifted from ai_metric', () => {
    const wordModel = models.find(m => m.name === 'word-model')!;
    const names = (wordModel.bom.model!.performanceMetrics ?? []).map(m => m.name);
    expect(names).toContain('charErrorRates');
    expect(names).toContain('wordAccuracies');
  });

  it('word-model: task from ai_domain[0], modelArchitecture from ai_typeOfModel', () => {
    const wordModel = models.find(m => m.name === 'word-model')!;
    const model = wordModel.bom.model!;
    expect(model.task).toBe('handwriting recognition');
    expect(model.modelArchitecture).toContain('Deep Neural network');
    expect(model.intendedUse).toContain('Offline Handwritten Text Recognition');
  });

  it('word-model: datasetRefs resolved from trainedOn/testedOn relationship', () => {
    const wordModel = models.find(m => m.name === 'word-model')!;
    expect(wordModel.bom.model!.datasetRefs).toEqual(['IAMdataset']);
  });

  it('word-model: raw ai_AIPackage carried via document passthrough', () => {
    const wordModel = models.find(m => m.name === 'word-model')!;
    expect(wordModel.bom.document?.ai_safetyRiskAssessment).toBe('low');
    expect(wordModel.bom.document?.ai_hyperparameter).toBeDefined();
  });

  it('IAMdataset: modality/dataClassification/intendedUse/provenance lifted; recordCount NEVER set (trap)', () => {
    const dataset = datasets[0].bom.dataset!;
    expect(dataset.modality).toEqual(['image']);
    expect(dataset.dataClassification).toBe('clear');
    expect(dataset.intendedUse).toContain('line level or word level');
    expect(dataset.provenance).toContain('Lancaster');
    expect(dataset.recordCount).toBeUndefined();
    // dataset_datasetSize is present in the source but deliberately not mapped.
    expect(datasets[0].bom.document?.dataset_datasetSize).toBe(4620000000);
  });
});

describe('parseSPDX3 — spdx-ai-model-2 (1 model + 1 dataset)', () => {
  const { subjects } = parseSPDX3(JSON.parse(SPDX3_MODEL2));
  const models = subjectsByKind(subjects, 'aiModel');
  const datasets = subjectsByKind(subjects, 'dataset');

  it('emits exactly 1 aiModel subject and 1 dataset subject', () => {
    expect(models).toHaveLength(1);
    expect(datasets).toHaveLength(1);
  });

  it('model: performanceMetrics lifted (precision/recall/f1)', () => {
    const names = (models[0].bom.model!.performanceMetrics ?? []).map(m => m.name);
    expect(names).toEqual(expect.arrayContaining(['precision', 'recall', 'f1']));
  });

  it('model: no datasetRefs (trainedOn is from a File, not the AIPackage)', () => {
    expect(models[0].bom.model!.datasetRefs).toBeUndefined();
  });

  it('dataset: modality is text; recordCount NEVER set despite dataset_datasetSize', () => {
    const dataset = datasets[0].bom.dataset!;
    expect(dataset.modality).toEqual(['text']);
    expect(dataset.recordCount).toBeUndefined();
    expect(datasets[0].bom.document?.dataset_datasetSize).toBe(117553);
  });
});

describe('parseSPDX3 — spdx-ai-dataset-1 (0 models + 1 dataset)', () => {
  const { subjects } = parseSPDX3(JSON.parse(SPDX3_DATASET1));

  it('emits 0 aiModel subjects and exactly 1 dataset subject', () => {
    expect(subjectsByKind(subjects, 'aiModel')).toHaveLength(0);
    expect(subjectsByKind(subjects, 'dataset')).toHaveLength(1);
  });

  it('dataset: modality array, classification, provenance lifted; recordCount unset', () => {
    const dataset = subjects[0].bom.dataset!;
    expect(dataset.modality).toEqual(['structured', 'timestamp']);
    expect(dataset.dataClassification).toBe('clear');
    expect(dataset.provenance).toContain('collected from various sources');
    expect(dataset.intendedUse).toContain('greenhouse gas');
    expect(dataset.recordCount).toBeUndefined();
  });
});

describe('parseBom — SPDX-3 single-subject fallback', () => {
  it('returns the first subject BOM via the ParseResult contract', () => {
    const { format, normalized } = parseBom(SPDX3_MODEL1);
    expect(format).toBe('spdx-3-ai');
    expect(normalized.bomType).toBe(BOMType.AIModel);
    expect(normalized.format).toBe('spdx-3-ai');
  });
});

describe('parseSPDX3 — synthetic edge cases (branch coverage)', () => {
  function spdx3(graph: unknown[]): ReturnType<typeof parseSPDX3> {
    return parseSPDX3({ '@context': 'https://spdx.org/rdf/3.0.1/spdx-context.jsonld', '@graph': graph });
  }

  it('firstString: non-string first item and no-string array leave task unset', () => {
    const nonStringFirst = spdx3([
      { type: 'ai_AIPackage', spdxId: 'm1', name: 'm1', ai_domain: [{ nested: true }, ''] },
    ]).subjects[0].bom.model!;
    expect(nonStringFirst.task).toBeUndefined();

    const emptyDomain = spdx3([
      { type: 'ai_AIPackage', spdxId: 'm2', name: 'm2', ai_domain: [] },
    ]).subjects[0].bom.model!;
    expect(emptyDomain.task).toBeUndefined();
  });

  it('joinDistinct: non-array and string-less array leave modelArchitecture unset', () => {
    const nonArray = spdx3([
      { type: 'ai_AIPackage', spdxId: 'm1', name: 'm1', ai_typeOfModel: 'not-an-array' },
    ]).subjects[0].bom.model!;
    expect(nonArray.modelArchitecture).toBeUndefined();

    const noStrings = spdx3([
      { type: 'ai_AIPackage', spdxId: 'm2', name: 'm2', ai_typeOfModel: [{ x: 1 }, null] },
    ]).subjects[0].bom.model!;
    expect(noStrings.modelArchitecture).toBeUndefined();
  });

  it('dictionaryEntries: non-array, non-object entry, missing key, null/absent value', () => {
    const nonArray = spdx3([
      { type: 'ai_AIPackage', spdxId: 'm1', name: 'm1', ai_hyperparameter: 'nope' },
    ]).subjects[0].bom.model!;
    expect(nonArray.hyperparameters).toBeUndefined();

    const mixed = spdx3([
      {
        type: 'ai_AIPackage',
        spdxId: 'm2',
        name: 'm2',
        ai_hyperparameter: [
          'not-an-object',
          { type: 'DictionaryEntry', value: 'orphan' }, // no key -> skipped
          { type: 'DictionaryEntry', key: 'nullval', value: null }, // -> ''
          { type: 'DictionaryEntry', key: 'noval' }, // absent value -> ''
        ],
      },
    ]).subjects[0].bom.model!;
    expect(mixed.hyperparameters).toEqual([
      { name: 'nullval', value: '' },
      { name: 'noval', value: '' },
    ]);
  });

  it('datasetRefsFor: filters by from/type, handles scalar/array to, dedups, and falls back to raw id', () => {
    const subjects = spdx3([
      { type: 'dataset_DatasetPackage', spdxId: 'ds-known', name: 'KnownDS' },
      {
        type: 'ai_AIPackage',
        spdxId: 'model-x',
        name: 'model-x',
      },
      // wrong from -> ignored
      { type: 'Relationship', relationshipType: 'trainedOn', from: 'other-model', to: ['ds-known'] },
      // wrong relationshipType -> ignored
      { type: 'Relationship', relationshipType: 'contains', from: 'model-x', to: ['ds-known'] },
      // scalar `to`, resolvable name
      { type: 'Relationship', relationshipType: 'trainedOn', from: 'model-x', to: 'ds-known' },
      // duplicate (array) resolving to same name -> deduped
      { type: 'Relationship', relationshipType: 'testedOn', from: 'model-x', to: ['ds-known'] },
      // unresolvable id -> raw id kept
      { type: 'Relationship', relationshipType: 'testedOn', from: 'model-x', to: ['ds-missing'] },
    ]).subjects;
    const model = subjects.find(s => s.kind === 'aiModel')!.bom.model!;
    expect(model.datasetRefs).toEqual(['KnownDS', 'ds-missing']);
  });

  it('buildModelExtension: an ai_AIPackage with no ai_* fields yields an empty model extension', () => {
    const { subjects } = spdx3([{ type: 'ai_AIPackage', spdxId: 'bare', name: 'bare' }]);
    const model = subjects[0].bom.model!;
    expect(model).toEqual({});
    expect(subjects[0].bom.document?.spdxId).toBe('bare');
  });

  it('buildDatasetExtension: non-array modality and no dataset_* fields yield an empty dataset extension', () => {
    const { subjects } = spdx3([
      { type: 'dataset_DatasetPackage', spdxId: 'bare-ds', name: 'bare-ds', dataset_datasetType: 'scalar' },
    ]);
    const dataset = subjects[0].bom.dataset!;
    expect(dataset).toEqual({});
    expect(dataset.modality).toBeUndefined();
  });

  it('parseSPDX3: ignores non-AI/dataset elements and does not map id-less/name-less datasets', () => {
    const { subjects } = spdx3([
      { type: 'software_Package', spdxId: 'sw', name: 'sw' }, // ignored
      { type: 'dataset_DatasetPackage', name: 'no-id' }, // no spdxId -> not in name map (still emitted)
      { type: 'dataset_DatasetPackage', spdxId: 'no-name' }, // no name -> not in name map (still emitted)
      { type: 'ai_AIPackage', spdxId: 'm', name: 'm' },
      { type: 'Relationship', relationshipType: 'trainedOn', from: 'm', to: ['no-id', 'no-name'] },
    ]);
    // 2 dataset subjects + 1 model subject; software_Package ignored.
    expect(subjects.filter(s => s.kind === 'dataset')).toHaveLength(2);
    expect(subjects.filter(s => s.kind === 'aiModel')).toHaveLength(1);
    // Neither id-less nor name-less dataset made it into the resolution map, so
    // both refs fall back to their raw ids ('no-id' target had no spdxId -> its
    // relationship id is used verbatim).
    const model = subjects.find(s => s.kind === 'aiModel')!.bom.model!;
    expect(model.datasetRefs).toEqual(['no-id', 'no-name']);
  });
});

// Numeric scalar values (JSON numbers) must stringify BYTE-IDENTICALLY across TS
// and Go. The expected strings are pinned and shared by both languages'
// numeric-parity tests; the exponent forms below (1e-7, 0.000001) are the ones
// where a naive Go fmt.Sprintf("%v") diverges from JS String().
const SCALAR_CASES: Array<[number | boolean, string]> = [
  [1234567, '1234567'],
  [0.4669, '0.4669'],
  [1e-7, '1e-7'],
  [1e-6, '0.000001'],
  [true, 'true'],
];

describe('numeric scalar value parity (TS↔Go)', () => {
  it('parseMLBOM: performanceMetrics values stringify to the pinned shared strings', () => {
    const normalized = parseMLBOM({
      serialNumber: 'urn:uuid:num',
      components: [
        {
          type: 'machine-learning-model',
          name: 'm',
          modelCard: {
            quantitativeAnalysis: {
              performanceMetrics: SCALAR_CASES.map(([value], i) => ({
                type: `m${i}`,
                value,
              })),
            },
          },
        },
      ],
    });
    const values = (normalized.model?.performanceMetrics ?? []).map(m => m.value);
    expect(values).toEqual(SCALAR_CASES.map(([, expected]) => expected));
  });

  it('parseSPDX3: ai_metric / ai_hyperparameter values stringify to the pinned shared strings', () => {
    const { subjects } = parseSPDX3({
      '@context': 'https://spdx.org/rdf/3.0.1/spdx-context.jsonld',
      '@graph': [
        {
          type: 'ai_AIPackage',
          spdxId: 'm',
          name: 'm',
          ai_metric: SCALAR_CASES.map(([value], i) => ({
            type: 'DictionaryEntry',
            key: `metric${i}`,
            value,
          })),
          ai_hyperparameter: SCALAR_CASES.map(([value], i) => ({
            type: 'DictionaryEntry',
            key: `hp${i}`,
            value,
          })),
        },
      ],
    });
    const model = subjects[0].bom.model!;
    expect((model.performanceMetrics ?? []).map(m => m.value)).toEqual(
      SCALAR_CASES.map(([, expected]) => expected),
    );
    expect((model.hyperparameters ?? []).map(h => h.value)).toEqual(
      SCALAR_CASES.map(([, expected]) => expected),
    );
  });
});
