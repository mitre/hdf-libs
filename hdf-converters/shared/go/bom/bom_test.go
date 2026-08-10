package bom

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xeipuuv/gojsonschema"
)

const (
	fixturesDir   = "../../bom-fixtures"
	primitivesDir = "../../../../hdf-schema/src/schemas/primitives"
)

func loadFixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(fixturesDir, name))
	require.NoError(t, err)
	return data
}

func parseJSONObject(t *testing.T, data []byte) map[string]any {
	t.Helper()
	var obj map[string]any
	require.NoError(t, json.Unmarshal(data, &obj))
	return obj
}

// bomValidator compiles a validator for the Bom definition against the shipped
// primitive schemas (bom + common, which Bom $refs for Checksum). This is the
// round-trip gate — parity with the TS Ajv gate: BuildBom output must validate
// against the real schema definition, including the three-tier if/else
// discipline.
func bomValidator(t *testing.T) *gojsonschema.Schema {
	t.Helper()
	bomBytes, err := os.ReadFile(filepath.Join(primitivesDir, "bom.schema.json"))
	require.NoError(t, err)
	commonBytes, err := os.ReadFile(filepath.Join(primitivesDir, "common.schema.json"))
	require.NoError(t, err)

	var bomDoc map[string]any
	require.NoError(t, json.Unmarshal(bomBytes, &bomDoc))
	bomID, ok := bomDoc["$id"].(string)
	require.True(t, ok, "bom schema must carry a $id")

	sl := gojsonschema.NewSchemaLoader()
	sl.Validate = false
	require.NoError(t, sl.AddSchemas(gojsonschema.NewBytesLoader(commonBytes)))
	require.NoError(t, sl.AddSchemas(gojsonschema.NewBytesLoader(bomBytes)))

	root := fmt.Sprintf(`{"$ref":%q}`, bomID+"#/$defs/Bom")
	schema, err := sl.Compile(gojsonschema.NewStringLoader(root))
	require.NoError(t, err)
	return schema
}

func expectValidBom(t *testing.T, validator *gojsonschema.Schema, bom *BillOfMaterials) {
	t.Helper()
	data, err := json.Marshal(bom)
	require.NoError(t, err)
	result, err := validator.Validate(gojsonschema.NewBytesLoader(data))
	require.NoError(t, err)
	assert.Truef(t, result.Valid(), "schema errors: %v", result.Errors())
}

func pkgByName(t *testing.T, packages []SBOMPackage, name string) SBOMPackage {
	t.Helper()
	for _, p := range packages {
		if p.Name == name {
			return p
		}
	}
	t.Fatalf("expected package %q", name)
	return SBOMPackage{}
}

func TestDetectFormat(t *testing.T) {
	cyclonedx := parseJSONObject(t, loadFixture(t, "cyclonedx-sbom.json"))
	spdx := parseJSONObject(t, loadFixture(t, "spdx-sbom.json"))
	mlbom := parseJSONObject(t, loadFixture(t, "cyclonedx-mlbom.json"))

	t.Run("detects CycloneDX", func(t *testing.T) {
		assert.Equal(t, float64(1), DetectCycloneDX(cyclonedx))
		assert.Equal(t, &FormatDetection{Format: FormatCycloneDX, Confidence: 1}, DetectFormat(cyclonedx))
	})

	t.Run("detects SPDX", func(t *testing.T) {
		assert.Equal(t, float64(1), DetectSPDX(spdx))
		assert.Equal(t, &FormatDetection{Format: FormatSPDX, Confidence: 1}, DetectFormat(spdx))
	})

	t.Run("detects ML-BOM as cyclonedx-ml, not plain cyclonedx (precedence)", func(t *testing.T) {
		assert.Equal(t, float64(1), DetectCycloneDX(mlbom))
		assert.Equal(t, float64(1), DetectCycloneDXML(mlbom))
		assert.Equal(t, &FormatDetection{Format: FormatCycloneDXML, Confidence: 1}, DetectFormat(mlbom))
	})

	t.Run("returns 0 / nil for non-BOM input", func(t *testing.T) {
		assert.Equal(t, float64(0), DetectCycloneDX(nil))
		assert.Equal(t, float64(0), DetectCycloneDX([]any{1, 2}))
		assert.Equal(t, float64(0), DetectCycloneDXML(map[string]any{"bomFormat": "CycloneDX"}))
		assert.Equal(t, float64(0), DetectCycloneDXML(map[string]any{"bomFormat": "CycloneDX", "components": "nope"}))
		assert.Equal(t, float64(0), DetectSPDX(map[string]any{"spdxVersion": ""}))
		assert.Nil(t, DetectFormat(map[string]any{"foo": "bar"}))
	})
}

func TestParseBom_CycloneDX(t *testing.T) {
	validator := bomValidator(t)
	result, err := ParseBom(loadFixture(t, "cyclonedx-sbom.json"))
	require.NoError(t, err)
	normalized := result.Normalized

	t.Run("reports the format and sbom bomType", func(t *testing.T) {
		assert.Equal(t, FormatCycloneDX, result.Format)
		assert.Equal(t, BOMTypeSbom, normalized.BOMType)
		assert.Equal(t, FormatCycloneDX, normalized.Format)
	})

	t.Run("maps every top-level component to a package", func(t *testing.T) {
		assert.Len(t, normalized.Packages, 5)
		assert.Nil(t, normalized.Model)
		assert.Nil(t, normalized.Dataset)
	})

	t.Run("pins body-parser@1.20.4 with purl and MIT license", func(t *testing.T) {
		bp := pkgByName(t, normalized.Packages, "body-parser")
		require.NotNil(t, bp.Version)
		assert.Equal(t, "1.20.4", *bp.Version)
		require.NotNil(t, bp.Purl)
		assert.Equal(t, "pkg:npm/body-parser@1.20.4", *bp.Purl)
		assert.Equal(t, []string{"MIT"}, bp.Licenses)
	})

	t.Run("has no uniqueId (fixture carries no serialNumber)", func(t *testing.T) {
		assert.Nil(t, normalized.UniqueID)
	})

	t.Run("produces schema-valid output", func(t *testing.T) {
		expectValidBom(t, validator, BuildBom(BuildBomParts{
			BOMType: BOMTypeSbom, Format: FormatCycloneDX, Packages: normalized.Packages,
		}))
	})
}

func TestParseBom_SPDX(t *testing.T) {
	validator := bomValidator(t)
	result, err := ParseBom(loadFixture(t, "spdx-sbom.json"))
	require.NoError(t, err)
	normalized := result.Normalized

	t.Run("reports the format and sbom bomType", func(t *testing.T) {
		assert.Equal(t, FormatSPDX, result.Format)
		assert.Equal(t, BOMTypeSbom, normalized.BOMType)
	})

	t.Run("uses documentNamespace as uniqueId", func(t *testing.T) {
		require.NotNil(t, normalized.UniqueID)
		assert.Equal(t,
			"http://spdx.org/spdxdocs/tools-java/v1.1.5-444504E0-4F89-41D3-9A0C-0305E82C3301",
			*normalized.UniqueID)
	})

	t.Run("pins tools-java 1.5.1 with a github purl", func(t *testing.T) {
		assert.Len(t, normalized.Packages, 2)
		tj := pkgByName(t, normalized.Packages, "tools-java")
		require.NotNil(t, tj.Version)
		assert.Equal(t, "1.5.1", *tj.Version)
		require.NotNil(t, tj.Purl)
		assert.Equal(t, "pkg:github/spdx/tools-java@2235d5d7f7fe46ce1e0d54b7831c5681633b25cc", *tj.Purl)
	})

	t.Run("pins xlsx 0.16.6 with a maven purl", func(t *testing.T) {
		xlsx := pkgByName(t, normalized.Packages, "xlsx")
		require.NotNil(t, xlsx.Version)
		assert.Equal(t, "0.16.6", *xlsx.Version)
		require.NotNil(t, xlsx.Purl)
		assert.Equal(t, "pkg:maven/org.webjars.npm/xlsx@0.16.6", *xlsx.Purl)
	})

	t.Run("omits licenses when the source has none", func(t *testing.T) {
		assert.Nil(t, pkgByName(t, normalized.Packages, "tools-java").Licenses)
	})

	t.Run("produces schema-valid output", func(t *testing.T) {
		expectValidBom(t, validator, BuildBom(BuildBomParts{
			BOMType: BOMTypeSbom, Format: FormatSPDX,
			Packages: normalized.Packages, UniqueID: normalized.UniqueID,
		}))
	})
}

func TestParseBom_MLBOM(t *testing.T) {
	validator := bomValidator(t)
	result, err := ParseBom(loadFixture(t, "cyclonedx-mlbom.json"))
	require.NoError(t, err)
	normalized := result.Normalized

	t.Run("reports cyclonedx-ml and ai-model bomType", func(t *testing.T) {
		assert.Equal(t, FormatCycloneDXML, result.Format)
		assert.Equal(t, BOMTypeAIModel, normalized.BOMType)
		assert.Equal(t, FormatCycloneDXML, normalized.Format)
	})

	t.Run("populates the model extension and carries NO packages", func(t *testing.T) {
		assert.Nil(t, normalized.Packages)
		assert.Nil(t, normalized.Dataset)
		require.NotNil(t, normalized.Model)
		require.NotNil(t, normalized.Model.ModelArchitecture)
		assert.Equal(t, "The architecture of the model.", *normalized.Model.ModelArchitecture)
		require.NotNil(t, normalized.Model.IntendedUse)
		assert.Contains(t, *normalized.Model.IntendedUse,
			"Text-to-image generation for creative applications")
	})

	t.Run("never fabricates parameterCount or serializationFormat", func(t *testing.T) {
		assert.Nil(t, normalized.Model.ParameterCount)
		assert.Nil(t, normalized.Model.SerializationFormat)
	})

	t.Run("lifts learningApproach, task, performanceMetrics, and inputOutput.dataTypes", func(t *testing.T) {
		require.NotNil(t, normalized.Model.LearningApproach)
		assert.Equal(t, "supervised", *normalized.Model.LearningApproach)
		require.NotNil(t, normalized.Model.Task)
		assert.Equal(t, "task goes here", *normalized.Model.Task)
		require.Len(t, normalized.Model.PerformanceMetrics, 1)
		require.NotNil(t, normalized.Model.PerformanceMetrics[0].Name)
		assert.Equal(t, "The type of performance metric", *normalized.Model.PerformanceMetrics[0].Name)
		require.NotNil(t, normalized.Model.PerformanceMetrics[0].Value)
		assert.Equal(t, "The value of the performance metric", *normalized.Model.PerformanceMetrics[0].Value)
		require.NotNil(t, normalized.Model.InputOutput)
		assert.Equal(t, []string{"string", "byte[]"}, normalized.Model.InputOutput.DataTypes)
	})

	t.Run("never fabricates hyperparameters or the CycloneDX-less inputOutput fields", func(t *testing.T) {
		assert.Nil(t, normalized.Model.Hyperparameters)
		require.NotNil(t, normalized.Model.InputOutput)
		assert.Nil(t, normalized.Model.InputOutput.Modality)
		assert.Nil(t, normalized.Model.InputOutput.ContextLength)
		assert.Nil(t, normalized.Model.InputOutput.Tokenizer)
	})

	t.Run("carries the raw model component via document passthrough", func(t *testing.T) {
		require.NotNil(t, normalized.Document)
		assert.Equal(t, "machine-learning-model", normalized.Document["type"])
	})

	t.Run("uses serialNumber as uniqueId", func(t *testing.T) {
		require.NotNil(t, normalized.UniqueID)
		assert.Equal(t, "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79", *normalized.UniqueID)
	})

	t.Run("produces schema-valid output", func(t *testing.T) {
		expectValidBom(t, validator, BuildBom(BuildBomParts{
			BOMType: BOMTypeAIModel, Format: FormatCycloneDXML,
			Model: normalized.Model, Document: normalized.Document, UniqueID: normalized.UniqueID,
		}))
	})
}

// TestParseBom_MLBOMVariants sweeps the real CycloneDX-ML fixture set (spec
// versions 1.5/1.6/1.7, a considerations-only card, and a sparse trim). Every
// variant must detect as cyclonedx-ml and normalize to ai-model without ever
// fabricating parameterCount/serializationFormat/modelArchitecture.
func TestParseBom_MLBOMVariants(t *testing.T) {
	validator := bomValidator(t)
	cases := []struct {
		file string
		// modelArchitecture is the expected value, or "" when the source has none.
		modelArchitecture string
		// emptyModel requires the normalized model extension to be exactly {}.
		emptyModel bool
	}{
		{"cyclonedx-mlbom.json", "The architecture of the model.", false},
		{"cyclonedx-mlbom-1.5.json", "The architecture of the model.", false},
		{"cyclonedx-mlbom-1.7.json", "The architecture of the model.", false},
		{"cyclonedx-mlbom-considerations-1.6.json", "", true},
		{"cyclonedx-mlbom-sparse.json", "", true},
	}
	for _, tc := range cases {
		t.Run(tc.file, func(t *testing.T) {
			result, err := ParseBom(loadFixture(t, tc.file))
			require.NoError(t, err)
			n := result.Normalized

			assert.Equal(t, FormatCycloneDXML, result.Format)
			assert.Equal(t, BOMTypeAIModel, n.BOMType)
			assert.Equal(t, FormatCycloneDXML, n.Format)
			require.NotNil(t, n.Model)

			assert.Nil(t, n.Model.ParameterCount)
			assert.Nil(t, n.Model.SerializationFormat)

			if tc.modelArchitecture != "" {
				require.NotNil(t, n.Model.ModelArchitecture)
				assert.Equal(t, tc.modelArchitecture, *n.Model.ModelArchitecture)
			} else {
				assert.Nil(t, n.Model.ModelArchitecture)
			}

			if tc.emptyModel {
				assert.Equal(t, &AIModelBOMExtension{}, n.Model)
				assert.Nil(t, n.Model.LearningApproach)
				assert.Nil(t, n.Model.Task)
				assert.Nil(t, n.Model.PerformanceMetrics)
				assert.Nil(t, n.Model.InputOutput)
			}

			expectValidBom(t, validator, BuildBom(BuildBomParts{
				BOMType: BOMTypeAIModel, Format: FormatCycloneDXML,
				Model: n.Model, Document: n.Document, UniqueID: n.UniqueID,
			}))
		})
	}
}

func TestBuildBom_ThreeTier(t *testing.T) {
	validator := bomValidator(t)

	t.Run("drops a model extension on an sbom BOM", func(t *testing.T) {
		bom := BuildBom(BuildBomParts{
			BOMType:  BOMTypeSbom,
			Format:   FormatCycloneDX,
			Packages: []SBOMPackage{{Name: "x", Version: strPtr("1.0.0")}},
			Model:    &AIModelBOMExtension{ModelArchitecture: strPtr("transformer")},
		})
		assert.Nil(t, bom.Model)
		assert.Len(t, bom.Packages, 1)
		expectValidBom(t, validator, bom)
	})

	t.Run("drops packages/dataset on an ai-model BOM", func(t *testing.T) {
		count := int64(1)
		bom := BuildBom(BuildBomParts{
			BOMType:  BOMTypeAIModel,
			Format:   FormatCycloneDXML,
			Model:    &AIModelBOMExtension{ModelArchitecture: strPtr("diffusion")},
			Packages: []SBOMPackage{{Name: "x"}},
			Dataset:  &DatasetBOMExtension{RecordCount: &count},
		})
		assert.Nil(t, bom.Packages)
		assert.Nil(t, bom.Dataset)
		require.NotNil(t, bom.Model.ModelArchitecture)
		assert.Equal(t, "diffusion", *bom.Model.ModelArchitecture)
		expectValidBom(t, validator, bom)
	})

	t.Run("keeps a dataset extension only on a dataset BOM", func(t *testing.T) {
		count := int64(100)
		bom := BuildBom(BuildBomParts{
			BOMType: BOMTypeDataset,
			Format:  "croissant",
			Dataset: &DatasetBOMExtension{RecordCount: &count},
			Ref:     strPtr("https://example.com/ds.json"),
			License: strPtr("CC0-1.0"),
		})
		require.NotNil(t, bom.Dataset.RecordCount)
		assert.Equal(t, int64(100), *bom.Dataset.RecordCount)
		require.NotNil(t, bom.Ref)
		assert.Equal(t, "https://example.com/ds.json", *bom.Ref)
		require.NotNil(t, bom.License)
		assert.Equal(t, "CC0-1.0", *bom.License)
		expectValidBom(t, validator, bom)
	})

	t.Run("carries hashes when provided and non-empty", func(t *testing.T) {
		bom := BuildBom(BuildBomParts{
			BOMType:  BOMTypeSbom,
			Format:   FormatSPDX,
			Packages: []SBOMPackage{{Name: "openssl", Version: strPtr("3.0.0")}},
			Hashes: []Checksum{{
				Algorithm: "sha256",
				Value:     "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
			}},
		})
		assert.Len(t, bom.Hashes, 1)
		expectValidBom(t, validator, bom)
	})

	t.Run("omits empty hashes", func(t *testing.T) {
		bom := BuildBom(BuildBomParts{
			BOMType: BOMTypeSbom, Format: FormatSPDX, Hashes: []Checksum{},
		})
		assert.Nil(t, bom.Hashes)
	})
}

func TestParseBom_ErrorsAndEdgeCases(t *testing.T) {
	t.Run("errors on undetectable input", func(t *testing.T) {
		_, err := ParseBom([]byte(`{"foo":"bar"}`))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "could not detect a supported BOM format")
	})

	t.Run("errors on invalid JSON", func(t *testing.T) {
		_, err := ParseBom([]byte(`{not json`))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "parse JSON")
	})

	t.Run("validates input size before parsing (rejects oversized input)", func(t *testing.T) {
		huge := []byte(`{"bomFormat":"CycloneDX","pad":"` + strings.Repeat("a", 60*1024*1024) + `"}`)
		_, err := ParseBom(huge)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "exceeds maximum allowed size")
	})

	t.Run("re-parsing is stable", func(t *testing.T) {
		fixture := loadFixture(t, "cyclonedx-sbom.json")
		a, err := ParseBom(fixture)
		require.NoError(t, err)
		b, err := ParseBom(fixture)
		require.NoError(t, err)
		assert.Equal(t, a.Normalized, b.Normalized)
	})

	t.Run("tolerates a CycloneDX doc with no components", func(t *testing.T) {
		n := ParseCycloneDX(map[string]any{"bomFormat": "CycloneDX"})
		assert.NotNil(t, n.Packages)
		assert.Empty(t, n.Packages)
	})

	t.Run("skips SPDX packages with no name", func(t *testing.T) {
		n := ParseSPDX(map[string]any{"packages": []any{
			map[string]any{"versionInfo": "1.0.0"},
			map[string]any{"name": "ok"},
		}})
		require.Len(t, n.Packages, 1)
		assert.Equal(t, "ok", n.Packages[0].Name)
	})

	t.Run("handles an ML-BOM with no machine-learning-model component", func(t *testing.T) {
		n := ParseMLBOM(map[string]any{"components": []any{
			map[string]any{"type": "library", "name": "x"},
		}})
		assert.Equal(t, BOMTypeAIModel, n.BOMType)
		assert.Equal(t, &AIModelBOMExtension{}, n.Model)
		assert.Nil(t, n.Document)
	})

	t.Run("lifts dataset refs and falls back to architectureFamily", func(t *testing.T) {
		n := ParseMLBOM(map[string]any{"components": []any{
			map[string]any{
				"type": "machine-learning-model",
				"name": "m",
				"modelCard": map[string]any{
					"modelParameters": map[string]any{
						"architectureFamily": "transformer",
						"datasets": []any{
							"ds-ref-1",
							map[string]any{"ref": "ds-ref-2"},
							map[string]any{"name": "inline-only"},
						},
					},
				},
			},
		}})
		require.NotNil(t, n.Model.ModelArchitecture)
		assert.Equal(t, "transformer", *n.Model.ModelArchitecture)
		assert.Equal(t, []string{"ds-ref-1", "ds-ref-2"}, n.Model.DatasetRefs)
		assert.Nil(t, n.Model.IntendedUse)
	})
}

func TestCycloneDX_LicenseVariants(t *testing.T) {
	n := ParseCycloneDX(map[string]any{
		"bomFormat": "CycloneDX",
		"components": []any{
			map[string]any{"name": "by-name", "licenses": []any{
				map[string]any{"license": map[string]any{"name": "Apache-2.0"}}}},
			map[string]any{"name": "by-expr", "licenses": []any{
				map[string]any{"expression": "(MIT OR Apache-2.0)"}}},
			map[string]any{"name": "no-license-value", "licenses": []any{
				map[string]any{"license": map[string]any{}}, "not-an-object"}},
			map[string]any{"name": "no-version-no-purl"},
			map[string]any{"version": "1.0.0"},
		},
	})
	assert.Equal(t, []string{"Apache-2.0"}, pkgByName(t, n.Packages, "by-name").Licenses)
	assert.Equal(t, []string{"(MIT OR Apache-2.0)"}, pkgByName(t, n.Packages, "by-expr").Licenses)
	assert.Nil(t, pkgByName(t, n.Packages, "no-license-value").Licenses)
	bare := pkgByName(t, n.Packages, "no-version-no-purl")
	assert.Nil(t, bare.Version)
	assert.Nil(t, bare.Purl)
	assert.Len(t, n.Packages, 4)
}

func TestSPDX_ExternalRefsAndLicenseVariants(t *testing.T) {
	n := ParseSPDX(map[string]any{"packages": []any{
		map[string]any{
			"name": "no-purl",
			"externalRefs": []any{
				map[string]any{"referenceType": "cpe23Type", "referenceLocator": "cpe:2.3:a:x"},
				map[string]any{"referenceType": "purl"},
				"not-an-object",
			},
			"licenseConcluded": "NOASSERTION",
			"licenseDeclared":  "MIT",
		},
	}})
	pkg := pkgByName(t, n.Packages, "no-purl")
	assert.Nil(t, pkg.Purl)
	assert.Equal(t, []string{"MIT"}, pkg.Licenses)
}

func TestEnrichFromPurl(t *testing.T) {
	t.Run("fills a missing version from the purl", func(t *testing.T) {
		pkg := SBOMPackage{Name: "lodash", Purl: strPtr("pkg:npm/lodash@4.17.21")}
		enrichFromPurl(&pkg)
		require.NotNil(t, pkg.Version)
		assert.Equal(t, "4.17.21", *pkg.Version)
	})

	t.Run("does not overwrite an existing version", func(t *testing.T) {
		pkg := SBOMPackage{Name: "x", Version: strPtr("1.5.1"), Purl: strPtr("pkg:github/spdx/tools-java@abc123")}
		enrichFromPurl(&pkg)
		require.NotNil(t, pkg.Version)
		assert.Equal(t, "1.5.1", *pkg.Version)
	})

	t.Run("is a no-op without a purl", func(t *testing.T) {
		pkg := SBOMPackage{Name: "x"}
		enrichFromPurl(&pkg)
		assert.Nil(t, pkg.Version)
	})

	t.Run("fills a missing name from the purl", func(t *testing.T) {
		pkg := SBOMPackage{Purl: strPtr("pkg:npm/lodash@4.17.21")}
		enrichFromPurl(&pkg)
		assert.Equal(t, "lodash", pkg.Name)
	})
}

// Guards that the round-trip gate is meaningful: the schema validator must
// REJECT invalid BOMs, else the expectValidBom(...) assertions prove nothing.
func TestRoundTripValidatorRejectsInvalid(t *testing.T) {
	v := bomValidator(t)
	cases := map[string]string{
		"missing bomType":      `{"format":"cyclonedx","ref":"./x.json"}`,
		"unknown bomType":      `{"bomType":"vex","format":"cyclonedx"}`,
		"three-tier violation": `{"bomType":"sbom","format":"cyclonedx","model":{"parameterCount":1}}`,
	}
	for name, doc := range cases {
		t.Run(name, func(t *testing.T) {
			res, err := v.Validate(gojsonschema.NewStringLoader(doc))
			require.NoError(t, err)
			assert.Falsef(t, res.Valid(), "expected %s to be rejected by the bom schema", name)
		})
	}
}

// --- SPDX 3.0 AI/Dataset (JSON-LD) ---

func spdx3Subjects(t *testing.T, fixture string) []SPDX3Subject {
	t.Helper()
	obj := parseJSONObject(t, loadFixture(t, fixture))
	return ParseSPDX3(obj).Subjects
}

func subjectsByKind(subjects []SPDX3Subject, kind string) []SPDX3Subject {
	out := []SPDX3Subject{}
	for _, s := range subjects {
		if s.Kind == kind {
			out = append(out, s)
		}
	}
	return out
}

func modelByName(t *testing.T, subjects []SPDX3Subject, name string) SPDX3Subject {
	t.Helper()
	for _, s := range subjects {
		if s.Kind == "aiModel" && s.Name == name {
			return s
		}
	}
	t.Fatalf("no aiModel subject named %q", name)
	return SPDX3Subject{}
}

func TestDetectSPDX3(t *testing.T) {
	model1 := parseJSONObject(t, loadFixture(t, "spdx-ai-model-1.json"))
	assert.Equal(t, float64(1), DetectSPDX3(model1))
	assert.Equal(t, float64(0), DetectSPDX(model1))
	require.NotNil(t, DetectFormat(model1))
	assert.Equal(t, FormatSPDX3AI, DetectFormat(model1).Format)

	dataset1 := parseJSONObject(t, loadFixture(t, "spdx-ai-dataset-1.json"))
	assert.Equal(t, float64(1), DetectSPDX3(dataset1))
	assert.Equal(t, FormatSPDX3AI, DetectFormat(dataset1).Format)

	// SPDX 2.3 must still classify as spdx (no conflict).
	spdx23 := parseJSONObject(t, loadFixture(t, "spdx-sbom.json"))
	assert.Equal(t, float64(0), DetectSPDX3(spdx23))
	require.NotNil(t, DetectFormat(spdx23))
	assert.Equal(t, FormatSPDX, DetectFormat(spdx23).Format)

	// Graphs missing @context or an AI/dataset element score 0.
	assert.Equal(t, float64(0), DetectSPDX3(map[string]any{"@context": "x", "@graph": []any{map[string]any{"type": "software_Package"}}}))
	assert.Equal(t, float64(0), DetectSPDX3(map[string]any{"@graph": []any{map[string]any{"type": "ai_AIPackage"}}}))
	assert.Equal(t, float64(0), DetectSPDX3(map[string]any{"@context": "x", "@graph": "nope"}))
}

func TestDetectSPDX3Security(t *testing.T) {
	vexDoc := map[string]any{
		"@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld",
		"@graph": []any{
			map[string]any{"type": "software_Package", "spdxId": "pkg"},
			map[string]any{"type": "security_VexNotAffectedVulnAssessmentRelationship", "from": "cve"},
		},
	}
	assert.Equal(t, float64(1), DetectSPDX3Security(vexDoc))
	require.NotNil(t, DetectFormat(vexDoc))
	assert.Equal(t, FormatSPDX3Security, DetectFormat(vexDoc).Format)

	// Disjoint from the AI/Dataset detector.
	assert.Equal(t, float64(0), DetectSPDX3(vexDoc), "security VEX doc is not an AI/Dataset doc")

	// Each of the four VEX assessment subtypes fires.
	for _, subtype := range []string{
		"security_VexAffectedVulnAssessmentRelationship",
		"security_VexNotAffectedVulnAssessmentRelationship",
		"security_VexFixedVulnAssessmentRelationship",
		"security_VexUnderInvestigationVulnAssessmentRelationship",
	} {
		doc := map[string]any{"@context": "x", "@graph": []any{map[string]any{"type": subtype}}}
		assert.Equalf(t, float64(1), DetectSPDX3Security(doc), "subtype %s", subtype)
	}

	// Must NOT fire on SPDX 2.x, on AI/Dataset SPDX-3, or on non-VEX graphs.
	spdx23 := parseJSONObject(t, loadFixture(t, "spdx-sbom.json"))
	assert.Equal(t, float64(0), DetectSPDX3Security(spdx23))
	aiModel := parseJSONObject(t, loadFixture(t, "spdx-ai-model-1.json"))
	assert.Equal(t, float64(0), DetectSPDX3Security(aiModel))
	assert.Equal(t, float64(0), DetectSPDX3Security(map[string]any{"@graph": []any{map[string]any{"type": "security_VexFixedVulnAssessmentRelationship"}}}), "no @context")
	assert.Equal(t, float64(0), DetectSPDX3Security(map[string]any{"@context": "x", "@graph": []any{map[string]any{"type": "security_CvssV3VulnAssessmentRelationship"}}}), "CVSS relationship is not a VEX assessment")
	assert.Equal(t, float64(0), DetectSPDX3Security(map[string]any{"@context": "x", "@graph": "nope"}))
	assert.Equal(t, float64(0), DetectSPDX3Security(nil))
}

func TestParseSPDX3_Model1(t *testing.T) {
	v := bomValidator(t)
	subjects := spdx3Subjects(t, "spdx-ai-model-1.json")
	models := subjectsByKind(subjects, "aiModel")
	datasets := subjectsByKind(subjects, "dataset")

	require.Len(t, models, 2)
	require.Len(t, datasets, 1)

	for _, s := range subjects {
		assert.Equal(t, FormatSPDX3AI, s.Bom.Format)
		expectValidBom(t, v, &s.Bom.BillOfMaterials)
	}

	word := modelByName(t, subjects, "word-model")
	model := word.Bom.Model
	require.NotNil(t, model)

	// TRAP: hyperparameters populated, parameterCount NEVER set.
	assert.NotEmpty(t, model.Hyperparameters)
	assert.Nil(t, model.ParameterCount)
	assert.Contains(t, model.Hyperparameters, Hyperparameter{Name: strPtr("optimizer"), Value: strPtr("RMSprop")})

	metricNames := []string{}
	for _, m := range model.PerformanceMetrics {
		metricNames = append(metricNames, *m.Name)
	}
	assert.Contains(t, metricNames, "charErrorRates")
	assert.Contains(t, metricNames, "wordAccuracies")

	require.NotNil(t, model.Task)
	assert.Equal(t, "handwriting recognition", *model.Task)
	require.NotNil(t, model.ModelArchitecture)
	assert.Contains(t, *model.ModelArchitecture, "Deep Neural network")
	require.NotNil(t, model.IntendedUse)
	assert.Contains(t, *model.IntendedUse, "Offline Handwritten Text Recognition")
	assert.Equal(t, []string{"IAMdataset"}, model.DatasetRefs)

	// Raw element carried via document passthrough.
	assert.Equal(t, "low", word.Bom.Document["ai_safetyRiskAssessment"])
	assert.NotNil(t, word.Bom.Document["ai_hyperparameter"])

	ds := datasets[0].Bom.Dataset
	require.NotNil(t, ds)
	require.NotNil(t, ds.Modality)
	assert.Equal(t, []string{"image"}, ds.Modality.StringArray)
	require.NotNil(t, ds.DataClassification)
	assert.Equal(t, "clear", *ds.DataClassification)
	require.NotNil(t, ds.IntendedUse)
	assert.Contains(t, *ds.IntendedUse, "line level or word level")
	require.NotNil(t, ds.Provenance)
	assert.Contains(t, *ds.Provenance, "Lancaster")
	// TRAP: recordCount NEVER set despite dataset_datasetSize present.
	assert.Nil(t, ds.RecordCount)
	assert.Equal(t, float64(4620000000), datasets[0].Bom.Document["dataset_datasetSize"])
}

func TestParseSPDX3_Model2(t *testing.T) {
	subjects := spdx3Subjects(t, "spdx-ai-model-2.json")
	models := subjectsByKind(subjects, "aiModel")
	datasets := subjectsByKind(subjects, "dataset")

	require.Len(t, models, 1)
	require.Len(t, datasets, 1)

	metricNames := []string{}
	for _, m := range models[0].Bom.Model.PerformanceMetrics {
		metricNames = append(metricNames, *m.Name)
	}
	assert.Subset(t, metricNames, []string{"precision", "recall", "f1"})

	// trainedOn here is from a File, not the AIPackage -> no datasetRefs.
	assert.Nil(t, models[0].Bom.Model.DatasetRefs)

	ds := datasets[0].Bom.Dataset
	require.NotNil(t, ds.Modality)
	assert.Equal(t, []string{"text"}, ds.Modality.StringArray)
	assert.Nil(t, ds.RecordCount)
	assert.Equal(t, float64(117553), datasets[0].Bom.Document["dataset_datasetSize"])
}

func TestParseSPDX3_Dataset1(t *testing.T) {
	subjects := spdx3Subjects(t, "spdx-ai-dataset-1.json")
	require.Empty(t, subjectsByKind(subjects, "aiModel"))
	require.Len(t, subjectsByKind(subjects, "dataset"), 1)

	ds := subjects[0].Bom.Dataset
	require.NotNil(t, ds.Modality)
	assert.Equal(t, []string{"structured", "timestamp"}, ds.Modality.StringArray)
	require.NotNil(t, ds.DataClassification)
	assert.Equal(t, "clear", *ds.DataClassification)
	require.NotNil(t, ds.Provenance)
	assert.Contains(t, *ds.Provenance, "collected from various sources")
	require.NotNil(t, ds.IntendedUse)
	assert.Contains(t, *ds.IntendedUse, "greenhouse gas")
	assert.Nil(t, ds.RecordCount)
}

func TestParseBom_SPDX3SingleSubjectFallback(t *testing.T) {
	result, err := ParseBom(loadFixture(t, "spdx-ai-model-1.json"))
	require.NoError(t, err)
	assert.Equal(t, FormatSPDX3AI, result.Format)
	assert.Equal(t, BOMTypeAIModel, result.Normalized.BOMType)
	assert.Equal(t, FormatSPDX3AI, result.Normalized.Format)
}

// synthetic SPDX-3 edge-case inputs (branch coverage; not fixtures)
func spdx3Synthetic(graph ...map[string]any) *SPDX3ParseResult {
	els := make([]any, len(graph))
	for i, g := range graph {
		els[i] = g
	}
	return ParseSPDX3(map[string]any{
		"@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld",
		"@graph":   els,
	})
}

func TestParseSPDX3_FirstStringEdges(t *testing.T) {
	nonStringFirst := spdx3Synthetic(map[string]any{
		"type": "ai_AIPackage", "spdxId": "m1", "name": "m1",
		"ai_domain": []any{map[string]any{"nested": true}, ""},
	}).Subjects[0].Bom.Model
	assert.Nil(t, nonStringFirst.Task)

	emptyDomain := spdx3Synthetic(map[string]any{
		"type": "ai_AIPackage", "spdxId": "m2", "name": "m2",
		"ai_domain": []any{},
	}).Subjects[0].Bom.Model
	assert.Nil(t, emptyDomain.Task)
}

func TestParseSPDX3_JoinDistinctEdges(t *testing.T) {
	nonArray := spdx3Synthetic(map[string]any{
		"type": "ai_AIPackage", "spdxId": "m1", "name": "m1",
		"ai_typeOfModel": "not-an-array",
	}).Subjects[0].Bom.Model
	assert.Nil(t, nonArray.ModelArchitecture)

	noStrings := spdx3Synthetic(map[string]any{
		"type": "ai_AIPackage", "spdxId": "m2", "name": "m2",
		"ai_typeOfModel": []any{map[string]any{"x": 1}, nil},
	}).Subjects[0].Bom.Model
	assert.Nil(t, noStrings.ModelArchitecture)
}

func TestParseSPDX3_DictionaryEntriesEdges(t *testing.T) {
	nonArray := spdx3Synthetic(map[string]any{
		"type": "ai_AIPackage", "spdxId": "m1", "name": "m1",
		"ai_hyperparameter": "nope",
	}).Subjects[0].Bom.Model
	assert.Empty(t, nonArray.Hyperparameters)

	mixed := spdx3Synthetic(map[string]any{
		"type": "ai_AIPackage", "spdxId": "m2", "name": "m2",
		"ai_hyperparameter": []any{
			"not-an-object",
			map[string]any{"type": "DictionaryEntry", "value": "orphan"},              // no key -> skipped
			map[string]any{"type": "DictionaryEntry", "key": "nullval", "value": nil}, // -> ""
			map[string]any{"type": "DictionaryEntry", "key": "noval"},                 // absent value -> ""
		},
	}).Subjects[0].Bom.Model
	require.Len(t, mixed.Hyperparameters, 2)
	empty := ""
	assert.Equal(t, Hyperparameter{Name: strPtr("nullval"), Value: &empty}, mixed.Hyperparameters[0])
	assert.Equal(t, Hyperparameter{Name: strPtr("noval"), Value: &empty}, mixed.Hyperparameters[1])
}

func TestParseSPDX3_DatasetRefsForEdges(t *testing.T) {
	subjects := spdx3Synthetic(
		map[string]any{"type": "dataset_DatasetPackage", "spdxId": "ds-known", "name": "KnownDS"},
		map[string]any{"type": "ai_AIPackage", "spdxId": "model-x", "name": "model-x"},
		// wrong from -> ignored
		map[string]any{"type": "Relationship", "relationshipType": "trainedOn", "from": "other-model", "to": []any{"ds-known"}},
		// wrong relationshipType -> ignored
		map[string]any{"type": "Relationship", "relationshipType": "contains", "from": "model-x", "to": []any{"ds-known"}},
		// scalar `to`, resolvable name
		map[string]any{"type": "Relationship", "relationshipType": "trainedOn", "from": "model-x", "to": "ds-known"},
		// duplicate resolving to same name -> deduped
		map[string]any{"type": "Relationship", "relationshipType": "testedOn", "from": "model-x", "to": []any{"ds-known"}},
		// unresolvable id -> raw id kept
		map[string]any{"type": "Relationship", "relationshipType": "testedOn", "from": "model-x", "to": []any{"ds-missing"}},
	).Subjects
	model := modelByName(t, subjects, "model-x").Bom.Model
	assert.Equal(t, []string{"KnownDS", "ds-missing"}, model.DatasetRefs)
}

func TestParseSPDX3_EmptyExtensions(t *testing.T) {
	// ai_AIPackage with no ai_* fields and no relationships -> empty model.
	modelSubject := spdx3Synthetic(map[string]any{"type": "ai_AIPackage", "spdxId": "bare", "name": "bare"}).Subjects[0]
	model := modelSubject.Bom.Model
	require.NotNil(t, model)
	assert.Equal(t, &AIModelBOMExtension{}, model)
	assert.Equal(t, "bare", modelSubject.Bom.Document["spdxId"])

	// dataset_DatasetPackage with non-array modality and no dataset_* fields -> empty dataset.
	dataset := spdx3Synthetic(map[string]any{
		"type": "dataset_DatasetPackage", "spdxId": "bare-ds", "name": "bare-ds",
		"dataset_datasetType": "scalar",
	}).Subjects[0].Bom.Dataset
	require.NotNil(t, dataset)
	assert.Equal(t, &DatasetBOMExtension{}, dataset)
	assert.Nil(t, dataset.Modality)
}

func TestParseSPDX3_IgnoresOtherElementsAndUnmappedDatasets(t *testing.T) {
	subjects := spdx3Synthetic(
		map[string]any{"type": "software_Package", "spdxId": "sw", "name": "sw"}, // ignored
		map[string]any{"type": "dataset_DatasetPackage", "name": "no-id"},        // no spdxId -> not in name map
		map[string]any{"type": "dataset_DatasetPackage", "spdxId": "no-name"},    // no name -> not in name map
		map[string]any{"type": "ai_AIPackage", "spdxId": "m", "name": "m"},
		map[string]any{"type": "Relationship", "relationshipType": "trainedOn", "from": "m", "to": []any{"no-id", "no-name"}},
	).Subjects

	assert.Len(t, subjectsByKind(subjects, "dataset"), 2)
	assert.Len(t, subjectsByKind(subjects, "aiModel"), 1)
	// Neither id-less nor name-less dataset is resolvable -> refs fall back to raw ids.
	model := modelByName(t, subjects, "m").Bom.Model
	assert.Equal(t, []string{"no-id", "no-name"}, model.DatasetRefs)
}

// scalarParityCases pins the numeric/boolean scalar values that MUST stringify
// byte-identically in Go and TS. The expected strings match the TS
// SCALAR_CASES exactly; the exponent forms (1e-7, 0.000001) are where a naive
// fmt.Sprintf("%v") would diverge from JS String().
var scalarParityCases = []struct {
	value    any
	expected string
}{
	{float64(1234567), "1234567"},
	{float64(0.4669), "0.4669"},
	{float64(1e-7), "1e-7"},
	{float64(1e-6), "0.000001"},
	{true, "true"},
}

func TestScalarValueParity_MLBOM(t *testing.T) {
	metrics := make([]any, len(scalarParityCases))
	for i, c := range scalarParityCases {
		metrics[i] = map[string]any{"type": fmt.Sprintf("m%d", i), "value": c.value}
	}
	n := ParseMLBOM(map[string]any{
		"serialNumber": "urn:uuid:num",
		"components": []any{map[string]any{
			"type": "machine-learning-model",
			"name": "m",
			"modelCard": map[string]any{
				"quantitativeAnalysis": map[string]any{"performanceMetrics": metrics},
			},
		}},
	})
	require.Len(t, n.Model.PerformanceMetrics, len(scalarParityCases))
	for i, c := range scalarParityCases {
		require.NotNil(t, n.Model.PerformanceMetrics[i].Value)
		assert.Equal(t, c.expected, *n.Model.PerformanceMetrics[i].Value)
	}
}

func TestScalarValueParity_SPDX3(t *testing.T) {
	metrics := make([]any, len(scalarParityCases))
	hyperparams := make([]any, len(scalarParityCases))
	for i, c := range scalarParityCases {
		metrics[i] = map[string]any{"type": "DictionaryEntry", "key": fmt.Sprintf("metric%d", i), "value": c.value}
		hyperparams[i] = map[string]any{"type": "DictionaryEntry", "key": fmt.Sprintf("hp%d", i), "value": c.value}
	}
	model := spdx3Synthetic(map[string]any{
		"type": "ai_AIPackage", "spdxId": "m", "name": "m",
		"ai_metric":         metrics,
		"ai_hyperparameter": hyperparams,
	}).Subjects[0].Bom.Model
	require.Len(t, model.PerformanceMetrics, len(scalarParityCases))
	require.Len(t, model.Hyperparameters, len(scalarParityCases))
	for i, c := range scalarParityCases {
		require.NotNil(t, model.PerformanceMetrics[i].Value)
		assert.Equal(t, c.expected, *model.PerformanceMetrics[i].Value)
		require.NotNil(t, model.Hyperparameters[i].Value)
		assert.Equal(t, c.expected, *model.Hyperparameters[i].Value)
	}
}
