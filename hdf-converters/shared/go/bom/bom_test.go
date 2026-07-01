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
			Packages: []SBOMPackage{},
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
