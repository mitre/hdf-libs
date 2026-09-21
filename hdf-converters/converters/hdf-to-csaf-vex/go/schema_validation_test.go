package hdftocsafvex

import (
	"bytes"
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	corpus "github.com/mitre/hdf-libs/hdf-converters/v3/internal/corpus"
	shared "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go"
	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	testhdf "github.com/mitre/hdf-libs/hdf-schema/testhdf/go/v3"
	"github.com/stretchr/testify/require"
)

const testCVE = "CVE-2021-44228"

// csafValidator compiles the OASIS CSAF v2.0 JSON schema (draft 2020-12). The
// CSAF schema $refs the FIRST.org CVSS schemas by URL; those are vendored
// alongside it and registered as companions so it compiles offline.
func csafValidator(t *testing.T) *shared.SchemaValidator {
	t.Helper()
	base := filepath.Join("..", "schemas")
	return shared.NewSchemaValidatorWithResources(t,
		filepath.Join(base, "csaf_json_schema.json"),
		map[string]string{
			"https://www.first.org/cvss/cvss-v2.0.json": filepath.Join(base, "cvss-v2.0.json"),
			"https://www.first.org/cvss/cvss-v3.0.json": filepath.Join(base, "cvss-v3.0.json"),
			"https://www.first.org/cvss/cvss-v3.1.json": filepath.Join(base, "cvss-v3.1.json"),
		})
}

// hdfAmendmentsValidator compiles the HDF Amendments schema, so an input this
// suite claims is legal HDF is asserted to be, not assumed. A converter fed
// input its own source schema rejects proves nothing about real documents.
func hdfAmendmentsValidator(t *testing.T) *shared.SchemaValidator {
	t.Helper()
	return shared.NewSchemaValidator(t, filepath.Join(shared.GetConvertersDir(),
		"..", "..", "hdf-validators", "go", "schemas", "hdf-amendments.schema.json"))
}

// TestConvertHDFToCSAFVEX_SchemaValid gates the converter output on the OASIS
// CSAF v2.0 JSON schema, for the golden fixtures and for the sparse HDF that
// reaches CSAF's minLength-constrained text fields.
func TestConvertHDFToCSAFVEX_SchemaValid(t *testing.T) {
	v := csafValidator(t)

	// Exactly the TestGoldenParity inputs, so no frozen golden escapes the schema.
	for _, name := range []string{"sec-vex-amendments.json", "uc-01-fixed-amendments.json"} {
		t.Run(name, func(t *testing.T) {
			out, err := ConvertHDFToCSAFVEX(loadInput(t, name), "1.0.0")
			require.NoError(t, err)
			v.RequireValid(t, name, out)
		})
	}

	hdfV := hdfAmendmentsValidator(t)
	for _, tc := range []struct {
		name       string
		amendments hdf.HDFAmendments
	}{
		{
			// evidence.description is optional in HDF; CSAF requires
			// references[].summary with minLength 1.
			name: "evidence without description",
			amendments: func() hdf.HDFAmendments {
				doc := testhdf.Amendments("a", testhdf.Override(hdf.OverrideTypeWaiver, testCVE,
					testhdf.OverrideStatus(hdf.Failed), testhdf.OverrideReason("accepted")))
				doc.Overrides[0].Evidence = []hdf.Evidence{{
					Type: hdf.URL, Data: "https://example.com/advisory",
				}}
				return doc
			}(),
		},
		{
			// externalReferences.description is optional for the same sink.
			name: "external reference without description",
			amendments: func() hdf.HDFAmendments {
				href := "https://example.com/vendor-advisory"
				doc := testhdf.Amendments("a", testhdf.Override(hdf.OverrideTypeWaiver, testCVE,
					testhdf.OverrideStatus(hdf.Failed), testhdf.OverrideReason("accepted")))
				doc.Overrides[0].ExternalReferences = []hdf.ExternalReference{{
					SourceName: "vendor", Href: &href,
				}}
				return doc
			}(),
		},
		{
			// A reason written by the reverse importer can be nothing but the
			// machine-generated 'Products:' line, which strips to no prose at
			// all; CSAF requires threats[].details with minLength 1.
			name: "reason is only a products line",
			amendments: testhdf.Amendments("a", testhdf.Override(hdf.OverrideTypeWaiver, testCVE,
				testhdf.OverrideStatus(hdf.Failed), testhdf.OverrideReason("Products: CSAFPID-0001"))),
		},
		{
			name: "reason is whitespace only",
			amendments: testhdf.Amendments("a", testhdf.Override(hdf.OverrideTypeWaiver, testCVE,
				testhdf.OverrideStatus(hdf.Failed), testhdf.OverrideReason("   "))),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			input, err := json.Marshal(tc.amendments)
			require.NoError(t, err)
			hdfV.RequireValid(t, tc.name+" (input)", input)

			out, err := ConvertHDFToCSAFVEX(input, "1.0.0")
			require.NoError(t, err)
			v.RequireValid(t, tc.name, out)
		})
	}
}

// TestConvertHDFToCSAFVEX_AdversarialCorpus runs the shared corpus, so this
// converter is held to both contracts an exporter owes rather than only to
// fully-populated fixtures — the gap that let its empty-summary defect ship.
func TestConvertHDFToCSAFVEX_AdversarialCorpus(t *testing.T) {
	corpus.RunSchemaCorpus(t, csafValidator(t), corpus.AmendmentsCorpus(), func(in []byte) ([]byte, error) {
		return ConvertHDFToCSAFVEX(in, "1.0.0")
	})
}

// TestConvertHDFToCSAFVEX_OmitsEmptyProductStatus covers the one path that
// emits a vulnerability without filling any product bucket: an override whose
// type the HDF enum forbids but a typed decode accepts, carrying enrichment that
// still produces output. CSAF constrains product_status with minProperties 1.
func TestConvertHDFToCSAFVEX_OmitsEmptyProductStatus(t *testing.T) {
	doc := testhdf.Amendments("a", testhdf.Override("not-a-real-override-type", testCVE,
		testhdf.OverrideStatus(hdf.Failed), testhdf.OverrideReason("accepted")))
	doc.Overrides[0].Cvss = completeCvss31(t)

	input, err := json.Marshal(doc)
	require.NoError(t, err)
	out, err := ConvertHDFToCSAFVEX(input, "1.0.0")
	require.NoError(t, err)

	var parsed struct {
		Vulnerabilities []map[string]any `json:"vulnerabilities"`
	}
	require.NoError(t, json.Unmarshal(out, &parsed))
	require.Len(t, parsed.Vulnerabilities, 1)
	require.NotContains(t, parsed.Vulnerabilities[0], "product_status")
}

// TestCorpusGoldenParity freezes this converter's output for every MustConvert
// corpus case, and the TypeScript suite asserts against the SAME files. That is
// what makes the cross-language claim checkable: the corpus exercises the sparse
// inputs (empty reason, no milestones, undescribed evidence) where the two
// implementations are most likely to drift, which the happy-path goldens never
// touched. Every value is deterministic, so the comparison is byte-for-byte.
func TestCorpusGoldenParity(t *testing.T) {
	for _, c := range corpus.AmendmentsCorpus() {
		if c.Contract != corpus.MustConvert {
			continue // anything else may be rejected, so there is no output to freeze
		}
		t.Run(c.Name, func(t *testing.T) {
			out, err := ConvertHDFToCSAFVEX(c.Input, "1.0.0")
			require.NoError(t, err)

			goldenPath := filepath.Join(shared.GetConvertersDir(), "hdf-to-csaf-vex",
				"fixtures", "expected", "corpus-"+c.Name+".csaf-vex.json")
			if os.Getenv("UPDATE_GOLDEN") == "1" {
				require.NoError(t, os.WriteFile(goldenPath, out, 0o644))
				return
			}

			golden, err := os.ReadFile(goldenPath)
			require.NoError(t, err, "read golden %s (regenerate with UPDATE_GOLDEN=1)", goldenPath)
			require.Equal(t, string(golden), string(out), "golden mismatch for %s", c.Name)
		})
	}
}

// textSinkCases is the shared table the TypeScript peer also reads, so the two
// implementations of these two CSAF text rules are asserted against ONE
// definition rather than two literals that can drift apart.
type textSinkCases struct {
	ReferenceSummary struct {
		Cases []struct {
			Name        string `json:"name"`
			Description string `json:"description"`
			URL         string `json:"url"`
			Want        string `json:"want"`
		} `json:"cases"`
	} `json:"referenceSummary"`
	ReasonProse struct {
		Cases []struct {
			Name   string `json:"name"`
			Reason string `json:"reason"`
			Want   string `json:"want"`
		} `json:"cases"`
	} `json:"reasonProse"`
}

func loadTextSinkCases(t *testing.T) textSinkCases {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(shared.GetConvertersDir(), "..", "shared", "csaf-vex-text-cases.json"))
	require.NoError(t, err)
	var doc textSinkCases
	require.NoError(t, json.Unmarshal(raw, &doc))
	require.NotEmpty(t, doc.ReferenceSummary.Cases, "shared table is empty — the run would pass vacuously")
	require.NotEmpty(t, doc.ReasonProse.Cases, "shared table is empty — the run would pass vacuously")
	return doc
}

func TestTextSinks_MatchSharedTable(t *testing.T) {
	table := loadTextSinkCases(t)
	for _, c := range table.ReferenceSummary.Cases {
		t.Run("referenceSummary/"+c.Name, func(t *testing.T) {
			require.Equal(t, c.Want, referenceSummary(c.Description, c.URL))
		})
	}
	for _, c := range table.ReasonProse.Cases {
		t.Run("reasonProse/"+c.Name, func(t *testing.T) {
			require.Equal(t, c.Want, reasonProse(c.Reason))
		})
	}
}

// cvssScoreCases is the shared table the TypeScript peer also reads, so the
// completeness rule and the severity mapping are asserted against ONE
// definition in both languages. See the table's $comment for data provenance.
type cvssScoreCases struct {
	Severity map[string]string `json:"severity"`
	Cases    []struct {
		Name    string          `json:"name"`
		Why     string          `json:"why"`
		CVE     string          `json:"cve"`
		Product string          `json:"product"`
		Cvss    hdf.Cvss        `json:"cvss"`
		Want    json.RawMessage `json:"want"`
		Warning *string         `json:"warning"`
	} `json:"cases"`
}

// affectedPackageFor places a table product in the affectedPackages slot its
// prefix names (purl or cpe), the structured product identity the exporter reads.
func affectedPackageFor(product string) hdf.AffectedPackage {
	p := product
	if strings.HasPrefix(p, "cpe:") {
		return hdf.AffectedPackage{Cpe: &p}
	}
	return hdf.AffectedPackage{Purl: &p}
}

func loadCvssScoreCases(t *testing.T) cvssScoreCases {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "fixtures", "cvss-score-cases.json"))
	require.NoError(t, err)
	var doc cvssScoreCases
	require.NoError(t, json.Unmarshal(raw, &doc))
	require.NotEmpty(t, doc.Cases, "shared table is empty — the run would pass vacuously")
	// The table's own $comment would otherwise read as a sixth band.
	delete(doc.Severity, "$comment")
	require.NotEmpty(t, doc.Severity, "shared table is empty — the run would pass vacuously")
	return doc
}

// completeCvss31 is the table's v31-complete block: the CVSS shape a test that
// only needs a score to be emitted can rely on.
func completeCvss31(t *testing.T) *hdf.Cvss {
	t.Helper()
	for _, c := range loadCvssScoreCases(t).Cases {
		if c.Name == "v31-complete" {
			cv := c.Cvss
			return &cv
		}
	}
	t.Fatal("shared table has no v31-complete case")
	return nil
}

// TestCvssScores_MatchSharedTable holds the score export to the shared table:
// legal HDF in, a CSAF-valid document out, exactly the table's score (or none,
// with the table's warning), and — through the frozen goldens — the same bytes
// from both languages. It captures the process logger, so it must not run in
// parallel with anything that logs.
func TestCvssScores_MatchSharedTable(t *testing.T) {
	v := csafValidator(t)
	hdfV := hdfAmendmentsValidator(t)
	table := loadCvssScoreCases(t)

	var logs bytes.Buffer
	log.SetOutput(&logs)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })

	for _, c := range table.Cases {
		t.Run(c.Name, func(t *testing.T) {
			logs.Reset()
			doc := testhdf.Amendments("a", testhdf.Override(hdf.OverrideTypeWaiver, c.CVE,
				testhdf.OverrideStatus(hdf.Failed), testhdf.OverrideReason("accepted")))
			doc.Overrides[0].AffectedPackages = []hdf.AffectedPackage{affectedPackageFor(c.Product)}
			cv := c.Cvss
			doc.Overrides[0].Cvss = &cv

			input, err := json.Marshal(doc)
			require.NoError(t, err)
			hdfV.RequireValid(t, c.Name+" (input)", input)

			out, err := ConvertHDFToCSAFVEX(input, "1.0.0")
			require.NoError(t, err, c.Why)
			v.RequireValid(t, c.Name, out)

			var parsed struct {
				Vulnerabilities []struct {
					Scores []json.RawMessage `json:"scores"`
				} `json:"vulnerabilities"`
			}
			require.NoError(t, json.Unmarshal(out, &parsed))
			require.Len(t, parsed.Vulnerabilities, 1)
			if string(c.Want) == "null" {
				require.Empty(t, parsed.Vulnerabilities[0].Scores, c.Why)
			} else {
				require.Len(t, parsed.Vulnerabilities[0].Scores, 1, c.Why)
				require.JSONEq(t, string(c.Want), string(parsed.Vulnerabilities[0].Scores[0]), c.Why)
			}

			if c.Warning == nil {
				require.NotContains(t, logs.String(), "WARNING", c.Why)
			} else {
				require.Contains(t, logs.String(), "WARNING: "+*c.Warning, c.Why)
			}

			goldenPath := filepath.Join("..", "fixtures", "expected", "cvss-"+c.Name+".csaf-vex.json")
			if os.Getenv("UPDATE_GOLDEN") == "1" {
				require.NoError(t, os.WriteFile(goldenPath, out, 0o644))
				return
			}
			golden, err := os.ReadFile(goldenPath)
			require.NoError(t, err, "read golden %s (regenerate with UPDATE_GOLDEN=1)", goldenPath)
			require.Equal(t, string(golden), string(out), "golden mismatch for %s", c.Name)
		})
	}
}

// TestCsafSeverity_MatchesSharedTable pins the band mapping to the shared table
// and the table to the enum in the vendored FIRST.org schema, so neither the Go
// nor the TypeScript mapping can drift from what CSAF actually accepts.
func TestCsafSeverity_MatchesSharedTable(t *testing.T) {
	table := loadCvssScoreCases(t)
	for band, want := range table.Severity {
		t.Run(band, func(t *testing.T) {
			require.Equal(t, want, csafSeverity(hdf.CVSSSeverity(band)))
		})
	}

	raw, err := os.ReadFile(filepath.Join(shared.GetConvertersDir(), "hdf-to-csaf-vex", "schemas", "cvss-v3.1.json"))
	require.NoError(t, err)
	var first struct {
		Definitions struct {
			SeverityType struct {
				Enum []string `json:"enum"`
			} `json:"severityType"`
		} `json:"definitions"`
	}
	require.NoError(t, json.Unmarshal(raw, &first))

	got := make([]string, 0, len(table.Severity))
	for _, v := range table.Severity {
		got = append(got, v)
	}
	sort.Strings(got)
	enum := append([]string(nil), first.Definitions.SeverityType.Enum...)
	sort.Strings(enum)
	require.Equal(t, enum, got, "the table's severity values must be exactly FIRST's severityType enum")
	require.Equal(t, strings.ToUpper(strings.Join(enum, ",")), strings.Join(enum, ","), "FIRST's enum is uppercase")
}
