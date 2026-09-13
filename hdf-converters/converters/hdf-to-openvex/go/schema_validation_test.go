package hdftoopenvex

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	corpus "github.com/mitre/hdf-libs/hdf-converters/v3/internal/corpus"
	shared "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go"
	"github.com/mitre/hdf-libs/hdf-converters/v3/shared/go/vex"
	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	testhdf "github.com/mitre/hdf-libs/hdf-schema/testhdf/go/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func openvexValidator(t *testing.T) *shared.SchemaValidator {
	t.Helper()
	return shared.NewSchemaValidator(t, filepath.Join(shared.GetConvertersDir(),
		"openvex-to-hdf", "fixtures", "openvex_json_schema.json"))
}

func amendmentsValidator(t *testing.T) *shared.SchemaValidator {
	t.Helper()
	return shared.NewSchemaValidator(t, filepath.Join("..", "..", "..", "..",
		"hdf-validators", "go", "schemas", "hdf-amendments.schema.json"))
}

// TestConvertHDFToOpenVEX_SchemaValid gates the converter output on the OpenVEX
// v0.2.0 JSON schema (draft 2020-12). See the vendored schema under
// openvex-to-hdf/fixtures. The shared table cases run here too: the conditional
// requirements they probe are schema rules, so the schema is what must judge them.
func TestConvertHDFToOpenVEX_SchemaValid(t *testing.T) {
	v := openvexValidator(t)

	for _, name := range []string{"multi-status-amendments.json", "spring-boot-log4j-amendments.json"} {
		t.Run(name, func(t *testing.T) {
			input, err := os.ReadFile(filepath.Join("..", "fixtures", "input", name))
			require.NoError(t, err)
			out, err := ConvertHDFToOpenVEX(input, "1.0.0")
			require.NoError(t, err)
			v.RequireValid(t, name, out)
		})
	}

	hdfV := amendmentsValidator(t)
	for _, c := range loadStatementTextCases(t) {
		t.Run(c.Name, func(t *testing.T) {
			input := c.input(t, hdfV)
			out, err := ConvertHDFToOpenVEX(input, "1.0.0")
			require.NoError(t, err)
			v.RequireValid(t, c.Name, out)
		})
	}
}

// statementTextCase is one row of the shared Go/TS table pinning the text
// OpenVEX demands on a statement. An expected value of "" means the field must
// be absent — the schema requires presence, and a present-but-empty string
// satisfies the letter of that while telling a consumer nothing.
type statementTextCase struct {
	Name     string `json:"name"`
	Override struct {
		Type             string                `json:"type"`
		RequirementID    string                `json:"requirementId"`
		Status           string                `json:"status"`
		Reason           string                `json:"reason"`
		Justification    string                `json:"justification"`
		AffectedPackages []hdf.AffectedPackage `json:"affectedPackages"`
		Milestones       []hdf.Milestone       `json:"milestones"`
	} `json:"override"`
	Status          string `json:"status"`
	ActionStatement string `json:"actionStatement"`
	ImpactStatement string `json:"impactStatement"`
	Justification   string `json:"justification"`
	Why             string `json:"why"`
}

func loadStatementTextCases(t *testing.T) []statementTextCase {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "shared", "openvex-statement-text-cases.json"))
	require.NoError(t, err)

	var table struct {
		Cases []statementTextCase `json:"cases"`
	}
	require.NoError(t, json.Unmarshal(raw, &table))
	require.NotEmpty(t, table.Cases, "an empty table would pass vacuously")
	return table.Cases
}

// input renders the case as an HDF Amendments document, asserted valid against
// the HDF schema first: a converter fed input its own schema rejects proves
// nothing about what it does with real documents.
func (c statementTextCase) input(t *testing.T, hdfV *shared.SchemaValidator) []byte {
	t.Helper()
	o := testhdf.Override(hdf.OverrideType(c.Override.Type), c.Override.RequirementID,
		testhdf.OverrideStatus(hdf.ResultStatus(c.Override.Status)),
		testhdf.OverrideReason(c.Override.Reason))
	if c.Override.Justification != "" {
		j := hdf.Justification(c.Override.Justification)
		o.Justification = &j
	}
	o.AffectedPackages = c.Override.AffectedPackages
	o.Milestones = c.Override.Milestones

	raw, err := json.Marshal(testhdf.Amendments("openvex statement text", o))
	require.NoError(t, err)
	hdfV.RequireValid(t, c.Name+" (test input)", raw)
	return raw
}

// TestConvertHDFToOpenVEX_StatementTextMatchesSharedTable pins the statement text
// rule, implemented once per language, against one shared definition. Presence
// is asserted on the raw JSON rather than on the decoded struct: every field
// here carries omitempty, so an empty value and an absent one are the same zero
// value after decoding — which is exactly how a dropped required field went
// unnoticed.
func TestConvertHDFToOpenVEX_StatementTextMatchesSharedTable(t *testing.T) {
	hdfV := amendmentsValidator(t)

	for _, c := range loadStatementTextCases(t) {
		t.Run(c.Name, func(t *testing.T) {
			out, err := ConvertHDFToOpenVEX(c.input(t, hdfV), "1.0.0")
			require.NoError(t, err)

			var doc struct {
				Statements []map[string]any `json:"statements"`
			}
			require.NoError(t, json.Unmarshal(out, &doc))
			require.Len(t, doc.Statements, 1)
			s := doc.Statements[0]

			require.Equal(t, c.Status, s["status"], c.Why)
			requireField(t, s, "action_statement", c.ActionStatement, c.Why)
			requireField(t, s, "impact_statement", c.ImpactStatement, c.Why)
			requireField(t, s, "justification", c.Justification, c.Why)
		})
	}
}

func requireField(t *testing.T, statement map[string]any, key, want, why string) {
	t.Helper()
	if want == "" {
		require.NotContains(t, statement, key, "%s must be absent (%s)", key, why)
		return
	}
	require.Equal(t, want, statement[key], "%s (%s)", key, why)
}

// TestConvertHDFToOpenVEX_ConditionalTextIsNeverBlank holds the converter to the
// intent of the two conditional branches rather than their letter: the schema
// requires the fields to be PRESENT, so a present-but-blank string passes
// validation while leaving a downstream consumer with nothing to act on.
func TestConvertHDFToOpenVEX_ConditionalTextIsNeverBlank(t *testing.T) {
	hdfV := amendmentsValidator(t)

	for _, c := range loadStatementTextCases(t) {
		t.Run(c.Name, func(t *testing.T) {
			out, err := ConvertHDFToOpenVEX(c.input(t, hdfV), "1.0.0")
			require.NoError(t, err)
			requireConditionalTextIsUsable(t, out)
		})
	}
}

func requireConditionalTextIsUsable(t *testing.T, out []byte) {
	t.Helper()
	var doc Document
	require.NoError(t, json.Unmarshal(out, &doc))
	for _, s := range doc.Statements {
		switch s.Status {
		case string(vex.StatusAffected):
			require.NotEmpty(t, strings.TrimSpace(s.ActionStatement),
				"affected statement for %s carries no remediation text", s.Vulnerability.Name)
		case string(vex.StatusNotAffected):
			require.NotEmpty(t,
				strings.TrimSpace(s.Justification)+strings.TrimSpace(s.ImpactStatement),
				"not_affected statement for %s carries neither justification nor impact_statement",
				s.Vulnerability.Name)
		}
	}
}

// TestCorpusGoldenParity freezes this converter's output for every MustConvert
// corpus case, and the TypeScript suite asserts against the SAME files — the
// corpus exercises the sparse inputs where the two implementations are most
// likely to drift, which the happy-path goldens never touched.
//
// Both sides convert the CANONICALIZED case input. The document @id is a digest
// of the input bytes, and the Go and TS corpora are byte-equal only after
// canonicalization (same document, different key order), so feeding the raw
// bytes would compare two digests of two spellings rather than two converters.
func TestCorpusGoldenParity(t *testing.T) {
	for _, c := range corpus.AmendmentsCorpus() {
		if c.Contract != corpus.MustConvert {
			continue // anything else may be rejected, so there is no output to freeze
		}
		t.Run(c.Name, func(t *testing.T) {
			canonical, err := corpus.CanonicalJSON(c.Input)
			require.NoError(t, err)
			out, err := ConvertHDFToOpenVEX(canonical, "1.0.0")
			require.NoError(t, err)

			goldenPath := filepath.Join("..", "fixtures", "expected", "corpus-"+c.Name+".openvex.json")
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

// An override carrying no affectedPackages, no componentRef and no legacy
// Products: line has no product to name. OpenVEX types a component @id as an
// IRI and makes statements[].products optional, so the array is omitted rather
// than filled with a synthetic id that would assert a product the source never
// identified.
func TestConvertHDFToOpenVEX_OmitsProductsWhenNoneIdentified(t *testing.T) {
	input := []byte(`{"amendmentId":"a1","name":"n",` +
		`"overrides":[{"requirementId":"CVE-2021-44228","type":"waiver","status":"passed",` +
		`"reason":"no product information at all","appliedBy":{"identifier":"admin"},` +
		`"appliedAt":"2020-01-01T00:00:00Z"}]}`)

	out, err := ConvertHDFToOpenVEX(input, "1.0.0")
	require.NoError(t, err)

	var doc struct {
		Statements []struct {
			Products []struct {
				ID string `json:"@id"`
			} `json:"products"`
		} `json:"statements"`
	}
	require.NoError(t, json.Unmarshal(out, &doc))
	require.Len(t, doc.Statements, 1)
	assert.Empty(t, doc.Statements[0].Products,
		"a synthetic product id asserts traceability the source never had")
	assert.NotContains(t, string(out), "HDFPID",
		"the placeholder is not an IRI and fails the OpenVEX schema")
}

// The adversarial corpus, adopted with no exemptions. This is the assertion the
// card asked for and it could not pass while the converter minted a synthetic
// product id: every MustConvert amendments case failed the OpenVEX schema on
// products[].@id, which types as an IRI. Exempting those cases was rejected —
// exempting every case the run has would make the adoption prove nothing.
func TestConvertHDFToOpenVEX_AdversarialCorpus(t *testing.T) {
	v := openvexValidator(t)

	corpus.RunSchemaCorpus(t, v, corpus.AmendmentsCorpus(), func(in []byte) ([]byte, error) {
		return ConvertHDFToOpenVEX(in, "1.0.0")
	})
}
