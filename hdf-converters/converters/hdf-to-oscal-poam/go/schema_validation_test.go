package hdftooscalpoam

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	oscal "github.com/mitre/hdf-libs/hdf-converters/v3/converters/oscal-to-hdf/go"
	corpus "github.com/mitre/hdf-libs/hdf-converters/v3/internal/corpus"
	shared "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go"
	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// poamSchema is one vendored NIST OSCAL POA&M schema, compiled.
type poamSchema struct {
	file string
	v    *shared.SchemaValidator
}

// poamSchemas compiles every vendored POA&M schema the output must satisfy:
// 1.1.2, which the converter declares as "oscal-version", and 1.2.3, the current
// release, whose non-empty string patterns 1.1.2 does not apply. See
// ../schemas/provenance.txt.
func poamSchemas(t *testing.T) []poamSchema {
	t.Helper()
	files := []string{"oscal_poam_schema-v1.1.2.json", "oscal_poam_schema-v1.2.3.json"}
	schemas := make([]poamSchema, 0, len(files))
	for _, f := range files {
		schemas = append(schemas, poamSchema{f, shared.NewSchemaValidator(t,
			filepath.Join(shared.GetConvertersDir(), "hdf-to-oscal-poam", "schemas", f))})
	}
	return schemas
}

// minimalAmendments loads the repo's minimal amendments fixture and lets the
// caller rewrite fields on its single override.
func minimalAmendments(t *testing.T, override map[string]any) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(shared.GetConvertersDir(), "..", "..",
		"hdf-schema", "test", "fixtures", "minimal-amendments.json"))
	require.NoError(t, err)
	var doc map[string]any
	require.NoError(t, json.Unmarshal(raw, &doc))
	overrides, ok := doc["overrides"].([]any)
	require.True(t, ok)
	require.Len(t, overrides, 1)
	first, ok := overrides[0].(map[string]any)
	require.True(t, ok)
	for k, val := range override {
		first[k] = val
	}
	out, err := json.Marshal(doc)
	require.NoError(t, err)
	return out
}

// TestConvertHDFToOSCALPOAM_SchemaValid gates the converter output on every
// vendored NIST OSCAL POA&M schema.
func TestConvertHDFToOSCALPOAM_SchemaValid(t *testing.T) {
	appliedAt := time.Date(2026, 1, 15, 0, 0, 0, 0, time.UTC)
	expiresAt := time.Date(2027, 1, 15, 0, 0, 0, 0, time.UTC)
	sysRef := "https://example.com/ssp.json"

	cases := []struct {
		label      string
		amendments hdf.HDFAmendments
	}{
		{
			label: "minimal poam override",
			amendments: hdf.HDFAmendments{
				Name: "test-poam",
				Overrides: []hdf.StandaloneOverride{
					{
						Type: hdf.Poam, RequirementID: "AC-1", Reason: "Pending remediation",
						Status:    resultStatusPtr(hdf.Failed),
						AppliedBy: hdf.Identity{Type: hdf.Simple, Identifier: "admin@example.com"},
						AppliedAt: appliedAt, ExpiresAt: expiresAt,
					},
				},
			},
		},
		{
			label: "with system ref and multiple overrides",
			amendments: hdf.HDFAmendments{
				Name: "multi", SystemRef: &sysRef,
				Overrides: []hdf.StandaloneOverride{
					{
						Type: hdf.Poam, RequirementID: "AC-1", Reason: "r1",
						Status:    resultStatusPtr(hdf.Failed),
						AppliedBy: hdf.Identity{Type: hdf.Simple, Identifier: "a@example.com"},
						AppliedAt: appliedAt, ExpiresAt: expiresAt,
					},
					{
						Type: hdf.Poam, RequirementID: "AC-2", Reason: "r2",
						Status:    resultStatusPtr(hdf.Failed),
						AppliedBy: hdf.Identity{Type: hdf.Simple, Identifier: "b@example.com"},
						AppliedAt: appliedAt, ExpiresAt: expiresAt,
					},
				},
			},
		},
	}

	inputs := make([]struct {
		label string
		input []byte
	}, 0, len(cases)+1)
	for _, tc := range cases {
		input, err := json.Marshal(tc.amendments)
		require.NoError(t, err)
		inputs = append(inputs, struct {
			label string
			input []byte
		}{tc.label, input})
	}
	inputs = append(inputs, struct {
		label string
		input []byte
	}{"empty requirementId", minimalAmendments(t, map[string]any{"requirementId": ""})})

	for _, s := range poamSchemas(t) {
		for _, tc := range inputs {
			t.Run(s.file+"/"+tc.label, func(t *testing.T) {
				out, err := ConvertHDFToOSCALPOAM(tc.input, "1.0.0")
				require.NoError(t, err)
				s.v.RequireValid(t, tc.label, out)
			})
		}
	}
}

// TestConvertHDFToOSCALPOAM_EmptyRequirementIDTitle_1_2_3 pins the title
// fallback. OSCAL 1.2.x requires both titles to be a non-empty single line. HDF
// rejects an empty requirementId but not a whitespace-only one, and the
// converter's input guard is top-level only, so both still reach the fallback.
// The verdict is scoped to requirementId because the shared fixture's
// appliedBy.name is undeclared, which a 2020-12 validator also reports.
func TestConvertHDFToOSCALPOAM_EmptyRequirementIDTitle_1_2_3(t *testing.T) {
	schemas := poamSchemas(t)
	hdfV := shared.NewSchemaValidator(t, filepath.Join("..", "..", "..", "..",
		"hdf-validators", "go", "schemas", "hdf-amendments.schema.json"))
	for _, tc := range []struct {
		name, requirementID, wantTitle string
		hdfRejectsID                   bool
	}{
		{"empty requirementId falls back", "", "Unidentified requirement", true},
		{"whitespace-only requirementId falls back", "   ", "Unidentified requirement", false},
		{"a real requirementId is used verbatim", "SV-001", "SV-001", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			input := minimalAmendments(t, map[string]any{"requirementId": tc.requirementID})
			verr := hdfV.Validate(input)
			assert.Equal(t, tc.hdfRejectsID, verr != nil && strings.Contains(verr.Error(), "/overrides/0/requirementId"),
				"HDF amendments schema verdict on requirementId: %v", verr)

			out, err := ConvertHDFToOSCALPOAM(input, "1.0.0")
			require.NoError(t, err)
			for _, s := range schemas {
				s.v.RequireValid(t, s.file, out)
			}

			var doc struct {
				POAM struct {
					Risks []struct {
						Title string `json:"title"`
					} `json:"risks"`
					Items []struct {
						Title string `json:"title"`
					} `json:"poam-items"`
				} `json:"plan-of-action-and-milestones"`
			}
			require.NoError(t, json.Unmarshal(out, &doc))
			require.Len(t, doc.POAM.Risks, 1)
			require.Len(t, doc.POAM.Items, 1)
			assert.Equal(t, tc.wantTitle, doc.POAM.Risks[0].Title)
			assert.Equal(t, tc.wantTitle, doc.POAM.Items[0].Title)
		})
	}
}

// TestConvertHDFToOSCALPOAM_RiskRationaleWithoutRequirementID pins the
// absence sentence for an override that carries neither a reason nor an id: it
// must not end on a dangling "applied to ." clause.
func TestConvertHDFToOSCALPOAM_RiskRationaleWithoutRequirementID(t *testing.T) {
	for _, tc := range []struct{ name, requirementID, want string }{
		{"no identifier drops the applied-to clause", "", "No rationale was recorded for the waiver override."},
		{"an identifier is named", "SV-001", "No rationale was recorded for the waiver override applied to SV-001."},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, err := ConvertHDFToOSCALPOAM(minimalAmendments(t, map[string]any{
				"requirementId": tc.requirementID, "reason": "",
			}), "1.0.0")
			require.NoError(t, err)

			var doc struct {
				POAM struct {
					Risks []struct {
						Statement   string `json:"statement"`
						Description string `json:"description"`
					} `json:"risks"`
				} `json:"plan-of-action-and-milestones"`
			}
			require.NoError(t, json.Unmarshal(out, &doc))
			require.Len(t, doc.POAM.Risks, 1)
			assert.Equal(t, tc.want, doc.POAM.Risks[0].Statement)
			assert.Equal(t, tc.want, doc.POAM.Risks[0].Description)
		})
	}
}

// TestConvertHDFToOSCALPOAM_AdversarialCorpus runs the shared corpus against
// every vendored schema, so this converter is held to both contracts an exporter
// owes rather than only to fully-populated fixtures — the gap that let the
// defects in issue #236 ship.
func TestConvertHDFToOSCALPOAM_AdversarialCorpus(t *testing.T) {
	for _, s := range poamSchemas(t) {
		t.Run(s.file, func(t *testing.T) {
			corpus.RunSchemaCorpus(t, s.v, corpus.AmendmentsCorpus(), func(in []byte) ([]byte, error) {
				return ConvertHDFToOSCALPOAM(in, "1.0.0")
			})
		})
	}
}

// TestConvertHDFToOSCALPOAM_RejectsUnconvertibleInput pins the structural guard.
// Before it existed the converter zero-filled an arbitrary JSON object into
// HDFAmendments and emitted a confident, empty, schema-invalid document with a
// success exit — the core complaint in issue #236.
func TestConvertHDFToOSCALPOAM_RejectsUnconvertibleInput(t *testing.T) {
	for _, tc := range []struct{ name, input string }{
		{"arbitrary object", `{"foo":"bar"}`},
		{"empty object", `{}`},
		{"missing overrides", `{"name":"a"}`},
		{"empty overrides", `{"name":"a","overrides":[]}`},
		{"top-level array", `[]`},
		{"top-level null", `null`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ConvertHDFToOSCALPOAM([]byte(tc.input), "1.0.0")
			require.Error(t, err, "input that cannot be faithfully converted must be rejected")
		})
	}
}

// TestConvertHDFToOSCALPOAM_RiskStatementNeverOmitted covers the defect the
// adversarial corpus found that issue #236 did not report: Statement carries
// omitempty, so an override with an empty reason produced a risk with no
// statement — which the schema lists as required alongside title and status.
func TestConvertHDFToOSCALPOAM_RiskStatementNeverOmitted(t *testing.T) {
	appliedAt := time.Date(2026, 1, 15, 0, 0, 0, 0, time.UTC)
	expiresAt := time.Date(2027, 1, 15, 0, 0, 0, 0, time.UTC)

	input, err := json.Marshal(hdf.HDFAmendments{
		Name: "t",
		Overrides: []hdf.StandaloneOverride{{
			Type: hdf.Poam, RequirementID: "AC-1", Reason: "",
			Status:    resultStatusPtr(hdf.Failed),
			AppliedBy: hdf.Identity{Type: hdf.Simple, Identifier: "a@example.com"},
			AppliedAt: appliedAt, ExpiresAt: expiresAt,
		}},
	})
	require.NoError(t, err)

	out, err := ConvertHDFToOSCALPOAM(input, "1.0.0")
	require.NoError(t, err)

	var doc struct {
		POAM struct {
			Risks []struct {
				Statement   string `json:"statement"`
				Description string `json:"description"`
				Title       string `json:"title"`
			} `json:"risks"`
		} `json:"plan-of-action-and-milestones"`
	}
	require.NoError(t, json.Unmarshal(out, &doc))
	require.Len(t, doc.POAM.Risks, 1)
	require.NotEmpty(t, doc.POAM.Risks[0].Statement, "statement is schema-required")
	require.NotEmpty(t, doc.POAM.Risks[0].Description, "description is schema-required")
	require.NotEmpty(t, doc.POAM.Risks[0].Title)
}

// TestPOAMItemsMarshalAsEmptyArrayNotNull exercises the assembly directly with
// zero overrides, which the public entry point rejects. That unreachable-by-design
// state is exactly what must be pinned: a test that feeds one override proves
// nothing, because append yields a non-nil slice whether or not the field was
// pre-allocated. Reverting the make() call fails this test and only this test.
//
// risks is deliberately NOT asserted here: it carries omitempty, so a nil slice
// is omitted rather than nulled, and the schema permits its absence.
func TestPOAMItemsMarshalAsEmptyArrayNotNull(t *testing.T) {
	poam, err := amendmentsToPOAM(&hdf.HDFAmendments{Name: "t"}, "1.0.0")
	require.NoError(t, err)

	raw, err := json.Marshal(poam)
	require.NoError(t, err)
	require.Contains(t, string(raw), `"poam-items":[]`,
		"a nil slice marshals as null, which the schema rejects for a required array")
	require.NotContains(t, string(raw), `"poam-items":null`)
}

// TestPOAMTitleFallback covers the branch a document reaches when it carries
// overrides but no name. HDF requires name, so this only happens to a document
// that slipped past some other producer's validation — but OSCAL requires
// metadata.title, so emitting "" there would trade one silent gap for another.
func TestPOAMTitleFallback(t *testing.T) {
	id := "AMD-9"
	for _, tc := range []struct {
		name string
		a    hdf.HDFAmendments
		want string
	}{
		{"name wins", hdf.HDFAmendments{Name: "Q1 waivers", AmendmentID: &id}, "Q1 waivers"},
		{"falls back to amendmentId", hdf.HDFAmendments{Name: "", AmendmentID: &id}, "AMD-9"},
		{"falls back to a stated default", hdf.HDFAmendments{Name: ""}, "HDF Amendments"},
		{"whitespace-only name is not text", hdf.HDFAmendments{Name: "   "}, "HDF Amendments"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			poam, err := amendmentsToPOAM(&tc.a, "1.0.0")
			require.NoError(t, err)
			require.Equal(t, tc.want, poam.Metadata.Title)
		})
	}
}

// TestCorpusGoldenParity freezes this converter's output for every MustConvert corpus
// case, and the TypeScript suite asserts against the SAME files. That is what
// makes the cross-language claim checkable: the corpus exercises the sparse
// inputs (empty reason, no milestones, undescribed evidence) where the two
// implementations are most likely to drift, which the single happy-path golden
// never touched. Fresh UUIDs and the conversion timestamp are masked; the UUID
// reference graph survives masking, so wiring differences still fail.
func TestCorpusGoldenParity(t *testing.T) {
	for _, c := range corpus.AmendmentsCorpus() {
		if c.Contract != corpus.MustConvert {
			continue // anything else may be rejected, so there is no output to freeze
		}
		t.Run(c.Name, func(t *testing.T) {
			out, err := ConvertHDFToOSCALPOAM(c.Input, "1.0.0")
			require.NoError(t, err)

			goldenPath := filepath.Join(shared.GetConvertersDir(), "hdf-to-oscal-poam",
				"fixtures", "expected", "corpus-"+c.Name+".oscal-poam.json")
			if os.Getenv("UPDATE_GOLDEN") == "1" {
				require.NoError(t, os.WriteFile(goldenPath, out, 0o644))
				return
			}

			golden, err := os.ReadFile(goldenPath)
			require.NoError(t, err, "read golden %s (regenerate with UPDATE_GOLDEN=1)", goldenPath)

			maskedGolden, err := shared.MaskVolatileJSON(golden, poamVolatileKeys)
			require.NoError(t, err)
			maskedOut, err := shared.MaskVolatileJSON(out, poamVolatileKeys)
			require.NoError(t, err)
			require.Equal(t, maskedGolden, maskedOut, "golden mismatch for %s", c.Name)
		})
	}
}

// OSCAL types prop/@name as TokenDatatype, while HDF puts no constraint on
// amendments.labels keys, so a label key cannot be a prop name. Labels are
// label-key/label-value prop pairs, so every key shape — Kubernetes and OCI keys
// namespaced with '/', and the empty key — is carried verbatim in a valid document.
func TestConvertHDFToOSCALPOAM_LabelKeysAreTokens(t *testing.T) {
	v := shared.NewSchemaValidator(t, filepath.Join(shared.GetConvertersDir(),
		"hdf-to-oscal-poam", "schemas", "oscal_poam_schema-v1.1.2.json"))
	hdfV := amendmentsValidator(t)

	for _, tc := range []struct{ key string }{
		{"app.kubernetes.io/name"},
		{"env:prod"},
		{"2024-audit"},
		{"com.redhat.component"},
		{""},
	} {
		t.Run(tc.key, func(t *testing.T) {
			input := []byte(`{"name":"a","overrides":[{"requirementId":"r","type":"waiver",` +
				`"status":"notApplicable","reason":"accepted risk",` +
				`"appliedAt":"2020-01-01T00:00:00Z","expiresAt":"2099-12-31T00:00:00Z",` +
				`"appliedBy":{"identifier":"analyst","type":"username"}}],` +
				`"labels":{` + strconv.Quote(tc.key) + `:"x"}}`)

			// Asserted, not asserted-about: a converter fed input its own schema
			// rejects proves nothing about what it does with real documents.
			require.NoError(t, hdfV.Validate(input), "the test input is not valid HDF")

			out, err := ConvertHDFToOSCALPOAM(input, "1.0.0")
			require.NoError(t, err)
			require.NoError(t, v.Validate(out),
				"a label key that is not a token must not produce an invalid document")

			value := metadataPropNamed(t, out, "label-value")
			require.Equal(t, "x", value.Value)
			require.Equal(t, "label-1", value.Group)
			if tc.key == "" {
				empty := metadataPropNamed(t, out, "empty-field")
				require.Equal(t, "key", empty.Value, "an empty key is carried by empty-field")
				require.Equal(t, "label-1", empty.Group)
				return
			}
			key := metadataPropNamed(t, out, "label-key")
			require.Equal(t, tc.key, key.Value, "the key is carried verbatim as a value")
			require.Equal(t, "label-1", key.Group)
			require.Empty(t, key.Remarks)
		})
	}
}

// metadataPropNamed returns the metadata property with the given name, failing
// the test if it is absent. Asserting the property specifically keeps this from
// passing on a substring match elsewhere in the document.
func metadataPropNamed(t *testing.T, out []byte, name string) oscal.Property {
	t.Helper()

	var doc struct {
		POAM struct {
			Metadata struct {
				Props []oscal.Property `json:"props"`
			} `json:"metadata"`
		} `json:"plan-of-action-and-milestones"`
	}
	require.NoError(t, json.Unmarshal(out, &doc))

	for _, p := range doc.POAM.Metadata.Props {
		if p.Name == name {
			return p
		}
	}
	names := make([]string, 0, len(doc.POAM.Metadata.Props))
	for _, p := range doc.POAM.Metadata.Props {
		names = append(names, p.Name)
	}
	t.Fatalf("no metadata prop named %q; got %v", name, names)
	return oscal.Property{}
}

// amendmentsValidator guards the rule that makes these tests mean anything: a
// converter fed input its own schema rejects proves nothing about real documents.
func amendmentsValidator(t *testing.T) *shared.SchemaValidator {
	t.Helper()
	return shared.NewSchemaValidator(t, filepath.Join("..", "..", "..", "..",
		"hdf-validators", "go", "schemas", "hdf-amendments.schema.json"))
}

// componentRef and amendmentId are deliberately absent from this table: both are
// format:uuid in hdf-amendments, so a padded value is not valid HDF and testing
// it would prove nothing about real documents. baselineRef carries no format,
// which is why its padded form IS a real case here.
//
// OSCAL types many fields StringDatatype (^\S(.*\S)?$ — non-empty, no leading or
// trailing whitespace), while hdf-amendments puts no minLength on most of the
// strings that feed them. So an empty or padded value is valid HDF that yields a
// POA&M the schema rejects, at exit 0. Six sinks were affected, not the two the
// sweep first found; every free-text string now goes through one helper that
// trims and drops what is left empty. An empty requirementId is no longer valid
// HDF, so the title-fallback test covers it instead.
//
// Each input is asserted valid HDF first: a converter fed input its own schema
// rejects proves nothing about what it does with real documents.
func TestConvertHDFToOSCALPOAM_StringDatatypeSinks(t *testing.T) {
	v := shared.NewSchemaValidator(t, filepath.Join(shared.GetConvertersDir(),
		"hdf-to-oscal-poam", "schemas", "oscal_poam_schema-v1.1.2.json"))
	hdfV := shared.NewSchemaValidator(t, filepath.Join("..", "..", "..", "..",
		"hdf-validators", "go", "schemas", "hdf-amendments.schema.json"))

	const doc = `{"name":"a"%s,"overrides":[{"requirementId":%s,"type":"waiver",` +
		`"status":"notApplicable","reason":"r"%s,"appliedAt":"2020-01-01T00:00:00Z",` +
		`"expiresAt":"2099-12-31T00:00:00Z","appliedBy":{"identifier":%s,"type":"username"}}]}`

	for _, tc := range []struct{ name, root, reqID, override, ident string }{
		{"empty identifier", "", `"AC-2"`, "", `""`},
		{"padded identifier", "", `"AC-2"`, "", `"  analyst  "`},
		{"padded baselineRef", "", `"AC-2"`, `,"baselineRef":"  b  "`, `"analyst"`},
		{"empty label value", `,"labels":{"env":""}`, `"AC-2"`, "", `"analyst"`},
		{"padded label value", `,"labels":{"env":"  p  "}`, `"AC-2"`, "", `"analyst"`},
		{"padded version", `,"version":"  1.0  "`, `"AC-2"`, "", `"analyst"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			input := []byte(fmt.Sprintf(doc, tc.root, tc.reqID, tc.override, tc.ident))
			require.NoError(t, hdfV.Validate(input), "the test input is not valid HDF")

			out, err := ConvertHDFToOSCALPOAM(input, "1.0.0")
			require.NoError(t, err)
			require.NoError(t, v.Validate(out),
				"an empty or padded HDF string must not produce a document the schema rejects")
		})
	}
}

// A milestone title is carried byte-exact (ADR-0014 §4.6). OSCAL types task and
// remediation titles as a plain string (1.1.2) or MarkupLineDatatype ^[^\n]+$
// (1.2.3), not StringDatatype, and the HDF title pattern already forbids line
// feeds, so a title with unusual whitespace at an edge or a U+2028 inside is valid
// OSCAL as written and must not be trimmed.
func TestConvertHDFToOSCALPOAM_MilestoneTitleCarriedExactly(t *testing.T) {
	hdfV := amendmentsValidator(t)
	schemas := poamSchemas(t)
	for _, tc := range []struct{ name, title string }{
		{"leading form feed", "\fX"},
		{"trailing vertical tab", "X\v"},
		{"leading no-break space", "\u00a0X"},
		{"leading byte order mark", "\ufeffX"},
		{"line separator inside", "A\u2028B"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			title, err := json.Marshal(tc.title)
			require.NoError(t, err)
			input := []byte(`{"name":"a","overrides":[{"requirementId":"AC-2","type":"poam","status":"failed",` +
				`"reason":"r","appliedAt":"2020-01-01T00:00:00Z","expiresAt":"2099-12-31T00:00:00Z",` +
				`"appliedBy":{"identifier":"analyst","type":"username"},` +
				`"milestones":[{"title":` + string(title) + `,"description":"d",` +
				`"estimatedCompletion":"2099-12-31T00:00:00Z","status":"pending"}]}]}`)
			require.NoError(t, hdfV.Validate(input), "the test input is not valid HDF")

			out, err := ConvertHDFToOSCALPOAM(input, "1.0.0")
			require.NoError(t, err)
			for _, s := range schemas {
				s.v.RequireValid(t, s.file, out)
			}

			var doc oscal.OscalDocument
			require.NoError(t, json.Unmarshal(out, &doc))
			rem := doc.PlanOfActionAndMilestones.Risks[0].Remediations[0]
			require.Len(t, rem.Tasks, 1)
			assert.Equal(t, tc.title, rem.Title)
			assert.Equal(t, tc.title, rem.Tasks[0].Title)

			back, err := oscal.ConvertPOAMToHDF(out, "1.0.0")
			require.NoError(t, err)
			require.Len(t, back.Overrides, 1)
			require.Len(t, back.Overrides[0].Milestones, 1)
			require.NotNil(t, back.Overrides[0].Milestones[0].Title)
			assert.Equal(t, tc.title, *back.Overrides[0].Milestones[0].Title)
		})
	}
}

// The empty case omits the field rather than inventing a placeholder: OSCAL
// requires only uuid and type on a party, so the party survives and the
// responsible-party reference that points at it stays valid.
func TestConvertHDFToOSCALPOAM_EmptyIdentifierOmitsPartyName(t *testing.T) {
	input := []byte(`{"name":"a","overrides":[{"requirementId":"AC-2","type":"waiver",` +
		`"status":"notApplicable","reason":"r","appliedAt":"2020-01-01T00:00:00Z",` +
		`"expiresAt":"2099-12-31T00:00:00Z","appliedBy":{"identifier":"","type":"username"}}]}`)

	require.NoError(t, amendmentsValidator(t).Validate(input), "the test input is not valid HDF")

	out, err := ConvertHDFToOSCALPOAM(input, "1.0.0")
	require.NoError(t, err)

	var doc struct {
		POAM struct {
			Metadata struct {
				Parties []struct {
					UUID string  `json:"uuid"`
					Type string  `json:"type"`
					Name *string `json:"name"`
				} `json:"parties"`
				ResponsibleParties []struct {
					PartyUUIDs []string `json:"party-uuids"`
				} `json:"responsible-parties"`
			} `json:"metadata"`
		} `json:"plan-of-action-and-milestones"`
	}
	require.NoError(t, json.Unmarshal(out, &doc))
	require.Len(t, doc.POAM.Metadata.Parties, 1)
	assert.Nil(t, doc.POAM.Metadata.Parties[0].Name, "an empty identifier omits the name")
	assert.NotEmpty(t, doc.POAM.Metadata.Parties[0].UUID, "the party itself survives")

	// and nothing references a party that is no longer there
	for _, rp := range doc.POAM.Metadata.ResponsibleParties {
		for _, u := range rp.PartyUUIDs {
			assert.Equal(t, doc.POAM.Metadata.Parties[0].UUID, u,
				"a responsible-party must not reference a dropped party")
		}
	}
}

// One party per distinct (identifier, type, description) triple: two spellings
// of an identifier are two identities, each returned exactly, while a repeated
// identity is one party.
func TestConvertHDFToOSCALPOAM_PaddedIdentifierDedupes(t *testing.T) {
	override := func(reqID, ident string) string {
		return `{"requirementId":"` + reqID + `","type":"waiver","status":"notApplicable",` +
			`"reason":"r","appliedAt":"2020-01-01T00:00:00Z","expiresAt":"2099-12-31T00:00:00Z",` +
			`"appliedBy":{"identifier":"` + ident + `","type":"username"}}`
	}
	input := []byte(`{"name":"a","overrides":[` +
		override("AC-2", "analyst") + `,` + override("AC-3", "  analyst  ") + `,` + override("AC-4", "analyst") + `]}`)

	require.NoError(t, amendmentsValidator(t).Validate(input), "the test input is not valid HDF")

	out, err := ConvertHDFToOSCALPOAM(input, "1.0.0")
	require.NoError(t, err)

	var doc struct {
		POAM struct {
			Metadata struct {
				Parties []oscal.Party `json:"parties"`
			} `json:"metadata"`
		} `json:"plan-of-action-and-milestones"`
	}
	require.NoError(t, json.Unmarshal(out, &doc))
	require.NoError(t, poamSchemas(t)[1].v.Validate(out))
	require.Len(t, doc.POAM.Metadata.Parties, 2, "two identities, two parties")
	var identifiers []string
	for _, p := range doc.POAM.Metadata.Parties {
		assert.Equal(t, "analyst", p.Name, "the party name is display text")
		m, ok := oscal.FindVocabularyProp(p.Props, "identity-identifier")
		require.True(t, ok)
		identifiers = append(identifiers, m.Value)
	}
	assert.Equal(t, []string{"analyst", "  analyst  "}, identifiers)
}
