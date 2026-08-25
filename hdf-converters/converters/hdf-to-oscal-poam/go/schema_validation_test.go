package hdftooscalpoam

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	oscal "github.com/mitre/hdf-libs/hdf-converters/v3/converters/oscal-to-hdf/go"
	shared "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go"
	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	"github.com/stretchr/testify/require"
)

// TestConvertHDFToOSCALPOAM_SchemaValid gates the converter output on the NIST
// OSCAL v1.1.2 POA&M schema. The converter self-declares "oscal-version":
// "1.1.2", so its output must validate against exactly that schema. See
// ../schemas/PROVENANCE.md.
func TestConvertHDFToOSCALPOAM_SchemaValid(t *testing.T) {
	v := shared.NewSchemaValidator(t, filepath.Join(shared.GetConvertersDir(),
		"hdf-to-oscal-poam", "schemas", "oscal_poam_schema-v1.1.2.json"))

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

	for _, tc := range cases {
		t.Run(tc.label, func(t *testing.T) {
			input, err := json.Marshal(tc.amendments)
			require.NoError(t, err)
			out, err := ConvertHDFToOSCALPOAM(input, "1.0.0")
			require.NoError(t, err)
			v.RequireValid(t, tc.label, out)
		})
	}
}

// TestConvertHDFToOSCALPOAM_AdversarialCorpus runs the shared corpus, so this
// converter is held to both contracts an exporter owes rather than only to
// fully-populated fixtures — the gap that let the defects in issue #236 ship.
func TestConvertHDFToOSCALPOAM_AdversarialCorpus(t *testing.T) {
	v := shared.NewSchemaValidator(t, filepath.Join(shared.GetConvertersDir(),
		"hdf-to-oscal-poam", "schemas", "oscal_poam_schema-v1.1.2.json"))

	shared.RunSchemaCorpus(t, v, shared.AmendmentsCorpus(), func(in []byte) ([]byte, error) {
		return ConvertHDFToOSCALPOAM(in, "1.0.0")
	})
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
	for _, c := range shared.AmendmentsCorpus() {
		if c.Contract != shared.MustConvert {
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
// amendments.labels keys, so an arbitrary key copied through produced a POA&M
// the schema rejects from valid HDF. Every label key in this package's converter fixtures
// happens to be token-shaped today, so this is a latent defect rather than one
// real data currently triggers — but the shapes below are standard label
// conventions (Kubernetes and OCI keys are namespaced with '/') that HDF
// permits and OSCAL does not.
func TestConvertHDFToOSCALPOAM_LabelKeysAreTokens(t *testing.T) {
	v := shared.NewSchemaValidator(t, filepath.Join(shared.GetConvertersDir(),
		"hdf-to-oscal-poam", "schemas", "oscal_poam_schema-v1.1.2.json"))
	hdfV := shared.NewSchemaValidator(t, filepath.Join("..", "..", "..", "..",
		"hdf-validators", "go", "schemas", "hdf-amendments.schema.json"))

	for _, tc := range []struct {
		key  string
		want string
	}{
		{"app.kubernetes.io/name", "app.kubernetes.io_name"},
		{"env:prod", "env_prod"},
		{"2024-audit", "_2024-audit"},
		{"com.redhat.component", "com.redhat.component"},
		{"", "_"},
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

			prop := metadataPropNamed(t, out, tc.want)
			require.Equal(t, "x", prop.Value)
			switch {
			case tc.key == "":
				require.Empty(t, prop.Remarks, "an empty key has no source text to preserve")
			case tc.want != tc.key:
				require.Equal(t, tc.key, prop.Remarks,
					"a rewritten name must keep the source key, or the label is lost")
			default:
				require.Empty(t, prop.Remarks, "an unchanged name needs no remarks")
			}
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
