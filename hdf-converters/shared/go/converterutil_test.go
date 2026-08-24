package shared

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestInputChecksum(t *testing.T) {
	t.Run("produces sha256 checksum", func(t *testing.T) {
		checksum := InputChecksum([]byte("hello"))
		require.NotNil(t, checksum)
		assert.Equal(t, hdf.Sha256, checksum.Algorithm)
		assert.Equal(t, "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824", checksum.Value)
	})

	t.Run("empty input produces valid checksum", func(t *testing.T) {
		checksum := InputChecksum([]byte(""))
		require.NotNil(t, checksum)
		assert.Equal(t, hdf.Sha256, checksum.Algorithm)
		assert.Len(t, checksum.Value, 64)
	})

	t.Run("different input produces different checksum", func(t *testing.T) {
		c1 := InputChecksum([]byte("hello"))
		c2 := InputChecksum([]byte("world"))
		assert.NotEqual(t, c1.Value, c2.Value)
	})
}

func TestBuildNISTCCITags(t *testing.T) {
	t.Run("builds tags with nist only", func(t *testing.T) {
		tags := BuildNISTCCITags([]string{"SA-11", "RA-5"}, nil)
		assert.Len(t, tags, 1)
		nist, ok := tags["nist"].([]interface{})
		require.True(t, ok)
		assert.Equal(t, "SA-11", nist[0])
		assert.Equal(t, "RA-5", nist[1])
		_, hasCCI := tags["cci"]
		assert.False(t, hasCCI)
	})

	t.Run("builds tags with nist and cci", func(t *testing.T) {
		tags := BuildNISTCCITags(
			[]string{"SA-11"},
			[]string{"CCI-001453"},
		)
		assert.Len(t, tags, 2)
		cci, ok := tags["cci"].([]interface{})
		require.True(t, ok)
		assert.Equal(t, "CCI-001453", cci[0])
	})

	t.Run("omits cci when empty slice", func(t *testing.T) {
		tags := BuildNISTCCITags([]string{"SA-11"}, []string{})
		_, hasCCI := tags["cci"]
		assert.False(t, hasCCI)
	})
}

func TestBuildNISTCCITagsWithExtras(t *testing.T) {
	t.Run("adds extra keys", func(t *testing.T) {
		extras := map[string]interface{}{
			"cveid": "CVE-2024-1234",
		}
		tags := BuildNISTCCITagsWithExtras(
			[]string{"SA-11"},
			[]string{"CCI-001453"},
			extras,
		)
		assert.Len(t, tags, 3)
		assert.Equal(t, "CVE-2024-1234", tags["cveid"])
	})

	t.Run("handles nil extras", func(t *testing.T) {
		tags := BuildNISTCCITagsWithExtras(
			[]string{"SA-11"},
			nil,
			nil,
		)
		assert.Len(t, tags, 1)
	})
}

func TestValidateXMLSize_Normal(t *testing.T) {
	err := ValidateXMLSize([]byte("<root/>"), 0)
	assert.NoError(t, err)
}

func TestValidateXMLSize_TooLarge(t *testing.T) {
	big := make([]byte, 51*1024*1024)
	err := ValidateXMLSize(big, 0)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "exceeds maximum")
}

func TestValidateXMLSize_CustomLimit(t *testing.T) {
	err := ValidateXMLSize([]byte("<root/>"), 5)
	assert.Error(t, err)
}

func TestValidateXMLInput_Clean(t *testing.T) {
	assert.NoError(t, ValidateXMLInput([]byte("<root/>"), 0))
}

func TestValidateXMLInput_WithEntities(t *testing.T) {
	xml := []byte(`<!DOCTYPE foo [<!ENTITY x "y">]><foo/>`)
	err := ValidateXMLInput(xml, 0)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "entity declarations")
}

func TestValidateXMLInput_TooLarge(t *testing.T) {
	big := make([]byte, 51*1024*1024)
	err := ValidateXMLInput(big, 0)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "exceeds maximum")
}

func TestValidateXMLInput_CustomSizeLimit(t *testing.T) {
	err := ValidateXMLInput([]byte("<root/>"), 3)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "exceeds maximum")
}

func TestBuildHDFResults_MinimalFields(t *testing.T) {
	baseline := hdf.EvaluatedBaseline{Name: "test-baseline"}
	now := time.Now().UTC()

	result := BuildHDFResults(HDFResultsOptions{
		GeneratorName:    "test-to-hdf",
		ConverterVersion: "1.0.0",
		Baselines:        []hdf.EvaluatedBaseline{baseline},
		Timestamp:        &now,
	})

	require.NotNil(t, result)
	assert.Equal(t, []hdf.EvaluatedBaseline{baseline}, result.Baselines)
	require.NotNil(t, result.Generator)
	assert.Equal(t, "test-to-hdf", result.Generator.Name)
	assert.Equal(t, "1.0.0", result.Generator.Version)
	assert.Equal(t, &now, result.Timestamp)
	assert.Nil(t, result.Tool)
	assert.Nil(t, result.Components)
	assert.Nil(t, result.Statistics)
}

func TestBuildHDFResults_WithToolName(t *testing.T) {
	result := BuildHDFResults(HDFResultsOptions{
		GeneratorName:    "grype-to-hdf",
		ConverterVersion: "1.0.0",
		ToolName:         "Grype",
		Baselines:        []hdf.EvaluatedBaseline{},
	})

	require.NotNil(t, result.Tool)
	require.NotNil(t, result.Tool.Name)
	assert.Equal(t, "Grype", *result.Tool.Name)
	assert.Nil(t, result.Tool.Version)
	assert.Nil(t, result.Tool.Format)
}

func TestBuildHDFResults_WithAllToolFields(t *testing.T) {
	result := BuildHDFResults(HDFResultsOptions{
		GeneratorName:    "sarif-to-hdf",
		ConverterVersion: "1.0.0",
		ToolName:         "Semgrep",
		ToolVersion:      "1.5.0",
		ToolFormat:       "SARIF",
		Baselines:        []hdf.EvaluatedBaseline{},
	})

	require.NotNil(t, result.Tool)
	assert.Equal(t, "Semgrep", *result.Tool.Name)
	assert.Equal(t, "1.5.0", *result.Tool.Version)
	assert.Equal(t, "SARIF", *result.Tool.Format)
}

func TestBuildHDFResults_EmptyToolStringsOmitted(t *testing.T) {
	result := BuildHDFResults(HDFResultsOptions{
		GeneratorName:    "test-to-hdf",
		ConverterVersion: "1.0.0",
		Baselines:        []hdf.EvaluatedBaseline{},
	})

	assert.Nil(t, result.Tool)
}

func TestBuildHDFResults_WithTargetsAndStatistics(t *testing.T) {
	targets := []hdf.Component{{Name: "web-server"}}
	dur := 42.5
	stats := &hdf.Statistics{Duration: &dur}

	result := BuildHDFResults(HDFResultsOptions{
		GeneratorName:    "nessus-to-hdf",
		ConverterVersion: "1.0.0",
		Baselines:        []hdf.EvaluatedBaseline{},
		Components:       targets,
		Statistics:       stats,
	})

	assert.Equal(t, targets, result.Components)
	assert.Equal(t, stats, result.Statistics)
}

func TestBuildHDFResults_ToolPartialFields(t *testing.T) {
	// Only format set, no name/version
	result := BuildHDFResults(HDFResultsOptions{
		GeneratorName:    "test-to-hdf",
		ConverterVersion: "1.0.0",
		ToolFormat:       "XML",
		Baselines:        []hdf.EvaluatedBaseline{},
	})

	require.NotNil(t, result.Tool)
	assert.Nil(t, result.Tool.Name)
	assert.Nil(t, result.Tool.Version)
	assert.Equal(t, "XML", *result.Tool.Format)
}

func TestValidateJSONSize(t *testing.T) {
	t.Run("within limit", func(t *testing.T) {
		err := ValidateJSONSize([]byte(`{"key":"value"}`), "test-converter", 0)
		assert.NoError(t, err)
	})

	t.Run("exceeds custom limit", func(t *testing.T) {
		err := ValidateJSONSize([]byte(`{"key":"value"}`), "test-converter", 5)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "test-converter")
		assert.Contains(t, err.Error(), "exceeds maximum allowed size")
	})

	t.Run("empty input within limit", func(t *testing.T) {
		err := ValidateJSONSize([]byte{}, "test-converter", 0)
		assert.NoError(t, err)
	})

	t.Run("uses default max size", func(t *testing.T) {
		err := ValidateJSONSize([]byte("small"), "test-converter", 0)
		assert.NoError(t, err)
	})
}

func TestDeriveControlType(t *testing.T) {
	cases := []struct {
		tag      string
		expected *hdf.ControlType
		name     string
	}{
		{"AC-3", ptrControlType(hdf.Technical), "AC-3 is technical"},
		{"AC-1", ptrControlType(hdf.Policy), "AC-1 is policy (any *-1)"},
		{"AC-3(1)", ptrControlType(hdf.Technical), "AC-3(1) enhancement follows base"},
		{"AC-3.1", ptrControlType(hdf.Technical), "AC-3.1 dotted enhancement follows base"},
		{"AC-1(1)", ptrControlType(hdf.Policy), "AC-1(1) enhancement of policy stays policy"},
		{"PM-2", ptrControlType(hdf.Management), "PM-2 is management"},
		{"PM-1", ptrControlType(hdf.Policy), "PM-1 is policy via *-1 rule"},
		{"AT-2", ptrControlType(hdf.Operational), "AT-2 is operational"},
		{"IR-4", ptrControlType(hdf.Operational), "IR-4 is operational"},
		{"MA-3", ptrControlType(hdf.Operational), "MA-3 is operational"},
		{"SC-7", ptrControlType(hdf.Technical), "SC-7 is technical"},
		{"SI-2", ptrControlType(hdf.Technical), "SI-2 is technical"},
		{"IA-5", ptrControlType(hdf.Technical), "IA-5 is technical"},
		{"AU-12", ptrControlType(hdf.Operational), "AU-12 is operational"},
		{"CA-2", ptrControlType(hdf.Management), "CA-2 is management"},
		{"SR-3", ptrControlType(hdf.Management), "SR-3 is management"},
		{"ac-3", ptrControlType(hdf.Technical), "lowercase tag is normalized"},
		{"  AC-3  ", ptrControlType(hdf.Technical), "whitespace is trimmed"},
		{"SV-238196", nil, "STIG-prefixed ID is not classified"},
		{"CCI-000192", nil, "CCI ID is not classified"},
		{"XX-9", nil, "unknown family returns nil"},
		{"", nil, "empty string returns nil"},
		{"AC", nil, "missing sub-control returns nil"},
		{"AC-", nil, "trailing dash returns nil"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := DeriveControlType(tc.tag)
			if tc.expected == nil {
				assert.Nil(t, got, "expected nil for tag %q", tc.tag)
			} else {
				require.NotNil(t, got, "expected non-nil for tag %q", tc.tag)
				assert.Equal(t, *tc.expected, *got)
			}
		})
	}
}

func TestDeriveControlTypeFromTags(t *testing.T) {
	t.Run("single technical tag", func(t *testing.T) {
		got := DeriveControlTypeFromTags([]string{"AC-3"})
		require.NotNil(t, got)
		assert.Equal(t, hdf.Technical, *got)
	})

	t.Run("technical wins over management", func(t *testing.T) {
		got := DeriveControlTypeFromTags([]string{"PM-2", "AC-3"})
		require.NotNil(t, got)
		assert.Equal(t, hdf.Technical, *got, "technical beats management")
	})

	t.Run("operational wins over management", func(t *testing.T) {
		got := DeriveControlTypeFromTags([]string{"PM-2", "AT-2"})
		require.NotNil(t, got)
		assert.Equal(t, hdf.Operational, *got)
	})

	t.Run("technical wins over operational", func(t *testing.T) {
		got := DeriveControlTypeFromTags([]string{"AT-2", "AC-3"})
		require.NotNil(t, got)
		assert.Equal(t, hdf.Technical, *got)
	})

	t.Run("policy wins over nothing", func(t *testing.T) {
		got := DeriveControlTypeFromTags([]string{"AC-1"})
		require.NotNil(t, got)
		assert.Equal(t, hdf.Policy, *got)
	})

	t.Run("technical wins over policy", func(t *testing.T) {
		got := DeriveControlTypeFromTags([]string{"AC-1", "SC-7"})
		require.NotNil(t, got)
		assert.Equal(t, hdf.Technical, *got)
	})

	t.Run("ignores unknown families", func(t *testing.T) {
		got := DeriveControlTypeFromTags([]string{"SV-12345", "AC-3"})
		require.NotNil(t, got)
		assert.Equal(t, hdf.Technical, *got)
	})

	t.Run("empty slice returns nil", func(t *testing.T) {
		got := DeriveControlTypeFromTags(nil)
		assert.Nil(t, got)
	})

	t.Run("all unknown returns nil", func(t *testing.T) {
		got := DeriveControlTypeFromTags([]string{"SV-1", "CCI-1"})
		assert.Nil(t, got)
	})

	t.Run("static-fallback bundle DefaultStaticAnalysisNIST returns nil", func(t *testing.T) {
		got := DeriveControlTypeFromTags([]string{"SA-11", "RA-5"})
		assert.Nil(t, got, "exact-match static fallback bundle carries no per-finding signal")
	})

	t.Run("static-fallback bundle DefaultRemediationNIST returns nil", func(t *testing.T) {
		got := DeriveControlTypeFromTags([]string{"SI-2", "RA-5"})
		assert.Nil(t, got)
	})

	t.Run("static-fallback bundle DefaultComponentManagementNIST returns nil", func(t *testing.T) {
		got := DeriveControlTypeFromTags([]string{"CM-8"})
		assert.Nil(t, got)
	})

	t.Run("static-fallback order-independent", func(t *testing.T) {
		got := DeriveControlTypeFromTags([]string{"RA-5", "SA-11"})
		assert.Nil(t, got)
	})

	t.Run("non-fallback superset bypasses the gate", func(t *testing.T) {
		got := DeriveControlTypeFromTags([]string{"SA-11", "RA-5", "AC-3"})
		require.NotNil(t, got)
		assert.Equal(t, hdf.Technical, *got, "real signal (AC-3) wins over fallback-bundle pattern")
	})

	t.Run("standalone real-signal tag not in fallback bundle", func(t *testing.T) {
		got := DeriveControlTypeFromTags([]string{"SA-11"})
		require.NotNil(t, got)
		assert.Equal(t, hdf.Management, *got, "single SA-11 (not the bundle) keeps real signal")
	})
}

func TestNISTTagsFromMap(t *testing.T) {
	t.Run("[]string is returned as-is", func(t *testing.T) {
		tags := map[string]interface{}{"nist": []string{"AC-3", "SI-2"}}
		assert.Equal(t, []string{"AC-3", "SI-2"}, NISTTagsFromMap(tags))
	})

	t.Run("[]interface{} of strings is normalized", func(t *testing.T) {
		tags := map[string]interface{}{
			"nist": []interface{}{"AC-3", "SI-2"},
		}
		assert.Equal(t, []string{"AC-3", "SI-2"}, NISTTagsFromMap(tags))
	})

	t.Run("missing key returns nil", func(t *testing.T) {
		tags := map[string]interface{}{"cci": []string{"CCI-1"}}
		assert.Nil(t, NISTTagsFromMap(tags))
	})

	t.Run("empty []string returns nil", func(t *testing.T) {
		tags := map[string]interface{}{"nist": []string{}}
		assert.Nil(t, NISTTagsFromMap(tags))
	})

	t.Run("empty []interface{} returns nil", func(t *testing.T) {
		tags := map[string]interface{}{"nist": []interface{}{}}
		assert.Nil(t, NISTTagsFromMap(tags))
	})

	t.Run("[]interface{} with non-string elements drops them", func(t *testing.T) {
		tags := map[string]interface{}{
			"nist": []interface{}{"AC-3", 42, "SI-2"},
		}
		assert.Equal(t, []string{"AC-3", "SI-2"}, NISTTagsFromMap(tags))
	})

	t.Run("nil tags returns nil", func(t *testing.T) {
		assert.Nil(t, NISTTagsFromMap(nil))
	})

	t.Run("unexpected type returns nil", func(t *testing.T) {
		tags := map[string]interface{}{"nist": "AC-3"}
		assert.Nil(t, NISTTagsFromMap(tags))
	})
}

func TestDeriveVerificationMethod(t *testing.T) {
	t.Run("non-empty code is automated", func(t *testing.T) {
		code := "control 'AC-3' do; impact 0.7; end"
		got := DeriveVerificationMethod(&code)
		require.NotNil(t, got)
		assert.Equal(t, hdf.VerificationMethodEnumAutomated, *got)
	})

	t.Run("nil code returns nil", func(t *testing.T) {
		got := DeriveVerificationMethod(nil)
		assert.Nil(t, got, "converter must distinguish manual-by-design vs manual-pending-automation")
	})

	t.Run("empty string returns nil", func(t *testing.T) {
		empty := ""
		got := DeriveVerificationMethod(&empty)
		assert.Nil(t, got, "empty code is not a runnable check")
	})
}

func ptrControlType(ct hdf.ControlType) *hdf.ControlType {
	return &ct
}

func TestDigestToChecksums(t *testing.T) {
	cases := []struct {
		name, digest string
		want         []hdf.Checksum
	}{
		{"sha256", "sha256:abc", []hdf.Checksum{{Algorithm: hdf.Sha256, Value: "abc"}}},
		{"sha384", "sha384:abc", []hdf.Checksum{{Algorithm: hdf.Sha384, Value: "abc"}}},
		{"sha512", "sha512:deadbeef", []hdf.Checksum{{Algorithm: hdf.Sha512, Value: "deadbeef"}}},
		{"blake3", "blake3:abc", []hdf.Checksum{{Algorithm: hdf.Blake3, Value: "abc"}}},
		{"unrepresentable sha1 dropped", "sha1:abc", nil},
		{"unrepresentable md5 dropped", "md5:abc", nil},
		{"no prefix dropped", "abc123", nil},
		{"empty dropped", "", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, DigestToChecksums(tc.digest))
		})
	}
}

func TestMarkUnratedSeverity(t *testing.T) {
	t.Run("tags an unrated severity", func(t *testing.T) {
		for _, sev := range []string{"", "unknown", "UNASSIGNED", "unSpecified"} {
			tags := map[string]interface{}{"nist": []string{"RA-5"}}
			MarkUnratedSeverity(tags, sev)
			assert.Equal(t, "unrated", tags["severity_rating"], "%q", sev)
		}
	})
	t.Run("leaves rated severities untagged", func(t *testing.T) {
		for _, sev := range []string{"critical", "low", "info", "none", "negligible", "wibble"} {
			tags := map[string]interface{}{}
			MarkUnratedSeverity(tags, sev)
			assert.NotContains(t, tags, "severity_rating", "%q", sev)
		}
	})
	t.Run("nil map is a no-op", func(t *testing.T) {
		assert.NotPanics(t, func() { MarkUnratedSeverity(nil, "unknown") })
	})
}

// --- Structural input guard ---------------------------------------------------
//
// Every HDF exporter owes the same prologue before it converts anything: reject
// empty input, reject oversized input, decode, then reject a document missing
// the one top-level field that makes it the document type it claims to be. Four
// exporters hand-rolled this and one (hdf-to-oscal-poam) skipped it entirely,
// zero-filling arbitrary JSON into a typed struct. These pin the shared version.

func TestRequireHDFResults_RejectsMalformedInput(t *testing.T) {
	for _, tc := range []struct {
		name  string
		input string
	}{
		{"empty input", ``},
		{"not json", `not json`},
		{"top-level array", `[]`},
		{"top-level null", `null`},
		{"missing baselines", `{"generator":{"name":"t","version":"0.0.0"}}`},
		{"wrong-typed baselines", `{"baselines":"not-an-array"}`},
		{"null baselines", `{"baselines":null}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var out hdf.HDFResults
			err := RequireHDFResults([]byte(tc.input), "probe", &out)
			require.Error(t, err, "structurally invalid HDF must be rejected, not zero-filled")
			require.Contains(t, err.Error(), "probe: ",
				"every error is prefixed with the converter name so the source is unambiguous")
		})
	}
}

func TestRequireHDFResults_AcceptsSparseButValidInput(t *testing.T) {
	// An assessment that evaluated nothing is legal HDF: baselines carries no
	// minItems. A guard that rejected it would break a real use case.
	var out hdf.HDFResults
	require.NoError(t, RequireHDFResults([]byte(`{"baselines":[]}`), "probe", &out))
	require.NotNil(t, out.Baselines)
}

func TestRequireHDFResults_MissingFieldMessageIsCanonical(t *testing.T) {
	// Pinned because exportmap and hdf-to-oscal-sar already emit exactly this and
	// consumers may match on it; adopting the shared guard must not churn it.
	var out hdf.HDFResults
	err := RequireHDFResults([]byte(`{}`), "hdf-to-oscal-sar", &out)
	require.EqualError(t, err, "hdf-to-oscal-sar: invalid HDF structure: missing baselines field")
}

func TestRequireHDFAmendments_RejectsMalformedInput(t *testing.T) {
	for _, tc := range []struct {
		name  string
		input string
	}{
		{"empty input", ``},
		{"not json", `not json`},
		{"top-level array", `[]`},
		{"top-level null", `null`},
		{"missing overrides", `{"name":"a"}`},
		{"wrong-typed overrides", `{"name":"a","overrides":"nope"}`},
		{"null overrides", `{"name":"a","overrides":null}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var out hdf.HDFAmendments
			err := RequireHDFAmendments([]byte(tc.input), "probe", &out)
			require.Error(t, err, "structurally invalid HDF must be rejected, not zero-filled")
		})
	}
}

// TestRequireHDFAmendments_RejectsEmptyOverrides pins the asymmetry between the
// two document types, which is easy to mistake for an inconsistency: the results
// schema puts no minItems on baselines, so an assessment that evaluated nothing
// is legal HDF, while the amendments schema puts minItems 1 on overrides — a
// document that amends nothing is not a valid amendments document and must not
// be silently converted into an empty one.
func TestRequireHDFAmendments_RejectsEmptyOverrides(t *testing.T) {
	var out hdf.HDFAmendments
	err := RequireHDFAmendments([]byte(`{"name":"a","overrides":[]}`), "probe", &out)
	require.Error(t, err, "overrides has minItems 1; an empty array is not a convertible document")
}

// TestRequireHDFAmendments_MatchesCorpusTiers ties the guard to the shared
// adversarial corpus: every amendments case the corpus labels HDF-invalid at the
// top level must be rejected, and every valid one accepted.
func TestRequireHDFAmendments_MatchesCorpusTiers(t *testing.T) {
	for _, c := range AmendmentsCorpus() {
		var out hdf.HDFAmendments
		err := RequireHDFAmendments(c.Input, "probe", &out)
		if c.HDFValid {
			require.NoError(t, err, "%s is valid HDF; the guard must not reject it", c.Name)
			continue
		}
		require.Error(t, err, "%s is HDF-invalid and must be rejected", c.Name)
	}
}

func TestRequireHDFAmendments_MissingFieldMessageIsCanonical(t *testing.T) {
	var out hdf.HDFAmendments
	err := RequireHDFAmendments([]byte(`{"name":"a"}`), "hdf-to-oscal-poam", &out)
	require.EqualError(t, err, "hdf-to-oscal-poam: invalid HDF structure: missing overrides field")
}

// TestRequireHDFResultsDoc_MatchesTypedGuard pins that the generic-map variant
// (what exportmap needs, since it maps fields dynamically) applies the same
// contract as the typed one. Two decode targets are legitimate; two different
// contracts would not be.
func TestRequireHDFResultsDoc_MatchesTypedGuard(t *testing.T) {
	for _, input := range []string{
		``, `not json`, `[]`, `null`, `{}`, `{"baselines":"x"}`, `{"baselines":null}`,
	} {
		var typed hdf.HDFResults
		typedErr := RequireHDFResults([]byte(input), "probe", &typed)
		_, _, docErr := RequireHDFResultsDoc([]byte(input), "probe")
		require.Equal(t, typedErr != nil, docErr != nil,
			"typed and map guards disagree on %q", input)
	}

	doc, baselines, err := RequireHDFResultsDoc([]byte(`{"baselines":[],"timestamp":"t"}`), "probe")
	require.NoError(t, err)
	require.Equal(t, "t", doc["timestamp"])
	require.Empty(t, baselines)
}

// TestRequireHDFResults_DiagnosticsDifferOnWrongTypedField makes a real
// divergence visible rather than leaving it hidden behind a prefix-only
// assertion. A wrong-typed baselines is rejected by every guard, but the typed
// form fails during decode and reports a parse error, while the map form and the
// TypeScript peer report a missing field. Both reject; only the diagnostic
// differs, and pinning it here means a future change to either message is a
// deliberate edit rather than a silent drift.
func TestRequireHDFResults_DiagnosticsDifferOnWrongTypedField(t *testing.T) {
	input := []byte(`{"baselines":"not-an-array"}`)

	var typed hdf.HDFResults
	typedErr := RequireHDFResults(input, "probe", &typed)
	require.ErrorContains(t, typedErr, "probe: failed to parse HDF JSON")

	_, _, docErr := RequireHDFResultsDoc(input, "probe")
	require.EqualError(t, docErr, "probe: invalid HDF structure: missing baselines field")
}

// TestRequireHDFResults_RejectsCorpusTopLevelShapes ties the guard to the shared
// adversarial corpus: every corpus case whose defect is top-level shape must be
// rejected here. Cases whose defect is nested (an empty requirements array, a
// requirement missing id) must NOT be — this guard is deliberately top-level
// only, and silently widening it would mask where validation actually belongs.
func TestRequireHDFResults_RejectsCorpusTopLevelShapes(t *testing.T) {
	topLevel := map[string]bool{
		"baselines-missing": true, "baselines-null": true,
		"baselines-wrong-type": true, "top-level-array": true,
	}
	for _, c := range ResultsCorpus() {
		var out hdf.HDFResults
		err := RequireHDFResults(c.Input, "probe", &out)
		if topLevel[c.Name] {
			require.Error(t, err, "%s is a top-level shape defect and must be rejected", c.Name)
			continue
		}
		require.NoError(t, err, "%s is not a top-level shape defect; the guard must not reject it", c.Name)
	}
}

// --- Nil-slice normalization --------------------------------------------------

// TestOrEmpty_NilSliceMarshalsAsEmptyArray is the assertion that matters: the
// helper exists because encoding/json renders a nil slice as null, and a target
// schema that requires an array rejects null. Asserting on the marshaled BYTES
// rather than the returned slice is deliberate — len() cannot tell nil from
// empty, so a struct-level assertion would pass against the very bug this
// prevents.
func TestOrEmpty_NilSliceMarshalsAsEmptyArray(t *testing.T) {
	type doc struct {
		Items []string `json:"items"`
	}

	raw, err := json.Marshal(doc{Items: nil})
	require.NoError(t, err)
	require.JSONEq(t, `{"items":null}`, string(raw),
		"precondition: a nil slice marshals to null, which is why OrEmpty exists")

	raw, err = json.Marshal(doc{Items: OrEmpty[string](nil)})
	require.NoError(t, err)
	require.JSONEq(t, `{"items":[]}`, string(raw))
}

func TestOrEmpty_PreservesEmptyAndPopulated(t *testing.T) {
	require.Equal(t, []string{}, OrEmpty([]string{}))
	require.Equal(t, []string{"a", "b"}, OrEmpty([]string{"a", "b"}))
}

// TestOrEmpty_IsGenericOverElementType pins that this is one generic helper
// rather than a string-only copy: the nil-slice-to-null defect is a property of
// encoding/json, not of []string, and the exporter sites that need it carry
// structs (cklb rules, OSCAL poam-items) as often as strings.
func TestOrEmpty_IsGenericOverElementType(t *testing.T) {
	type rule struct {
		ID string `json:"id"`
	}

	raw, err := json.Marshal(map[string]any{"rules": OrEmpty[rule](nil)})
	require.NoError(t, err)
	require.JSONEq(t, `{"rules":[]}`, string(raw))

	raw, err = json.Marshal(map[string]any{"n": OrEmpty[int](nil)})
	require.NoError(t, err)
	require.JSONEq(t, `{"n":[]}`, string(raw))

	require.Equal(t, []rule{{ID: "V-1"}}, OrEmpty([]rule{{ID: "V-1"}}))
}

// --- Non-empty text fallback --------------------------------------------------

// firstNonEmptyCase is one row of the table the TypeScript peer also reads, so the two
// implementations are asserted against ONE definition rather than two literals
// that can drift apart.
type firstNonEmptyCase struct {
	Name       string   `json:"name"`
	Candidates []string `json:"candidates"`
	Want       string   `json:"want"`
}

func loadFirstNonEmptyCases(t *testing.T) []firstNonEmptyCase {
	t.Helper()
	path := filepath.Join(getSharedDir(), "..", "first-non-empty-cases.json")
	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	var doc struct {
		Cases []firstNonEmptyCase `json:"cases"`
	}
	require.NoError(t, json.Unmarshal(raw, &doc))
	require.NotEmpty(t, doc.Cases, "shared table is empty — the run would pass vacuously")
	return doc.Cases
}

func TestFirstNonEmpty_MatchesSharedTable(t *testing.T) {
	for _, c := range loadFirstNonEmptyCases(t) {
		t.Run(c.Name, func(t *testing.T) {
			require.Equal(t, c.Want, FirstNonEmpty(c.Candidates...))
		})
	}
}

// TestFirstNonEmpty_DoesNotOmit pins the boundary the card draws: this helper
// substitutes, it never decides to omit. A caller whose correct behaviour is to
// leave the field out entirely must do that itself — folding omission in here
// would make the helper silently responsible for schema shape.
func TestFirstNonEmpty_DoesNotOmit(t *testing.T) {
	require.Equal(t, "", FirstNonEmpty("", " "),
		"all-empty input yields empty, so the caller can still choose to omit")
}
