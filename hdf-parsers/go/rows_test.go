package hdfparsers

import (
	"testing"

	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func ptrFloat(f float64) *float64 { return &f }
func ptrStr(s string) *string     { return &s }

// withCveStruct installs structured CVE-ecosystem data (cvss[], epss, kev,
// cwe[], affectedPackages[]) directly on the typed Evaluated_Requirement
// fields added in Wave 1.
type cveData struct {
	cvss             []hdf.Cvss
	epss             *hdf.Epss
	kev              *hdf.Kev
	cwe              []string
	affectedPackages []hdf.AffectedPackage
}

func withCveStruct(data cveData) func(*hdf.EvaluatedRequirement) {
	return func(r *hdf.EvaluatedRequirement) {
		r.Cvss = data.cvss
		r.Epss = data.epss
		r.Kev = data.kev
		r.Cwe = data.cwe
		r.AffectedPackages = data.affectedPackages
	}
}

// withLegacyTag installs key/value pairs on the requirement's tags map.
// Used to verify legacy fallback behavior (e.g. tags.cvss_base_score from
// older converter output).
func withLegacyTag(key string, value interface{}) func(*hdf.EvaluatedRequirement) {
	return func(r *hdf.EvaluatedRequirement) {
		if r.Tags == nil {
			r.Tags = map[string]interface{}{}
		}
		r.Tags[key] = value
	}
}

func TestFlattenToRows_NoBaselines(t *testing.T) {
	rows := FlattenToRows(hdf.HDFResults{})
	assert.Empty(t, rows)
}

func TestFlattenToRows_BasicShape(t *testing.T) {
	results := makeResults([]hdf.EvaluatedBaseline{
		makeBaseline("base", []hdf.EvaluatedRequirement{
			makeReq("V-1"),
		}),
	})

	rows := FlattenToRows(results)
	require.Len(t, rows, 1)
	assert.Equal(t, "V-1", rows[0]["id"])
	assert.Equal(t, "base", rows[0]["baseline"])
}

func TestFlattenToRows_FullStructuredCveData(t *testing.T) {
	results := makeResults([]hdf.EvaluatedBaseline{
		makeBaseline("base", []hdf.EvaluatedRequirement{
			makeReq("CVE-1", withCveStruct(cveData{
				cvss: []hdf.Cvss{{
					BaseScore:     ptrFloat(7.5),
					BaseVector:    ptrStr("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
					Version:       hdf.The31,
					ComputedScore: ptrFloat(8.1),
				}},
				epss: &hdf.Epss{Score: 0.42, Percentile: 0.88, Date: "2026-05-26"},
				kev:  &hdf.Kev{InKev: true},
				cwe:  []string{"CWE-79", "CWE-89"},
				affectedPackages: []hdf.AffectedPackage{
					{Name: "openssl", Version: "1.1.1k", Ecosystem: hdf.RPM},
				},
			})),
		}),
	})

	rows := FlattenToRows(results)
	require.Len(t, rows, 1)
	r := rows[0]

	assert.Equal(t, "7.5", r["cvss_base_score"])
	assert.Equal(t, "8.1", r["cvss_computed_score"])
	assert.Equal(t, "0.42", r["epss_score"])
	assert.Equal(t, "0.88", r["epss_percentile"])
	assert.Equal(t, "true", r["kev_in_kev"])
	assert.Equal(t, "CWE-79;CWE-89", r["cwe"])
	assert.Equal(t, "openssl@1.1.1k", r["affected_packages"])
}

func TestFlattenToRows_LegacyTagFallbackForCvssBase(t *testing.T) {
	// No structured cvss[] but legacy tags.cvss_base_score present.
	results := makeResults([]hdf.EvaluatedBaseline{
		makeBaseline("base", []hdf.EvaluatedRequirement{
			makeReq("CVE-Legacy", withLegacyTag("cvss_base_score", "6.4")),
		}),
	})

	rows := FlattenToRows(results)
	require.Len(t, rows, 1)
	assert.Equal(t, "6.4", rows[0]["cvss_base_score"])
	assert.NotContains(t, rows[0], "cvss_computed_score")
}

func TestFlattenToRows_StructuredOverridesLegacy(t *testing.T) {
	// Both structured cvss[] and legacy tag present — structured wins.
	results := makeResults([]hdf.EvaluatedBaseline{
		makeBaseline("base", []hdf.EvaluatedRequirement{
			makeReq("CVE-Both",
				withCveStruct(cveData{cvss: []hdf.Cvss{{BaseScore: ptrFloat(9.8), BaseVector: ptrStr("CVSS:3.1/AV:N"), Version: hdf.The31}}}),
				withLegacyTag("cvss_base_score", "3.2"),
			),
		}),
	})

	rows := FlattenToRows(results)
	require.Len(t, rows, 1)
	assert.Equal(t, "9.8", rows[0]["cvss_base_score"])
}

func TestFlattenToRows_MultipleCvssEntriesFirstWins(t *testing.T) {
	results := makeResults([]hdf.EvaluatedBaseline{
		makeBaseline("base", []hdf.EvaluatedRequirement{
			makeReq("CVE-Multi", withCveStruct(cveData{
				cvss: []hdf.Cvss{
					{BaseScore: ptrFloat(7.5), BaseVector: ptrStr("CVSS:3.1/AV:N"), Version: hdf.The31},
					{BaseScore: ptrFloat(3.1), BaseVector: ptrStr("CVSS:3.1/AV:L"), Version: hdf.The31},
				},
			})),
		}),
	})

	rows := FlattenToRows(results)
	require.Len(t, rows, 1)
	assert.Equal(t, "7.5", rows[0]["cvss_base_score"])
}

func TestFlattenToRows_CweJoined(t *testing.T) {
	results := makeResults([]hdf.EvaluatedBaseline{
		makeBaseline("base", []hdf.EvaluatedRequirement{
			makeReq("CVE-Cwe", withCveStruct(cveData{cwe: []string{"CWE-79", "CWE-89", "CWE-352"}})),
		}),
	})

	rows := FlattenToRows(results)
	require.Len(t, rows, 1)
	assert.Equal(t, "CWE-79;CWE-89;CWE-352", rows[0]["cwe"])
}

func TestFlattenToRows_AffectedPackagesJoined(t *testing.T) {
	results := makeResults([]hdf.EvaluatedBaseline{
		makeBaseline("base", []hdf.EvaluatedRequirement{
			makeReq("CVE-Pkg", withCveStruct(cveData{
				affectedPackages: []hdf.AffectedPackage{
					{Name: "openssl", Version: "1.1.1k", Ecosystem: hdf.RPM},
					{Name: "libcurl", Version: "7.81.0", Ecosystem: hdf.RPM},
				},
			})),
		}),
	})

	rows := FlattenToRows(results)
	require.Len(t, rows, 1)
	assert.Equal(t, "openssl@1.1.1k;libcurl@7.81.0", rows[0]["affected_packages"])
}

func TestFlattenToRows_AffectedPackageMissingVersion(t *testing.T) {
	// Schema requires version, but defensively the flatten handles an empty
	// version string by emitting the name alone.
	results := makeResults([]hdf.EvaluatedBaseline{
		makeBaseline("base", []hdf.EvaluatedRequirement{
			makeReq("CVE-NoVer", withCveStruct(cveData{
				affectedPackages: []hdf.AffectedPackage{
					{Name: "openssl", Version: "", Ecosystem: hdf.RPM},
				},
			})),
		}),
	})

	rows := FlattenToRows(results)
	require.Len(t, rows, 1)
	assert.Equal(t, "openssl", rows[0]["affected_packages"])
}

func TestFlattenToRows_NoCveDataOmitsColumns(t *testing.T) {
	results := makeResults([]hdf.EvaluatedBaseline{
		makeBaseline("base", []hdf.EvaluatedRequirement{
			makeReq("V-NoCve"),
		}),
	})

	rows := FlattenToRows(results)
	require.Len(t, rows, 1)
	r := rows[0]
	for _, key := range []string{"cvss_base_score", "cvss_computed_score", "epss_score", "epss_percentile", "kev_in_kev", "cwe", "affected_packages"} {
		_, ok := r[key]
		assert.False(t, ok, "expected %q to be omitted, got value %q", key, r[key])
	}
}

func TestFlattenToRows_KevFalse(t *testing.T) {
	results := makeResults([]hdf.EvaluatedBaseline{
		makeBaseline("base", []hdf.EvaluatedRequirement{
			makeReq("CVE-NotInKev", withCveStruct(cveData{kev: &hdf.Kev{InKev: false}})),
		}),
	})

	rows := FlattenToRows(results)
	require.Len(t, rows, 1)
	assert.Equal(t, "false", rows[0]["kev_in_kev"])
}

func TestFlattenToRows_MultipleRequirementsAndBaselines(t *testing.T) {
	results := makeResults([]hdf.EvaluatedBaseline{
		makeBaseline("baseline-A", []hdf.EvaluatedRequirement{
			makeReq("CVE-A1", withCveStruct(cveData{cvss: []hdf.Cvss{{BaseScore: ptrFloat(5.0), BaseVector: ptrStr("CVSS:3.1/AV:N"), Version: hdf.The31}}})),
			makeReq("CVE-A2"),
		}),
		makeBaseline("baseline-B", []hdf.EvaluatedRequirement{
			makeReq("CVE-B1", withCveStruct(cveData{cvss: []hdf.Cvss{{BaseScore: ptrFloat(9.5), BaseVector: ptrStr("CVSS:3.1/AV:N"), Version: hdf.The31}}})),
		}),
	})

	rows := FlattenToRows(results)
	require.Len(t, rows, 3)
	assert.Equal(t, "baseline-A", rows[0]["baseline"])
	assert.Equal(t, "CVE-A1", rows[0]["id"])
	assert.Equal(t, "5", rows[0]["cvss_base_score"])
	assert.Equal(t, "baseline-A", rows[1]["baseline"])
	assert.Equal(t, "CVE-A2", rows[1]["id"])
	assert.Equal(t, "baseline-B", rows[2]["baseline"])
	assert.Equal(t, "9.5", rows[2]["cvss_base_score"])
}

func TestFlattenToRows_CvssBaseScoreNumericLegacy(t *testing.T) {
	// Legacy tag value can be a numeric type (newer converters emit float).
	results := makeResults([]hdf.EvaluatedBaseline{
		makeBaseline("base", []hdf.EvaluatedRequirement{
			makeReq("CVE-NumLegacy", withLegacyTag("cvss_base_score", 6.4)),
		}),
	})

	rows := FlattenToRows(results)
	require.Len(t, rows, 1)
	assert.Equal(t, "6.4", rows[0]["cvss_base_score"])
}

func TestFlattenToRows_LegacyCvssBaseScoreEmptyString(t *testing.T) {
	// Empty-string legacy tag should not populate the column.
	results := makeResults([]hdf.EvaluatedBaseline{
		makeBaseline("base", []hdf.EvaluatedRequirement{
			makeReq("CVE-Empty", withLegacyTag("cvss_base_score", "")),
		}),
	})

	rows := FlattenToRows(results)
	require.Len(t, rows, 1)
	_, ok := rows[0]["cvss_base_score"]
	assert.False(t, ok)
}

func TestFlattenToRows_CvssBaseScoreLegacyIntCoerces(t *testing.T) {
	results := makeResults([]hdf.EvaluatedBaseline{
		makeBaseline("base", []hdf.EvaluatedRequirement{
			makeReq("CVE-Int", withLegacyTag("cvss_base_score", 7)),
		}),
	})

	rows := FlattenToRows(results)
	require.Len(t, rows, 1)
	assert.Equal(t, "7", rows[0]["cvss_base_score"])
}
