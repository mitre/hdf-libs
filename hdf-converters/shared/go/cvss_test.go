package shared

import (
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"testing"

	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCvssVersionFromVector(t *testing.T) {
	tests := []struct {
		name   string
		vector string
		want   hdf.Version
	}{
		{"v2.0 prefix", "CVSS:2.0/AV:N/AC:L", hdf.The20},
		{"v3.0 prefix", "CVSS:3.0/AV:N/AC:L", hdf.The30},
		{"v3.1 prefix", "CVSS:3.1/AV:N/AC:L", hdf.The31},
		{"v4.0 prefix", "CVSS:4.0/AV:N/AC:L", hdf.The40},
		{"empty defaults to 3.1", "", hdf.The31},
		{"malformed/unprefixed defaults to 3.1", "AV:N/AC:L", hdf.The31},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, CvssVersionFromVector(tc.vector))
		})
	}
}

func TestCvssVersionFromVector_Fallback(t *testing.T) {
	// An explicit fallback sets the version for an absent/unrecognized prefix
	// (e.g. Nessus historical output defaults to 3.0); a recognized prefix wins.
	assert.Equal(t, hdf.The30, CvssVersionFromVector("", hdf.The30))
	assert.Equal(t, hdf.The30, CvssVersionFromVector("AV:N/AC:L", hdf.The30))
	assert.Equal(t, hdf.The31, CvssVersionFromVector("CVSS:3.1/AV:N", hdf.The30))
	assert.Equal(t, hdf.The30, CvssVersionFromVector("CVSS:3.0/AV:N", hdf.The30))
	// Omitting the fallback keeps the 3.1 default (existing callers unchanged).
	assert.Equal(t, hdf.The31, CvssVersionFromVector(""))
}

func TestCvssVersionFromString(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want hdf.Version
	}{
		{"2.0", "2.0", hdf.The20},
		{"3.0", "3.0", hdf.The30},
		{"3.1 falls through to default", "3.1", hdf.The31},
		{"4.0", "4.0", hdf.The40},
		{"empty defaults to 3.1", "", hdf.The31},
		{"unrecognized defaults to 3.1", "9.9", hdf.The31},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, CvssVersionFromString(tc.in))
		})
	}
}

func TestCvssSeverityFromScore(t *testing.T) {
	tests := []struct {
		score float64
		want  hdf.CVSSSeverity
	}{
		{0.0, hdf.None},
		{0.1, hdf.CVSSSeverityLow},
		{3.9, hdf.CVSSSeverityLow},
		{4.0, hdf.CVSSSeverityMedium},
		{6.9, hdf.CVSSSeverityMedium},
		{7.0, hdf.CVSSSeverityHigh},
		{8.9, hdf.CVSSSeverityHigh},
		{9.0, hdf.CVSSSeverityCritical},
		{10.0, hdf.CVSSSeverityCritical},
	}
	for _, tc := range tests {
		assert.Equal(t, tc.want, CvssSeverityFromScore(hdf.The31, tc.score))
	}
}

func floatPtr(f float64) *float64 { return &f }

func TestBuildCvss(t *testing.T) {
	t.Run("all base fields present", func(t *testing.T) {
		cv := BuildCvss(CvssInput{
			Version:    hdf.The31,
			BaseScore:  floatPtr(9.8),
			BaseVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
			Source:     "CVE-2021-44228",
		})
		assert.Equal(t, hdf.The31, cv.Version)
		require.NotNil(t, cv.BaseScore)
		assert.InDelta(t, 9.8, *cv.BaseScore, 0.001)
		require.NotNil(t, cv.BaseSeverity)
		assert.Equal(t, hdf.CVSSSeverityCritical, *cv.BaseSeverity)
		require.NotNil(t, cv.BaseVector)
		assert.Equal(t, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", *cv.BaseVector)
		require.NotNil(t, cv.Source)
		assert.Equal(t, "CVE-2021-44228", *cv.Source)
	})

	t.Run("score only, no vector or source; CVSS 2.0 has no none rating", func(t *testing.T) {
		cv := BuildCvss(CvssInput{Version: hdf.The20, BaseScore: floatPtr(0.0)})
		assert.Equal(t, hdf.The20, cv.Version)
		require.NotNil(t, cv.BaseScore)
		assert.InDelta(t, 0.0, *cv.BaseScore, 0.001)
		require.NotNil(t, cv.BaseSeverity)
		assert.Equal(t, hdf.CVSSSeverityLow, *cv.BaseSeverity)
		assert.Nil(t, cv.BaseVector)
		assert.Nil(t, cv.Source)
	})

	t.Run("vector only, no score", func(t *testing.T) {
		cv := BuildCvss(CvssInput{Version: hdf.The40, BaseVector: "CVSS:4.0/AV:N/AC:L"})
		assert.Equal(t, hdf.The40, cv.Version)
		assert.Nil(t, cv.BaseScore)
		assert.Nil(t, cv.BaseSeverity)
		require.NotNil(t, cv.BaseVector)
		assert.Equal(t, "CVSS:4.0/AV:N/AC:L", *cv.BaseVector)
		assert.Nil(t, cv.Source)
	})

	t.Run("version only, all optional fields omitted", func(t *testing.T) {
		cv := BuildCvss(CvssInput{Version: hdf.The31})
		assert.Equal(t, hdf.The31, cv.Version)
		assert.Nil(t, cv.BaseScore)
		assert.Nil(t, cv.BaseSeverity)
		assert.Nil(t, cv.BaseVector)
		assert.Nil(t, cv.Source)
	})
}

type cvssBuildCases struct {
	BuildCases []struct {
		Name  string `json:"name"`
		Input struct {
			Version    hdf.Version `json:"version"`
			BaseScore  *float64    `json:"baseScore"`
			BaseVector string      `json:"baseVector"`
		} `json:"input"`
		Want struct {
			BaseScore    *float64          `json:"baseScore"`
			BaseSeverity *hdf.CVSSSeverity `json:"baseSeverity"`
		} `json:"want"`
	} `json:"buildCases"`
	VersionCases []struct {
		Vector   string      `json:"vector"`
		Fallback hdf.Version `json:"fallback"`
		Want     hdf.Version `json:"want"`
	} `json:"versionCases"`
}

func loadCvssBuildCases(t *testing.T) cvssBuildCases {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(getSharedDir(), "..", "cvss-build-cases.json"))
	require.NoError(t, err)
	var doc cvssBuildCases
	require.NoError(t, json.Unmarshal(raw, &doc))
	require.NotEmpty(t, doc.BuildCases, "shared table is empty — the run would pass vacuously")
	require.NotEmpty(t, doc.VersionCases, "shared table is empty — the run would pass vacuously")
	return doc
}

func TestBuildCvss_SharedCases(t *testing.T) {
	for _, c := range loadCvssBuildCases(t).BuildCases {
		t.Run(c.Name, func(t *testing.T) {
			got := BuildCvss(CvssInput{Version: c.Input.Version, BaseScore: c.Input.BaseScore, BaseVector: c.Input.BaseVector})
			assert.Equal(t, c.Want.BaseScore, got.BaseScore, "baseScore")
			assert.Equal(t, c.Want.BaseSeverity, got.BaseSeverity, "baseSeverity")
		})
	}
}

func TestCvssVersionFromVector_SharedCases(t *testing.T) {
	for _, c := range loadCvssBuildCases(t).VersionCases {
		var got hdf.Version
		if c.Fallback == "" {
			got = CvssVersionFromVector(c.Vector)
		} else {
			got = CvssVersionFromVector(c.Vector, c.Fallback)
		}
		assert.Equal(t, c.Want, got, "vector %q fallback %q", c.Vector, c.Fallback)
	}
}

// A source can hand the builder a non-finite score: strconv.ParseFloat accepts
// NaN, Inf and Infinity. json.Marshal refuses one, so a single such score would
// fail the whole document; the TypeScript peer has always read it as absent.
func TestBuildCvss_NonFiniteScoreReadsAsAbsent(t *testing.T) {
	for name, score := range map[string]float64{
		"NaN":               math.NaN(),
		"positive infinity": math.Inf(1),
		"negative infinity": math.Inf(-1),
	} {
		t.Run(name, func(t *testing.T) {
			t.Run("with a vector, the vector supplies the score", func(t *testing.T) {
				got := BuildCvss(CvssInput{Version: hdf.The20, BaseScore: &score, BaseVector: "AV:N/AC:L/Au:N/C:C/I:C/A:C"})
				require.NotNil(t, got.BaseScore)
				assert.InDelta(t, 10.0, *got.BaseScore, 1e-9)
				require.NotNil(t, got.BaseSeverity)
				assert.Equal(t, hdf.CVSSSeverityHigh, *got.BaseSeverity)
				_, err := json.Marshal(got)
				require.NoError(t, err)
			})

			t.Run("without a vector, the entry carries no score", func(t *testing.T) {
				got := BuildCvss(CvssInput{Version: hdf.The20, BaseScore: &score})
				assert.Nil(t, got.BaseScore)
				assert.Nil(t, got.BaseSeverity)
				_, err := json.Marshal(got)
				require.NoError(t, err)
			})
		})
	}
}
