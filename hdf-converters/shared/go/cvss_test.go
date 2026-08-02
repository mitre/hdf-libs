package shared

import (
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
		{"v3.1 prefix falls through to default", "CVSS:3.1/AV:N/AC:L", hdf.The31},
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
		assert.Equal(t, tc.want, CvssSeverityFromScore(tc.score))
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

	t.Run("score only, no vector or source", func(t *testing.T) {
		cv := BuildCvss(CvssInput{Version: hdf.The20, BaseScore: floatPtr(0.0)})
		assert.Equal(t, hdf.The20, cv.Version)
		require.NotNil(t, cv.BaseScore)
		assert.InDelta(t, 0.0, *cv.BaseScore, 0.001)
		require.NotNil(t, cv.BaseSeverity)
		assert.Equal(t, hdf.None, *cv.BaseSeverity)
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
