package hdfutil

import (
	"crypto/sha256"
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type cvss31Case struct {
	Vector   string  `json:"vector"`
	Base     float64 `json:"base"`
	Temporal float64 `json:"temporal"`
	Note     string  `json:"note"`
}

func loadCvss31Cases(t *testing.T) []cvss31Case {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "testdata", "cvss31-vectors.json"))
	require.NoError(t, err)
	var fx struct {
		Cases []cvss31Case `json:"cases"`
	}
	require.NoError(t, json.Unmarshal(data, &fx))
	require.NotEmpty(t, fx.Cases)
	return fx.Cases
}

func TestComputeCvssScore31(t *testing.T) {
	for _, c := range loadCvss31Cases(t) {
		c := c
		t.Run(c.Vector, func(t *testing.T) {
			s, err := ComputeCvssScore(c.Vector)
			require.NoError(t, err)
			assert.Equal(t, "3.1", s.Version)
			assert.Equal(t, c.Base, s.BaseScore, "base")
			assert.Equal(t, c.Temporal, s.TemporalScore, "temporal")
		})
	}
}

func TestComputeCvssScore_UnsupportedVersion(t *testing.T) {
	for _, v := range []string{
		"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
		"AV:N/AC:L/Au:N/C:C/I:C/A:C",
		"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
	} {
		_, err := ComputeCvssScore(v)
		assert.Error(t, err, v)
	}
}

func TestComputeCvssScore_InvalidVector(t *testing.T) {
	_, err := ComputeCvssScore("CVSS:3.1/AV:N/AC:L")
	assert.Error(t, err, "missing required base metric")

	_, err = ComputeCvssScore("CVSS:3.1/AV:Z/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
	assert.ErrorContains(t, err, "AV", "out-of-enum base metric value")

	_, err = ComputeCvssScore("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:Z/C:H/I:H/A:H")
	assert.ErrorContains(t, err, "Scope", "invalid Scope value")

	_, err = ComputeCvssScore("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:Z")
	assert.ErrorContains(t, err, "E", "out-of-enum temporal value")
}

func TestCvssScoreToSeverity(t *testing.T) {
	tests := []struct {
		score    float64
		expected string
	}{
		{0.0, "none"},
		{0.05, "none"},
		{0.1, "low"},
		{3.9, "low"},
		{4.0, "medium"},
		{6.9, "medium"},
		{7.0, "high"},
		{8.9, "high"},
		{9.0, "critical"},
		{10.0, "critical"},
		// Clamping
		{-1.0, "none"},
		{11.5, "critical"},
		// Non-finite inputs match the TypeScript counterpart (-> "none").
		{math.NaN(), "none"},
		{math.Inf(1), "none"},
		{math.Inf(-1), "none"},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.expected, CvssScoreToSeverity(tt.score), "CvssScoreToSeverity(%v)", tt.score)
	}
}

func TestParseCvssVector(t *testing.T) {
	t.Run("CVSS 3.1 standard", func(t *testing.T) {
		v, metrics := ParseCvssVector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
		assert.Equal(t, "3.1", v)
		require.Len(t, metrics, 8)
		assert.Equal(t, "N", metrics["AV"])
		assert.Equal(t, "L", metrics["AC"])
		assert.Equal(t, "N", metrics["PR"])
		assert.Equal(t, "N", metrics["UI"])
		assert.Equal(t, "U", metrics["S"])
		assert.Equal(t, "H", metrics["C"])
		assert.Equal(t, "H", metrics["I"])
		assert.Equal(t, "H", metrics["A"])
	})

	t.Run("CVSS 3.0", func(t *testing.T) {
		v, metrics := ParseCvssVector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H")
		assert.Equal(t, "3.0", v)
		assert.Len(t, metrics, 8)
	})

	t.Run("CVSS 2.0 legacy (no prefix)", func(t *testing.T) {
		v, metrics := ParseCvssVector("AV:N/AC:L/Au:N/C:N/I:P/A:N")
		assert.Equal(t, "2.0", v)
		require.Len(t, metrics, 6)
		assert.Equal(t, "N", metrics["AV"])
		assert.Equal(t, "L", metrics["AC"])
		assert.Equal(t, "N", metrics["Au"])
		assert.Equal(t, "N", metrics["C"])
		assert.Equal(t, "P", metrics["I"])
		assert.Equal(t, "N", metrics["A"])
	})

	t.Run("CVSS 4.0", func(t *testing.T) {
		v, metrics := ParseCvssVector("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N")
		assert.Equal(t, "4.0", v)
		require.Len(t, metrics, 11)
		assert.Equal(t, "N", metrics["AT"])
		assert.Equal(t, "H", metrics["VC"])
		assert.Equal(t, "N", metrics["SA"])
	})

	t.Run("Temporal + Environmental tail", func(t *testing.T) {
		v, metrics := ParseCvssVector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:U/RL:O/RC:C/MAV:N/CR:H")
		assert.Equal(t, "3.1", v)
		assert.Equal(t, "U", metrics["E"])
		assert.Equal(t, "O", metrics["RL"])
		assert.Equal(t, "C", metrics["RC"])
		assert.Equal(t, "N", metrics["MAV"])
		assert.Equal(t, "H", metrics["CR"])
	})

	t.Run("empty string yields unknown", func(t *testing.T) {
		v, metrics := ParseCvssVector("")
		assert.Equal(t, "unknown", v)
		assert.Empty(t, metrics)
	})

	t.Run("no slashes or colons yields unknown", func(t *testing.T) {
		v, metrics := ParseCvssVector("not a vector")
		assert.Equal(t, "unknown", v)
		assert.Empty(t, metrics)
	})

	t.Run("skips malformed segments with empty value", func(t *testing.T) {
		v, metrics := ParseCvssVector("CVSS:3.1/AV:N/AC:/PR:N")
		assert.Equal(t, "3.1", v)
		assert.Equal(t, "N", metrics["AV"])
		assert.Equal(t, "N", metrics["PR"])
		_, hasAC := metrics["AC"]
		assert.False(t, hasAC)
	})

	t.Run("skips empty segments from leading/trailing slashes", func(t *testing.T) {
		v, metrics := ParseCvssVector("/CVSS:3.1/AV:N/AC:L/")
		assert.Equal(t, "3.1", v)
		assert.Equal(t, "N", metrics["AV"])
		assert.Equal(t, "L", metrics["AC"])
	})

	t.Run("permissive: keeps unknown metric keys", func(t *testing.T) {
		v, metrics := ParseCvssVector("CVSS:3.1/UnknownKey:X/AV:N")
		assert.Equal(t, "3.1", v)
		assert.Equal(t, "X", metrics["UnknownKey"])
		assert.Equal(t, "N", metrics["AV"])
	})
}

func TestValidateCvssVector(t *testing.T) {
	t.Run("valid v3.1", func(t *testing.T) {
		valid, errs := ValidateCvssVector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "")
		assert.True(t, valid)
		assert.Empty(t, errs)
	})

	t.Run("valid v3.0", func(t *testing.T) {
		valid, errs := ValidateCvssVector("CVSS:3.0/AV:L/AC:H/PR:H/UI:R/S:C/C:L/I:L/A:N", "")
		assert.True(t, valid)
		assert.Empty(t, errs)
	})

	t.Run("valid v2.0", func(t *testing.T) {
		valid, errs := ValidateCvssVector("AV:N/AC:L/Au:N/C:N/I:P/A:N", "")
		assert.True(t, valid)
		assert.Empty(t, errs)
	})

	t.Run("valid v4.0", func(t *testing.T) {
		valid, errs := ValidateCvssVector("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", "")
		assert.True(t, valid)
		assert.Empty(t, errs)
	})

	t.Run("v3.1 missing PR", func(t *testing.T) {
		valid, errs := ValidateCvssVector("CVSS:3.1/AV:N/AC:L/UI:N/S:U/C:H/I:H/A:H", "")
		assert.False(t, valid)
		assert.NotEmpty(t, errs)
		assert.True(t, hasErr(errs, "PR"))
	})

	t.Run("v4 missing AT", func(t *testing.T) {
		valid, errs := ValidateCvssVector("CVSS:4.0/AV:N/AC:L/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", "")
		assert.False(t, valid)
		assert.True(t, hasErr(errs, "AT"))
	})

	t.Run("v2 missing Au", func(t *testing.T) {
		valid, errs := ValidateCvssVector("AV:N/AC:L/C:N/I:P/A:N", "")
		assert.False(t, valid)
		assert.True(t, hasErr(errs, "Au"))
	})

	t.Run("invalid AV:Z", func(t *testing.T) {
		valid, errs := ValidateCvssVector("CVSS:3.1/AV:Z/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "")
		assert.False(t, valid)
		assert.True(t, hasErr(errs, "AV"))
	})

	t.Run("invalid v4 VC:X", func(t *testing.T) {
		valid, errs := ValidateCvssVector("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:X/VI:H/VA:H/SC:N/SI:N/SA:N", "")
		assert.False(t, valid)
		assert.True(t, hasErr(errs, "VC"))
	})

	t.Run("unknown metric does not error (forward-compat)", func(t *testing.T) {
		valid, errs := ValidateCvssVector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/XX:Y", "")
		assert.True(t, valid)
		assert.Empty(t, errs)
	})

	t.Run("explicit version override accepted", func(t *testing.T) {
		valid, errs := ValidateCvssVector("AV:N/AC:L/Au:N/C:N/I:P/A:N", "2.0")
		assert.True(t, valid)
		assert.Empty(t, errs)
	})

	t.Run("explicit override forces grammar mismatch", func(t *testing.T) {
		valid, _ := ValidateCvssVector("AV:N/AC:L/Au:N/C:N/I:P/A:N", "3.1")
		assert.False(t, valid)
	})

	t.Run("unsupported version", func(t *testing.T) {
		valid, errs := ValidateCvssVector("CVSS:9.9/AV:N", "")
		assert.False(t, valid)
		assert.NotEmpty(t, errs)
	})

	t.Run("empty input", func(t *testing.T) {
		valid, errs := ValidateCvssVector("", "")
		assert.False(t, valid)
		assert.NotEmpty(t, errs)
	})

	t.Run("v3.1 with valid temporal extension", func(t *testing.T) {
		valid, errs := ValidateCvssVector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:U/RL:O/RC:C", "")
		assert.True(t, valid)
		assert.Empty(t, errs)
	})

	t.Run("v3.1 invalid temporal E:Q", func(t *testing.T) {
		valid, errs := ValidateCvssVector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:Q", "")
		assert.False(t, valid)
		assert.True(t, hasErr(errs, "E"))
	})
}

type cvss40Case struct {
	Vector      string  `json:"vector"`
	MacroVector string  `json:"macroVector"`
	Base        float64 `json:"base"`
	Temporal    float64 `json:"temporal"`
	Note        string  `json:"note"`
}

func loadCvss40Cases(t *testing.T) []cvss40Case {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "testdata", "cvss40-vectors.json"))
	require.NoError(t, err)
	var fx struct {
		Cases []cvss40Case `json:"cases"`
	}
	require.NoError(t, json.Unmarshal(data, &fx))
	require.NotEmpty(t, fx.Cases)
	return fx.Cases
}

func TestComputeCvss40Score(t *testing.T) {
	for _, c := range loadCvss40Cases(t) {
		c := c
		t.Run(c.Vector, func(t *testing.T) {
			s, err := ComputeCvss40Score(c.Vector)
			require.NoError(t, err)
			assert.Equal(t, "4.0", s.Version)
			assert.Equal(t, c.Base, s.BaseScore, "base")
			assert.Equal(t, c.Temporal, s.TemporalScore, "temporal")
		})
	}
}

func TestComputeCvss40Score_FirstTestVector(t *testing.T) {
	// The card's first failing test: exact FIRST-reference score for this vector.
	s, err := ComputeCvss40Score("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N")
	require.NoError(t, err)
	assert.Equal(t, "4.0", s.Version)
	assert.Equal(t, 9.3, s.TemporalScore)
}

func TestComputeCvss40Score_MacroVector(t *testing.T) {
	for _, c := range loadCvss40Cases(t) {
		c := c
		t.Run(c.Vector, func(t *testing.T) {
			assert.Equal(t, c.MacroVector, Cvss40MacroVector(c.Vector))
		})
	}
}

func TestComputeCvss40Score_Errors(t *testing.T) {
	cases := map[string]string{
		"wrong version (3.1)":  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
		"missing base metrics": "CVSS:4.0/AV:N/AC:L",
		"invalid AV value":     "CVSS:4.0/AV:Z/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
		"invalid E value":      "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:Z",
	}
	for name, v := range cases {
		v := v
		t.Run(name, func(t *testing.T) {
			_, err := ComputeCvss40Score(v)
			assert.Error(t, err)
		})
	}
}

// TestCvss40DataParity enforces the AC that the shared MacroVector data tables
// are byte-identical across Go (//go:embed) and TS (bundled import).
func TestCvss40DataParity(t *testing.T) {
	goData, err := os.ReadFile("cvss40-data.json")
	require.NoError(t, err)
	tsData, err := os.ReadFile(filepath.Join("..", "src", "cvss", "cvss40-data.json"))
	require.NoError(t, err)
	assert.Equal(t,
		sha256.Sum256(goData), sha256.Sum256(tsData),
		"go/cvss40-data.json and src/cvss/cvss40-data.json must be byte-identical")

	var d struct {
		Lookup map[string]float64 `json:"lookup"`
	}
	require.NoError(t, json.Unmarshal(goData, &d))
	assert.Len(t, d.Lookup, 270, "FIRST MacroVector lookup has 270 entries")
}

func hasErr(errs []string, substr string) bool {
	for _, e := range errs {
		if containsSubstr(e, substr) {
			return true
		}
	}
	return false
}

func containsSubstr(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
