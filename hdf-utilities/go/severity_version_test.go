package hdfutil

import (
	"math"
	"testing"

	"github.com/stretchr/testify/assert"
)

type cvssSeverityCase struct {
	Version  string  `json:"version"`
	Score    float64 `json:"score"`
	Severity string  `json:"severity"`
}

func TestCvssSeverityForVersion(t *testing.T) {
	for _, c := range loadVectorCases[cvssSeverityCase](t, "cvss-severity-cases.json") {
		assert.Equal(t, c.Severity, CvssSeverityForVersion(c.Version, c.Score), "CVSS %s score %v", c.Version, c.Score)
	}
}

func TestCvssSeverityForVersion_NonFiniteIsNoRating(t *testing.T) {
	for _, version := range []string{"2.0", "3.1"} {
		for _, score := range []float64{math.NaN(), math.Inf(1), math.Inf(-1)} {
			assert.Equal(t, "none", CvssSeverityForVersion(version, score), "CVSS %s score %v", version, score)
		}
	}
}
