package hdfutil

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRoundImpact(t *testing.T) {
	// The float-division noise case: 9.8/10 stores as 0.9800000000000001;
	// RoundImpact returns the clean 0.98 double (would fail without rounding).
	assert.Equal(t, 0.98, RoundImpact(9.8/10.0))
	assert.Equal(t, 0.82, RoundImpact(8.2/10.0))

	// Already-clean values are unchanged.
	assert.Equal(t, 0.5, RoundImpact(0.5))
	assert.Equal(t, 0.0, RoundImpact(0.0))
	assert.Equal(t, 1.0, RoundImpact(1.0))

	// Rounds to 2 decimal places (half away from zero).
	assert.Equal(t, 0.13, RoundImpact(0.125))

	// Idempotent.
	once := RoundImpact(9.8 / 10.0)
	assert.Equal(t, once, RoundImpact(once))
}
