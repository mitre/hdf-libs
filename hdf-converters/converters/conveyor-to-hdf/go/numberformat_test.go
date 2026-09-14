package conveyor

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// Conveyor types depth and heuristic score as JSON numbers, and the committed
// capture happens to hold only integers. %.0f truncated anything else to an
// integer while the TypeScript peer printed it in full, so the two languages
// disagreed on a value neither of them should have been altering. The
// TypeScript peer asserts these same strings.
func TestBuildCodeDescRendersNonIntegralNumbersLosslessly(t *testing.T) {
	section := ConveyorSection{
		TitleText:      "suspicious macro",
		BodyFormat:     "TEXT",
		Classification: "TLP:C",
		Depth:          2.5,
		Heuristic:      &Heuristic{HeurID: "AL_MOLDY_1", Score: 137.5, Name: "Macro"},
	}
	got := buildCodeDesc(section, "Moldy")

	assert.Contains(t, got, "depth:2.5", "a non-integral depth must survive, not be truncated")
	assert.Contains(t, got, "heuristic_score:137.5", "a non-integral score must survive, not be truncated")
	assert.NotContains(t, got, "depth:2\n", "truncation leaked through")
	assert.NotContains(t, got, "heuristic_score:137,", "truncation leaked through")
}

// Integral values keep rendering exactly as before, so the committed capture's
// goldens do not move.
func TestBuildCodeDescKeepsIntegralNumbersUnchanged(t *testing.T) {
	section := ConveyorSection{
		BodyFormat:     "TEXT",
		Classification: "TLP:C",
		Depth:          0,
		Heuristic:      &Heuristic{HeurID: "AL_1", Score: 1000, Name: "H"},
	}
	got := buildCodeDesc(section, "Moldy")
	assert.Contains(t, got, "depth:0")
	assert.Contains(t, got, "heuristic_score:1000")
}
