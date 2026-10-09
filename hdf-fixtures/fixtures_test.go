package fixtures

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// duplicate-baselines.json is a copy of prisma-to-hdf's live golden. Nothing
// but this test ties the two together: the moment that converter regenerates
// its golden, the shared corpus stops being that converter's output while
// still claiming to be, so the copy is pinned to the hash the README records
// and to the golden's current bytes.
func TestDuplicateBaselinesIsThePrismaGolden(t *testing.T) {
	const recorded = "7273e11d8bf3d55de0ca2654114f66caf6728dc97959c10bdc5847574b902152"
	assert.Equal(t, recorded, fmt.Sprintf("%x", sha256.Sum256(Results.DuplicateBaselines)),
		"the shared copy must match the hash README.md records")

	golden, err := os.ReadFile(filepath.Join("..", "hdf-converters", "converters", "prisma-to-hdf", "fixtures", "expected", "prismacloud_sample.csv.hdf.json"))
	require.NoError(t, err)
	assert.Equal(t, recorded, fmt.Sprintf("%x", sha256.Sum256(golden)),
		"prisma-to-hdf's golden moved; regenerate the shared copy and update the recorded hash")
}
