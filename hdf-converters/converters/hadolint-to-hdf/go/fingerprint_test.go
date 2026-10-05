package hadolint

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/mitre/hdf-libs/hdf-converters/v3/registry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFingerprint_RecordedReports(t *testing.T) {
	for _, name := range []string{"real.json", "shellcheck.json"} {
		t.Run(name, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join("..", "fixtures", "input", name))
			require.NoError(t, err)
			result := registry.DetectConverter(data)
			require.NotNil(t, result, "should detect hadolint")
			assert.Equal(t, "hadolint-to-hdf", result.Fingerprint.ID)
			assert.Equal(t, 1.0, result.Confidence)
		})
	}
}

// The field shape alone could belong to another line-oriented linter, so a
// code outside hadolint's namespace scores lower than a DL or SC rule.
func TestFingerprint_ForeignRuleCodeScoresLower(t *testing.T) {
	input := `[{"code":"E501","column":1,"file":"a.py","level":"warning","line":3,"message":"line too long"}]`
	result := registry.DetectConverter([]byte(input))
	if result != nil && result.Fingerprint.ID == "hadolint-to-hdf" {
		assert.Less(t, result.Confidence, 1.0)
	}
}

func TestFingerprint_NotHadolint(t *testing.T) {
	for name, input := range map[string]string{
		"an object":        `{"code":"DL3002"}`,
		"an empty array":   `[]`,
		"gosec":            `{"Issues":[],"GosecVersion":"2.0"}`,
		"wrong level":      `[{"code":"DL3002","column":1,"file":"D","level":"critical","line":1,"message":"m"}]`,
		"line not numeric": `[{"code":"DL3002","column":1,"file":"D","level":"warning","line":"1","message":"m"}]`,
		"no message":       `[{"code":"DL3002","column":1,"file":"D","level":"warning","line":1}]`,
	} {
		t.Run(name, func(t *testing.T) {
			result := registry.DetectConverter([]byte(input))
			if result != nil {
				assert.NotEqual(t, "hadolint-to-hdf", result.Fingerprint.ID)
			}
		})
	}
}
