package shared

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The TypeScript peer reads the same ../testdata/ensure-default-description-cases.json.
func TestEnsureDefaultDescription_Vectors(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "testdata", "ensure-default-description-cases.json"))
	require.NoError(t, err)
	var file struct {
		Cases []struct {
			Name         string            `json:"name"`
			Descriptions []hdf.Description `json:"descriptions"`
			Data         string            `json:"data"`
			Want         []hdf.Description `json:"want"`
		} `json:"cases"`
	}
	require.NoError(t, json.Unmarshal(raw, &file))
	require.NotEmpty(t, file.Cases)
	for _, c := range file.Cases {
		t.Run(c.Name, func(t *testing.T) {
			assert.Equal(t, c.Want, EnsureDefaultDescription(c.Descriptions, c.Data))
		})
	}
}

func TestEnsureDefaultDescription_NilGetsDefault(t *testing.T) {
	assert.Equal(t, []hdf.Description{{Label: "default", Data: ""}}, EnsureDefaultDescription(nil, ""))
}

func TestEnsureDefaultDescription_DoesNotWriteIntoInput(t *testing.T) {
	in := make([]hdf.Description, 1, 4)
	in[0] = hdf.Description{Label: "check", Data: "c"}
	out := EnsureDefaultDescription(in, "")
	require.Len(t, out, 2)
	assert.Equal(t, []hdf.Description{{Label: "check", Data: "c"}}, in)
	assert.Equal(t, hdf.Description{}, in[:2][1], "spare capacity in the input must stay unwritten")
}
