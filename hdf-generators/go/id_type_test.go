package generators

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateInSpecProfileIDTypeGroup(t *testing.T) {
	req := makeRequirement("SV-215812", 0.7)
	req.Tags = map[string]interface{}{"gid": "V-215812", "stig_id": "CISC-ND-000010"}
	profile, err := GenerateInSpecProfile(hdf.HDFBaseline{Name: "b", Requirements: []hdf.BaselineRequirement{req}}, &GeneratorOptions{IDType: "group"})
	require.NoError(t, err)
	require.Contains(t, profile.Controls, "controls/V-215812.rb")
	assert.True(t, strings.HasPrefix(profile.Controls["controls/V-215812.rb"], "control 'V-215812' do"))
}

// The TypeScript peer (generateInSpecProfile) asserts against this same table.
func TestGenerateInSpecProfile_IDTypeSharedTable(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "testdata", "id-type-cases.json"))
	require.NoError(t, err)
	var table struct {
		Cases []struct {
			Why          string                    `json:"why"`
			IDType       string                    `json:"idType"`
			Requirements []hdf.BaselineRequirement `json:"requirements"`
			Controls     map[string]string         `json:"controls"`
			Error        string                    `json:"error"`
			PerFileOnly  bool                      `json:"perFileOnly"`
		} `json:"cases"`
	}
	require.NoError(t, json.Unmarshal(data, &table))
	require.NotEmpty(t, table.Cases, "empty table would pass vacuously")

	for _, c := range table.Cases {
		t.Run(c.Why, func(t *testing.T) {
			baseline := hdf.HDFBaseline{Name: "b", Requirements: c.Requirements}
			for _, single := range []bool{false, true} {
				profile, err := GenerateInSpecProfile(baseline, &GeneratorOptions{IDType: c.IDType, SingleFile: single})
				wantErr := c.Error != "" && (!single || !c.PerFileOnly)
				if wantErr {
					require.EqualError(t, err, c.Error, "single file %v", single)
					continue
				}
				require.NoError(t, err)
				if c.Error != "" {
					continue
				}
				if single {
					for _, first := range c.Controls {
						assert.Contains(t, profile.Controls["controls/controls.rb"], first+"\n")
					}
					continue
				}
				firstLines := map[string]string{}
				for name, src := range profile.Controls {
					firstLines[name] = strings.SplitN(src, "\n", 2)[0]
				}
				assert.Equal(t, c.Controls, firstLines)
			}
		})
	}
}
