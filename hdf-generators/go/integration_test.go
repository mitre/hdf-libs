package generators

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	hdf "github.com/mitre/hdf-schema"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func loadFixture(t *testing.T) hdf.HDFBaseline {
	t.Helper()
	data, err := os.ReadFile("testdata/win2022-stig-baseline.json")
	require.NoError(t, err, "fixture file must exist (symlink from test/fixtures/)")
	var baseline hdf.HDFBaseline
	require.NoError(t, json.Unmarshal(data, &baseline))
	return baseline
}

func TestIntegration_LoadFixture(t *testing.T) {
	baseline := loadFixture(t)
	assert.Equal(t, "microsoft-windows-server-2022-stig-baseline", baseline.Name)
	assert.NotNil(t, baseline.Title)
	assert.Equal(t, "Microsoft Windows Server 2022 Security Technical Implementation Guide", *baseline.Title)
	assert.Len(t, baseline.Requirements, 18)
}

func TestIntegration_GeneratesAllControls(t *testing.T) {
	baseline := loadFixture(t)
	profile := GenerateInSpecProfile(baseline, nil)
	assert.Len(t, profile.Controls, 18)
	for _, req := range baseline.Requirements {
		filename := "controls/" + req.ID + ".rb"
		_, ok := profile.Controls[filename]
		assert.True(t, ok, "missing control file for %s", req.ID)
	}
}

func TestIntegration_ValidRubyBlocks(t *testing.T) {
	baseline := loadFixture(t)
	profile := GenerateInSpecProfile(baseline, nil)
	for filename, ruby := range profile.Controls {
		id := strings.TrimSuffix(strings.TrimPrefix(filename, "controls/"), ".rb")
		assert.True(t, strings.HasPrefix(ruby, "control '"+id+"' do\n"),
			"control %s should start with control block", id)
		assert.True(t, strings.HasSuffix(ruby, "end\n"),
			"control %s should end with 'end'", id)
	}
}

func TestIntegration_STIGMetadataInTags(t *testing.T) {
	baseline := loadFixture(t)
	profile := GenerateInSpecProfile(baseline, nil)

	sv238 := profile.Controls["controls/SV-254238.rb"]
	assert.Contains(t, sv238, "tag cci: ['CCI-000366']")
	assert.Contains(t, sv238, "tag nist: ['CM-6 b']")
	assert.Contains(t, sv238, "tag severity: 'medium'")
	assert.Contains(t, sv238, "tag stig_id: 'WN22-00-000010'")
}

func TestIntegration_MultipleCCIsAndNIST(t *testing.T) {
	baseline := loadFixture(t)
	profile := GenerateInSpecProfile(baseline, nil)

	sv240 := profile.Controls["controls/SV-254240.rb"]
	assert.Contains(t, sv240, "'CCI-000366'")
	assert.Contains(t, sv240, "'CCI-001312'")
	assert.Contains(t, sv240, "'CM-6 b'")
	assert.Contains(t, sv240, "'SI-11 a'")
}

func TestIntegration_CheckAndFixDescriptions(t *testing.T) {
	baseline := loadFixture(t)
	profile := GenerateInSpecProfile(baseline, nil)

	sv238 := profile.Controls["controls/SV-254238.rb"]
	assert.Contains(t, sv238, "desc 'check'")
	assert.Contains(t, sv238, "desc 'fix'")
}

func TestIntegration_InSpecYml(t *testing.T) {
	baseline := loadFixture(t)
	profile := GenerateInSpecProfile(baseline, nil)

	assert.Contains(t, profile.InSpecYml, "name: microsoft-windows-server-2022-stig-baseline")
	assert.Contains(t, profile.InSpecYml, "title: Microsoft Windows Server 2022 Security Technical Implementation Guide")
	assert.Contains(t, profile.InSpecYml, "version: '2.7.0'")
	assert.Contains(t, profile.InSpecYml, "maintainer: MITRE SAF Team")
	assert.Contains(t, profile.InSpecYml, "license: Apache-2.0")
}

func TestIntegration_SingleFile(t *testing.T) {
	baseline := loadFixture(t)
	opts := &GeneratorOptions{SingleFile: true}
	profile := GenerateInSpecProfile(baseline, opts)

	assert.Len(t, profile.Controls, 1)
	content, ok := profile.Controls["controls/controls.rb"]
	assert.True(t, ok)
	for _, req := range baseline.Requirements {
		assert.Contains(t, content, "control '"+req.ID+"' do")
	}
}

func TestIntegration_MetadataOverrides(t *testing.T) {
	baseline := loadFixture(t)
	opts := &GeneratorOptions{
		Metadata: &ProfileMetadata{
			Maintainer: "Custom Team",
			Version:    "99.0.0",
		},
	}
	profile := GenerateInSpecProfile(baseline, opts)

	assert.Contains(t, profile.InSpecYml, "maintainer: Custom Team")
	assert.Contains(t, profile.InSpecYml, "version: '99.0.0'")
	assert.NotContains(t, profile.InSpecYml, "maintainer: MITRE SAF Team")
	assert.NotContains(t, profile.InSpecYml, "version: '2.7.0'")
}

func TestIntegration_HighImpactControls(t *testing.T) {
	baseline := loadFixture(t)
	profile := GenerateInSpecProfile(baseline, nil)

	sv240 := profile.Controls["controls/SV-254240.rb"]
	assert.Contains(t, sv240, "impact 0.7")
	assert.Contains(t, sv240, "tag severity: 'high'")
}

func TestIntegration_MultiLineDescriptions(t *testing.T) {
	baseline := loadFixture(t)
	profile := GenerateInSpecProfile(baseline, nil)

	sv240 := profile.Controls["controls/SV-254240.rb"]
	assert.Contains(t, sv240, "web browser")
	assert.Contains(t, sv240, "administrative account")
}
