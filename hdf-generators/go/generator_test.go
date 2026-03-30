package generators

import (
	"strings"
	"testing"

	hdf "github.com/mitre/hdf-schema"
	"github.com/stretchr/testify/assert"
)

func makeBaseline(name string, reqs []hdf.BaselineRequirement) hdf.HDFBaseline {
	return hdf.HDFBaseline{
		Name:         name,
		Requirements: reqs,
		Groups:       []hdf.RequirementGroup{},
		Supports:     []hdf.SupportedPlatform{},
	}
}

func TestGenerateInSpecYml_MinimalBaseline(t *testing.T) {
	baseline := makeBaseline("my-profile", []hdf.BaselineRequirement{makeRequirement("SV-001", 0.5)})
	yml := GenerateInSpecYml(baseline, nil)
	assert.Contains(t, yml, "name: my-profile")
	assert.Contains(t, yml, "inspec_version: '>=6.0'")
}

func TestGenerateInSpecYml_CustomInSpecVersion(t *testing.T) {
	baseline := makeBaseline("my-profile", []hdf.BaselineRequirement{makeRequirement("SV-001", 0.5)})
	opts := &GeneratorOptions{InSpecVersion: "~>5.0"}
	yml := GenerateInSpecYml(baseline, opts)
	assert.Contains(t, yml, "inspec_version: '~>5.0'")
}

func TestGenerateInSpecYml_WithTitle(t *testing.T) {
	baseline := makeBaseline("my-profile", []hdf.BaselineRequirement{makeRequirement("SV-001", 0.5)})
	baseline.Title = ptr("My Security Profile")
	yml := GenerateInSpecYml(baseline, nil)
	assert.Contains(t, yml, "title: My Security Profile")
}

func TestGenerateInSpecYml_WithSummary(t *testing.T) {
	baseline := makeBaseline("my-profile", []hdf.BaselineRequirement{makeRequirement("SV-001", 0.5)})
	baseline.Summary = ptr("A test profile")
	yml := GenerateInSpecYml(baseline, nil)
	assert.Contains(t, yml, "summary: A test profile")
}

func TestGenerateInSpecYml_WithVersion(t *testing.T) {
	baseline := makeBaseline("my-profile", []hdf.BaselineRequirement{makeRequirement("SV-001", 0.5)})
	baseline.Version = ptr("1.2.3")
	yml := GenerateInSpecYml(baseline, nil)
	assert.Contains(t, yml, "version: '1.2.3'")
}

func TestGenerateInSpecYml_MetadataOverrides(t *testing.T) {
	baseline := makeBaseline("my-profile", []hdf.BaselineRequirement{makeRequirement("SV-001", 0.5)})
	baseline.Version = ptr("1.0.0")
	opts := &GeneratorOptions{
		Metadata: &ProfileMetadata{
			Maintainer: "MITRE SAF Team",
			Copyright:  "MITRE Corporation",
			License:    "Apache-2.0",
			Version:    "2.0.0",
		},
	}
	yml := GenerateInSpecYml(baseline, opts)
	assert.Contains(t, yml, "maintainer: MITRE SAF Team")
	assert.Contains(t, yml, "copyright: MITRE Corporation")
	assert.Contains(t, yml, "license: Apache-2.0")
	assert.Contains(t, yml, "version: '2.0.0'")
	assert.NotContains(t, yml, "version: '1.0.0'")
}

func TestGenerateInSpecYml_WithSupports(t *testing.T) {
	baseline := makeBaseline("my-profile", []hdf.BaselineRequirement{makeRequirement("SV-001", 0.5)})
	baseline.Supports = []hdf.SupportedPlatform{
		{PlatformName: ptr("ubuntu"), Platform: ptr("os"), PlatformFamily: ptr("debian"), Release: ptr("20.04")},
	}
	yml := GenerateInSpecYml(baseline, nil)
	assert.Contains(t, yml, "supports:")
	assert.Contains(t, yml, "platform-name: ubuntu")
	assert.Contains(t, yml, "platform: os")
	assert.Contains(t, yml, "platform-family: debian")
	assert.Contains(t, yml, "release: 20.04")
}

func TestGenerateInSpecYml_WithDepends(t *testing.T) {
	baseline := makeBaseline("my-profile", []hdf.BaselineRequirement{makeRequirement("SV-001", 0.5)})
	baseline.Depends = []hdf.Dependency{
		{Name: ptr("base-profile"), Git: ptr("https://github.com/org/base.git"), Branch: ptr("main")},
		{Name: ptr("local"), Path: ptr("../other")},
	}
	yml := GenerateInSpecYml(baseline, nil)
	assert.Contains(t, yml, "depends:")
	assert.Contains(t, yml, "name: base-profile")
	assert.Contains(t, yml, "git: 'https://github.com/org/base.git'")
	assert.Contains(t, yml, "branch: main")
	assert.Contains(t, yml, "path: ../other")
}

func TestGenerateInSpecYml_WithInputs(t *testing.T) {
	baseline := makeBaseline("my-profile", []hdf.BaselineRequirement{makeRequirement("SV-001", 0.5)})
	baseline.Inputs = []map[string]interface{}{
		{"disable_slow_controls": true},
		{"max_retries": 3.0},
	}
	yml := GenerateInSpecYml(baseline, nil)
	assert.Contains(t, yml, "inputs:")
	assert.Contains(t, yml, "disable_slow_controls: true")
	assert.Contains(t, yml, "max_retries: 3")
}

func TestGenerateInSpecYml_OmitsEmptyOptional(t *testing.T) {
	baseline := makeBaseline("my-profile", []hdf.BaselineRequirement{makeRequirement("SV-001", 0.5)})
	yml := GenerateInSpecYml(baseline, nil)
	assert.NotContains(t, yml, "title:")
	assert.NotContains(t, yml, "summary:")
	assert.NotContains(t, yml, "depends:")
	assert.NotContains(t, yml, "supports:")
}

func TestGenerateInSpecProfile_OneFilePerControl(t *testing.T) {
	baseline := makeBaseline("test-profile", []hdf.BaselineRequirement{
		makeRequirement("SV-001", 0.5),
		makeRequirement("SV-002", 0.7),
	})
	profile := GenerateInSpecProfile(baseline, nil)
	assert.Contains(t, profile.InSpecYml, "name: test-profile")
	assert.Len(t, profile.Controls, 2)
	assert.Contains(t, profile.Controls, "controls/SV-001.rb")
	assert.Contains(t, profile.Controls, "controls/SV-002.rb")
}

func TestGenerateInSpecProfile_SingleFile(t *testing.T) {
	baseline := makeBaseline("test-profile", []hdf.BaselineRequirement{
		makeRequirement("SV-001", 0.5),
		makeRequirement("SV-002", 0.7),
	})
	opts := &GeneratorOptions{SingleFile: true}
	profile := GenerateInSpecProfile(baseline, opts)
	assert.Len(t, profile.Controls, 1)
	content, ok := profile.Controls["controls/controls.rb"]
	assert.True(t, ok)
	assert.Contains(t, content, "control 'SV-001' do")
	assert.Contains(t, content, "control 'SV-002' do")
}

func TestGenerateInSpecProfile_EmptyRequirements(t *testing.T) {
	baseline := makeBaseline("empty-profile", []hdf.BaselineRequirement{})
	profile := GenerateInSpecProfile(baseline, nil)
	assert.Contains(t, profile.InSpecYml, "name: empty-profile")
	assert.Len(t, profile.Controls, 0)
}

func TestGenerateInSpecProfile_ValidRubyOutput(t *testing.T) {
	req := makeRequirement("SV-001", 0.5)
	req.Title = ptr("Test Control")
	req.Tags = map[string]interface{}{"nist": []interface{}{"AC-2"}}
	baseline := makeBaseline("test-profile", []hdf.BaselineRequirement{req})
	profile := GenerateInSpecProfile(baseline, nil)
	ruby := profile.Controls["controls/SV-001.rb"]
	assert.True(t, strings.HasPrefix(ruby, "control 'SV-001' do\n"))
	assert.True(t, strings.HasSuffix(ruby, "end\n"))
}

func TestGenerateInSpecProfile_WithMetadata(t *testing.T) {
	baseline := makeBaseline("test-profile", []hdf.BaselineRequirement{makeRequirement("SV-001", 0.5)})
	opts := &GeneratorOptions{
		Metadata: &ProfileMetadata{Maintainer: "Test Team", License: "MIT"},
	}
	profile := GenerateInSpecProfile(baseline, opts)
	assert.Contains(t, profile.InSpecYml, "maintainer: Test Team")
	assert.Contains(t, profile.InSpecYml, "license: MIT")
}
