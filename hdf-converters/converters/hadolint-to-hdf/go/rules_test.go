package hadolint

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The two rule families are documented in different projects.
func TestRuleReferenceURL_PerRuleFamily(t *testing.T) {
	assert.Equal(t, "https://github.com/hadolint/hadolint/wiki/DL3002", ruleReferenceURL("DL3002"))
	assert.Equal(t, "https://github.com/koalaman/shellcheck/wiki/SC2154", ruleReferenceURL("SC2154"))
}

// The rule code reaches a URL, so a report carrying a crafted code must not be
// able to steer the link. Anything that is not a rule code yields no link.
func TestRuleReferenceURL_RejectsAnythingNotARuleCode(t *testing.T) {
	for _, code := range []string{
		"",
		"DL1000x",
		"E501",
		"../../../../attacker/evilrepo/main/payload",
		"..%2f..%2fadmin",
		"//evil.example.com/x",
		"@evil.example.com/x",
		"http://169.254.169.254/latest/meta-data",
		"DL3002?x=1",
		"DL3002#frag",
	} {
		assert.Empty(t, ruleReferenceURL(code), "code %q must not produce a link", code)
	}
}

func TestConvert_LinksTheRuleDocumentation(t *testing.T) {
	result := convertFixture(t, "shellcheck.json")

	dl := requirementByID(t, result, "DL3002")
	require.Len(t, dl.Refs, 1)
	assert.Equal(t, "https://github.com/hadolint/hadolint/wiki/DL3002", *dl.Refs[0].URL)

	sc := requirementByID(t, result, "SC2154")
	require.Len(t, sc.Refs, 1)
	assert.Equal(t, "https://github.com/koalaman/shellcheck/wiki/SC2154", *sc.Refs[0].URL)
}

// A rule the linter could emit but the link pattern does not cover still
// converts; it simply carries no reference.
func TestConvert_UnlinkableRuleStillConverts(t *testing.T) {
	input := []byte(`[{"code":"E501","column":1,"file":"Dockerfile","level":"warning","line":1,"message":"m"}]`)
	result, err := ConvertHadolintToHDF(input, testVersion)
	require.NoError(t, err)
	assert.Empty(t, requirementByID(t, result, "E501").Refs)
}
