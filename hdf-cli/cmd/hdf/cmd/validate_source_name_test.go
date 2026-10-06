package cmd

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// hdf validate shares displayNameFor with hdf validate threshold — deliberately,
// so the two cannot drift on how they name the document they are talking about.
// It therefore had the same unattributable stdin verdict, and gains the same flag
// in the same change rather than drifting the other way.
func TestValidate_StdinCanBeNamed(t *testing.T) {
	stdout, _, err := executeCommandWithStdin(t, []byte(testResultsForThreshold),
		"validate", "-", "--source-name", "grype.json")
	require.NoError(t, err)
	assert.Contains(t, stdout, "grype.json", "the supplied name must carry the verdict")
	assert.NotContains(t, stdout, "<stdin>", "and must replace the placeholder")
}

// The pass verdict above is not enough: hdf validate renders ✗ from several
// separate branches (legacy-v2, unrecognized type, schema-invalid) and all of
// them consume the same displayName, so one of them is asserted here to pin that
// the name reaches the failure path too — not just the happy one.
func TestValidate_StdinNameCarriesTheFailureVerdict(t *testing.T) {
	_, stderr, err := executeCommandWithStdin(t, []byte(`{"not":"an hdf document"}`),
		"validate", "-", "--source-name", "bad-doc.json")
	require.Error(t, err)
	// Anchored to the ✗ line, not a bare substring: the returned error ALSO
	// carries displayName and cobra echoes it to stderr, so an unanchored
	// Contains passes even when the verdict line itself renders the raw "-".
	assert.Contains(t, stderr, "✗ bad-doc.json", "the failure VERDICT LINE must carry the supplied name")
	assert.NotContains(t, stderr, "✗ <stdin>")
	assert.NotContains(t, stderr, "✗ -", "and must not fall back to the raw dash")
}

func TestValidate_StdinKeepsItsPlaceholderWithoutTheFlag(t *testing.T) {
	stdout, _, err := executeCommandWithStdin(t, []byte(testResultsForThreshold),
		"validate", "-")
	require.NoError(t, err)
	assert.Contains(t, stdout, "<stdin>", "absent the flag nothing changes")
}

// Same refusal as the threshold command, for the same reason: a name applied to a
// real file could misattribute it, which is worse than no name at all.
func TestValidate_SourceNameWithAFileIsRefused(t *testing.T) {
	dir := t.TempDir()
	results := writeResultsAt(t, dir, "results.json", testResultsForThreshold)

	_, _, err := executeCommand("validate", results, "--source-name", "something-else.json")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--source-name", "the refusal must name the flag")
	assert.NotContains(t, err.Error(), "valid HDF",
		"and must refuse before validating, not report a verdict for a mislabelled document")
}

// Both commands share validateSourceName, so both must refuse — the helper
// existing is not evidence that validate calls it.
func TestValidate_SourceNameWithAControlCharacterIsRefused(t *testing.T) {
	for _, tc := range []struct{ name, value string }{
		{"newline forges a verdict", "clean.json\n✓ other.json is a valid HDF results file"},
		{"ANSI escape", "\x1b[31mRED\x1b[0m"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stdout, stderr, err := executeCommandWithStdin(t, []byte(testResultsForThreshold),
				"validate", "-", "--source-name", tc.value)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "--source-name")
			assert.NotContains(t, stdout+stderr, "✓", "no verdict may be rendered")
			assert.NotContains(t, stdout+stderr, "✗")
		})
	}
}

func TestValidate_OrdinarySourceNameIsAccepted(t *testing.T) {
	stdout, _, err := executeCommandWithStdin(t, []byte(testResultsForThreshold),
		"validate", "-", "--source-name", "a name with spaces.json")
	require.NoError(t, err)
	assert.Contains(t, stdout, "✓ a name with spaces.json",
		"anchored to the verdict line, as the sibling is: a bare substring is the shape that let a broken render pass on wft3f.22")
}

// One name cannot label several documents, and that holds even when every
// argument is `-`: a bulk run would print the name against the first and the raw
// dash against the rest.
func TestValidate_SourceNameWithSeveralArgsIsRefused(t *testing.T) {
	_, _, err := executeCommand("validate", "-", "-", "--source-name", "one-name.json")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "single document")
}
