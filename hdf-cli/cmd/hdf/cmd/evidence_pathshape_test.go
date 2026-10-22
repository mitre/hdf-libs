package cmd

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// absoluteOutsideRef builds a reference that is genuinely absolute on the running
// platform and valid to RECORD, for the cases that mean "an artifact outside the
// package". A leading separator alone is not enough: on Windows it is drive-relative,
// so every case built that way resolved back inside the package and stopped exercising
// anything. The IsAbs precondition is what makes that failure loud instead of silent.
func absoluteOutsideRef(t *testing.T, parts ...string) string {
	t.Helper()
	root := string(filepath.Separator)
	if vol := filepath.VolumeName(os.TempDir()); vol != "" {
		root = vol + root
	}
	p := filepath.Join(append([]string{root}, parts...)...)
	require.True(t, filepath.IsAbs(p), "precondition: %q must be absolute on this platform", p)
	// Forward-slashed because all five reference fields are uri-reference; a recorded
	// Windows separator makes the document schema-invalid before the guard is reached.
	return filepath.ToSlash(p)
}

// recordedRelRef renders a relative reference for recording. Separate from
// absoluteOutsideRef because a relative reference must stay relative — only its
// separators change.
func recordedRelRef(parts ...string) string { return filepath.ToSlash(filepath.Join(parts...)) }

// escapesPackageRef is the ONE containment predicate packageSubtreeRef,
// checkContentRefShape and collect's archive-entry guard all share.
//
// The backslash row is what gives this table power on unix. Restoring the original
// defect — filepath.IsAbs alone — leaves every OTHER row passing here, because
// "/x.json" is absolute on unix; only `\x.json` separates the two spellings on this
// platform, so that one row is the whole local falsifier for a Windows-only bug.
func TestEscapesPackageRef_ContainmentRule(t *testing.T) {
	for _, tc := range []struct {
		uri  string
		want bool
		why  string
	}{
		{"scans/rhel9.json", false, "package-relative by the contents[] contract"},
		{"./scans/rhel9.json", false, "a leading dot is still relative"},
		{"../outside.json", false, "escaping, but the caller's ../ check owns that, not this one"},
		{"/x.json", true, "root-anchored: outside on EVERY platform, which is the whole point"},
		{"/scans/rhel9.json", true, "root-anchored with a subdirectory"},
		{`\x.json`, true, "ALSO root-anchored on Windows, and reachable as the legal uri-reference %5Cx.json"},
		{"", false, "an empty reference names nothing to contain"},
	} {
		t.Run(tc.uri, func(t *testing.T) {
			assert.Equal(t, tc.want, escapesPackageRef(tc.uri), tc.why)
		})
	}
	// The three callers must keep applying this one rule. checkContentRefShape refuses
	// exactly what this reports, so a future fourth spelling diverges loudly here.
	assert.Error(t, checkContentRefShape("/x.json", "contents[0].uri"),
		"the archive-entry check must refuse what the containment predicate reports as outside")
	assert.NoError(t, checkContentRefShape("scans/rhel9.json", "contents[0].uri"),
		"and must accept what it reports as inside")
}
