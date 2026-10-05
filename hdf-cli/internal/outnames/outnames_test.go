package outnames

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The single-input cases are the bulk-convert naming convention the CLI has
// always used; numbering must never change them.
func TestNames_UnnumberedConvention(t *testing.T) {
	tests := []struct {
		name  string
		input string
		toFmt string
		want  string
	}{
		{"nessus to hdf", "scan.nessus", "hdf", "scan.hdf.json"},
		{"sarif to hdf", "report.sarif", "hdf", "report.hdf.json"},
		{"json to csv", "results.json", "csv", "results.hdf.csv"},
		{"no extension", "scanfile", "hdf", "scanfile.hdf.json"},
		{"nested path", "/path/to/scan.xml", "hdf", "scan.hdf.json"},
		{"default format", "scan.xml", "", "scan.hdf.json"},
		{"dotted stem keeps all but the last extension", "scan.v2.xml", "hdf", "scan.v2.hdf.json"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Names([]string{tt.input}, tt.toFmt)
			require.NoError(t, err)
			assert.Equal(t, []string{tt.want}, got)
		})
	}
}

// Distinct basenames in one batch are never numbered — the common case is
// untouched.
func TestNames_DistinctBasenamesAreNotNumbered(t *testing.T) {
	got, err := Names([]string{"scans/a.nessus", "scans/b.nessus"}, "hdf")
	require.NoError(t, err)
	assert.Equal(t, []string{"a.hdf.json", "b.hdf.json"}, got)
}

// The motivating case: two per-host scans with one file name. EVERY member of
// the group is numbered — leaving the first bare would make "which input got the
// unnumbered name" an arbitrary detail a reader has to know to interpret.
func TestNames_SameBasenameNumbersEveryMemberFromOne(t *testing.T) {
	got, err := Names([]string{"scans/host1/results.json", "scans/host2/results.json"}, "hdf")
	require.NoError(t, err)
	assert.Equal(t, []string{"results.1.hdf.json", "results.2.hdf.json"}, got)
}

// Numbering carries the non-HDF target extension too, and sits before it.
func TestNames_NumberedNonHDFTarget(t *testing.T) {
	got, err := Names([]string{"scans/host1/results.json", "scans/host2/results.json"}, "html")
	require.NoError(t, err)
	assert.Equal(t, []string{"results.1.hdf.html", "results.2.hdf.html"}, got)
}

func TestNames_ThreeWayCollision(t *testing.T) {
	got, err := Names([]string{"a/r.json", "b/r.json", "c/r.json"}, "hdf")
	require.NoError(t, err)
	assert.Equal(t, []string{"r.1.hdf.json", "r.2.hdf.json", "r.3.hdf.json"}, got)
}

// Numbering must not manufacture a new collision: a literal results.1.json
// already owns results.1.hdf.json, so the numbered group skips that index. The
// literal name wins because it is the one a caller can predict.
func TestNames_NumberingSkipsALiteralName(t *testing.T) {
	got, err := Names([]string{"a/results.json", "b/results.json", "results.1.json"}, "hdf")
	require.NoError(t, err)
	assert.Equal(t, []string{"results.2.hdf.json", "results.3.hdf.json", "results.1.hdf.json"}, got)
	assert.Len(t, uniq(got), 3, "every input must get its own output name")
}

// The skip applies wherever the literal sits in the input order, because the
// names a group cannot use are reserved before any number is handed out.
func TestNames_NumberingSkipsALiteralNameGivenFirst(t *testing.T) {
	got, err := Names([]string{"results.1.json", "a/results.json", "b/results.json"}, "hdf")
	require.NoError(t, err)
	assert.Equal(t, []string{"results.1.hdf.json", "results.2.hdf.json", "results.3.hdf.json"}, got)
}

// Two numbered groups whose stems differ only by a dotted component cannot
// collide, because a numbered name's last component is always the index.
func TestNames_DottedStemsDoNotCrossCollide(t *testing.T) {
	got, err := Names([]string{"a/r.json", "b/r.json", "a/r.1.json", "b/r.1.json"}, "hdf")
	require.NoError(t, err)
	assert.Equal(t, []string{"r.1.hdf.json", "r.2.hdf.json", "r.1.1.hdf.json", "r.1.2.hdf.json"}, got)
	assert.Len(t, uniq(got), 4, "every input must get its own output name")
}

// The same file named twice is one conversion, not a collision: it keeps one
// unnumbered name, as the CLI has always tolerated a repeated argument.
func TestNames_RepeatedInputTolerated(t *testing.T) {
	got, err := Names([]string{"scans/results.json", "./scans/results.json"}, "hdf")
	require.NoError(t, err)
	assert.Equal(t, []string{"results.hdf.json", "results.hdf.json"}, got)
}

// A repeat alongside a genuine collision numbers the two distinct files only,
// and both spellings of the repeated one keep the same number.
func TestNames_RepeatedInputAlongsideCollision(t *testing.T) {
	got, err := Names([]string{"a/results.json", "a/results.json", "b/results.json"}, "hdf")
	require.NoError(t, err)
	assert.Equal(t, []string{"results.1.hdf.json", "results.1.hdf.json", "results.2.hdf.json"}, got)
}

// The number is positional, so the same input set must always produce the same
// assignment — a caller re-running a command cannot get the files swapped.
func TestNames_AssignmentIsDeterministic(t *testing.T) {
	inputs := []string{"d/r.json", "a/r.json", "c/other.json", "b/r.json", "r.1.json"}
	first, err := Names(inputs, "hdf")
	require.NoError(t, err)
	assert.Equal(t,
		[]string{"r.2.hdf.json", "r.3.hdf.json", "other.hdf.json", "r.4.hdf.json", "r.1.hdf.json"},
		first)
	for i := 0; i < 50; i++ {
		again, err := Names(inputs, "hdf")
		require.NoError(t, err)
		require.Equal(t, first, again, "run %d disagreed with the first", i)
	}
}

// Input order is what assigns the numbers, so reordering the arguments
// deliberately reorders the outputs rather than silently keeping a hidden
// association.
func TestNames_InputOrderAssignsTheNumbers(t *testing.T) {
	forward, err := Names([]string{"a/r.json", "b/r.json"}, "hdf")
	require.NoError(t, err)
	assert.Equal(t, []string{"r.1.hdf.json", "r.2.hdf.json"}, forward)

	reversed, err := Names([]string{"b/r.json", "a/r.json"}, "hdf")
	require.NoError(t, err)
	assert.Equal(t, []string{"r.1.hdf.json", "r.2.hdf.json"}, reversed)
}

func TestNames_EmptyInput(t *testing.T) {
	got, err := Names(nil, "hdf")
	require.NoError(t, err)
	assert.Empty(t, got)
}

// A path that names no file at all cannot produce an output name.
func TestNames_InputWithoutBasenameRefused(t *testing.T) {
	for _, in := range []string{"/", ".", "..", ""} {
		_, err := Names([]string{in}, "hdf")
		require.Error(t, err, "input %q must be refused", in)
		assert.Equal(t, `input "`+in+`" has no file name to derive an output name from`, err.Error())
	}
}

// A trailing separator is indistinguishable from a file name after cleaning, and
// the batch enumerators never pass a directory, so it keeps the plain
// convention rather than becoming a special case.
func TestNames_TrailingSeparatorNamesTheLastSegment(t *testing.T) {
	got, err := Names([]string{"scans/"}, "hdf")
	require.NoError(t, err)
	assert.Equal(t, []string{"scans.hdf.json"}, got)
}

// Plain is how a caller tells a numbered name from an unnumbered one, so it must
// agree with Names on every input Names accepts.
func TestPlain(t *testing.T) {
	assert.Equal(t, "results.hdf.json", Plain("scans/host1/results.json", "hdf"))
	assert.Equal(t, "results.hdf.csv", Plain("results.json", "csv"))
	assert.Equal(t, "scan.v2.hdf.json", Plain("scan.v2.xml", ""))
	assert.Equal(t, "", Plain("/", "hdf"), "an input naming no file has no plain name")

	inputs := []string{"a/r.json", "b/r.json", "c/other.json"}
	names, err := Names(inputs, "hdf")
	require.NoError(t, err)
	gotNumbered := []bool{}
	for i, name := range names {
		gotNumbered = append(gotNumbered, name != Plain(inputs[i], "hdf"))
	}
	assert.Equal(t, []bool{true, true, false}, gotNumbered)
}

func uniq(values []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, v := range values {
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out
}
