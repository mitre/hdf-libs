package cmd

import (
	"strings"
	"testing"
	"testing/fstest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The size from the directory listing can be stale: a file that grew after it was
// listed must still be refused rather than read whole, and one under the limit is read.
func TestReadScannedFile_CapsAFileThatGrewAfterItWasListed(t *testing.T) {
	oldMax := maxSizeMB
	maxSizeMB = 1
	t.Cleanup(func() { maxSizeMB = oldMax })

	fsys := fstest.MapFS{
		"grown.log": {Data: []byte(strings.Repeat("x", 2*1024*1024))},
		"small.log": {Data: []byte("ok")},
	}

	data, within, err := readScannedFile(fsys, "grown.log", 10)
	require.NoError(t, err)
	assert.False(t, within, "the bytes actually read decide, not the listed size")
	assert.LessOrEqual(t, len(data), 1024*1024+1, "never more than the limit plus one byte")

	_, within, err = readScannedFile(fsys, "grown.log", 2*1024*1024)
	require.NoError(t, err)
	assert.False(t, within, "a listed size over the limit is refused without opening")

	data, within, err = readScannedFile(fsys, "small.log", 2)
	require.NoError(t, err)
	assert.True(t, within)
	assert.Equal(t, "ok", string(data))

	_, _, err = readScannedFile(fsys, "absent.log", 2)
	assert.Error(t, err)
}
