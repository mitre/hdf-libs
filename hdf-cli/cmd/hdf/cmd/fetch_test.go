package cmd

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The Long text's source list is hand-written, so cobra's own "Available Commands"
// cannot stand in for it: every registered fetcher must be listed and exemplified.
func TestFetchCmd_LongNamesEveryRegisteredSource(t *testing.T) {
	cmd := NewFetchCmd()
	sources, examples := fetchLongSections(t, cmd.Long)

	subs := cmd.Commands()
	require.NotEmpty(t, subs)
	for _, sub := range subs {
		name := sub.Name()
		t.Run(name, func(t *testing.T) {
			listed := false
			for _, line := range sources {
				if fields := strings.Fields(line); len(fields) > 1 && fields[0] == name {
					listed = true
				}
			}
			assert.True(t, listed, "Available sources must list %q with a description", name)
			assert.Contains(t, examples, "hdf fetch "+name+" ", "Examples must show %q", name)
		})
	}
}

func fetchLongSections(t *testing.T, long string) (sources []string, examples string) {
	t.Helper()
	_, afterSources, ok := strings.Cut(long, "Available sources:\n")
	require.True(t, ok, "Long must carry an Available sources block")
	sourceBlock, afterExamples, ok := strings.Cut(afterSources, "\nExamples:\n")
	require.True(t, ok, "Long must carry an Examples block after the sources")
	for _, line := range strings.Split(sourceBlock, "\n") {
		if strings.TrimSpace(line) != "" {
			sources = append(sources, line)
		}
	}
	return sources, afterExamples
}
