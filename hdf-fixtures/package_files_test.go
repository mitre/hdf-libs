package fixtures

import (
	"encoding/json"
	"os"
	"regexp"
	"slices"
	"testing"
)

// The npm tarball ships only the directories in package.json `files`, so a
// category the TS index or the Go embeds reference must be listed there.
func TestEveryFixtureDirectoryIsInTheNpmTarball(t *testing.T) {
	raw, err := os.ReadFile("package.json")
	if err != nil {
		t.Fatal(err)
	}
	var pkg struct {
		Files []string `json:"files"`
	}
	if err := json.Unmarshal(raw, &pkg); err != nil {
		t.Fatal(err)
	}

	sources := map[string]*regexp.Regexp{
		"fixtures.go":  regexp.MustCompile(`(?m)^//go:embed ([^/\s]+)/`),
		"src/index.ts": regexp.MustCompile(`fixture\('([^']+)',`),
	}
	for file, re := range sources {
		src, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		matches := re.FindAllSubmatch(src, -1)
		if len(matches) == 0 {
			t.Fatalf("%s: no fixture references found; the pattern is stale", file)
		}
		for _, m := range matches {
			dir := string(m[1])
			if !slices.Contains(pkg.Files, dir) {
				t.Errorf("%s references %s/, which package.json files %v leaves out of the tarball",
					file, dir, pkg.Files)
			}
		}
	}
}
