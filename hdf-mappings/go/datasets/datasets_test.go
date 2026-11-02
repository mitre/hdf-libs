package datasets_test

import (
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/mitre/hdf-libs/hdf-mappings/go/v3/datasets"
)

// The package is the one home for every mapping dataset, so the set of files it
// carries is part of its contract. Walking the DIRECTORY rather than the embed
// is deliberate: a file the embed patterns miss — a .JSON suffix, a .json5, a
// nested subdirectory — would be invisible to Go yet importable by TypeScript,
// which is exactly the cross-language divergence this layout exists to prevent.
var wantFiles = map[string][]string{
	"catalogs": {
		"nist-descriptions-rev5.json",
		"nist-descriptions.json",
	},
	"mappings": {
		"awsconfig-mappings.json",
		"cci-mappings.json",
		"checkov-cci-nist-mappings.json",
		"cwe-nist-mappings.json",
		"hadolint-nist-mappings.json",
		"hipcheck-nist-mappings.json",
		"nessus-nist-mappings.json",
		"nikto-nist-mappings.json",
		"nist-cci-mappings.json",
		"nist-revision-crosswalk.json",
		"owasp-nist-mappings.json",
		"scoutsuite-nist-mappings.json",
	},
}

// Every exported dataset var, so a var added without a test entry — or dropped
// while a consumer still names it — fails here.
func declaredVars() map[string][]byte {
	return map[string][]byte{
		"catalogs/nist-descriptions.json":         datasets.NISTDescriptionsRev4,
		"catalogs/nist-descriptions-rev5.json":    datasets.NISTDescriptionsRev5,
		"mappings/nist-revision-crosswalk.json":   datasets.NISTRevisionCrosswalk,
		"mappings/cci-mappings.json":              datasets.CCIMappings,
		"mappings/nist-cci-mappings.json":         datasets.NISTCCIMappings,
		"mappings/cwe-nist-mappings.json":         datasets.CWENIST,
		"mappings/owasp-nist-mappings.json":       datasets.OWASPNIST,
		"mappings/awsconfig-mappings.json":        datasets.AWSConfigMappings,
		"mappings/checkov-cci-nist-mappings.json": datasets.CheckovCCINIST,
		"mappings/hadolint-nist-mappings.json":    datasets.HadolintNIST,
		"mappings/hipcheck-nist-mappings.json":    datasets.HipcheckNIST,
		"mappings/nessus-nist-mappings.json":      datasets.NessusNIST,
		"mappings/nikto-nist-mappings.json":       datasets.NiktoNIST,
		"mappings/scoutsuite-nist-mappings.json":  datasets.ScoutSuiteNIST,
	}
}

// A dataset in a third directory would escape both the embed patterns and the
// per-directory checks below, while TypeScript could still import it.
func TestPackageHoldsOnlyTheDeclaredDirectories(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("reading the package directory: %v", err)
	}
	var dirs, files []string
	for _, e := range entries {
		if e.IsDir() {
			// testdata is the Go tooling's own convention and is excluded from
			// the embed patterns; it holds the dead-strip probe, not a dataset.
			// It is still checked for datasets, which TypeScript could import.
			if e.Name() == "testdata" {
				assertNoDatasetsUnder(t, e.Name())
				continue
			}
			dirs = append(dirs, e.Name())
			continue
		}
		files = append(files, e.Name())
	}
	var want []string
	for dir := range wantFiles {
		want = append(want, dir)
	}
	sort.Strings(dirs)
	sort.Strings(want)
	if len(dirs) != len(want) {
		t.Fatalf("package holds directories %v, want %v", dirs, want)
	}
	for i := range dirs {
		if dirs[i] != want[i] {
			t.Errorf("package holds directory %q, want %q", dirs[i], want[i])
		}
	}
	for _, f := range files {
		if filepath.Ext(f) != ".go" {
			t.Errorf("package holds a loose file %q; every dataset belongs in one of %v", f, want)
		}
	}
}

func TestDirectoriesHoldExactlyTheDeclaredDatasets(t *testing.T) {
	for dir, want := range wantFiles {
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatalf("reading %s: %v", dir, err)
		}
		var got []string
		for _, e := range entries {
			if e.IsDir() {
				t.Errorf("%s holds a subdirectory %q; the embed patterns do not descend, so Go would not see its contents while TypeScript could import them", dir, e.Name())
				continue
			}
			got = append(got, e.Name())
		}
		sort.Strings(got)
		if len(got) != len(want) {
			t.Errorf("%s holds %d files, want %d\ngot:  %v\nwant: %v", dir, len(got), len(want), got, want)
			continue
		}
		for i := range got {
			if got[i] != want[i] {
				t.Errorf("%s file %d: got %q, want %q", dir, i, got[i], want[i])
			}
		}
	}
}

func TestEveryDeclaredFileHasAVarAndViceVersa(t *testing.T) {
	vars := declaredVars()
	for dir, files := range wantFiles {
		for _, f := range files {
			name := filepath.ToSlash(filepath.Join(dir, f))
			if _, ok := vars[name]; !ok {
				t.Errorf("%s is on disk but no exported var embeds it", name)
			}
		}
	}
	if len(vars) != len(wantFiles["catalogs"])+len(wantFiles["mappings"]) {
		t.Errorf("declared %d vars but %d files are expected on disk", len(vars), len(wantFiles["catalogs"])+len(wantFiles["mappings"]))
	}
}

func TestEveryDatasetIsNonEmptyAndParses(t *testing.T) {
	for name, raw := range declaredVars() {
		if len(raw) == 0 {
			t.Errorf("%s: embedded as zero bytes", name)
			continue
		}
		var doc json.RawMessage
		if err := json.Unmarshal(raw, &doc); err != nil {
			t.Errorf("%s: not JSON: %v", name, err)
		}
	}
}

// The vars must be the embedded image, not a copy, so a consumer naming one
// dataset does not pay for the rest. Comparing against the file on disk also
// catches an //go:embed directive pointing at the wrong file.
func TestEachVarMatchesItsFileOnDisk(t *testing.T) {
	for name, raw := range declaredVars() {
		onDisk, err := os.ReadFile(name)
		if err != nil {
			t.Errorf("%s: unreadable on disk: %v", name, err)
			continue
		}
		if string(raw) != string(onDisk) {
			t.Errorf("%s: embedded bytes (%d) differ from the file on disk (%d)", name, len(raw), len(onDisk))
		}
	}
}

// A dataset parked under testdata would escape the embed patterns and the
// per-directory checks, while TypeScript could still import it by path.
func assertNoDatasetsUnder(t *testing.T, dir string) {
	t.Helper()
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && filepath.Ext(path) == ".json" {
			t.Errorf("%s holds %q; a dataset belongs in catalogs/ or mappings/", dir, path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking %s: %v", dir, err)
	}
}
