package cmd

import (
	"bytes"
	"crypto/sha512"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	"github.com/stretchr/testify/require"
)

func TestEvidenceResolveRetainedSource(t *testing.T) {
	for _, target := range []string{"ecs", "splunk", "ocsf"} {
		t.Run(target, func(t *testing.T) {
			dir, entries := retainedSIEMPackage(t, target)
			stdout, _, err := executeCommand("evidence", "resolve", filepath.Join(dir, "evidence-package.json"),
				"--event", filepath.Join(dir, "event.json"))
			require.NoError(t, err)
			require.Equal(t, entries["source.json"], []byte(stdout))
		})
	}
}

func TestEvidenceResolveRejectsUnverifiedArtifacts(t *testing.T) {
	for _, name := range []string{"source.json", "events.ndjson", "manifest.json"} {
		for _, corruption := range []string{"modified", "missing", "symlink"} {
			t.Run(name+"/"+corruption, func(t *testing.T) {
				dir, entries := retainedSIEMPackage(t, "ecs")
				path := filepath.Join(dir, name)
				want := "mismatch"
				switch corruption {
				case "modified":
					require.NoError(t, os.WriteFile(path, append(bytes.Clone(entries[name]), ' '), 0o600))
				case "missing":
					require.NoError(t, os.Remove(path))
					want = "read contained artifact"
				case "symlink":
					outside := filepath.Join(t.TempDir(), name)
					require.NoError(t, os.WriteFile(outside, entries[name], 0o600))
					require.NoError(t, os.Remove(path))
					require.NoError(t, os.Symlink(outside, path))
					want = "read contained artifact"
				}
				stdout, _, err := executeCommand("evidence", "resolve", filepath.Join(dir, "evidence-package.json"), "--event", filepath.Join(dir, "event.json"))
				require.ErrorContains(t, err, want)
				require.Empty(t, stdout)
			})
		}
	}
}

func TestEvidenceResolveRejectsInvalidInventory(t *testing.T) {
	cases := []struct {
		name   string
		change func(*hdf.HDFEvidencePackage)
		want   string
	}{
		{"source checksum missing", func(p *hdf.HDFEvidencePackage) { p.Contents[0].Checksum = nil }, "checksums disagree"},
		{"event checksum missing", func(p *hdf.HDFEvidencePackage) { p.ExternalEvidence[0].Checksum = nil }, "explicit SHA512"},
		{"manifest checksum missing", func(p *hdf.HDFEvidencePackage) { p.ExternalEvidence[1].Checksum = nil }, "explicit SHA512"},
		{"source type", func(p *hdf.HDFEvidencePackage) { p.Contents[0].Type = hdf.HdfBaseline }, "wrong type or format"},
		{"event format", func(p *hdf.HDFEvidencePackage) { p.ExternalEvidence[0].Format = "raw-log" }, "wrong type or format"},
		{"profile format", func(p *hdf.HDFEvidencePackage) { p.ExternalEvidence[1].Format = "raw-log" }, "missing or ambiguous SIEM profile"},
		{"duplicate source", func(p *hdf.HDFEvidencePackage) { p.Contents = append(p.Contents, p.Contents[0]) }, "ambiguous package artifact"},
		{"duplicate event", func(p *hdf.HDFEvidencePackage) {
			p.ExternalEvidence = append(p.ExternalEvidence, p.ExternalEvidence[0])
		}, "ambiguous package artifact"},
		{"duplicate profile", func(p *hdf.HDFEvidencePackage) {
			p.ExternalEvidence = append(p.ExternalEvidence, p.ExternalEvidence[1])
		}, "ambiguous SIEM profile"},
		{"encoded source alias", func(p *hdf.HDFEvidencePackage) {
			ref := p.Contents[0]
			ref.URI = "%73ource.json"
			p.Contents = append(p.Contents, ref)
		}, "ambiguous package artifact"},
		{"unsupported checksum", func(p *hdf.HDFEvidencePackage) { p.ExternalEvidence[0].Checksum.Algorithm = hdf.Sha256 }, "explicit SHA512"},
		{"unsafe profile", func(p *hdf.HDFEvidencePackage) { p.ExternalEvidence[1].URI = "../manifest.json" }, "relative artifact path"},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			dir, entries := retainedSIEMPackage(t, "ecs")
			var pkg hdf.HDFEvidencePackage
			require.NoError(t, json.Unmarshal(entries["evidence-package.json"], &pkg))
			tt.change(&pkg)
			writeSIEMInventory(t, dir, pkg)
			stdout, _, err := executeCommand("evidence", "resolve", filepath.Join(dir, "evidence-package.json"), "--event", filepath.Join(dir, "event.json"))
			require.ErrorContains(t, err, tt.want)
			require.Empty(t, stdout)
		})
	}
}

func TestEvidenceResolveDetectsRecordMismatch(t *testing.T) {
	dir, _ := retainedSIEMPackage(t, "ecs")
	path := filepath.Join(dir, "event.json")
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	var event map[string]interface{}
	require.NoError(t, json.Unmarshal(data, &event))
	event["hdf"].(map[string]interface{})["source"].(map[string]interface{})["requirement"] = map[string]interface{}{"id": "altered"}
	data, err = json.Marshal(event)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, data, 0o600))
	stdout, _, err := executeCommand("evidence", "resolve", filepath.Join(dir, "evidence-package.json"), "--event", path)
	require.ErrorContains(t, err, "record mismatch")
	require.Empty(t, stdout)
}

func TestEvidenceResolveUsesExactManifestKeys(t *testing.T) {
	for _, format := range []string{"ecs", "x-splunk-export"} {
		t.Run(format, func(t *testing.T) {
			dir, entries := retainedSIEMPackage(t, "ecs")
			manifest := bytes.TrimSpace(entries["manifest.json"])
			manifest = append(bytes.Clone(manifest[:len(manifest)-1]), []byte(`,"Target":"splunk"}`)...)
			updateSIEMManifest(t, dir, manifest)
			data, err := os.ReadFile(filepath.Join(dir, "evidence-package.json"))
			require.NoError(t, err)
			var pkg hdf.HDFEvidencePackage
			require.NoError(t, json.Unmarshal(data, &pkg))
			pkg.ExternalEvidence[0].Format = format
			writeSIEMInventory(t, dir, pkg)
			stdout, _, err := executeCommand("evidence", "resolve", filepath.Join(dir, "evidence-package.json"), "--event", filepath.Join(dir, "event.json"))
			if format == "ecs" {
				require.NoError(t, err)
				require.Equal(t, entries["source.json"], []byte(stdout))
			} else {
				require.ErrorContains(t, err, "wrong type or format")
				require.Empty(t, stdout)
			}
		})
	}
}

func TestEvidenceResolveRejectsInvalidManifest(t *testing.T) {
	for _, test := range []struct{ field, value, want string }{
		{"target", "other", "unsupported SIEM target"},
		{"events", "../events.ndjson", "invalid SIEM profile inventory"},
		{"profileVersion", "2.0", "unsupported source profile"},
		{"outputProfile", "compact/1", "unsupported source profile"},
	} {
		t.Run(test.field, func(t *testing.T) {
			dir, entries := retainedSIEMPackage(t, "ecs")
			var manifest map[string]interface{}
			require.NoError(t, json.Unmarshal(entries["manifest.json"], &manifest))
			manifest[test.field] = test.value
			data, err := json.Marshal(manifest)
			require.NoError(t, err)
			updateSIEMManifest(t, dir, data)
			stdout, _, err := executeCommand("evidence", "resolve", filepath.Join(dir, "evidence-package.json"), "--event", filepath.Join(dir, "event.json"))
			require.ErrorContains(t, err, test.want)
			require.Empty(t, stdout)
		})
	}
}

func TestEvidenceResolveRejectsBrokenSourceLinks(t *testing.T) {
	for _, test := range []struct{ name, want string }{
		{"missing href", "missing source artifact location"},
		{"escaping href", "relative artifact path"},
		{"missing checksum", "checksums disagree"},
		{"missing source entry", "missing or ambiguous package artifact"},
		{"no artifacts", "invalid SIEM profile inventory"},
	} {
		t.Run(test.name, func(t *testing.T) {
			dir, entries := retainedSIEMPackage(t, "ecs")
			var manifest map[string]interface{}
			require.NoError(t, json.Unmarshal(entries["manifest.json"], &manifest))
			artifact := manifest["artifacts"].([]interface{})[0].(map[string]interface{})
			switch test.name {
			case "missing href":
				delete(artifact, "href")
			case "escaping href":
				artifact["href"] = "../source.json"
			case "missing checksum":
				delete(artifact, "checksum")
			case "missing source entry":
				artifact["href"] = "unlisted.json"
			case "no artifacts":
				manifest["artifacts"] = []interface{}{}
			}
			data, err := json.Marshal(manifest)
			require.NoError(t, err)
			updateSIEMManifest(t, dir, data)
			stdout, _, err := executeCommand("evidence", "resolve", filepath.Join(dir, "evidence-package.json"), "--event", filepath.Join(dir, "event.json"))
			require.ErrorContains(t, err, test.want)
			require.Empty(t, stdout)
		})
	}
}

func TestEvidenceResolveRejectsInvalidRequests(t *testing.T) {
	dir, _ := retainedSIEMPackage(t, "ecs")
	for _, args := range [][]string{
		{filepath.Join(dir, "evidence-package.json")},
		{filepath.Join(dir, "evidence-package.json"), "--event", filepath.Join(dir, "event.json"), "--manifest", "../manifest.json"},
		{filepath.Join(dir, "event.json"), "--event", filepath.Join(dir, "event.json")},
	} {
		stdout, _, err := executeCommand(append([]string{"evidence", "resolve"}, args...)...)
		require.Error(t, err)
		require.Empty(t, stdout)
	}
}

func TestEvidenceResolveNestedSelection(t *testing.T) {
	dir := t.TempDir()
	pkg := hdf.HDFEvidencePackage{Name: "Multiple exports"}
	var expected []byte
	for _, target := range []string{"ecs", "splunk"} {
		_, entries := retainedSIEMPackage(t, target)
		subdir := filepath.Join(dir, target+"%data")
		require.NoError(t, os.Mkdir(subdir, 0o700))
		for name, data := range entries {
			require.NoError(t, os.WriteFile(filepath.Join(subdir, name), data, 0o600))
		}
		var nested hdf.HDFEvidencePackage
		require.NoError(t, json.Unmarshal(entries["evidence-package.json"], &nested))
		for _, entry := range nested.Contents {
			entry.URI = target + "%25data/" + entry.URI
			pkg.Contents = append(pkg.Contents, entry)
		}
		for _, entry := range nested.ExternalEvidence {
			entry.URI = target + "%25data/" + entry.URI
			pkg.ExternalEvidence = append(pkg.ExternalEvidence, entry)
		}
		if target == "ecs" {
			expected = entries["source.json"]
			require.NoError(t, os.WriteFile(filepath.Join(dir, "event.json"), bytes.Split(entries["events.ndjson"], []byte("\n"))[0], 0o600))
		}
	}
	// Unrelated external evidence is outside the selected-export verification scope.
	pkg.ExternalEvidence = append(pkg.ExternalEvidence, hdf.ExternalEvidenceReference{URI: "https://example.invalid/unrelated", Format: "raw-log"})
	writeSIEMInventory(t, dir, pkg)
	args := []string{"evidence", "resolve", filepath.Join(dir, "evidence-package.json"), "--event", filepath.Join(dir, "event.json")}
	stdout, _, err := executeCommand(args...)
	require.ErrorContains(t, err, "ambiguous SIEM profile")
	require.Empty(t, stdout)
	stdout, _, err = executeCommand(append(args, "--manifest", "ecs%25data/manifest.json")...)
	require.NoError(t, err)
	require.Equal(t, expected, []byte(stdout))
	stdout, _, err = executeCommand(append(args, "--manifest", "missing.json")...)
	require.ErrorContains(t, err, "missing or ambiguous SIEM profile")
	require.Empty(t, stdout)
}

func TestEvidenceResolveHonorsInputPolicy(t *testing.T) {
	oldMax, oldFollow := maxSizeMB, noFollowSymlinks
	t.Cleanup(func() { maxSizeMB, noFollowSymlinks = oldMax, oldFollow })
	for _, name := range []string{"evidence-package.json", "source.json", "events.ndjson", "manifest.json", "event.json"} {
		for _, policy := range []string{"size", "symlink"} {
			t.Run(name+"/"+policy, func(t *testing.T) {
				dir, _ := retainedSIEMPackage(t, "ecs")
				path := filepath.Join(dir, name)
				data, err := os.ReadFile(path)
				require.NoError(t, err)
				flags, want := []string{"--max-size", "1"}, "file too large"
				if policy == "size" {
					require.NoError(t, os.WriteFile(path, append(data, bytes.Repeat([]byte(" "), 1024*1024)...), 0o600))
				} else {
					require.NoError(t, os.Rename(path, path+".real"))
					require.NoError(t, os.Symlink(path+".real", path))
					flags, want = []string{"--no-follow-symlinks"}, "refusing to follow symlink"
				}
				flags = append(flags, "evidence", "resolve", filepath.Join(dir, "evidence-package.json"), "--event", filepath.Join(dir, "event.json"))
				stdout, _, err := executeCommand(flags...)
				require.ErrorContains(t, err, want)
				require.Empty(t, stdout)
			})
		}
	}
}

func writeSIEMInventory(t *testing.T, dir string, pkg hdf.HDFEvidencePackage) {
	t.Helper()
	data, err := json.Marshal(pkg)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "evidence-package.json"), data, 0o600))
}

func updateSIEMManifest(t *testing.T, dir string, data []byte) {
	t.Helper()
	path := filepath.Join(dir, "evidence-package.json")
	inventory, err := os.ReadFile(path)
	require.NoError(t, err)
	var pkg hdf.HDFEvidencePackage
	require.NoError(t, json.Unmarshal(inventory, &pkg))
	pkg.ExternalEvidence[1].Checksum.Value = fmt.Sprintf("%x", sha512.Sum512(data))
	writeSIEMInventory(t, dir, pkg)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "manifest.json"), data, 0o600))
}

func retainedSIEMPackage(t *testing.T, target string) (string, map[string][]byte) {
	t.Helper()
	archive := filepath.Join(t.TempDir(), "export.zip")
	_, _, err := executeCommand("convert", "--bundle", bundleSourceFixture(t), "--to", target, "-o", archive)
	require.NoError(t, err)
	entries := zipEntries(t, archive)
	dir := t.TempDir()
	for name, data := range entries {
		require.NoError(t, os.WriteFile(filepath.Join(dir, name), data, 0o600))
	}
	require.NoError(t, os.WriteFile(filepath.Join(dir, "event.json"), bytes.Split(entries["events.ndjson"], []byte("\n"))[0], 0o600))
	return dir, entries
}
