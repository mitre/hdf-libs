package cmd

import (
	"bytes"
	"crypto/sha512"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/mitre/hdf-libs/hdf-converters/v3/shared/go/exportmap"
	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	validators "github.com/mitre/hdf-libs/hdf-validators/go/v3"
	"github.com/stretchr/testify/require"
)

func TestConvertBundleFlagPreservesLiteralInput(t *testing.T) {
	source, err := os.ReadFile(bundleSourceFixture(t))
	require.NoError(t, err)
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "bundle"), source, 0o600))
	t.Chdir(dir)
	stdout, _, err := executeCommand("convert", "bundle", "--to", "csv")
	require.NoError(t, err, "bundle must remain usable as an ordinary input filename")
	require.Contains(t, stdout, "Requirement ID")
	_, _, err = executeCommand("convert", "bundle", "--to", "ecs", "--bundle", "-o", "export.zip")
	require.NoError(t, err)
	entries := zipEntries(t, "export.zip")
	require.Equal(t, source, entries["source.json"])
	require.Contains(t, entries, "evidence-package.json")
}

func TestConvertBundleRetainsEvidencePackage(t *testing.T) {
	for _, target := range []string{"ecs", "splunk", "ocsf"} {
		t.Run(target, func(t *testing.T) {
			output := filepath.Join(t.TempDir(), "export.zip")
			_, _, err := executeCommand("convert", "--bundle", bundleSourceFixture(t), "--to", target, "-o", output)
			require.NoError(t, err)
			entries := zipEntries(t, output)
			inventory, ok := entries["evidence-package.json"]
			require.True(t, ok, "archive must deliver its standard evidence-package inventory")
			validation := validators.ValidateEvidencePackage(inventory)
			require.True(t, validation.Valid, "%s", validation.Error())
			var pkg hdf.HDFEvidencePackage
			require.NoError(t, json.Unmarshal(inventory, &pkg))
			require.Equal(t, "HDF SIEM export ("+target+")", pkg.Name)
			require.Nil(t, pkg.PreparedAt)
			require.Nil(t, pkg.PackageID)
			require.Nil(t, pkg.SystemRef)
			require.Nil(t, pkg.CompletenessCheck)
			require.Len(t, pkg.Contents, 1)
			require.Equal(t, hdf.HdfResults, pkg.Contents[0].Type)
			require.Equal(t, "source.json", pkg.Contents[0].URI)
			require.Len(t, pkg.ExternalEvidence, 2)
			format := target
			if target == "splunk" {
				format = "x-splunk-export"
			}
			require.Equal(t, "events.ndjson", pkg.ExternalEvidence[0].URI)
			require.Equal(t, format, pkg.ExternalEvidence[0].Format)
			require.Equal(t, "manifest.json", pkg.ExternalEvidence[1].URI)
			require.Equal(t, "x-hdf-siem-export-profile", pkg.ExternalEvidence[1].Format)
			for name, checksum := range map[string]*hdf.Checksum{
				"source.json":   pkg.Contents[0].Checksum,
				"events.ndjson": pkg.ExternalEvidence[0].Checksum,
				"manifest.json": pkg.ExternalEvidence[1].Checksum,
			} {
				require.NotNil(t, checksum, name)
				require.Equal(t, hdf.Sha512, checksum.Algorithm)
				require.Equal(t, fmt.Sprintf("%x", sha512.Sum512(entries[name])), checksum.Value)
			}
			info, err := os.Stat(output)
			require.NoError(t, err)
			require.Equal(t, os.FileMode(0o600), info.Mode().Perm())
		})
	}
}

func TestConvertBundleRetainsSourceArtifact(t *testing.T) {
	input := bundleSourceFixture(t)
	source, err := os.ReadFile(input)
	require.NoError(t, err)
	for _, target := range []string{"ecs", "splunk", "ocsf"} {
		t.Run(target, func(t *testing.T) {
			directory := t.TempDir()
			output := filepath.Join(directory, "bundle.zip")
			_, _, err := executeCommand("convert", "--bundle", input, "--to", target, "-o", output)
			require.NoError(t, err)
			entries := zipEntries(t, output)
			require.Len(t, entries, 4)
			require.Equal(t, source, entries["source.json"])
			require.NotEmpty(t, entries["manifest.json"])
			events := bytes.Split(bytes.TrimSpace(entries["events.ndjson"]), []byte("\n"))
			require.Len(t, events, 1)
			resolved, err := exportmap.ResolveExportEvent(events[0], entries["manifest.json"], []exportmap.BundleArtifact{{Href: "source.json", Bytes: entries["source.json"]}})
			require.NoError(t, err)
			require.Equal(t, source, resolved.Source)
			second := filepath.Join(directory, "second.zip")
			_, _, err = executeCommand("convert", "--bundle", input, "--to", target, "-o", second)
			require.NoError(t, err)
			firstBytes, err := os.ReadFile(output)
			require.NoError(t, err)
			secondBytes, err := os.ReadFile(second)
			require.NoError(t, err)
			require.Equal(t, firstBytes, secondBytes)
		})
	}
}

func TestConvertBundlePreservesConcurrentOutput(t *testing.T) {
	dir := t.TempDir()
	input, output := filepath.Join(dir, "input.json"), filepath.Join(dir, "export.zip")
	require.NoError(t, os.WriteFile(input, []byte("input"), 0o600))
	require.NoError(t, refuseArchiveOverInput(output, dir, input, "source", nil, false))
	sentinel := []byte("concurrent owner data")
	err := writeArchiveAtomically(output, []bundleEntry{{path: "source.json", data: []byte("input")}}, func(file *os.File) archiveWriter {
		require.NoError(t, os.WriteFile(output, sentinel, 0o600))
		return newArchiveWriter(file)
	}, false)
	require.Error(t, err, "must refuse an output created during archive construction")
	actual, readErr := os.ReadFile(output)
	require.NoError(t, readErr)
	require.Equal(t, sentinel, actual)
	leftovers, globErr := filepath.Glob(filepath.Join(dir, ".hdf-bundle-*"))
	require.NoError(t, globErr)
	require.Empty(t, leftovers)
}

func TestConvertBundleProtectsInputsAndExistingOutput(t *testing.T) {
	source, err := os.ReadFile(bundleSourceFixture(t))
	require.NoError(t, err)
	for _, alias := range []string{"same", "symlink", "hardlink"} {
		t.Run(alias, func(t *testing.T) {
			dir := t.TempDir()
			input := filepath.Join(dir, "input.json")
			require.NoError(t, os.WriteFile(input, source, 0o600))
			output := input
			if alias != "same" {
				output = filepath.Join(dir, "alias.json")
				if alias == "symlink" {
					require.NoError(t, os.Symlink(input, output))
				} else {
					require.NoError(t, os.Link(input, output))
				}
			}
			_, _, err := executeCommand("convert", "--bundle", input, "--to", "ecs", "-o", output)
			require.ErrorContains(t, err, "over the source document")
			actual, err := os.ReadFile(input)
			require.NoError(t, err)
			require.Equal(t, source, actual)
		})
	}
	dir := t.TempDir()
	output := filepath.Join(dir, "existing.zip")
	previous := []byte("existing deliverable")
	require.NoError(t, os.WriteFile(output, previous, 0o600))
	input := bundleSourceFixture(t)
	_, _, err = executeCommand("convert", "--bundle", input, "--to", "ecs", "-o", output)
	require.Error(t, err)
	actual, err := os.ReadFile(output)
	require.NoError(t, err)
	require.Equal(t, previous, actual)
	_, _, err = executeCommand("convert", "--bundle", input, "--to", "ecs", "-o", output, "--overwrite")
	require.NoError(t, err)
	require.Equal(t, source, zipEntries(t, output)["source.json"])
}

func TestConvertBundleResolveRetainedSource(t *testing.T) {
	input := bundleSourceFixture(t)
	source, err := os.ReadFile(input)
	require.NoError(t, err)
	var document map[string]interface{}
	require.NoError(t, json.Unmarshal(source, &document))
	document["baselines"].([]interface{})[0].(map[string]interface{})["requirements"].([]interface{})[0].(map[string]interface{})["impact"] = json.RawMessage("-0")
	source, err = json.Marshal(document)
	require.NoError(t, err)
	require.Contains(t, string(source), `"impact":-0`)
	validation := validators.ValidateResults(source)
	require.True(t, validation.Valid, "%s", validation.Error())
	input = filepath.Join(t.TempDir(), "negative-zero.json")
	require.NoError(t, os.WriteFile(input, source, 0o600))
	for _, target := range []string{"ecs", "splunk", "ocsf"} {
		t.Run(target, func(t *testing.T) {
			dir := t.TempDir()
			archive := filepath.Join(dir, "bundle.zip")
			_, _, err := executeCommand("convert", "--bundle", input, "--to", target, "-o", archive)
			require.NoError(t, err)
			entries := zipEntries(t, archive)
			for name, data := range entries {
				require.NoError(t, os.WriteFile(filepath.Join(dir, name), data, 0o600))
			}
			event := bytes.Split(bytes.TrimSpace(entries["events.ndjson"]), []byte("\n"))[0]
			eventFile := filepath.Join(dir, "event.json")
			require.NoError(t, os.WriteFile(eventFile, event, 0o600))
			stdout, _, err := executeCommand("evidence", "resolve", filepath.Join(dir, "evidence-package.json"), "--event", eventFile)
			require.NoError(t, err)
			require.Equal(t, source, []byte(stdout))
			// A literal percent in a local filename must be decoded exactly once.
			var manifest map[string]interface{}
			require.NoError(t, json.Unmarshal(entries["manifest.json"], &manifest))
			manifest["artifacts"].([]interface{})[0].(map[string]interface{})["href"] = "source%25file.json"
			encoded, err := json.Marshal(manifest)
			require.NoError(t, err)
			updateSIEMManifest(t, dir, encoded)
			var pkg hdf.HDFEvidencePackage
			packageBytes, err := os.ReadFile(filepath.Join(dir, "evidence-package.json"))
			require.NoError(t, err)
			require.NoError(t, json.Unmarshal(packageBytes, &pkg))
			pkg.Contents[0].URI = "source%25file.json"
			writeSIEMInventory(t, dir, pkg)
			require.NoError(t, os.Rename(filepath.Join(dir, "source.json"), filepath.Join(dir, "source%file.json")))
			stdout, _, err = executeCommand("evidence", "resolve", filepath.Join(dir, "evidence-package.json"), "--event", eventFile)
			require.NoError(t, err)
			require.Equal(t, source, []byte(stdout))
		})
	}
}

func TestConvertBundleRejectsUnsafeArtifactReferences(t *testing.T) {
	for _, href := range []string{"../outside.json", "%2e%2e/outside.json", "/absolute.json", "//server/file", "C:source.json", "C%3Asource.json", `folder\source.json`, "folder%5csource.json", "bad%00name", "https://example.invalid/source.json", "file:///source.json", "source.json?query=1", "source.json#part", ""} {
		t.Run(href, func(t *testing.T) {
			_, err := siemArtifactPath(href)
			require.ErrorContains(t, err, "relative artifact")
		})
	}
}

func TestConvertBundleResolveRejectsTampering(t *testing.T) {
	input := bundleSourceFixture(t)
	dir := t.TempDir()
	archive := filepath.Join(dir, "bundle.zip")
	_, _, err := executeCommand("convert", "--bundle", input, "--to", "ecs", "-o", archive)
	require.NoError(t, err)
	entries := zipEntries(t, archive)
	for name, data := range entries {
		require.NoError(t, os.WriteFile(filepath.Join(dir, name), data, 0o600))
	}
	event := bytes.Split(bytes.TrimSpace(entries["events.ndjson"]), []byte("\n"))[0]
	eventFile := filepath.Join(dir, "event.json")
	require.NoError(t, os.WriteFile(eventFile, event, 0o600))
	for _, corruption := range []string{"source", "record", "missing"} {
		t.Run(corruption, func(t *testing.T) {
			require.NoError(t, os.WriteFile(filepath.Join(dir, "source.json"), entries["source.json"], 0o600))
			require.NoError(t, os.WriteFile(eventFile, event, 0o600))
			switch corruption {
			case "source":
				require.NoError(t, os.WriteFile(filepath.Join(dir, "source.json"), append(bytes.Clone(entries["source.json"]), ' '), 0o600))
			case "record":
				var changed map[string]interface{}
				require.NoError(t, json.Unmarshal(event, &changed))
				changed["hdf"].(map[string]interface{})["source"].(map[string]interface{})["requirement"] = map[string]interface{}{"id": "tampered"}
				encoded, err := json.Marshal(changed)
				require.NoError(t, err)
				require.NoError(t, os.WriteFile(eventFile, encoded, 0o600))
			case "missing":
				require.NoError(t, os.Remove(filepath.Join(dir, "source.json")))
			}
			stdout, _, err := executeCommand("evidence", "resolve", filepath.Join(dir, "evidence-package.json"), "--event", eventFile)
			require.Error(t, err)
			require.Empty(t, strings.TrimSpace(stdout))
		})
	}
}

func TestConvertBundleInvalidRequestsPreserveOutput(t *testing.T) {
	dir := t.TempDir()
	input := bundleSourceFixture(t)
	output := filepath.Join(dir, "existing.zip")
	previous := []byte("previous complete archive")
	require.NoError(t, os.WriteFile(output, previous, 0o600))
	invalid := filepath.Join(dir, "invalid.json")
	require.NoError(t, os.WriteFile(invalid, []byte("invalid JSON"), 0o600))
	for _, args := range [][]string{
		{input, "-o", output, "--overwrite"},
		{input, "--to", "asff", "-o", output, "--overwrite"},
		{input, "--to", "ecs"},
		{input, input, "--to", "ecs", "-o", output, "--overwrite"},
		{filepath.Join(dir, "missing.json"), "--to", "ecs", "-o", output, "--overwrite"},
		{invalid, "--to", "ecs", "-o", output, "--overwrite"},
		{input, "--to", "ecs", "-o", dir},
		{input, "--to", "ecs", "-o", filepath.Join(dir, "missing", "new.zip")},
		{input, "--to", "ecs", "-o", input, "--overwrite"},
	} {
		_, _, err := executeCommand(append([]string{"convert", "--bundle"}, args...)...)
		require.Error(t, err, "arguments %v", args)
		actual, err := os.ReadFile(output)
		require.NoError(t, err)
		require.Equal(t, previous, actual)
	}
}

func TestConvertBundleRejectsIncompatibleFlags(t *testing.T) {
	input := bundleSourceFixture(t)
	for _, flags := range [][]string{{"--force"}, {"--labels", "test=true"}, {"--from", "hdf"}, {"--nist-rev", "4"}} {
		output := filepath.Join(t.TempDir(), "bundle.zip")
		args := append([]string{"convert", "--bundle", input, "--to", "ecs", "-o", output}, flags...)
		_, _, err := executeCommand(args...)
		require.ErrorContains(t, err, flags[0]+" is not supported with --bundle")
		require.NoFileExists(t, output)
	}
}

func TestConvertBundleHonorsInputPolicy(t *testing.T) {
	oldMax, oldFollow := maxSizeMB, noFollowSymlinks
	t.Cleanup(func() { maxSizeMB, noFollowSymlinks = oldMax, oldFollow })
	for _, policy := range []string{"symlink", "size"} {
		t.Run(policy, func(t *testing.T) {
			input := bundleSourceFixture(t)
			path := filepath.Join(t.TempDir(), "input.json")
			flags, want := []string{"--no-follow-symlinks"}, "refusing to follow symlink"
			if policy == "symlink" {
				require.NoError(t, os.Symlink(input, path))
			} else {
				data, err := os.ReadFile(input)
				require.NoError(t, err)
				require.NoError(t, os.WriteFile(path, append(data, bytes.Repeat([]byte(" "), 1024*1024)...), 0o600))
				flags, want = []string{"--max-size", "1"}, "file too large"
			}
			flags = append(flags, "convert", "--bundle", path, "--to", "ecs", "-o", filepath.Join(t.TempDir(), "export.zip"))
			stdout, _, err := executeCommand(flags...)
			require.ErrorContains(t, err, want)
			require.Empty(t, stdout)
		})
	}
}

func TestConvertBundlePreservesExtendedSource(t *testing.T) {
	source, err := os.ReadFile(bundleSourceFixture(t))
	require.NoError(t, err)
	var document map[string]interface{}
	require.NoError(t, json.Unmarshal(source, &document))
	baseline := document["baselines"].([]interface{})[0].(map[string]interface{})
	requirement := baseline["requirements"].([]interface{})[0].(map[string]interface{})
	for _, object := range []map[string]interface{}{document, baseline} {
		extensions, ok := object["extensions"].(map[string]interface{})
		if !ok {
			extensions = map[string]interface{}{}
			object["extensions"] = extensions
		}
		passthrough, ok := extensions["passthrough"].(map[string]interface{})
		if !ok {
			passthrough = map[string]interface{}{}
			extensions["passthrough"] = passthrough
		}
		passthrough["futureOptional"] = map[string]interface{}{"text": "café 東京 🚀", "nullable": nil}
	}
	requirement["tags"].(map[string]interface{})["futureOptional"] = map[string]interface{}{"text": "café 東京 🚀", "nullable": nil, "large": json.Number("9007199254740993")}
	requirement["impact"] = json.Number("-0")
	source, err = json.MarshalIndent(document, "", "  ")
	require.NoError(t, err)
	source = append(source, '\n')
	validation := validators.ValidateResults(source)
	require.True(t, validation.Valid, "adaptation must be schema-valid: %s", validation.Error())
	for _, target := range []string{"ecs", "splunk", "ocsf"} {
		t.Run(target, func(t *testing.T) {
			dir := t.TempDir()
			input, archive := filepath.Join(dir, "input.json"), filepath.Join(dir, "export.zip")
			require.NoError(t, os.WriteFile(input, source, 0o600))
			_, _, err := executeCommand("convert", input, "--to", target, "--bundle", "-o", archive)
			require.NoError(t, err)
			entries := zipEntries(t, archive)
			require.Equal(t, source, entries["source.json"])
			retained := filepath.Join(t.TempDir(), target+"-nested")
			require.NoError(t, os.Mkdir(retained, 0o700))
			for name, data := range entries {
				require.NoError(t, os.WriteFile(filepath.Join(retained, name), data, 0o600))
			}
			event := bytes.Split(entries["events.ndjson"], []byte("\n"))[0]
			require.NoError(t, os.WriteFile(filepath.Join(retained, "event.json"), event, 0o600))
			stdout, _, err := executeCommand("evidence", "resolve", filepath.Join(retained, "evidence-package.json"), "--event", filepath.Join(retained, "event.json"))
			require.NoError(t, err)
			require.Equal(t, source, []byte(stdout))
		})
	}
}

func TestConvertBundleEmptyAssessmentRetainsArtifact(t *testing.T) {
	source, err := os.ReadFile(bundleSourceFixture(t))
	require.NoError(t, err)
	var document map[string]interface{}
	require.NoError(t, json.Unmarshal(source, &document))
	document["baselines"] = []interface{}{}
	source, err = json.Marshal(document)
	require.NoError(t, err)
	validation := validators.ValidateResults(source)
	require.True(t, validation.Valid, "empty assessment must remain schema-confirmed: %s", validation.Error())
	dir := t.TempDir()
	input := filepath.Join(dir, "empty.json")
	require.NoError(t, os.WriteFile(input, source, 0o600))
	for _, target := range []string{"ecs", "splunk", "ocsf"} {
		output := filepath.Join(dir, target+".zip")
		_, _, err := executeCommand("convert", "--bundle", input, "--to", target, "-o", output)
		require.NoError(t, err)
		entries := zipEntries(t, output)
		require.Len(t, entries, 4)
		require.Empty(t, entries["events.ndjson"])
		require.Equal(t, source, entries["source.json"])
		require.NotEmpty(t, entries["manifest.json"])
	}
}

func TestConvertBundleResolveRejectsUnreadableInputs(t *testing.T) {
	dir, _ := retainedSIEMPackage(t, "ecs")
	_, _, err := executeCommand("evidence", "resolve", filepath.Join(dir, "missing.json"), "--event", filepath.Join(dir, "event.json"))
	require.ErrorContains(t, err, "file not found")
	_, _, err = executeCommand("evidence", "resolve", filepath.Join(dir, "evidence-package.json"), "--event", filepath.Join(dir, "missing.json"))
	require.ErrorContains(t, err, "file not found")
	for _, data := range []string{"invalid JSON", `{"artifacts":"wrong type"}`} {
		updateSIEMManifest(t, dir, []byte(data))
		stdout, _, err := executeCommand("evidence", "resolve", filepath.Join(dir, "evidence-package.json"), "--event", filepath.Join(dir, "event.json"))
		require.ErrorContains(t, err, "decode SIEM profile")
		require.Empty(t, stdout)
	}
}

func bundleSourceFixture(t *testing.T) string {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	require.True(t, ok)
	path := filepath.Join(filepath.Dir(filename), "testdata", "evidence-verify", "postgres-results.json")
	source, err := os.ReadFile(path)
	require.NoError(t, err)
	validation := validators.ValidateResults(source)
	require.True(t, validation.Valid, "%s", validation.Error())
	return path
}
