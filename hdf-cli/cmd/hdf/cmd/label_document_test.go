package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	testhdf "github.com/mitre/hdf-libs/hdf-schema/testhdf/go/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func labelDocumentCases() map[string]any {
	return map[string]any{
		"evidence-package": testhdf.EvidencePackage("Assessment", testhdf.Content("results.json", hdf.HdfResults)),
		"system":           testhdf.System("Portal", testhdf.Component("web", hdf.Host)),
		"plan":             testhdf.Plan("Quarterly", testhdf.Assessment("RHEL9")),
		"amendments":       testhdf.Amendments("Deviations", testhdf.Override(hdf.OverrideTypeWaiver, "SV-257777")),
		"baseline":         testhdf.BaselineDoc("RHEL9", testhdf.BaselineReq("SV-257777")),
	}
}

func writeLabelDocument(t *testing.T, document any) string {
	t.Helper()
	data, err := json.Marshal(document)
	require.NoError(t, err)
	require.NoError(t, validateHDFDocument(data), "the constructed input must be schema-confirmed")
	path := filepath.Join(t.TempDir(), "input.json")
	require.NoError(t, os.WriteFile(path, data, 0o600))
	return path
}

func readLabelDocument(t *testing.T, path string) map[string]json.RawMessage {
	t.Helper()
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	require.NoError(t, validateHDFDocument(data))
	var doc map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(data, &doc))
	return doc
}

func TestLabelDocumentLifecycle(t *testing.T) {
	for name, document := range labelDocumentCases() {
		t.Run(name, func(t *testing.T) {
			path := writeLabelDocument(t, document)
			before := readLabelDocument(t, path)
			_, _, err := executeCommand("label", "set", path, "--scope", "document", "pipeline=nightly", "team=security", "--external-id", "ci-run= project/run=4821 ", "--external-id", "grc=record-42")
			require.NoError(t, err)
			_, _, err = executeCommand("label", "set", path, "--scope", "document", "pipeline=weekly", "--external-id", "grc=record-43")
			require.NoError(t, err)
			after := readLabelDocument(t, path)
			assert.JSONEq(t, `{"pipeline":"weekly","team":"security"}`, string(after["labels"]))
			assert.JSONEq(t, `{"ci-run":" project/run=4821 ","grc":"record-43"}`, string(after["externalIds"]))
			for key, value := range before {
				assert.JSONEq(t, string(value), string(after[key]), "unrelated field %s", key)
			}
			stdout, _, err := executeCommand("label", "show", path, "--scope", "document", "--json")
			require.NoError(t, err)
			assert.JSONEq(t, `{"labels":{"pipeline":"weekly","team":"security"},"externalIds":{"ci-run":" project/run=4821 ","grc":"record-43"}}`, stdout)
			stdout, _, err = executeCommand("label", "show", path, "--scope", "document")
			require.NoError(t, err)
			assert.Contains(t, stdout, "pipeline = weekly")
			assert.Contains(t, stdout, "ci-run =  project/run=4821 ")
			_, _, err = executeCommand("label", "remove", path, "--scope", "document", "pipeline", "missing", "--external-id", "grc")
			require.NoError(t, err)
			after = readLabelDocument(t, path)
			assert.JSONEq(t, `{"team":"security"}`, string(after["labels"]))
			assert.JSONEq(t, `{"ci-run":" project/run=4821 "}`, string(after["externalIds"]))
			_, _, err = executeCommand("label", "remove", path, "--scope", "document", "team", "--external-id", "ci-run")
			require.NoError(t, err)
			stdout, _, err = executeCommand("label", "show", path, "--scope", "document", "--json")
			require.NoError(t, err)
			assert.JSONEq(t, `{"labels":{},"externalIds":{}}`, stdout)
		})
	}
}

func TestLabelDocumentScopeIsolation(t *testing.T) {
	doc := testhdf.System("Portal", testhdf.Component("web", hdf.Host, func(c *hdf.Component) {
		c.Labels = map[string]string{"team": "platform"}
		c.ExternalIDS = map[string]string{"cmdb": "CI0012345"}
	}))
	path := writeLabelDocument(t, doc)
	_, _, err := executeCommand("label", "set", path, "--scope", "document", "team=security", "--external-id", "ci-run=4821")
	require.NoError(t, err)
	before := readLabelDocument(t, path)
	_, _, err = executeCommand("label", "set", path, "team=operations", "--external-id", "cmdb=CI9999999")
	require.NoError(t, err)
	after := readLabelDocument(t, path)
	assert.JSONEq(t, string(before["labels"]), string(after["labels"]))
	assert.JSONEq(t, string(before["externalIds"]), string(after["externalIds"]))
	assert.JSONEq(t, `[{"name":"web","type":"host","labels":{"team":"operations"},"externalIds":{"cmdb":"CI9999999"}}]`, string(after["components"]))
}

func TestLabelDocumentRejectsBeforeWrite(t *testing.T) {
	cases := [][]string{
		{"set", "--scope", "invalid", "team=security"},
		{"set", "--scope", "", "team=security"},
		{"set", "--scope", "document", "team=security", "--component-id", "00000000-0000-4000-8000-000000000001"},
		{"set", "--scope", "document", "--generate-component-id"},
		{"set", "--scope", "document", "team=security", "--component-id", ""},
		{"set", "--scope", "document", "team=security", "--generate-component-id=false"},
		{"set", "--scope", "document", "team=security", "--component-name", ""},
		{"set", "--scope", "document", "--external-id", "ci-run=4821", "--component-name", "web"},
		{"set", "--scope", "document", "--external-id", "ci-run="},
		{"set", "--scope", "document", "--external-id", "ci-run=1", "--external-id", "ci-run=2"},
		{"remove", "--scope", "document", "--external-id", "ci-run", "--component-name", "web"},
		{"remove", "--scope", "invalid", "team"},
	}
	for _, args := range cases {
		t.Run(args[0]+"/"+args[len(args)-1], func(t *testing.T) {
			path := writeLabelDocument(t, labelDocumentCases()["system"])
			before, err := os.ReadFile(path)
			require.NoError(t, err)
			output := filepath.Join(t.TempDir(), "out.json")
			argv := append([]string{"label", args[0], path}, args[1:]...)
			argv = append(argv, "-o", output)
			_, _, err = executeCommand(argv...)
			require.Error(t, err)
			after, readErr := os.ReadFile(path)
			require.NoError(t, readErr)
			assert.Equal(t, before, after)
			_, statErr := os.Stat(output)
			assert.True(t, os.IsNotExist(statErr))
		})
	}
}

// Characterization guards for validation and the existing component defaults.
func TestLabelDocumentBoundaries(t *testing.T) {
	for _, command := range []string{"set", "show", "remove"} {
		for _, data := range []string{`not json`, `{"packageId":"invalid","contents":[]}`} {
			t.Run(command+data, func(t *testing.T) {
				path := filepath.Join(t.TempDir(), "invalid.json")
				require.NoError(t, os.WriteFile(path, []byte(data), 0o600))
				args := []string{"label", command, path, "--scope", "document"}
				switch command {
				case "set":
					args = append(args, "team=security")
				case "remove":
					args = append(args, "team")
				}
				stdout, _, err := executeCommand(args...)
				require.Error(t, err)
				assert.Empty(t, stdout)
				after, err := os.ReadFile(path)
				require.NoError(t, err)
				assert.Equal(t, data, string(after))
			})
		}
	}
	path := writeLabelDocument(t, labelDocumentCases()["system"])
	stdout, _, err := executeCommand("label", "show", path, "--scope", "document", "--json")
	require.NoError(t, err)
	assert.JSONEq(t, `{"labels":{},"externalIds":{}}`, stdout)
	_, _, err = executeCommand("label", "remove", path, "--scope", "document", "missing", "--external-id", "missing")
	require.NoError(t, err)
	_, _, err = executeCommand("label", "set", path, "--scope", "component", "team=platform")
	require.NoError(t, err)
	explicit, _, err := executeCommand("label", "show", path, "--scope", "component", "--json")
	require.NoError(t, err)
	implicit, _, err := executeCommand("label", "show", path, "--json")
	require.NoError(t, err)
	assert.JSONEq(t, implicit, explicit)
	assert.JSONEq(t, `[{"name":"web","type":"host","labels":{"team":"platform"},"externalIds":{}}]`, explicit)
	_, _, err = executeCommand("label", "remove", path, "--scope", "component", "team")
	require.NoError(t, err)
	assert.NotContains(t, readLabelDocument(t, path), "labels")
}

func TestLabelDocumentOutputAndUnsupportedTypes(t *testing.T) {
	path := writeLabelDocument(t, labelDocumentCases()["evidence-package"])
	before, err := os.ReadFile(path)
	require.NoError(t, err)
	output := filepath.Join(t.TempDir(), "out.json")
	_, _, err = executeCommand("label", "set", path, "--scope", "document", "team=security", "-o", output)
	require.NoError(t, err)
	after, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, before, after)
	assert.JSONEq(t, `{"team":"security"}`, string(readLabelDocument(t, output)["labels"]))
	_, _, err = executeCommand("label", "set", path, "team=security")
	require.ErrorContains(t, err, "--scope document")
	results := writeLabelDocument(t, testhdf.Results(testhdf.Req("SV-257777")))
	for _, command := range []string{"set", "show", "remove"} {
		argv := []string{"label", command, results, "--scope", "document"}
		if command == "set" {
			argv = append(argv, "team=security")
		}
		if command == "remove" {
			argv = append(argv, "team")
		}
		_, _, err = executeCommand(argv...)
		require.ErrorContains(t, err, "document scope")
	}
}
