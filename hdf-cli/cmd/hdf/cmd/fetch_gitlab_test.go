package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// minimalGitLabReportJSON is a valid GitLab security report for CLI tests.
const minimalGitLabReportJSON = `{
	"version": "15.0.0",
	"scan": {
		"scanner": {"id": "semgrep", "name": "Semgrep", "version": "1.0.0"},
		"type": "sast",
		"start_time": "2026-01-15T10:00:00",
		"end_time": "2026-01-15T10:05:00",
		"status": "success"
	},
	"vulnerabilities": [{
		"id": "vuln-1",
		"name": "SQL Injection",
		"description": "User input used in SQL query",
		"severity": "Critical",
		"solution": "Use parameterized queries",
		"identifiers": [{"type": "cwe", "name": "CWE-89", "value": "89"}],
		"location": {"file": "app.py", "start_line": 42}
	}]
}`

// TestFetchGitlabCmd_IsSubcommand verifies the command is reachable.
func TestFetchGitlabCmd_IsSubcommand(t *testing.T) {
	root := NewRootCmd()
	fetch, _, err := root.Find([]string{"fetch", "gitlab"})
	require.NoError(t, err)
	assert.Equal(t, "gitlab", fetch.Name())
}

// TestFetchGitlabCmd_MissingRequiredFlags verifies required flags.
func TestFetchGitlabCmd_MissingRequiredFlags(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{"missing project", []string{"gitlab", "--job", "semgrep-sast"}},
		{"missing job", []string{"gitlab", "--project", "my-project"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := NewFetchCmd()
			cmd.SetArgs(tt.args)
			err := cmd.Execute()
			require.Error(t, err)
		})
	}
}

// TestFetchGitlabCmd_MissingToken verifies token error message.
func TestFetchGitlabCmd_MissingToken(t *testing.T) {
	t.Setenv("GITLAB_TOKEN", "")
	t.Setenv("GLAB_TOKEN", "")
	t.Setenv("GLAB_CONFIG_DIR", t.TempDir())

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, minimalGitLabReportJSON)
	}))
	defer srv.Close()

	cmd := NewFetchCmd()
	cmd.SetArgs([]string{"gitlab", "--url", srv.URL, "--project", "my-project", "--job", "semgrep-sast"})

	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "GITLAB_TOKEN")
}

// TestFetchGitlabCmd_InvalidURL verifies URL scheme validation.
func TestFetchGitlabCmd_InvalidURL(t *testing.T) {
	t.Setenv("GITLAB_TOKEN", "tok")

	cmd := NewFetchCmd()
	cmd.SetArgs([]string{"gitlab", "--url", "ftp://bad-scheme", "--project", "proj", "--job", "job"})

	err := cmd.Execute()
	require.Error(t, err)
}

// TestFetchGitlabCmd_InvalidFormat verifies format validation.
func TestFetchGitlabCmd_InvalidFormat(t *testing.T) {
	t.Setenv("GITLAB_TOKEN", "tok")

	cmd := NewFetchCmd()
	cmd.SetArgs([]string{"gitlab", "--url", "https://gitlab.com", "--project", "proj", "--job", "job", "--format", "xml"})

	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid --format")
}

// TestFetchGitlabCmd_Help verifies help text contents.
func TestFetchGitlabCmd_Help(t *testing.T) {
	root := NewRootCmd()
	root.SetArgs([]string{"fetch", "gitlab", "--help"})
	var out bytes.Buffer
	root.SetOut(&out)
	_ = root.Execute()
	help := out.String()
	assert.Contains(t, help, "project")
	assert.Contains(t, help, "job")
	assert.Contains(t, help, "scan-type")
	assert.Contains(t, help, "format")
	assert.Contains(t, help, "GITLAB_TOKEN")
	assert.Contains(t, help, "semgrep-sast")
}

// TestFetchGitlabCmd_Success exercises the full fetch → convert → write pipeline.
func TestFetchGitlabCmd_Success(t *testing.T) {
	t.Setenv("GITLAB_TOKEN", "tok")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Contains(t, r.URL.Path, "/api/v4/projects/")
		assert.Equal(t, "tok", r.Header.Get("PRIVATE-TOKEN"))
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, minimalGitLabReportJSON)
	}))
	defer srv.Close()

	tmpFile := t.TempDir() + "/output.json"

	cmd := NewFetchCmd()
	cmd.SetArgs([]string{
		"gitlab",
		"--url", srv.URL,
		"--project", "my-project",
		"--job", "semgrep-sast",
		"--output", tmpFile,
	})

	err := cmd.Execute()
	require.NoError(t, err)

	data, err := os.ReadFile(tmpFile)
	require.NoError(t, err)
	assertHDFOutput(t, data)

	s := string(data)
	assert.Contains(t, s, "gitlab-to-hdf")
}

// TestFetchGitlabCmd_RawFormat verifies --format raw writes native output.
func TestFetchGitlabCmd_RawFormat(t *testing.T) {
	t.Setenv("GITLAB_TOKEN", "tok")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, minimalGitLabReportJSON)
	}))
	defer srv.Close()

	tmpFile := t.TempDir() + "/raw-output.json"

	cmd := NewFetchCmd()
	cmd.SetArgs([]string{
		"gitlab",
		"--url", srv.URL,
		"--project", "my-project",
		"--job", "semgrep-sast",
		"--format", "raw",
		"--output", tmpFile,
	})

	err := cmd.Execute()
	require.NoError(t, err)

	data, err := os.ReadFile(tmpFile)
	require.NoError(t, err)

	// Raw output should contain the native GitLab report fields, not HDF fields
	var parsed map[string]interface{}
	require.NoError(t, json.Unmarshal(data, &parsed))
	assert.Contains(t, parsed, "vulnerabilities", "raw output should contain GitLab report fields")
	assert.Contains(t, parsed, "scan", "raw output should contain scan metadata")
	assert.NotContains(t, parsed, "baselines", "raw output should not contain HDF fields")
}

// TestFetchCmd_Help_ListsGitlab verifies the fetch parent command lists gitlab.
func TestFetchCmd_Help_ListsGitlab(t *testing.T) {
	root := NewRootCmd()
	root.SetArgs([]string{"fetch", "--help"})
	var out bytes.Buffer
	root.SetOut(&out)
	_ = root.Execute()
	assert.Contains(t, out.String(), "gitlab")
}
