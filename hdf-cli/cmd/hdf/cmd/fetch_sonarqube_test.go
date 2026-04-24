package cmd

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	sonarqubeconv "github.com/mitre/hdf-libs/hdf-converters/v3/converters/sonarqube-to-hdf/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// writeSonarIssuesPage writes a minimal IssuesResponse JSON to the response writer.
func writeSonarIssuesPage(w http.ResponseWriter, issues []sonarqubeconv.Issue, total int) {
	if issues == nil {
		issues = []sonarqubeconv.Issue{}
	}
	resp := sonarqubeconv.IssuesResponse{
		Total:    total,
		Page:     1,
		PageSize: 500,
		Paging: sonarqubeconv.Paging{
			PageIndex: 1,
			PageSize:  500,
			Total:     total,
		},
		Issues: issues,
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func TestFetchSonarqubeCmd_MissingToken(t *testing.T) {
	t.Setenv("SONARQUBE_TOKEN", "")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeSonarIssuesPage(w, nil, 0)
	}))
	defer srv.Close()

	cmd := NewFetchCmd()
	cmd.SetArgs([]string{"sonarqube", "--url", srv.URL, "--project-key", "my-project"})

	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "SONARQUBE_TOKEN")
}

func TestFetchSonarqubeCmd_InvalidURL(t *testing.T) {
	t.Setenv("SONARQUBE_TOKEN", "tok")

	cmd := NewFetchCmd()
	cmd.SetArgs([]string{"sonarqube", "--url", "ftp://bad-scheme", "--project-key", "proj"})

	err := cmd.Execute()
	require.Error(t, err)
}

func TestFetchSonarqubeCmd_MissingRequiredFlags(t *testing.T) {
	t.Setenv("SONARQUBE_TOKEN", "tok")

	tests := []struct {
		name string
		args []string
	}{
		{"missing url", []string{"sonarqube", "--project-key", "proj"}},
		{"missing project-key", []string{"sonarqube", "--url", "http://localhost:9000"}},
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

func TestFetchSonarqubeCmd_BranchAndPullRequestMutuallyExclusive(t *testing.T) {
	t.Setenv("SONARQUBE_TOKEN", "tok")

	cmd := NewFetchCmd()
	cmd.SetArgs([]string{
		"sonarqube",
		"--url", "http://localhost:9000",
		"--project-key", "proj",
		"--branch", "main",
		"--pull-request", "42",
	})

	err := cmd.Execute()
	require.Error(t, err)
}

func TestFetchSonarqubeCmd_Success(t *testing.T) {
	t.Setenv("SONARQUBE_TOKEN", "tok")

	line := 10
	issue := sonarqubeconv.Issue{
		Key:          "issue-1",
		Rule:         "java:S001",
		Severity:     "MAJOR",
		Component:    "proj:File.java",
		Project:      "proj",
		Line:         &line,
		Status:       "OPEN",
		Message:      "Test issue",
		CreationDate: "2026-01-01T00:00:00+0000",
		UpdateDate:   "2026-01-01T00:00:00+0000",
		Type:         "CODE_SMELL",
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/server/version" {
			w.Header().Set("Content-Type", "text/plain")
			_, _ = fmt.Fprint(w, "10.8.1")
			return
		}
		assert.Equal(t, "/api/issues/search", r.URL.Path)
		assert.Contains(t, r.Header.Get("Authorization"), "Bearer tok")
		writeSonarIssuesPage(w, []sonarqubeconv.Issue{issue}, 1)
	}))
	defer srv.Close()

	tmpFile := t.TempDir() + "/output.json"

	cmd := NewFetchCmd()
	cmd.SetArgs([]string{
		"sonarqube",
		"--url", srv.URL,
		"--project-key", "proj",
		"--output", tmpFile,
	})

	err := cmd.Execute()
	require.NoError(t, err)

	// Verify output is valid HDF JSON
	data, err := os.ReadFile(tmpFile)
	require.NoError(t, err)
	assertHDFOutput(t, data)

	s := string(data)
	assert.Contains(t, s, "sonarqube-to-hdf")
	assert.Contains(t, s, "proj")
}
