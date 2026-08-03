package cmd

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ddFindingsServer serves a single findings page and a user_profile endpoint,
// asserting the DefectDojo token auth header on every request.
func ddFindingsServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "Token tok", r.Header.Get("Authorization"))
		if r.URL.Path == "/api/v2/user_profile/" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"username":"admin"}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"next":null,"results":[
			{"id":1,"title":"Finding","severity":"High","active":true,
			 "related_fields":{"test":{"test_type":{"name":"Trivy Scan"}}}}]}`))
	}))
}

func TestFetchDefectDojoCmd_MissingToken(t *testing.T) {
	t.Setenv("DEFECTDOJO_API_TOKEN", "")

	cmd := NewFetchCmd()
	cmd.SetArgs([]string{"defectdojo", "--url", "http://localhost:8080"})

	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "DEFECTDOJO_API_TOKEN")
}

func TestFetchDefectDojoCmd_InvalidURL(t *testing.T) {
	t.Setenv("DEFECTDOJO_API_TOKEN", "tok")

	cmd := NewFetchCmd()
	cmd.SetArgs([]string{"defectdojo", "--url", "ftp://bad-scheme"})

	err := cmd.Execute()
	require.Error(t, err)
}

func TestFetchDefectDojoCmd_MissingURL(t *testing.T) {
	t.Setenv("DEFECTDOJO_API_TOKEN", "tok")

	cmd := NewFetchCmd()
	cmd.SetArgs([]string{"defectdojo"})

	err := cmd.Execute()
	require.Error(t, err)
}

func TestFetchDefectDojoCmd_CheckFlagWired(t *testing.T) {
	fetch := newFetchDefectDojoCmd()
	flag := fetch.Flags().Lookup("check")
	require.NotNil(t, flag, "--check flag must be declared on hdf fetch defectdojo")
	assert.Equal(t, "false", flag.DefValue, "--check should default to false")
}

func TestFetchDefectDojoCmd_Check(t *testing.T) {
	t.Setenv("DEFECTDOJO_API_TOKEN", "tok")
	srv := ddFindingsServer(t)
	defer srv.Close()

	cmd := NewFetchCmd()
	cmd.SetArgs([]string{"defectdojo", "--url", srv.URL, "--check"})

	err := cmd.Execute()
	require.NoError(t, err)
}

func TestFetchDefectDojoCmd_Success(t *testing.T) {
	t.Setenv("DEFECTDOJO_API_TOKEN", "tok")
	srv := ddFindingsServer(t)
	defer srv.Close()

	tmpFile := t.TempDir() + "/output.json"

	cmd := NewFetchCmd()
	cmd.SetArgs([]string{"defectdojo", "--url", srv.URL, "--output", tmpFile})

	err := cmd.Execute()
	require.NoError(t, err)

	data, err := os.ReadFile(tmpFile)
	require.NoError(t, err)
	assertHDFOutput(t, data)

	s := string(data)
	assert.Contains(t, s, "defectdojo-to-hdf")
	assert.Contains(t, s, "DefectDojo: Trivy Scan")
}

func TestFetchDefectDojoCmd_RawFormat(t *testing.T) {
	t.Setenv("DEFECTDOJO_API_TOKEN", "tok")
	srv := ddFindingsServer(t)
	defer srv.Close()

	tmpFile := t.TempDir() + "/raw.json"

	cmd := NewFetchCmd()
	cmd.SetArgs([]string{"defectdojo", "--url", srv.URL, "--format", "raw", "--output", tmpFile})

	err := cmd.Execute()
	require.NoError(t, err)

	data, err := os.ReadFile(tmpFile)
	require.NoError(t, err)
	assert.Contains(t, string(data), "\"results\"")
}
