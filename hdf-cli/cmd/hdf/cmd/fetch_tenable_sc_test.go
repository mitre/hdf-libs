package cmd

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFetchTenableSCCmd_Registered(t *testing.T) {
	root := NewRootCmd()
	fetch, _, err := root.Find([]string{"fetch", "tenable-sc"})
	require.NoError(t, err)
	assert.Equal(t, "tenable-sc", fetch.Name())
}

func TestFetchTenableSCCmd_RequiresAccessKey(t *testing.T) {
	t.Setenv("TENABLE_SC_ACCESS_KEY", "")
	t.Setenv("TENABLE_SC_SECRET_KEY", "sk")

	cmd := NewFetchCmd()
	cmd.SetArgs([]string{"tenable-sc", "--url", "https://example.com", "--scan-id", "42"})
	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "TENABLE_SC_ACCESS_KEY")
}

func TestFetchTenableSCCmd_RequiresSecretKey(t *testing.T) {
	t.Setenv("TENABLE_SC_ACCESS_KEY", "ak")
	t.Setenv("TENABLE_SC_SECRET_KEY", "")

	cmd := NewFetchCmd()
	cmd.SetArgs([]string{"tenable-sc", "--url", "https://example.com", "--scan-id", "42"})
	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "TENABLE_SC_SECRET_KEY")
}

func TestFetchTenableSCCmd_MissingRequiredFlags(t *testing.T) {
	t.Setenv("TENABLE_SC_ACCESS_KEY", "ak")
	t.Setenv("TENABLE_SC_SECRET_KEY", "sk")

	tests := []struct {
		name string
		args []string
	}{
		{"missing url", []string{"tenable-sc", "--scan-id", "42"}},
		{"missing scan-id", []string{"tenable-sc", "--url", "https://example.com"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := NewFetchCmd()
			cmd.SetArgs(tt.args)
			cmd.SetOut(&bytes.Buffer{})
			cmd.SetErr(&bytes.Buffer{})
			require.Error(t, cmd.Execute())
		})
	}
}

func TestFetchTenableSCCmd_InvalidScanID(t *testing.T) {
	t.Setenv("TENABLE_SC_ACCESS_KEY", "ak")
	t.Setenv("TENABLE_SC_SECRET_KEY", "sk")

	cmd := NewFetchCmd()
	cmd.SetArgs([]string{"tenable-sc", "--url", "https://example.com", "--scan-id", "../1"})
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "scan ID")
}

func TestFetchTenableSCCmd_EndToEnd_RawFormat(t *testing.T) {
	// Use the real .nessus fixture as the download response.
	fixturePath := filepath.Join(
		"..", "..", "..", "..",
		"hdf-converters", "converters", "nessus-to-hdf", "fixtures", "input", "compliance.nessus",
	)
	xml, err := os.ReadFile(fixturePath)
	require.NoError(t, err)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/rest/scanResult/42/download", r.URL.Path)
		assert.Equal(t, "v2", r.URL.Query().Get("downloadType"))
		assert.Contains(t, r.Header.Get("x-apikey"), "accesskey=ak")
		_, _ = w.Write(xml)
	}))
	defer srv.Close()

	t.Setenv("TENABLE_SC_ACCESS_KEY", "ak")
	t.Setenv("TENABLE_SC_SECRET_KEY", "sk")

	outPath := filepath.Join(t.TempDir(), "out.nessus")

	root := NewRootCmd()
	root.SetArgs([]string{
		"fetch", "tenable-sc",
		"--url", srv.URL,
		"--scan-id", "42",
		"--format", "raw",
		"-o", outPath,
	})
	root.SetContext(context.Background())
	root.SetOut(&bytes.Buffer{})
	root.SetErr(&bytes.Buffer{})
	require.NoError(t, root.Execute())

	written, err := os.ReadFile(outPath)
	require.NoError(t, err)
	assert.Equal(t, xml, written, "raw output should match the fixture bytes")
}

func TestFetchTenableSCCmd_EndToEnd_HDFFormat(t *testing.T) {
	fixturePath := filepath.Join(
		"..", "..", "..", "..",
		"hdf-converters", "converters", "nessus-to-hdf", "fixtures", "input", "compliance.nessus",
	)
	xml, err := os.ReadFile(fixturePath)
	require.NoError(t, err)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(xml)
	}))
	defer srv.Close()

	t.Setenv("TENABLE_SC_ACCESS_KEY", "ak")
	t.Setenv("TENABLE_SC_SECRET_KEY", "sk")

	outPath := filepath.Join(t.TempDir(), "out.json")

	root := NewRootCmd()
	root.SetArgs([]string{
		"fetch", "tenable-sc",
		"--url", srv.URL,
		"--scan-id", "42",
		"-o", outPath,
	})
	root.SetContext(context.Background())
	root.SetOut(&bytes.Buffer{})
	root.SetErr(&bytes.Buffer{})
	require.NoError(t, root.Execute())

	written, err := os.ReadFile(outPath)
	require.NoError(t, err)
	assert.Contains(t, string(written), "baselines",
		"HDF output should contain baselines key")
}

func TestFetchTenableSCCmd_KeyLeakageGuard(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	secretAK := "leak-test-ak-cli"
	secretSK := "leak-test-sk-cli"
	t.Setenv("TENABLE_SC_ACCESS_KEY", secretAK)
	t.Setenv("TENABLE_SC_SECRET_KEY", secretSK)

	root := NewRootCmd()
	root.SetArgs([]string{"fetch", "tenable-sc", "--url", srv.URL, "--scan-id", "42"})
	root.SetContext(context.Background())
	root.SetOut(&bytes.Buffer{})
	root.SetErr(&bytes.Buffer{})
	err := root.Execute()
	require.Error(t, err)
	assert.NotContains(t, err.Error(), secretAK)
	assert.NotContains(t, err.Error(), secretSK)
}
