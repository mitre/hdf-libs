package cmd

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVerifyTenableSCCmd_Registered(t *testing.T) {
	root := NewRootCmd()
	verify, _, err := root.Find([]string{"verify", "tenable-sc"})
	require.NoError(t, err)
	assert.Equal(t, "tenable-sc", verify.Name())
}

func TestVerifyTenableSCCmd_RequiresAccessKey(t *testing.T) {
	t.Setenv("TENABLE_SC_ACCESS_KEY", "")
	t.Setenv("TENABLE_SC_SECRET_KEY", "sk")

	root := NewRootCmd()
	root.SetArgs([]string{"verify", "tenable-sc", "--url", "https://example.com"})
	root.SetOut(&bytes.Buffer{})
	root.SetErr(&bytes.Buffer{})
	err := root.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "TENABLE_SC_ACCESS_KEY")
}

func TestVerifyTenableSCCmd_RequiresSecretKey(t *testing.T) {
	t.Setenv("TENABLE_SC_ACCESS_KEY", "ak")
	t.Setenv("TENABLE_SC_SECRET_KEY", "")

	root := NewRootCmd()
	root.SetArgs([]string{"verify", "tenable-sc", "--url", "https://example.com"})
	root.SetOut(&bytes.Buffer{})
	root.SetErr(&bytes.Buffer{})
	err := root.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "TENABLE_SC_SECRET_KEY")
}

func TestVerifyTenableSCCmd_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/rest/currentUser", r.URL.Path)
		assert.Contains(t, r.Header.Get("x-apikey"), "accesskey=ak")
		assert.Contains(t, r.Header.Get("x-apikey"), "secretkey=sk")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"response":{"username":"test"}}`))
	}))
	defer srv.Close()

	t.Setenv("TENABLE_SC_ACCESS_KEY", "ak")
	t.Setenv("TENABLE_SC_SECRET_KEY", "sk")

	root := NewRootCmd()
	root.SetArgs([]string{"verify", "tenable-sc", "--url", srv.URL})
	root.SetContext(context.Background())
	out := &bytes.Buffer{}
	root.SetOut(out)
	root.SetErr(out)
	require.NoError(t, root.Execute())
}

func TestVerifyTenableSCCmd_Unauthorized(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	secretAK := "leak-test-access-key-xyz"
	secretSK := "leak-test-secret-key-xyz"
	t.Setenv("TENABLE_SC_ACCESS_KEY", secretAK)
	t.Setenv("TENABLE_SC_SECRET_KEY", secretSK)

	root := NewRootCmd()
	root.SetArgs([]string{"verify", "tenable-sc", "--url", srv.URL})
	root.SetContext(context.Background())
	out := &bytes.Buffer{}
	root.SetOut(out)
	root.SetErr(out)
	err := root.Execute()
	require.Error(t, err)
	assert.NotContains(t, err.Error(), secretAK, "verify CLI error must not leak the access key")
	assert.NotContains(t, err.Error(), secretSK, "verify CLI error must not leak the secret key")
}
