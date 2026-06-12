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

func TestVerifySplunkCmd_Registered(t *testing.T) {
	root := NewRootCmd()
	verify, _, err := root.Find([]string{"verify", "splunk"})
	require.NoError(t, err)
	assert.Equal(t, "splunk", verify.Name())
}

func TestVerifySplunkCmd_RequiresToken(t *testing.T) {
	t.Setenv("SPLUNK_TOKEN", "")

	root := NewRootCmd()
	root.SetArgs([]string{"verify", "splunk", "--url", "https://example.com"})
	root.SetOut(&bytes.Buffer{})
	root.SetErr(&bytes.Buffer{})
	err := root.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "SPLUNK_TOKEN")
}

func TestVerifySplunkCmd_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/services/server/info", r.URL.Path)
		assert.Equal(t, "Bearer tok", r.Header.Get("Authorization"))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"generator":"splunk"}`))
	}))
	defer srv.Close()

	t.Setenv("SPLUNK_TOKEN", "tok")

	root := NewRootCmd()
	root.SetArgs([]string{"verify", "splunk", "--url", srv.URL})
	root.SetContext(context.Background())
	out := &bytes.Buffer{}
	root.SetOut(out)
	root.SetErr(out)
	require.NoError(t, root.Execute())
}

func TestVerifySplunkCmd_Unauthorized(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	t.Setenv("SPLUNK_TOKEN", "leak-test-token-abc")

	root := NewRootCmd()
	root.SetArgs([]string{"verify", "splunk", "--url", srv.URL})
	root.SetContext(context.Background())
	out := &bytes.Buffer{}
	root.SetOut(out)
	root.SetErr(out)
	err := root.Execute()
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "leak-test-token-abc",
		"verify CLI error must not leak the token value")
}
