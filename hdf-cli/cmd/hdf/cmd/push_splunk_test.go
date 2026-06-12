package cmd

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPushSplunkCmd_Registered(t *testing.T) {
	root := NewRootCmd()
	push, _, err := root.Find([]string{"push", "splunk"})
	require.NoError(t, err)
	assert.Equal(t, "splunk", push.Name())
}

func TestPushSplunkCmd_RequiresFlags(t *testing.T) {
	root := NewRootCmd()
	root.SetArgs([]string{"push", "splunk"})
	root.SetOut(&bytes.Buffer{})
	root.SetErr(&bytes.Buffer{})
	err := root.Execute()
	require.Error(t, err, "missing required --url / --index / positional must fail")
}

func TestPushSplunkCmd_RequiresToken(t *testing.T) {
	t.Setenv("SPLUNK_TOKEN", "")

	tmp, err := os.CreateTemp("", "hdf-*.json")
	require.NoError(t, err)
	defer os.Remove(tmp.Name())
	_, _ = tmp.WriteString(`{"baselines":[]}`)
	tmp.Close()

	root := NewRootCmd()
	root.SetArgs([]string{"push", "splunk", "--url", "https://example.com", "--index", "hdf", tmp.Name()})
	root.SetOut(&bytes.Buffer{})
	root.SetErr(&bytes.Buffer{})
	err = root.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "SPLUNK_TOKEN")
}

func TestPushSplunkCmd_EndToEnd(t *testing.T) {
	// Mount a fake Splunk server that handles the preflight + 3 record POSTs.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasPrefix(r.URL.Path, "/services/data/indexes/hdf"):
			_, _ = w.Write([]byte(`{"entry":[{"name":"hdf"}]}`))
		case r.URL.Path == "/services/receivers/simple":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{}`))
		default:
			http.Error(w, "unexpected", http.StatusInternalServerError)
		}
	}))
	defer srv.Close()

	t.Setenv("SPLUNK_TOKEN", "tok")

	tmp, err := os.CreateTemp("", "hdf-*.json")
	require.NoError(t, err)
	defer os.Remove(tmp.Name())
	_, _ = tmp.WriteString(`{
		"baselines": [{
			"name": "Test",
			"version": "1.0",
			"integrity": {"algorithm": "sha256", "checksum": "deadbeef"},
			"requirements": [{
				"id": "REQ-1",
				"title": "t",
				"impact": 0.5,
				"tags": {},
				"descriptions": [{"label": "default", "data": "d"}],
				"results": [{"status": "passed", "codeDesc": "ok", "startTime": "2026-01-01T00:00:00Z"}]
			}]
		}]
	}`)
	tmp.Close()

	root := NewRootCmd()
	root.SetArgs([]string{"push", "splunk", "--url", srv.URL, "--index", "hdf", tmp.Name()})
	root.SetContext(context.Background())
	out := &bytes.Buffer{}
	root.SetOut(out)
	root.SetErr(out)
	require.NoError(t, root.Execute())
}
