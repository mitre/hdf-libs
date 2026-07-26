package defectdojo

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	converter "github.com/mitre/hdf-libs/hdf-converters/v3/converters/defectdojo-to-hdf/go"
	shared "github.com/mitre/hdf-libs/hdf-converters/v3/fetchers/shared/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testToken = "test-token" //nolint:gosec // test-only credential

// ddServer serves a two-page findings response and a user_profile endpoint,
// asserting the DefectDojo token auth header on every request.
func ddServer(t *testing.T) *httptest.Server {
	t.Helper()
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "Token "+testToken, r.Header.Get("Authorization"), "auth header must be sent")

		if r.URL.Path == "/api/v2/user_profile/" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"username":"admin"}`))
			return
		}

		w.Header().Set("Content-Type", "application/json")
		if r.URL.Query().Get("offset") == "100" {
			// page 2 (terminal)
			_, _ = w.Write([]byte(`{"next":null,"results":[
				{"id":2,"title":"Second","severity":"Medium","active":true,
				 "related_fields":{"test":{"test_type":{"name":"Trivy Scan"}}}}]}`))
			return
		}
		// page 1 → link to page 2 on the same host
		next := fmt.Sprintf("%s/api/v2/findings/?limit=100&offset=100", srv.URL)
		_, _ = fmt.Fprintf(w, `{"next":%q,"results":[
			{"id":1,"title":"First","severity":"High","active":true,
			 "related_fields":{"test":{"test_type":{"name":"Trivy Scan"}}}}]}`, next)
	}))
	return srv
}

func TestDefectDojoFetcher_FetchPaginatesAndFeedsConverter(t *testing.T) {
	srv := ddServer(t)
	defer srv.Close()
	t.Setenv(defectDojoTokenEnv, testToken)

	f, err := NewDefectDojoFetcher(DefectDojoParams{URL: srv.URL}, shared.TLSOptions{})
	require.NoError(t, err)

	data, err := f.Fetch(context.Background())
	require.NoError(t, err)

	// assembled envelope carries both pages
	var env struct {
		Results []json.RawMessage `json:"results"`
	}
	require.NoError(t, json.Unmarshal(data, &env))
	assert.Len(t, env.Results, 2)

	// the assembled bytes feed the converter and produce valid HDF
	result, err := converter.ConvertDefectDojo(data, "0.1.0")
	require.NoError(t, err)
	assert.Len(t, result.Baselines, 1)
	assert.Equal(t, "DefectDojo: Trivy Scan", result.Baselines[0].Name)
	assert.Len(t, result.Baselines[0].Requirements, 2)
}

func TestDefectDojoFetcher_Verify(t *testing.T) {
	srv := ddServer(t)
	defer srv.Close()
	t.Setenv(defectDojoTokenEnv, testToken)

	f, err := NewDefectDojoFetcher(DefectDojoParams{URL: srv.URL}, shared.TLSOptions{})
	require.NoError(t, err)
	assert.NoError(t, f.Verify(context.Background()))
}

func TestDefectDojoFetcher_MissingToken(t *testing.T) {
	srv := ddServer(t)
	defer srv.Close()
	t.Setenv(defectDojoTokenEnv, "")

	f, err := NewDefectDojoFetcher(DefectDojoParams{URL: srv.URL}, shared.TLSOptions{})
	require.NoError(t, err)
	_, err = f.Fetch(context.Background())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "token not found")
}

func TestDefectDojoFetcher_URLValidation(t *testing.T) {
	_, err := NewDefectDojoFetcher(DefectDojoParams{URL: ""}, shared.TLSOptions{})
	assert.Error(t, err)
	_, err = NewDefectDojoFetcher(DefectDojoParams{URL: "ftp://example.com"}, shared.TLSOptions{})
	assert.Error(t, err)

	// injection constructor validates too
	_, err = NewDefectDojoFetcherWithClient(DefectDojoParams{URL: ""}, http.DefaultClient)
	assert.Error(t, err)
}
