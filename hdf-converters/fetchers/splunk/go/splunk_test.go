package splunk

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	shared "github.com/mitre/hdf-libs/hdf-converters/v3/fetchers/shared/go"
)

// ---- helpers ----

func splunkServer(t *testing.T, handler http.HandlerFunc) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return srv
}

func newTestSplunkFetcher(t *testing.T, serverURL string) *SplunkFetcher {
	t.Helper()
	f, err := NewSplunkFetcherWithClient(SplunkParams{
		URL:   serverURL,
		Index: "test-index",
		GUID:  "test-guid",
	}, &http.Client{})
	require.NoError(t, err)
	return f
}

// writeSplunkSearchResponse writes a mock search job creation response with a SID.
func writeSplunkSearchResponse(w http.ResponseWriter, sid string) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(splunkSearchResponse{SID: sid})
}

// writeSplunkResultsResponse writes a mock results response with fields and rows.
func writeSplunkResultsResponse(w http.ResponseWriter, events []string) {
	rows := make([][]string, 0, len(events))
	for _, e := range events {
		rows = append(rows, []string{"2026-01-01T00:00:00Z", "source", "sourcetype", e})
	}
	resp := splunkResultsResponse{
		Fields: []splunkField{
			{Name: "_time"},
			{Name: "source"},
			{Name: "sourcetype"},
			{Name: "_raw"},
		},
		Rows: rows,
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

// ---- URL validation tests ----

func TestNewSplunkFetcher_URLValidation(t *testing.T) { //nolint:dupl // URL validation pattern shared across fetcher tests
	valid := []string{
		"http://splunk.example.com",
		"https://splunk.example.com",
		"http://localhost:8089",
		"https://splunk.example.com:8089",
	}
	for _, u := range valid {
		t.Run("valid/"+u, func(t *testing.T) {
			_, err := NewSplunkFetcher(SplunkParams{URL: u, Index: "idx", GUID: "guid"}, shared.TLSOptions{})
			assert.NoError(t, err, "URL %q should be valid", u)
		})
	}

	invalid := []string{
		"",
		"ftp://splunk.example.com",
		"file:///etc/passwd",
		"ssh://host",
		"not-a-url",
	}
	for _, u := range invalid {
		t.Run("invalid/"+u, func(t *testing.T) {
			_, err := NewSplunkFetcher(SplunkParams{URL: u, Index: "idx", GUID: "guid"}, shared.TLSOptions{})
			require.Error(t, err)
		})
	}
}

// ---- identifier validation tests ----

func TestNewSplunkFetcher_IdentifierValidation(t *testing.T) {
	baseURL := "https://splunk.example.com"

	// Valid identifiers
	validIDs := []string{
		"test-index",
		"hdf_events",
		"abc123",
		"my.index.name",
		"A-B-C",
	}
	for _, id := range validIDs {
		t.Run("valid-index/"+id, func(t *testing.T) {
			_, err := NewSplunkFetcher(SplunkParams{URL: baseURL, Index: id, GUID: "guid123"}, shared.TLSOptions{})
			assert.NoError(t, err)
		})
		t.Run("valid-guid/"+id, func(t *testing.T) {
			_, err := NewSplunkFetcher(SplunkParams{URL: baseURL, Index: "idx", GUID: id}, shared.TLSOptions{})
			assert.NoError(t, err)
		})
	}

	// Invalid identifiers — SPL injection / path traversal attempts
	invalidIDs := []string{
		"",
		"idx|delete",
		"idx[subsearch]",
		"../../etc/passwd",
		"test index",
		"`whoami`",
		"idx;drop",
	}
	for _, id := range invalidIDs {
		t.Run("invalid-index/"+id, func(t *testing.T) {
			_, err := NewSplunkFetcher(SplunkParams{URL: baseURL, Index: id, GUID: "guid"}, shared.TLSOptions{})
			require.Error(t, err, "index %q should be rejected", id)
		})
		if id != "" { // GUID="" is tested by the index case
			t.Run("invalid-guid/"+id, func(t *testing.T) {
				_, err := NewSplunkFetcher(SplunkParams{URL: baseURL, Index: "idx", GUID: id}, shared.TLSOptions{})
				require.Error(t, err, "GUID %q should be rejected", id)
			})
		}
	}
}

// ---- SID validation tests ----

func TestSplunkFetcher_SIDValidation(t *testing.T) {
	// Table-driven rejection tests for malicious SIDs
	rejectCases := []struct {
		name string
		sid  string
	}{
		{"path traversal", "../../admin/delete"},
		{"pipe injection", "sid|malicious"},
		{"space", "sid with space"},
		{"semicolon", "sid;drop"},
		{"backtick", "`whoami`"},
	}
	for _, tc := range rejectCases {
		t.Run("rejects/"+tc.name, func(t *testing.T) {
			srv := splunkServer(t, func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodPost {
					writeSplunkSearchResponse(w, tc.sid)
					return
				}
				http.Error(w, "should not reach here", http.StatusInternalServerError)
			})

			f := newTestSplunkFetcher(t, srv.URL)
			t.Setenv("SPLUNK_TOKEN", "tok")

			_, err := f.Fetch(context.Background())
			require.Error(t, err, "SID %q should be rejected", tc.sid)
			assert.Contains(t, err.Error(), "unsafe SID")
		})
	}

	t.Run("accepts valid SID formats", func(t *testing.T) {
		// Valid Splunk SIDs: numeric.numeric, scheduler prefixed, etc.
		validSIDs := []string{
			"1609459200.12345",
			"scheduler__admin__search__RMD50abc123",
			"test-sid-123",
			"abc_def.123",
		}
		for _, sid := range validSIDs {
			t.Run(sid, func(t *testing.T) {
				srv := splunkServer(t, func(w http.ResponseWriter, r *http.Request) {
					if r.Method == http.MethodPost {
						writeSplunkSearchResponse(w, sid)
						return
					}
					if r.Method == http.MethodGet {
						writeSplunkResultsResponse(w, []string{`{"test":"data"}`})
						return
					}
				})

				f := newTestSplunkFetcher(t, srv.URL)
				t.Setenv("SPLUNK_TOKEN", "tok")

				_, err := f.Fetch(context.Background())
				assert.NoError(t, err, "SID %q should be accepted", sid)
			})
		}
	})
}

// ---- token tests ----

func TestSplunkFetcher_Fetch_NoToken(t *testing.T) {
	srv := splunkServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	f := newTestSplunkFetcher(t, srv.URL)
	t.Setenv("SPLUNK_TOKEN", "")

	_, err := f.Fetch(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "SPLUNK_TOKEN")
}

func TestSplunkFetcher_Fetch_AuthError(t *testing.T) {
	srv := splunkServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	})

	f := newTestSplunkFetcher(t, srv.URL)
	t.Setenv("SPLUNK_TOKEN", "bad-token")

	_, err := f.Fetch(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "splunk API returned HTTP 401")
}

//nolint:dupl // Token-leakage tests are structurally identical across fetchers by design
func TestSplunkFetcher_TokenNotInErrorMessages(t *testing.T) {
	srv := splunkServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	})

	f := newTestSplunkFetcher(t, srv.URL)
	secretToken := "super-secret-splunk-token-12345"
	t.Setenv("SPLUNK_TOKEN", secretToken)

	_, err := f.Fetch(context.Background())
	require.Error(t, err)
	assert.NotContains(t, err.Error(), secretToken, "token must not appear in error messages")
	assert.NotContains(t, err.Error(), "Bearer "+secretToken, "token must not appear in error messages")
}

// ---- response truncation test ----

func TestSplunkFetcher_ResponseTruncation(t *testing.T) {
	// Create a server that returns a body larger than the limit
	srv := splunkServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			writeSplunkSearchResponse(w, "test-sid")
			return
		}
		// Return a body larger than splunkMaxResponseSize
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		// Write just over the limit
		_, _ = w.Write([]byte(`{"fields":[{"name":"_raw"}],"rows":[`))
		for i := 0; i < splunkMaxResponseSize/10; i++ {
			if i > 0 {
				_, _ = w.Write([]byte(","))
			}
			_, _ = w.Write([]byte(`["xxxxxxxxxx"]`))
		}
		_, _ = w.Write([]byte("]}"))
	})

	f := newTestSplunkFetcher(t, srv.URL)
	t.Setenv("SPLUNK_TOKEN", "tok")

	_, err := f.Fetch(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "exceeded", "should report response size exceeded, not a JSON parse error")
}

// ---- successful fetch test ----

func TestSplunkFetcher_Fetch_Success(t *testing.T) {
	headerEvent := `{"meta":{"guid":"test-guid","subtype":"header","hdf_splunk_schema":"1.0","filetype":"evaluation","filename":"test.json"},"profiles":[],"platform":{"name":"centos","release":"7.6"},"statistics":{"duration":1.0},"version":"4.0.0"}`
	profileEvent := `{"meta":{"guid":"test-guid","subtype":"profile","hdf_splunk_schema":"1.0","filetype":"evaluation","filename":"test.json","profile_sha256":"abc123","is_baseline":true},"name":"test-profile","sha256":"abc123","title":"Test","version":"1.0","supports":[],"groups":[],"attributes":[],"controls":[]}`
	controlEvent := `{"meta":{"guid":"test-guid","subtype":"control","hdf_splunk_schema":"1.0","filetype":"evaluation","filename":"test.json","profile_sha256":"abc123","status":"Passed","is_baseline":true,"is_waived":false,"overlay_depth":1},"id":"V-12345","title":"Test Control","desc":"","descriptions":{"default":"test"},"impact":0.5,"code":"","tags":{"nist":["AC-1"]},"results":[{"status":"passed","code_desc":"test","start_time":"2026-01-01T00:00:00Z","run_time":0.01}],"refs":[],"source_location":{"line":1,"ref":"test.rb"}}`

	requestCount := 0
	srv := splunkServer(t, func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		if r.Method == http.MethodPost && r.URL.Path == "/services/search/jobs" {
			assert.Equal(t, "Bearer test-token", r.Header.Get("Authorization"))

			// Validate POST body parameters — ensures the fetcher sends
			// the correct SPL query, exec_mode, and output_mode.
			require.NoError(t, r.ParseForm())
			assert.Equal(t, "blocking", r.PostFormValue("exec_mode"),
				"search job must use blocking exec_mode")
			assert.Equal(t, "json", r.PostFormValue("output_mode"),
				"search job must request JSON output")
			searchQuery := r.PostFormValue("search")
			assert.Contains(t, searchQuery, "test-index",
				"SPL query must reference the configured index")
			assert.Contains(t, searchQuery, "test-guid",
				"SPL query must reference the configured GUID")
			assert.Contains(t, searchQuery, "| fields _raw",
				"SPL query must limit fields to _raw to reduce data transfer")

			writeSplunkSearchResponse(w, "test-sid-123")
			return
		}
		if r.Method == http.MethodGet && r.URL.Path == "/services/search/v2/jobs/test-sid-123/results" {
			// Verify count parameter is set (not unlimited)
			assert.Equal(t, fmt.Sprintf("%d", splunkMaxResults), r.URL.Query().Get("count"),
				"results request should cap count instead of using 0 (unlimited)")
			writeSplunkResultsResponse(w, []string{headerEvent, profileEvent, controlEvent})
			return
		}
		http.Error(w, fmt.Sprintf("unexpected request: %s %s", r.Method, r.URL.Path), http.StatusBadRequest)
	})

	f := newTestSplunkFetcher(t, srv.URL)
	t.Setenv("SPLUNK_TOKEN", "test-token")

	data, err := f.Fetch(context.Background())
	require.NoError(t, err)

	// Output should be a JSON array of events
	var events []json.RawMessage
	require.NoError(t, json.Unmarshal(data, &events))
	assert.Len(t, events, 3, "Should have 3 events (header + profile + control)")
	assert.Equal(t, 2, requestCount, "Should make 2 API calls (create job + fetch results)")
}

// ---- truncation warning test ----

func TestSplunkFetcher_TruncationWarning(t *testing.T) {
	// Build a response with exactly splunkMaxResults rows to trigger the warning.
	// We just need the row count to match — content doesn't matter for this test.
	rows := make([][]string, splunkMaxResults)
	for i := range rows {
		rows[i] = []string{"2026-01-01T00:00:00Z", "s", "st", `{"i":` + fmt.Sprintf("%d", i) + `}`}
	}
	resp := splunkResultsResponse{
		Fields: []splunkField{{Name: "_time"}, {Name: "source"}, {Name: "sourcetype"}, {Name: "_raw"}},
		Rows:   rows,
	}

	srv := splunkServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			writeSplunkSearchResponse(w, "test-sid")
			return
		}
		// Return all rows as a single large response; disable the 10MB limit
		// by writing the JSON directly (the test only checks that the fetcher
		// logs a warning, not that it reads the full body).
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	})

	f := newTestSplunkFetcher(t, srv.URL)
	t.Setenv("SPLUNK_TOKEN", "tok")

	// The warning is emitted via log.Printf. We capture it to verify.
	var logBuf strings.Builder
	log.SetOutput(&logBuf)
	defer log.SetOutput(os.Stderr)

	data, err := f.Fetch(context.Background())
	require.NoError(t, err)
	assert.NotEmpty(t, data)
	assert.Contains(t, logBuf.String(), "truncated",
		"fetcher should log a warning when results hit the maximum count")
}

// ---- context cancellation test ----

func TestSplunkFetcher_Timeout(t *testing.T) {
	srv := splunkServer(t, func(w http.ResponseWriter, r *http.Request) {
		writeSplunkSearchResponse(w, "test-sid")
	})

	f := newTestSplunkFetcher(t, srv.URL)
	t.Setenv("SPLUNK_TOKEN", "tok")

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel before fetch

	_, err := f.Fetch(ctx)
	require.Error(t, err)
	assert.ErrorIs(t, err, context.Canceled)
}
