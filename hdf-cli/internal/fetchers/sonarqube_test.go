package fetchers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	sonarqubeconv "github.com/mitre/hdf-converters/converters/sonarqube-to-hdf/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---- helpers ----

func mustUnmarshalSonarqube(t *testing.T, data []byte) sonarqubeconv.IssuesResponse {
	t.Helper()
	var r sonarqubeconv.IssuesResponse
	require.NoError(t, json.Unmarshal(data, &r))
	return r
}

func sonarqubeServer(t *testing.T, handler http.HandlerFunc) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return srv
}

func newTestFetcher(t *testing.T, serverURL string) *SonarqubeFetcher {
	t.Helper()
	f, err := newSonarqubeFetcherWithClient(SonarqubeParams{
		URL:        serverURL,
		ProjectKey: "test-project",
	}, &http.Client{})
	require.NoError(t, err)
	return f
}

// ---- URL validation tests ----

func TestNewSonarqubeFetcher_URLValidation(t *testing.T) {
	valid := []string{
		"http://sonarqube.example.com",
		"https://sonarqube.example.com",
		"http://localhost:9000",
		"https://sonarcloud.io",
	}
	for _, u := range valid {
		t.Run("valid/"+u, func(t *testing.T) {
			_, err := NewSonarqubeFetcher(SonarqubeParams{URL: u, ProjectKey: "key"})
			assert.NoError(t, err, "URL %q should be valid", u)
		})
	}

	invalid := []string{
		"",
		"ftp://sonarqube.example.com",
		"file:///etc/passwd",
		"ssh://host",
		"not-a-url",
	}
	for _, u := range invalid {
		t.Run("invalid/"+u, func(t *testing.T) {
			_, err := NewSonarqubeFetcher(SonarqubeParams{URL: u, ProjectKey: "key"})
			require.Error(t, err)
		})
	}
}

// ---- token tests ----

func TestSonarqubeFetcher_MissingToken(t *testing.T) {
	srv := sonarqubeServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	f := newTestFetcher(t, srv.URL)

	// Ensure token is not set
	t.Setenv("SONARQUBE_TOKEN", "")

	_, err := f.Fetch(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "SONARQUBE_TOKEN")
	// Token value must not appear in the error message
	assert.NotContains(t, err.Error(), "Bearer")
}

func TestSonarqubeFetcher_TokenSentAsBearer(t *testing.T) {
	var capturedAuth string
	srv := sonarqubeServer(t, func(w http.ResponseWriter, r *http.Request) {
		capturedAuth = r.Header.Get("Authorization")
		writeIssuesPage(w, nil, nil, nil, 0, 1)
	})

	f := newTestFetcher(t, srv.URL)
	t.Setenv("SONARQUBE_TOKEN", "test-token-value")

	_, err := f.Fetch(context.Background())
	require.NoError(t, err)

	assert.Equal(t, "Bearer test-token-value", capturedAuth)
}

// ---- pagination tests ----

func writeIssuesPage(w http.ResponseWriter, issues []sonarqubeconv.Issue, components []sonarqubeconv.Component, rules []sonarqubeconv.Rule, total, pageIndex int) {
	if issues == nil {
		issues = []sonarqubeconv.Issue{}
	}
	resp := sonarqubeconv.IssuesResponse{
		Total:    total,
		Page:     pageIndex,
		PageSize: sonarqubePageSize,
		Paging: sonarqubeconv.Paging{
			PageIndex: pageIndex,
			PageSize:  sonarqubePageSize,
			Total:     total,
		},
		Issues:     issues,
		Components: components,
		Rules:      rules,
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func TestSonarqubeFetcher_SinglePage(t *testing.T) {
	issue := sonarqubeconv.Issue{
		Key:          "issue-1",
		Rule:         "java:S001",
		Severity:     "MAJOR",
		Component:    "proj:File.java",
		Project:      "proj",
		Status:       "OPEN",
		Message:      "Test issue",
		CreationDate: "2026-01-01T00:00:00+0000",
		UpdateDate:   "2026-01-01T00:00:00+0000",
		Type:         "CODE_SMELL",
	}

	srv := sonarqubeServer(t, func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/issues/search", r.URL.Path)
		assert.Equal(t, "test-project", r.URL.Query().Get("componentKeys"))
		writeIssuesPage(w, []sonarqubeconv.Issue{issue}, nil, nil, 1, 1)
	})

	f := newTestFetcher(t, srv.URL)
	t.Setenv("SONARQUBE_TOKEN", "tok")

	data, err := f.Fetch(context.Background())
	require.NoError(t, err)

	result := mustUnmarshalSonarqube(t, data)
	require.Len(t, result.Issues, 1)
	assert.Equal(t, "issue-1", result.Issues[0].Key)
}

func TestSonarqubeFetcher_Pagination(t *testing.T) {
	// 3 issues across 2 pages. total=3 so fetcher stops when len(allIssues) >= total.
	page1Issues := []sonarqubeconv.Issue{
		{Key: "i1", Rule: "r:S1", Severity: "MAJOR", Component: "p:f", Project: "p", Status: "OPEN", Message: "m", CreationDate: "2026-01-01T00:00:00+0000", UpdateDate: "2026-01-01T00:00:00+0000", Type: "BUG"},
		{Key: "i2", Rule: "r:S1", Severity: "MAJOR", Component: "p:f", Project: "p", Status: "OPEN", Message: "m", CreationDate: "2026-01-01T00:00:00+0000", UpdateDate: "2026-01-01T00:00:00+0000", Type: "BUG"},
	}
	page2Issues := []sonarqubeconv.Issue{
		{Key: "i3", Rule: "r:S1", Severity: "MAJOR", Component: "p:f", Project: "p", Status: "OPEN", Message: "m", CreationDate: "2026-01-01T00:00:00+0000", UpdateDate: "2026-01-01T00:00:00+0000", Type: "BUG"},
	}

	calls := 0
	srv := sonarqubeServer(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		pageParam := r.URL.Query().Get("p")
		switch pageParam {
		case "1":
			// Page 1: 2 issues, total=3 → fetcher must request page 2
			writeIssuesPage(w, page1Issues, nil, nil, 3, 1)
		case "2":
			// Page 2: 1 issue, allIssues(3) >= total(3) → stop
			writeIssuesPage(w, page2Issues, nil, nil, 3, 2)
		default:
			http.Error(w, "unexpected page", http.StatusBadRequest)
		}
	})

	f := newTestFetcher(t, srv.URL)
	t.Setenv("SONARQUBE_TOKEN", "tok")

	data, err := f.Fetch(context.Background())
	require.NoError(t, err)

	result := mustUnmarshalSonarqube(t, data)
	assert.Equal(t, 2, calls, "should have made 2 API calls")
	assert.Len(t, result.Issues, 3, "should accumulate all issues")
}

func TestSonarqubeFetcher_PageLimitExceeded(t *testing.T) {
	// Always return 1 issue with a total much larger than maxPages can handle.
	// After maxPages calls, fetcher should return an error.
	calls := 0
	srv := sonarqubeServer(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		writeIssuesPage(w, []sonarqubeconv.Issue{
			{Key: fmt.Sprintf("i%d", calls), Rule: "r:S1", Severity: "MAJOR", Component: "p:f", Project: "p", Status: "OPEN", Message: "m", CreationDate: "2026-01-01T00:00:00+0000", UpdateDate: "2026-01-01T00:00:00+0000", Type: "BUG"},
		}, nil, nil, 999999999, calls)
	})

	f := newTestFetcher(t, srv.URL)
	f.maxPages = 3
	t.Setenv("SONARQUBE_TOKEN", "tok")

	_, err := f.Fetch(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "maximum page limit")
}

func TestSonarqubeFetcher_ContextCancelled(t *testing.T) {
	srv := sonarqubeServer(t, func(w http.ResponseWriter, r *http.Request) {
		writeIssuesPage(w, nil, nil, nil, 0, 1)
	})

	f := newTestFetcher(t, srv.URL)
	t.Setenv("SONARQUBE_TOKEN", "tok")

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel before fetch

	_, err := f.Fetch(ctx)
	require.Error(t, err)
	assert.ErrorIs(t, err, context.Canceled)
}

// contextCapturingSonarqubeTransport wraps an inner transport and records the
// request context so tests can inspect whether a deadline was applied.
type contextCapturingSonarqubeTransport struct {
	inner       http.RoundTripper
	capturedCtx context.Context
}

func (t *contextCapturingSonarqubeTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	t.capturedCtx = req.Context()
	return t.inner.RoundTrip(req)
}

func TestSonarqubeFetcher_DefaultTimeoutApplied(t *testing.T) {
	srv := sonarqubeServer(t, func(w http.ResponseWriter, r *http.Request) {
		writeIssuesPage(w, nil, nil, nil, 0, 1)
	})

	capturingTransport := &contextCapturingSonarqubeTransport{inner: http.DefaultTransport}
	f, err := newSonarqubeFetcherWithClient(SonarqubeParams{
		URL:        srv.URL,
		ProjectKey: "test-project",
	}, &http.Client{Transport: capturingTransport})
	require.NoError(t, err)
	t.Setenv("SONARQUBE_TOKEN", "tok")

	ctx := context.Background()
	_, hasDeadline := ctx.Deadline()
	require.False(t, hasDeadline, "precondition: background context has no deadline")

	_, err = f.Fetch(ctx)
	require.NoError(t, err)

	require.NotNil(t, capturingTransport.capturedCtx, "transport should have captured a context")
	_, deadlineSet := capturingTransport.capturedCtx.Deadline()
	assert.True(t, deadlineSet, "Fetch must wrap a deadline-free context with a timeout")
}

func TestSonarqubeFetcher_HTTP401(t *testing.T) {
	srv := sonarqubeServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	})

	f := newTestFetcher(t, srv.URL)
	t.Setenv("SONARQUBE_TOKEN", "tok")

	_, err := f.Fetch(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "401")
}

func TestSonarqubeFetcher_HTTP500(t *testing.T) {
	srv := sonarqubeServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})

	f := newTestFetcher(t, srv.URL)
	t.Setenv("SONARQUBE_TOKEN", "tok")

	_, err := f.Fetch(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "500")
}

func TestSonarqubeFetcher_ComponentsAndRulesAccumulated(t *testing.T) {
	comp := sonarqubeconv.Component{Key: "proj:File.java", Name: "File.java", Path: "src/File.java"}
	rule := sonarqubeconv.Rule{Key: "java:S001", Name: "Test Rule"}

	srv := sonarqubeServer(t, func(w http.ResponseWriter, r *http.Request) {
		writeIssuesPage(w,
			[]sonarqubeconv.Issue{{Key: "i1", Rule: "java:S001", Severity: "MAJOR", Component: "proj:File.java", Project: "proj", Status: "OPEN", Message: "m", CreationDate: "2026-01-01T00:00:00+0000", UpdateDate: "2026-01-01T00:00:00+0000", Type: "BUG"}},
			[]sonarqubeconv.Component{comp},
			[]sonarqubeconv.Rule{rule},
			1, 1)
	})

	f := newTestFetcher(t, srv.URL)
	t.Setenv("SONARQUBE_TOKEN", "tok")

	data, err := f.Fetch(context.Background())
	require.NoError(t, err)

	result := mustUnmarshalSonarqube(t, data)
	assert.Len(t, result.Issues, 1)
	require.Len(t, result.Components, 1)
	assert.Equal(t, "proj:File.java", result.Components[0].Key)
	require.Len(t, result.Rules, 1)
	assert.Equal(t, "java:S001", result.Rules[0].Key)
}

func TestSonarqubeFetcher_OptionalParams(t *testing.T) {
	var capturedQuery string
	srv := sonarqubeServer(t, func(w http.ResponseWriter, r *http.Request) {
		capturedQuery = r.URL.RawQuery
		writeIssuesPage(w, nil, nil, nil, 0, 1)
	})

	f, err := newSonarqubeFetcherWithClient(SonarqubeParams{
		URL:          srv.URL,
		ProjectKey:   "my-project",
		Branch:       "main",
		Organization: "my-org",
	}, &http.Client{})
	require.NoError(t, err)
	t.Setenv("SONARQUBE_TOKEN", "tok")

	_, err = f.Fetch(context.Background())
	require.NoError(t, err)

	assert.Contains(t, capturedQuery, "branch=main")
	assert.Contains(t, capturedQuery, "organization=my-org")
	assert.Contains(t, capturedQuery, "componentKeys=my-project")
}

func TestSonarqubeFetcher_FetchAndConvert(t *testing.T) {
	line := 42
	issue := sonarqubeconv.Issue{
		Key:          "issue-1",
		Rule:         "java:S2259",
		Severity:     "BLOCKER",
		Component:    "proj:File.java",
		Project:      "proj",
		Line:         &line,
		Status:       "OPEN",
		Message:      "Null pointer",
		CreationDate: "2026-01-15T10:30:00+0000",
		UpdateDate:   "2026-01-15T10:30:00+0000",
		Type:         "BUG",
		Tags:         []string{"cwe-476"},
	}

	srv := sonarqubeServer(t, func(w http.ResponseWriter, r *http.Request) {
		writeIssuesPage(w, []sonarqubeconv.Issue{issue}, nil, nil, 1, 1)
	})

	f := newTestFetcher(t, srv.URL)
	t.Setenv("SONARQUBE_TOKEN", "tok")

	raw, err := f.Fetch(context.Background())
	require.NoError(t, err)

	// Verify the output is directly consumable by ConvertSonarqubeToHDF
	result, err := sonarqubeconv.ConvertSonarqubeToHDF(raw, "test-version")
	require.NoError(t, err, "fetcher output must be directly consumable by ConvertSonarqubeToHDF")
	require.Len(t, result.Baselines, 1)
	require.Len(t, result.Baselines[0].Requirements, 1)

	req := result.Baselines[0].Requirements[0]
	assert.Equal(t, "java:S2259", req.ID)
	assert.Equal(t, 1.0, req.Impact) // BLOCKER
}

//nolint:dupl // Token-leakage tests are structurally identical across fetchers by design
func TestSonarqubeFetcher_TokenNotInErrorMessages(t *testing.T) {
	srv := sonarqubeServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	})

	f := newTestFetcher(t, srv.URL)
	secretToken := "super-secret-api-token-12345"
	t.Setenv("SONARQUBE_TOKEN", secretToken)

	_, err := f.Fetch(context.Background())
	require.Error(t, err)
	assert.NotContains(t, err.Error(), secretToken, "token must not appear in error messages")
	assert.NotContains(t, err.Error(), "Bearer "+secretToken, "token must not appear in error messages")
}

func TestSonarqubeFetcher_EmptyResults(t *testing.T) {
	srv := sonarqubeServer(t, func(w http.ResponseWriter, r *http.Request) {
		writeIssuesPage(w, []sonarqubeconv.Issue{}, nil, nil, 0, 1)
	})

	f := newTestFetcher(t, srv.URL)
	t.Setenv("SONARQUBE_TOKEN", "tok")

	data, err := f.Fetch(context.Background())
	require.NoError(t, err)

	result := mustUnmarshalSonarqube(t, data)
	assert.Empty(t, result.Issues)
	assert.Equal(t, 0, result.Total)
}

func TestSonarqubeFetcher_ResponseExceedsMaxSize(t *testing.T) {
	// Return a response body larger than the 10MB limit.
	// The fetcher should return an explicit size-limit error rather than
	// silently truncating the body and producing a confusing JSON parse error.
	const maxResponseSize = 10 * 1024 * 1024

	srv := sonarqubeServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// Write maxResponseSize + 1 bytes to exceed the limit
		oversized := make([]byte, maxResponseSize+1)
		for i := range oversized {
			oversized[i] = 'x'
		}
		_, _ = w.Write(oversized)
	})

	f := newTestFetcher(t, srv.URL)
	t.Setenv("SONARQUBE_TOKEN", "tok")

	_, err := f.Fetch(context.Background())
	require.Error(t, err)
	// Must mention the byte limit, not a JSON parse error
	assert.Contains(t, err.Error(), "byte limit", "error should mention size limit, not be a JSON parse error")
	assert.NotContains(t, err.Error(), "parsing API response", "should fail on size, not JSON parsing")
}

func TestSonarqubeFetcher_InvalidJSONResponse(t *testing.T) {
	srv := sonarqubeServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, "not valid json")
	})

	f := newTestFetcher(t, srv.URL)
	t.Setenv("SONARQUBE_TOKEN", "tok")

	_, err := f.Fetch(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "parsing API response")
}
