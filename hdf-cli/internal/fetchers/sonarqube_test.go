package fetchers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	sonarqubeconv "github.com/mitre/hdf-libs/hdf-converters/v3/converters/sonarqube-to-hdf/go"
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
	// Wrap handler to intercept /api/server/version (needed for version
	// auto-detection) and delegate everything else to the test handler.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/server/version" {
			w.Header().Set("Content-Type", "text/plain")
			_, _ = fmt.Fprint(w, "10.8.1")
			return
		}
		handler(w, r)
	}))
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
			_, err := NewSonarqubeFetcher(SonarqubeParams{URL: u, ProjectKey: "key"}, TLSOptions{})
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
			_, err := NewSonarqubeFetcher(SonarqubeParams{URL: u, ProjectKey: "key"}, TLSOptions{})
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

// ---- Rule enrichment tests (SonarQube 26+ /api/rules/show) ----

const (
	sonarqubeIssuesSearchPath = "/api/issues/search"
	sonarqubeRulesShowPath    = "/api/rules/show"
)

// writeRuleShowResponse writes a /api/rules/show JSON response.
func writeRuleShowResponse(w http.ResponseWriter, rule sonarqubeconv.Rule) {
	type ruleShow struct {
		Rule sonarqubeconv.Rule `json:"rule"`
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(ruleShow{Rule: rule})
}

func TestSonarqubeFetcher_EnrichesRules(t *testing.T) {
	issue := sonarqubeconv.Issue{
		Key:          "issue-1",
		Rule:         "secrets:S6706",
		Severity:     "BLOCKER",
		Component:    "proj:File.ts",
		Project:      "proj",
		Status:       "OPEN",
		Message:      "Hard-coded credential",
		CreationDate: "2026-01-01T00:00:00+0000",
		UpdateDate:   "2026-01-01T00:00:00+0000",
		Type:         "VULNERABILITY",
		Tags:         []string{"cwe"},
	}

	// Rule as returned by /api/issues/search (minimal, SQ 26 format)
	issueRule := sonarqubeconv.Rule{
		Key:      "secrets:S6706",
		Name:     "Cryptographic private keys should not be disclosed",
		Status:   "READY",
		Lang:     "secrets",
		LangName: "Secrets",
	}

	// Rule as returned by /api/rules/show (enriched with details)
	enrichedRule := sonarqubeconv.Rule{
		Key:      "secrets:S6706",
		Name:     "Cryptographic private keys should not be disclosed",
		SysTags:  []string{"cwe"},
		HTMLDesc: "<p>Secret leaks description</p>",
		DescriptionSections: []sonarqubeconv.DescriptionSection{
			{Key: "resources", Content: `<ul><li>CWE - <a href="https://cwe.mitre.org/data/definitions/798">CWE-798</a></li></ul>`},
			{Key: "root_cause", Content: "<p>Trust boundaries are violated.</p>"},
		},
	}

	srv := sonarqubeServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case sonarqubeIssuesSearchPath:
			writeIssuesPage(w,
				[]sonarqubeconv.Issue{issue},
				nil,
				[]sonarqubeconv.Rule{issueRule},
				1, 1)
		case sonarqubeRulesShowPath:
			assert.Equal(t, "secrets:S6706", r.URL.Query().Get("key"))
			writeRuleShowResponse(w, enrichedRule)
		default:
			http.Error(w, "unexpected path", http.StatusNotFound)
		}
	})

	f := newTestFetcher(t, srv.URL)
	t.Setenv("SONARQUBE_TOKEN", "tok")

	data, err := f.Fetch(context.Background())
	require.NoError(t, err)

	result := mustUnmarshalSonarqube(t, data)
	require.Len(t, result.Rules, 1)

	rule := result.Rules[0]
	assert.Equal(t, "secrets:S6706", rule.Key)
	assert.Equal(t, []string{"cwe"}, rule.SysTags, "sysTags should be enriched")
	assert.Equal(t, "<p>Secret leaks description</p>", rule.HTMLDesc, "htmlDesc should be enriched")
	require.Len(t, rule.DescriptionSections, 2, "descriptionSections should be enriched")
	assert.Equal(t, "resources", rule.DescriptionSections[0].Key)
	assert.Contains(t, rule.DescriptionSections[0].Content, "CWE-798")
}

func TestSonarqubeFetcher_EnrichmentFailsGracefully(t *testing.T) {
	issue := sonarqubeconv.Issue{
		Key: "i1", Rule: "java:S001", Severity: "MAJOR", Component: "p:f",
		Project: "p", Status: "OPEN", Message: "m",
		CreationDate: "2026-01-01T00:00:00+0000",
		UpdateDate:   "2026-01-01T00:00:00+0000", Type: "BUG",
	}

	issueRule := sonarqubeconv.Rule{Key: "java:S001", Name: "Test Rule"}

	srv := sonarqubeServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case sonarqubeIssuesSearchPath:
			writeIssuesPage(w, []sonarqubeconv.Issue{issue}, nil, []sonarqubeconv.Rule{issueRule}, 1, 1)
		case sonarqubeRulesShowPath:
			// Return 404 to simulate rule not found
			http.Error(w, "not found", http.StatusNotFound)
		default:
			http.Error(w, "unexpected", http.StatusNotFound)
		}
	})

	f := newTestFetcher(t, srv.URL)
	t.Setenv("SONARQUBE_TOKEN", "tok")

	data, err := f.Fetch(context.Background())
	require.NoError(t, err, "enrichment failure should not fail the overall fetch")

	result := mustUnmarshalSonarqube(t, data)
	require.Len(t, result.Issues, 1)
	require.Len(t, result.Rules, 1)
	assert.Equal(t, "java:S001", result.Rules[0].Key)
}

func TestSonarqubeFetcher_FetchAndConvert_WithEnrichment(t *testing.T) {
	// Full pipeline test: fetch → enrich → convert, verify CWE IDs in HDF output
	line := 15
	issue := sonarqubeconv.Issue{
		Key:          "issue-1",
		Rule:         "secrets:S6706",
		Severity:     "BLOCKER",
		Component:    "proj:server.ts",
		Project:      "proj",
		Line:         &line,
		Status:       "OPEN",
		Message:      "Hard-coded credential",
		CreationDate: "2026-03-01T10:00:00+0000",
		UpdateDate:   "2026-03-05T02:59:39+0000",
		Type:         "VULNERABILITY",
		Tags:         []string{"cwe"},
	}

	// Minimal rule from issues/search
	issueRule := sonarqubeconv.Rule{
		Key:      "secrets:S6706",
		Name:     "Cryptographic private keys should not be disclosed",
		Status:   "READY",
		Lang:     "secrets",
		LangName: "Secrets",
	}

	// Enriched rule from rules/show
	enrichedRule := sonarqubeconv.Rule{
		Key:     "secrets:S6706",
		Name:    "Cryptographic private keys should not be disclosed",
		SysTags: []string{"cwe"},
		DescriptionSections: []sonarqubeconv.DescriptionSection{
			{
				Key:     "resources",
				Content: `<ul><li>CWE - <a href="https://cwe.mitre.org/data/definitions/798">CWE-798 - Use of Hard-coded Credentials</a></li><li>CWE - <a href="https://cwe.mitre.org/data/definitions/259">CWE-259 - Use of Hard-coded Password</a></li></ul>`,
			},
			{
				Key:     "root_cause",
				Content: "<p>Trust boundaries are violated when a secret is exposed.</p>",
			},
		},
	}

	srv := sonarqubeServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case sonarqubeIssuesSearchPath:
			writeIssuesPage(w,
				[]sonarqubeconv.Issue{issue},
				nil,
				[]sonarqubeconv.Rule{issueRule},
				1, 1)
		case sonarqubeRulesShowPath:
			writeRuleShowResponse(w, enrichedRule)
		default:
			http.Error(w, "unexpected", http.StatusNotFound)
		}
	})

	f := newTestFetcher(t, srv.URL)
	t.Setenv("SONARQUBE_TOKEN", "tok")

	raw, err := f.Fetch(context.Background())
	require.NoError(t, err)

	// Convert fetched data to HDF
	hdfResult, err := sonarqubeconv.ConvertSonarqubeToHDF(raw, "test-version")
	require.NoError(t, err)
	require.Len(t, hdfResult.Baselines, 1)
	require.Len(t, hdfResult.Baselines[0].Requirements, 1)

	req := hdfResult.Baselines[0].Requirements[0]
	assert.Equal(t, "secrets:S6706", req.ID)

	// Verify CWE IDs were extracted from enriched descriptionSections
	cweVal, ok := req.Tags["cwe"]
	require.True(t, ok, "expected 'cwe' tag")
	cweSlice, ok := cweVal.([]string)
	require.True(t, ok, "cwe should be []string")
	assert.Contains(t, cweSlice, "CWE-798", "should extract CWE-798 from enriched descriptionSections")
	assert.Contains(t, cweSlice, "CWE-259", "should extract CWE-259 from enriched descriptionSections")

	// Verify NIST mappings were derived from CWE
	nistVal, ok := req.Tags["nist"]
	require.True(t, ok, "expected 'nist' tag")
	nistSlice, ok := nistVal.([]string)
	require.True(t, ok, "nist should be []string")
	assert.NotEmpty(t, nistSlice, "NIST controls should be derived from CWE mappings")
}

// ---- 10K limit component tree tests ----

func TestSonarqubeFetcher_ComponentTreeWhenOverLimit(t *testing.T) {
	// Simulate the 10K Elasticsearch limit: the project has 12000 issues total.
	// The project-level query hits the cap at page 21 (p*ps > 10000).
	// The fetcher should detect this and fetch by sub-component instead.
	//
	// Project structure:
	//   test-project (12000 issues total)
	//     ├─ test-project:src/main (8000 issues)
	//     └─ test-project:src/test (4000 issues)

	srv := sonarqubeServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/issues/search":
			component := r.URL.Query().Get("componentKeys")
			page := r.URL.Query().Get("p")
			pageNum := 1
			if page != "" {
				_, _ = fmt.Sscanf(page, "%d", &pageNum)
			}

			var total int
			switch component {
			case "test-project":
				total = 12000
			case "test-project:src/main":
				total = 8000
			case "test-project:src/test":
				total = 4000
			default:
				writeIssuesPage(w, nil, nil, nil, 0, 1)
				return
			}

			// Simulate 10K cap
			if pageNum*sonarqubePageSize > 10000 {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = fmt.Fprint(w, `{"errors":[{"msg":"Can return only the first 10000 results."}]}`)
				return
			}

			start := (pageNum - 1) * sonarqubePageSize
			remaining := total - start
			if remaining <= 0 {
				writeIssuesPage(w, nil, nil, nil, total, pageNum)
				return
			}
			if remaining > sonarqubePageSize {
				remaining = sonarqubePageSize
			}

			issues := make([]sonarqubeconv.Issue, remaining)
			for i := range issues {
				issues[i] = sonarqubeconv.Issue{
					Key: fmt.Sprintf("%s-%d-%d", component, pageNum, i), Rule: "java:S001",
					Severity: "MAJOR", Component: component + ":File.java", Project: "test-project",
					Status: "OPEN", Message: "m",
					CreationDate: "2026-01-01T00:00:00+0000",
					UpdateDate:   "2026-01-01T00:00:00+0000", Type: "BUG",
				}
			}
			writeIssuesPage(w, issues, nil, nil, total, pageNum)

		case "/api/components/tree":
			// Return two child components for the project
			component := r.URL.Query().Get("component")
			if component == "test-project" {
				w.Header().Set("Content-Type", "application/json")
				_, _ = fmt.Fprint(w, `{"paging":{"pageIndex":1,"pageSize":500,"total":2},"components":[{"key":"test-project:src/main","name":"src/main","qualifier":"DIR","path":"src/main"},{"key":"test-project:src/test","name":"src/test","qualifier":"DIR","path":"src/test"}]}`)
			} else {
				w.Header().Set("Content-Type", "application/json")
				_, _ = fmt.Fprint(w, `{"paging":{"pageIndex":1,"pageSize":500,"total":0},"components":[]}`)
			}

		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})

	f := newTestFetcher(t, srv.URL)
	t.Setenv("SONARQUBE_TOKEN", "tok")

	data, err := f.Fetch(context.Background())
	require.NoError(t, err)

	result := mustUnmarshalSonarqube(t, data)

	// Should have fetched all 12000 issues via component tree (8000 + 4000)
	assert.Equal(t, 12000, len(result.Issues), "should fetch all issues via component tree traversal")

	// Verify keys are unique (no duplicates)
	seen := make(map[string]bool)
	for _, issue := range result.Issues {
		assert.False(t, seen[issue.Key], "duplicate issue key: %s", issue.Key)
		seen[issue.Key] = true
	}
}

func TestSonarqubeFetcher_NoComponentTreeWhenUnderLimit(t *testing.T) {
	// When total < 10K, normal pagination should work without component tree
	var componentTreeSeen bool
	srv := sonarqubeServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/components/tree" {
			componentTreeSeen = true
		}
		issues := []sonarqubeconv.Issue{
			{Key: "i1", Rule: "java:S001", Severity: "MAJOR", Component: "p:f",
				Project: "p", Status: "OPEN", Message: "m",
				CreationDate: "2026-01-01T00:00:00+0000",
				UpdateDate:   "2026-01-01T00:00:00+0000", Type: "BUG"},
		}
		writeIssuesPage(w, issues, nil, nil, 1, 1)
	})

	f := newTestFetcher(t, srv.URL)
	t.Setenv("SONARQUBE_TOKEN", "tok")

	data, err := f.Fetch(context.Background())
	require.NoError(t, err)

	result := mustUnmarshalSonarqube(t, data)
	assert.Len(t, result.Issues, 1)
	assert.False(t, componentTreeSeen, "should not use component tree when under 10K limit")
}
