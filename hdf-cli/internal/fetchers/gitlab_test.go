package fetchers

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---- helpers ----

func gitlabServer(t *testing.T, handler http.HandlerFunc) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return srv
}

func newTestGitLabFetcher(t *testing.T, serverURL string) *GitLabFetcher {
	t.Helper()
	f, err := newGitLabFetcherWithClient(GitLabParams{
		URL:       serverURL,
		ProjectID: "test-project",
		Ref:       "main",
		ScanType:  "sast",
		JobName:   "semgrep-sast",
	}, &http.Client{})
	require.NoError(t, err)
	return f
}

// gitlabTokenTestCase defines a single token resolution test.
type gitlabTokenTestCase struct {
	gitlabToken   string
	glabToken     string
	glabConfigDir string // if non-empty, set GLAB_CONFIG_DIR
	expectedToken string
	expectError   bool
	errorContains string
}

// runGitLabTokenTest is a shared helper for token resolution tests to avoid duplication.
func runGitLabTokenTest(t *testing.T, tc gitlabTokenTestCase) {
	t.Helper()
	var capturedAuth string
	srv := gitlabServer(t, func(w http.ResponseWriter, r *http.Request) {
		capturedAuth = r.Header.Get("PRIVATE-TOKEN")
		_, _ = fmt.Fprint(w, minimalGitLabReport)
	})

	f := newTestGitLabFetcher(t, srv.URL)
	t.Setenv("GITLAB_TOKEN", tc.gitlabToken)
	t.Setenv("GLAB_TOKEN", tc.glabToken)
	if tc.glabConfigDir != "" {
		t.Setenv("GLAB_CONFIG_DIR", tc.glabConfigDir)
	}

	_, err := f.Fetch(context.Background())
	if tc.expectError {
		require.Error(t, err)
		if tc.errorContains != "" {
			assert.Contains(t, err.Error(), tc.errorContains)
		}
		return
	}
	require.NoError(t, err)
	assert.Equal(t, tc.expectedToken, capturedAuth)
}

// minimalGitLabReport is a valid GitLab security report JSON for testing.
const minimalGitLabReport = `{
	"version": "15.0.0",
	"scan": {
		"scanner": {"id": "semgrep", "name": "Semgrep", "version": "1.0.0"},
		"type": "sast",
		"start_time": "2026-01-15T10:00:00",
		"end_time": "2026-01-15T10:05:00",
		"status": "success"
	},
	"vulnerabilities": [{
		"id": "vuln-1",
		"name": "SQL Injection",
		"description": "User input used in SQL query",
		"severity": "Critical",
		"solution": "Use parameterized queries",
		"identifiers": [{"type": "cwe", "name": "CWE-89", "value": "89"}],
		"location": {"file": "app.py", "start_line": 42}
	}]
}`

// ---- URL validation tests ----

func TestNewGitLabFetcher_URLValidation(t *testing.T) { //nolint:dupl // URL validation pattern shared across fetcher tests
	valid := []string{
		"http://gitlab.example.com",
		"https://gitlab.example.com",
		"http://localhost:8080",
		"https://gitlab.com",
	}
	for _, u := range valid {
		t.Run("valid/"+u, func(t *testing.T) {
			_, err := NewGitLabFetcher(GitLabParams{URL: u, ProjectID: "proj", JobName: "job"}, TLSOptions{})
			assert.NoError(t, err, "URL %q should be valid", u)
		})
	}

	invalid := []string{
		"",
		"ftp://gitlab.example.com",
		"file:///etc/passwd",
		"ssh://host",
		"not-a-url",
	}
	for _, u := range invalid {
		t.Run("invalid/"+u, func(t *testing.T) {
			_, err := NewGitLabFetcher(GitLabParams{URL: u, ProjectID: "proj", JobName: "job"}, TLSOptions{})
			require.Error(t, err)
		})
	}
}

// ---- token resolution tests ----

func TestGitLabFetcher_TokenResolution(t *testing.T) {
	t.Run("GITLAB_TOKEN", func(t *testing.T) {
		runGitLabTokenTest(t, gitlabTokenTestCase{
			gitlabToken:   "glpat-test-token",
			glabToken:     "",
			expectedToken: "glpat-test-token",
		})
	})

	t.Run("GLAB_TOKEN fallback", func(t *testing.T) {
		runGitLabTokenTest(t, gitlabTokenTestCase{
			gitlabToken:   "",
			glabToken:     "glab-fallback-token",
			expectedToken: "glab-fallback-token",
		})
	})

	t.Run("GITLAB_TOKEN takes priority", func(t *testing.T) {
		runGitLabTokenTest(t, gitlabTokenTestCase{
			gitlabToken:   "primary-token",
			glabToken:     "fallback-token",
			expectedToken: "primary-token",
		})
	})

	t.Run("missing all sources", func(t *testing.T) {
		runGitLabTokenTest(t, gitlabTokenTestCase{
			gitlabToken:   "",
			glabToken:     "",
			glabConfigDir: t.TempDir(),
			expectError:   true,
			errorContains: "GITLAB_TOKEN",
		})
	})
}

func TestGitLabFetcher_TokenFromGlabConfig(t *testing.T) {
	t.Run("bare hostname", func(t *testing.T) {
		configDir := t.TempDir()
		configPath := filepath.Join(configDir, "config.yml")
		configContent := "hosts:\n  127.0.0.1:\n    token: test-config-value\n" //nolint:gosec // test-only credential
		require.NoError(t, os.WriteFile(configPath, []byte(configContent), 0o600))

		runGitLabTokenTest(t, gitlabTokenTestCase{ //nolint:gosec // test-only credential in config fixture
			gitlabToken:   "",
			glabToken:     "",
			glabConfigDir: configDir,
			expectedToken: "test-config-value",
		})
	})

	t.Run("hostname with port", func(t *testing.T) {
		// glab stores "localhost:9090" as the config key when authenticating
		// to a non-standard port. The fetcher must match the exact host:port.
		srv := gitlabServer(t, func(w http.ResponseWriter, r *http.Request) {
			_, _ = fmt.Fprint(w, minimalGitLabReport)
		})

		// Extract the test server's host:port so the config key matches.
		srvURL, err := url.Parse(srv.URL)
		require.NoError(t, err)

		configDir := t.TempDir()
		configPath := filepath.Join(configDir, "config.yml")
		configContent := fmt.Sprintf("hosts:\n  %s:\n    token: port-config-value\n", srvURL.Host) //nolint:gosec // test-only credential
		require.NoError(t, os.WriteFile(configPath, []byte(configContent), 0o600))                 //#nosec G703 -- test fixture in t.TempDir()

		f, err := newGitLabFetcherWithClient(GitLabParams{
			URL:       srv.URL,
			ProjectID: "test-project",
			Ref:       "main",
			ScanType:  "sast",
			JobName:   "semgrep-sast",
		}, &http.Client{})
		require.NoError(t, err)

		t.Setenv("GITLAB_TOKEN", "")
		t.Setenv("GLAB_TOKEN", "")
		t.Setenv("GLAB_CONFIG_DIR", configDir)

		_, err = f.Fetch(context.Background())
		require.NoError(t, err)
	})
}

func TestGitLabFetcher_TokenNotInErrorMessages(t *testing.T) {
	srv := gitlabServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	})

	f := newTestGitLabFetcher(t, srv.URL)
	testToken := "glpat-test-only-value-00000" //nolint:gosec // test-only credential
	t.Setenv("GITLAB_TOKEN", testToken)

	_, err := f.Fetch(context.Background())
	require.Error(t, err)
	assert.NotContains(t, err.Error(), testToken, "token must not appear in error messages")
	assert.NotContains(t, err.Error(), "PRIVATE-TOKEN", "auth header name must not appear in error messages")
}

// ---- HTTP response tests ----

func TestGitLabFetcher_SuccessfulFetch(t *testing.T) {
	srv := gitlabServer(t, func(w http.ResponseWriter, r *http.Request) {
		assert.Contains(t, r.URL.Path, "/api/v4/projects/")
		assert.Contains(t, r.URL.Path, "/jobs/artifacts/")
		assert.Contains(t, r.URL.Path, "/raw/gl-sast-report.json")
		assert.Equal(t, "semgrep-sast", r.URL.Query().Get("job"))
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, minimalGitLabReport)
	})

	f := newTestGitLabFetcher(t, srv.URL)
	t.Setenv("GITLAB_TOKEN", "tok")

	data, err := f.Fetch(context.Background())
	require.NoError(t, err)
	assert.Contains(t, string(data), "vuln-1")
	assert.Contains(t, string(data), "SQL Injection")
}

func TestGitLabFetcher_HTTPErrors(t *testing.T) {
	codes := []int{http.StatusUnauthorized, http.StatusNotFound, http.StatusInternalServerError}
	for _, code := range codes {
		t.Run(fmt.Sprintf("HTTP_%d", code), func(t *testing.T) {
			srv := gitlabServer(t, func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(code)
			})
			f := newTestGitLabFetcher(t, srv.URL)
			t.Setenv("GITLAB_TOKEN", "tok")
			_, err := f.Fetch(context.Background())
			require.Error(t, err)
			assert.Contains(t, err.Error(), fmt.Sprintf("%d", code))
		})
	}
}

// ---- context tests ----

func TestGitLabFetcher_ContextCancelled(t *testing.T) {
	srv := gitlabServer(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, minimalGitLabReport)
	})

	f := newTestGitLabFetcher(t, srv.URL)
	t.Setenv("GITLAB_TOKEN", "tok")

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel before fetch

	_, err := f.Fetch(ctx)
	require.Error(t, err)
}

func TestGitLabFetcher_ResponseSizeLimit(t *testing.T) {
	// Use a small limit for the test to avoid allocating 10MB.
	const testLimit int64 = 1024

	oversizedBody := make([]byte, testLimit+1)
	for i := range oversizedBody {
		oversizedBody[i] = 'x'
	}

	srv := gitlabServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(oversizedBody)
	})

	t.Run("exceeds limit", func(t *testing.T) {
		f, err := newGitLabFetcherWithClient(GitLabParams{
			URL:             srv.URL,
			ProjectID:       "proj",
			Ref:             "main",
			ScanType:        "sast",
			JobName:         "job",
			MaxResponseSize: testLimit,
		}, &http.Client{})
		require.NoError(t, err)
		t.Setenv("GITLAB_TOKEN", "tok")

		_, err = f.Fetch(context.Background())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "exceeded")
	})

	t.Run("no limit allows large response", func(t *testing.T) {
		f, err := newGitLabFetcherWithClient(GitLabParams{
			URL:             srv.URL,
			ProjectID:       "proj",
			Ref:             "main",
			ScanType:        "sast",
			JobName:         "job",
			MaxResponseSize: -1,
		}, &http.Client{})
		require.NoError(t, err)
		t.Setenv("GITLAB_TOKEN", "tok")

		data, err := f.Fetch(context.Background())
		require.NoError(t, err)
		assert.Len(t, data, int(testLimit+1))
	})

	t.Run("custom higher limit allows response", func(t *testing.T) {
		f, err := newGitLabFetcherWithClient(GitLabParams{
			URL:             srv.URL,
			ProjectID:       "proj",
			Ref:             "main",
			ScanType:        "sast",
			JobName:         "job",
			MaxResponseSize: testLimit + 100,
		}, &http.Client{})
		require.NoError(t, err)
		t.Setenv("GITLAB_TOKEN", "tok")

		data, err := f.Fetch(context.Background())
		require.NoError(t, err)
		assert.Len(t, data, int(testLimit+1))
	})
}

// contextCapturingGitLabTransport records the request context.
type contextCapturingGitLabTransport struct {
	inner       http.RoundTripper
	capturedCtx context.Context
}

func (t *contextCapturingGitLabTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	t.capturedCtx = req.Context()
	return t.inner.RoundTrip(req)
}

func TestGitLabFetcher_DefaultTimeoutApplied(t *testing.T) {
	srv := gitlabServer(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, minimalGitLabReport)
	})

	capturingTransport := &contextCapturingGitLabTransport{inner: http.DefaultTransport}
	f, err := newGitLabFetcherWithClient(GitLabParams{
		URL:       srv.URL,
		ProjectID: "test-project",
		Ref:       "main",
		ScanType:  "sast",
		JobName:   "semgrep-sast",
	}, &http.Client{Transport: capturingTransport})
	require.NoError(t, err)
	t.Setenv("GITLAB_TOKEN", "tok")

	ctx := context.Background()
	_, hasDeadline := ctx.Deadline()
	require.False(t, hasDeadline, "precondition: background context has no deadline")

	_, err = f.Fetch(ctx)
	require.NoError(t, err)

	require.NotNil(t, capturingTransport.capturedCtx, "transport should have captured a context")
	_, deadlineSet := capturingTransport.capturedCtx.Deadline()
	assert.True(t, deadlineSet, "Fetch must wrap a deadline-free context with a timeout")
}

// ---- scan type and artifact path tests ----

func TestArtifactPathForScanType(t *testing.T) {
	tests := []struct {
		scanType string
		expected string
	}{
		{"sast", "gl-sast-report.json"},
		{"dast", "gl-dast-report.json"},
		{"dependency-scanning", "gl-dependency-scanning-report.json"},
		{"container-scanning", "gl-container-scanning-report.json"},
		{"secret-detection", "gl-secret-detection-report.json"},
		{"api-fuzzing", "gl-api-fuzzing-report.json"},
		{"", "gl-sast-report.json"},
		{"unknown", "gl-sast-report.json"},
	}

	for _, tt := range tests {
		t.Run(tt.scanType, func(t *testing.T) {
			result := artifactPathForScanType(tt.scanType)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestGitLabFetcher_URLPathConstruction(t *testing.T) {
	t.Run("custom artifact path", func(t *testing.T) {
		var capturedPath string
		srv := gitlabServer(t, func(w http.ResponseWriter, r *http.Request) {
			capturedPath = r.URL.Path
			_, _ = fmt.Fprint(w, minimalGitLabReport)
		})

		f, err := newGitLabFetcherWithClient(GitLabParams{
			URL:          srv.URL,
			ProjectID:    "my-project",
			Ref:          "main",
			ArtifactPath: "custom/report.json",
			JobName:      "my-job",
		}, &http.Client{})
		require.NoError(t, err)
		t.Setenv("GITLAB_TOKEN", "tok")

		_, err = f.Fetch(context.Background())
		require.NoError(t, err)
		assert.Contains(t, capturedPath, "custom/report.json")
	})

	t.Run("namespace project ID not double-encoded", func(t *testing.T) {
		var capturedPath string
		srv := gitlabServer(t, func(w http.ResponseWriter, r *http.Request) {
			capturedPath = r.URL.RawPath // RawPath preserves %2F
			if capturedPath == "" {
				capturedPath = r.URL.Path
			}
			_, _ = fmt.Fprint(w, minimalGitLabReport)
		})

		f, err := newGitLabFetcherWithClient(GitLabParams{
			URL:       srv.URL,
			ProjectID: "namespace/project",
			Ref:       "main",
			ScanType:  "sast",
			JobName:   "semgrep-sast",
		}, &http.Client{})
		require.NoError(t, err)
		t.Setenv("GITLAB_TOKEN", "tok")

		_, err = f.Fetch(context.Background())
		require.NoError(t, err)
		// The path must contain %2F, not %252F (double-encoded) or a bare /
		// that would split the project ID into two path segments.
		assert.Contains(t, capturedPath, "/projects/namespace%2Fproject/",
			"namespace/project must be encoded as namespace%%2Fproject, not double-encoded")
	})

	t.Run("default ref", func(t *testing.T) {
		var capturedPath string
		srv := gitlabServer(t, func(w http.ResponseWriter, r *http.Request) {
			capturedPath = r.URL.Path
			_, _ = fmt.Fprint(w, minimalGitLabReport)
		})

		f, err := newGitLabFetcherWithClient(GitLabParams{
			URL:       srv.URL,
			ProjectID: "my-project",
			ScanType:  "sast",
			JobName:   "my-job",
		}, &http.Client{})
		require.NoError(t, err)
		t.Setenv("GITLAB_TOKEN", "tok")

		_, err = f.Fetch(context.Background())
		require.NoError(t, err)
		assert.Contains(t, capturedPath, "/artifacts/main/")
	})
}

// ---- FetchAndConvert integration test ----

func TestGitLabFetcher_FetchAndConvert(t *testing.T) {
	srv := gitlabServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, minimalGitLabReport)
	})

	f := newTestGitLabFetcher(t, srv.URL)
	t.Setenv("GITLAB_TOKEN", "tok")

	raw, err := f.Fetch(context.Background())
	require.NoError(t, err)

	// Verify the output contains expected GitLab report fields
	assert.NotEmpty(t, raw)
	assert.Contains(t, string(raw), "vulnerabilities")
	assert.Contains(t, string(raw), "scan")
}
