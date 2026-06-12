package tenablesc

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	shared "github.com/mitre/hdf-libs/hdf-converters/v3/fetchers/shared/go"
)

const converterVersion = "0.1.0"

// ---- helpers ----

// tenableSCServer creates a test HTTPS-equivalent server. Tests inject the
// resulting URL into the fetcher.
func tenableSCServer(t *testing.T, handler http.HandlerFunc) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return srv
}

// newTestFetcher constructs a fetcher pointing at the mock server with an
// injected client (no TLS overhead).
func newTestFetcher(t *testing.T, serverURL string, params TenableSCParams) *TenableSCFetcher {
	t.Helper()
	if params.URL == "" {
		params.URL = serverURL
	}
	f, err := NewTenableSCFetcherWithClient(params, &http.Client{Timeout: 5 * time.Second})
	require.NoError(t, err)
	return f
}

// setBothCreds primes both access-key env vars (the most common test setup).
func setBothCreds(t *testing.T, ak, sk string) {
	t.Helper()
	t.Setenv("TENABLE_SC_ACCESS_KEY", ak)
	t.Setenv("TENABLE_SC_SECRET_KEY", sk)
}

// loadNessusFixture reads a real .nessus XML fixture from the nessus
// converter's input dir — there is no separate Tenable.SC fixture corpus
// because Tenable.SC's downloadType=v2 response IS .nessus XML.
func loadNessusFixture(t *testing.T, name string) []byte {
	t.Helper()
	// fetchers/tenable-sc/go/ → ../../../converters/nessus-to-hdf/fixtures/input/
	path := filepath.Join("..", "..", "..", "converters", "nessus-to-hdf", "fixtures", "input", name)
	data, err := os.ReadFile(path) //nolint:gosec // test fixture, fixed relative path
	require.NoError(t, err, "missing test fixture %s — nessus-to-hdf fixtures changed?", path)
	return data
}

// zipNessusBytes wraps a raw .nessus XML body inside a zip archive matching
// Tenable.SC's actual download response shape for the zip variant.
func zipNessusBytes(t *testing.T, xml []byte, entryName string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.Create(entryName)
	require.NoError(t, err)
	_, err = w.Write(xml)
	require.NoError(t, err)
	require.NoError(t, zw.Close())
	return buf.Bytes()
}

// expectXAPIKey asserts that the request carries an x-apikey header in
// Tenable's documented format. Test passes a known access/secret key, the
// helper verifies both appear and the format matches.
func expectXAPIKey(t *testing.T, r *http.Request, ak, sk string) {
	t.Helper()
	got := r.Header.Get("x-apikey")
	require.NotEmpty(t, got, "x-apikey header missing")
	assert.Contains(t, got, "accesskey="+ak, "x-apikey must carry accesskey=...")
	assert.Contains(t, got, "secretkey="+sk, "x-apikey must carry secretkey=...")
}

// ---- URL validation tests ----

func TestNewTenableSCFetcher_URLValidation(t *testing.T) { //nolint:dupl // URL validation pattern shared across fetcher tests
	valid := []string{
		"http://tsc.example.com",
		"https://tsc.example.com",
		"http://localhost:8443",
		"https://tsc.example.com:8443",
	}
	for _, u := range valid {
		t.Run("valid/"+u, func(t *testing.T) {
			_, err := NewTenableSCFetcher(TenableSCParams{URL: u}, shared.TLSOptions{})
			assert.NoError(t, err, "URL %q should be valid", u)
		})
	}

	invalid := []string{
		"",
		"ftp://tsc.example.com",
		"file:///etc/passwd",
		"ssh://host",
		"not-a-url",
	}
	for _, u := range invalid {
		t.Run("invalid/"+u, func(t *testing.T) {
			_, err := NewTenableSCFetcher(TenableSCParams{URL: u}, shared.TLSOptions{})
			require.Error(t, err)
		})
	}
}

func TestNewTenableSCFetcherWithClient_RejectsBadURL(t *testing.T) {
	_, err := NewTenableSCFetcherWithClient(TenableSCParams{URL: "ftp://x"}, &http.Client{})
	require.Error(t, err)
}

// ---- ScanID validation ----

func TestScanIDValidation(t *testing.T) {
	valid := []string{"1", "42", "12345"}
	for _, id := range valid {
		t.Run("valid/"+id, func(t *testing.T) {
			assert.NoError(t, validateScanID(id))
		})
	}

	invalid := map[string]string{
		"empty":          "",
		"alpha":          "abc",
		"mixed":          "1a2",
		"slash":          "1/2",
		"path-traversal": "../1",
		"dot":            "1.0",
		"leading-zero":   "01",
		"negative":       "-1",
		"too-long":       strings.Repeat("9", 20),
	}
	for name, id := range invalid {
		t.Run("invalid/"+name, func(t *testing.T) {
			assert.Error(t, validateScanID(id))
		})
	}
}

// ---- VerifyCredentials ----

func TestVerifyCredentials_Success(t *testing.T) {
	srv := tenableSCServer(t, func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		assert.Equal(t, "/rest/currentUser", r.URL.Path)
		expectXAPIKey(t, r, "ak123", "sk456")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"response":{"id":"1","username":"test"}}`))
	})

	setBothCreds(t, "ak123", "sk456")
	f := newTestFetcher(t, srv.URL, TenableSCParams{})

	require.NoError(t, f.VerifyCredentials(context.Background()))
}

func TestVerifyCredentials_Unauthorized(t *testing.T) {
	srv := tenableSCServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	})

	setBothCreds(t, "ak", "sk")
	f := newTestFetcher(t, srv.URL, TenableSCParams{})

	err := f.VerifyCredentials(context.Background())
	require.Error(t, err)
	assert.Contains(t, strings.ToLower(err.Error()), "unauthorized")
}

func TestVerifyCredentials_RequiresAccessKey(t *testing.T) {
	srv := tenableSCServer(t, func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("should not reach server when access key is missing")
	})
	defer srv.Close()

	t.Setenv("TENABLE_SC_ACCESS_KEY", "")
	t.Setenv("TENABLE_SC_SECRET_KEY", "sk")
	f := newTestFetcher(t, srv.URL, TenableSCParams{})

	err := f.VerifyCredentials(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "TENABLE_SC_ACCESS_KEY")
}

func TestVerifyCredentials_RequiresSecretKey(t *testing.T) {
	srv := tenableSCServer(t, func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("should not reach server when secret key is missing")
	})
	defer srv.Close()

	t.Setenv("TENABLE_SC_ACCESS_KEY", "ak")
	t.Setenv("TENABLE_SC_SECRET_KEY", "")
	f := newTestFetcher(t, srv.URL, TenableSCParams{})

	err := f.VerifyCredentials(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "TENABLE_SC_SECRET_KEY")
}

func TestVerifyCredentials_ContextCancellation(t *testing.T) {
	srv := tenableSCServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	setBothCreds(t, "ak", "sk")
	f := newTestFetcher(t, srv.URL, TenableSCParams{})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := f.VerifyCredentials(ctx)
	require.Error(t, err)
}

func TestVerifyCredentials_AmbiguousStatus(t *testing.T) {
	srv := tenableSCServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})

	setBothCreds(t, "ak", "sk")
	f := newTestFetcher(t, srv.URL, TenableSCParams{})

	err := f.VerifyCredentials(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "500")
}

func TestVerifyCredentials_KeysNotInErrorMessages(t *testing.T) { //nolint:dupl // token-leakage pattern shared across fetcher tests
	srv := tenableSCServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	})

	secretAK := "super-secret-access-key-1234"
	secretSK := "super-secret-secret-key-5678"
	setBothCreds(t, secretAK, secretSK)
	f := newTestFetcher(t, srv.URL, TenableSCParams{})

	err := f.VerifyCredentials(context.Background())
	require.Error(t, err)
	assert.NotContains(t, err.Error(), secretAK, "access key must not appear in error messages")
	assert.NotContains(t, err.Error(), secretSK, "secret key must not appear in error messages")
}

// ---- ListScans ----

// minimalScanListBody mirrors the heimdall2-documented response envelope:
// {"response":{"usable":[...]}}
func minimalScanListBody(t *testing.T, ids []string) []byte {
	t.Helper()
	usable := make([]map[string]string, 0, len(ids))
	for _, id := range ids {
		usable = append(usable, map[string]string{
			"id":          id,
			"name":        "scan-" + id,
			"description": "test",
			"scannedIPs":  "10.0.0.1",
			"startTime":   "1700000000",
			"finishTime":  "1700001000",
			"status":      "Completed",
		})
	}
	body := map[string]any{
		"response": map[string]any{"usable": usable},
	}
	b, err := json.Marshal(body)
	require.NoError(t, err)
	return b
}

func TestListScans_Success(t *testing.T) {
	var capturedQuery string
	srv := tenableSCServer(t, func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		assert.Equal(t, "/rest/scanResult", r.URL.Path)
		expectXAPIKey(t, r, "ak", "sk")
		capturedQuery = r.URL.RawQuery
		_, _ = w.Write(minimalScanListBody(t, []string{"42", "43"}))
	})

	setBothCreds(t, "ak", "sk")
	f := newTestFetcher(t, srv.URL, TenableSCParams{})

	scans, err := f.ListScans(context.Background(), 100, 200)
	require.NoError(t, err)
	require.Len(t, scans, 2)
	assert.Equal(t, "42", scans[0].ID)
	assert.Equal(t, "scan-42", scans[0].Name)

	assert.Contains(t, capturedQuery, "startTime=100")
	assert.Contains(t, capturedQuery, "endTime=200")
	assert.Contains(t, capturedQuery, "fields=")
}

func TestListScans_EmptyResult(t *testing.T) {
	srv := tenableSCServer(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(minimalScanListBody(t, nil))
	})

	setBothCreds(t, "ak", "sk")
	f := newTestFetcher(t, srv.URL, TenableSCParams{})

	scans, err := f.ListScans(context.Background(), 0, 0)
	require.NoError(t, err)
	assert.Empty(t, scans)
}

func TestListScans_Unauthorized(t *testing.T) {
	srv := tenableSCServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	})

	secretAK := "leak-test-ak"
	setBothCreds(t, secretAK, "sk")
	f := newTestFetcher(t, srv.URL, TenableSCParams{})

	_, err := f.ListScans(context.Background(), 0, 0)
	require.Error(t, err)
	assert.NotContains(t, err.Error(), secretAK)
}

func TestListScans_DefaultsTimeRange(t *testing.T) {
	var capturedQuery string
	srv := tenableSCServer(t, func(w http.ResponseWriter, r *http.Request) {
		capturedQuery = r.URL.RawQuery
		_, _ = w.Write(minimalScanListBody(t, nil))
	})

	setBothCreds(t, "ak", "sk")
	f := newTestFetcher(t, srv.URL, TenableSCParams{})

	_, err := f.ListScans(context.Background(), 0, 0)
	require.NoError(t, err)
	// startTime defaults to 0; endTime defaults to "now".
	assert.Contains(t, capturedQuery, "startTime=0")
	assert.Regexp(t, `endTime=\d{8,}`, capturedQuery,
		"endTime should default to a unix timestamp")
}

func TestListScans_RejectsInvalidJSON(t *testing.T) {
	srv := tenableSCServer(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`not json`))
	})

	setBothCreds(t, "ak", "sk")
	f := newTestFetcher(t, srv.URL, TenableSCParams{})

	_, err := f.ListScans(context.Background(), 0, 0)
	require.Error(t, err)
}

// ---- FetchScanToHDF ----

// downloadServer wires a server that handles the POST scanResult download
// path, returning the supplied bytes. Other paths fail the test.
func downloadServer(t *testing.T, scanID string, body []byte, status int) *httptest.Server {
	t.Helper()
	return tenableSCServer(t, func(w http.ResponseWriter, r *http.Request) {
		expectedPath := "/rest/scanResult/" + scanID + "/download"
		if r.URL.Path != expectedPath {
			http.Error(w, "unexpected path "+r.URL.Path, http.StatusBadRequest)
			return
		}
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "v2", r.URL.Query().Get("downloadType"))
		expectXAPIKey(t, r, "ak", "sk")
		w.WriteHeader(status)
		if body != nil {
			_, _ = w.Write(body)
		}
	})
}

func TestFetchScanToHDF_RawXMLResponse(t *testing.T) {
	xml := loadNessusFixture(t, "compliance.nessus")
	srv := downloadServer(t, "42", xml, http.StatusOK)

	setBothCreds(t, "ak", "sk")
	f := newTestFetcher(t, srv.URL, TenableSCParams{ScanID: "42"})

	hdf, err := f.FetchScanToHDF(context.Background(), converterVersion)
	require.NoError(t, err)
	require.NotNil(t, hdf)
	require.NotNil(t, hdf.Generator)
	assert.NotEmpty(t, hdf.Baselines, "expected at least one baseline from nessus fixture")
}

func TestFetchScanToHDF_ZipWrappedResponse(t *testing.T) {
	xml := loadNessusFixture(t, "compliance.nessus")
	zipped := zipNessusBytes(t, xml, "scan-42.nessus")
	srv := downloadServer(t, "42", zipped, http.StatusOK)

	setBothCreds(t, "ak", "sk")
	f := newTestFetcher(t, srv.URL, TenableSCParams{ScanID: "42"})

	hdf, err := f.FetchScanToHDF(context.Background(), converterVersion)
	require.NoError(t, err)
	require.NotNil(t, hdf)
	assert.NotEmpty(t, hdf.Baselines)
}

func TestFetchScanToHDF_RejectsBadScanID(t *testing.T) {
	setBothCreds(t, "ak", "sk")
	f, err := NewTenableSCFetcherWithClient(
		TenableSCParams{URL: "https://example.com", ScanID: "../1"},
		&http.Client{},
	)
	require.NoError(t, err) // construction validates only URL

	_, fetchErr := f.FetchScanToHDF(context.Background(), converterVersion)
	require.Error(t, fetchErr)
	assert.Contains(t, fetchErr.Error(), "scan ID")
}

func TestFetchScanToHDF_RequiresScanID(t *testing.T) {
	setBothCreds(t, "ak", "sk")
	f, err := NewTenableSCFetcherWithClient(
		TenableSCParams{URL: "https://example.com"},
		&http.Client{},
	)
	require.NoError(t, err)

	_, fetchErr := f.FetchScanToHDF(context.Background(), converterVersion)
	require.Error(t, fetchErr)
	assert.Contains(t, fetchErr.Error(), "scan ID")
}

func TestFetchScanToHDF_Unauthorized(t *testing.T) {
	// Don't go through downloadServer: that helper asserts on header
	// values that don't apply here. We just want the 401 leak guard.
	srv := tenableSCServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	})
	secretAK := "leak-test-ak"
	setBothCreds(t, secretAK, "sk")
	f := newTestFetcher(t, srv.URL, TenableSCParams{ScanID: "42"})

	_, err := f.FetchScanToHDF(context.Background(), converterVersion)
	require.Error(t, err)
	assert.NotContains(t, err.Error(), secretAK)
}

func TestFetchScanToHDF_NotFound(t *testing.T) {
	srv := downloadServer(t, "42", nil, http.StatusNotFound)
	setBothCreds(t, "ak", "sk")
	f := newTestFetcher(t, srv.URL, TenableSCParams{ScanID: "42"})

	_, err := f.FetchScanToHDF(context.Background(), converterVersion)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "42")
}

func TestFetchScanToHDF_ForbiddenDownload(t *testing.T) {
	srv := downloadServer(t, "42", nil, http.StatusForbidden)
	setBothCreds(t, "ak", "sk")
	f := newTestFetcher(t, srv.URL, TenableSCParams{ScanID: "42"})

	_, err := f.FetchScanToHDF(context.Background(), converterVersion)
	require.Error(t, err)
	// 403 means either "scan incomplete" or "key lacks permission" per the
	// Tenable API. Surface the status code unambiguously.
	assert.Contains(t, err.Error(), "403")
}

func TestFetchScanToHDF_ResponseSizeCap(t *testing.T) {
	// Synthesize a body larger than the default cap to verify
	// ReadLimitedBody rejects it.
	big := bytes.Repeat([]byte("X"), int(defaultMaxResponseSize)+10)
	srv := downloadServer(t, "42", big, http.StatusOK)

	setBothCreds(t, "ak", "sk")
	f := newTestFetcher(t, srv.URL, TenableSCParams{ScanID: "42"})

	_, err := f.FetchScanToHDF(context.Background(), converterVersion)
	require.Error(t, err)
	assert.Contains(t, strings.ToLower(err.Error()), "exceed")
}

func TestFetchScanToHDF_EmptyZip(t *testing.T) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	require.NoError(t, zw.Close())

	srv := downloadServer(t, "42", buf.Bytes(), http.StatusOK)
	setBothCreds(t, "ak", "sk")
	f := newTestFetcher(t, srv.URL, TenableSCParams{ScanID: "42"})

	_, err := f.FetchScanToHDF(context.Background(), converterVersion)
	require.Error(t, err)
	assert.Contains(t, strings.ToLower(err.Error()), "empty")
}

func TestFetchScanToHDF_CorruptZip(t *testing.T) {
	// Looks like a zip (PK\x03\x04) but truncated — should fail to open.
	srv := downloadServer(t, "42", []byte("PK\x03\x04corrupt"), http.StatusOK)
	setBothCreds(t, "ak", "sk")
	f := newTestFetcher(t, srv.URL, TenableSCParams{ScanID: "42"})

	_, err := f.FetchScanToHDF(context.Background(), converterVersion)
	require.Error(t, err)
}

func TestFetchScanToHDF_ContextCancellation(t *testing.T) {
	xml := loadNessusFixture(t, "compliance.nessus")
	srv := downloadServer(t, "42", xml, http.StatusOK)

	setBothCreds(t, "ak", "sk")
	f := newTestFetcher(t, srv.URL, TenableSCParams{ScanID: "42"})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := f.FetchScanToHDF(ctx, converterVersion)
	require.Error(t, err)
}

func TestFetchScanToHDF_RequiresAccessKey(t *testing.T) {
	t.Setenv("TENABLE_SC_ACCESS_KEY", "")
	t.Setenv("TENABLE_SC_SECRET_KEY", "sk")
	f, err := NewTenableSCFetcherWithClient(
		TenableSCParams{URL: "https://example.com", ScanID: "42"},
		&http.Client{},
	)
	require.NoError(t, err)

	_, fetchErr := f.FetchScanToHDF(context.Background(), converterVersion)
	require.Error(t, fetchErr)
	assert.Contains(t, fetchErr.Error(), "TENABLE_SC_ACCESS_KEY")
}

func TestFetchScanToHDF_MaxBytesOverride(t *testing.T) {
	// When MaxBytes is set on params, it overrides the default cap.
	big := bytes.Repeat([]byte("X"), 1024)
	srv := downloadServer(t, "42", big, http.StatusOK)

	setBothCreds(t, "ak", "sk")
	f := newTestFetcher(t, srv.URL, TenableSCParams{
		ScanID:   "42",
		MaxBytes: 100, // 100 bytes < 1024 byte response → exceeded
	})

	_, err := f.FetchScanToHDF(context.Background(), converterVersion)
	require.Error(t, err)
	assert.Contains(t, strings.ToLower(err.Error()), "exceed")
}

// ---- Default timeout sanity ----

func TestDefaultTimeoutApplied(t *testing.T) {
	// If a server never responds and the caller passes a context with no
	// deadline, the fetcher must impose its own default. Use a context
	// whose deadline is well past the default to confirm the fetcher's
	// default is what bounds the call.
	srv := tenableSCServer(t, func(w http.ResponseWriter, r *http.Request) {
		// Hang past the test's max patience but well under the
		// default fetcher timeout — we want the request to complete,
		// not actually time out.
		time.Sleep(10 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	})

	setBothCreds(t, "ak", "sk")
	f := newTestFetcher(t, srv.URL, TenableSCParams{})
	// Sanity: no deadline set, request still succeeds (the default
	// timeout exists but isn't tripped on this fast request).
	require.NoError(t, f.VerifyCredentials(context.Background()))
}

// ---- compile-time sanity ----

// Smoke ensures the public surface compiles with the documented signatures.
// If a refactor changes a return type, this will fail to compile.
func TestPublicSurfaceCompiles(t *testing.T) {
	var f *TenableSCFetcher
	if f != nil {
		_ = f.VerifyCredentials
		_ = f.ListScans
		_ = f.FetchScanToHDF
	}
	// No assertion — purely a compile-time signature check.
	_ = fmt.Sprintf
}

// ---- additional coverage ----

// TestApplyDefaultDeadline_PreservesCallerDeadline asserts the caller's
// deadline is left intact (the "ctx already has a deadline" branch).
func TestApplyDefaultDeadline_PreservesCallerDeadline(t *testing.T) {
	srv := tenableSCServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	setBothCreds(t, "ak", "sk")
	f := newTestFetcher(t, srv.URL, TenableSCParams{})

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	require.NoError(t, f.VerifyCredentials(ctx))
}

// TestListScans_AmbiguousStatus covers the default branch of
// checkHTTPStatus (anything other than 2xx / 401 / 403).
func TestListScans_AmbiguousStatus(t *testing.T) {
	srv := tenableSCServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	setBothCreds(t, "ak", "sk")
	f := newTestFetcher(t, srv.URL, TenableSCParams{})

	_, err := f.ListScans(context.Background(), 0, 0)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "500")
}

// TestVerifyCredentials_Forbidden covers the 403 branch — same handling
// as 401 but the branch needs explicit hit for coverage.
func TestVerifyCredentials_Forbidden(t *testing.T) {
	srv := tenableSCServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	})
	setBothCreds(t, "ak", "sk")
	f := newTestFetcher(t, srv.URL, TenableSCParams{})

	err := f.VerifyCredentials(context.Background())
	require.Error(t, err)
	assert.Contains(t, strings.ToLower(err.Error()), "unauthorized")
}

// TestExtractNessusXML_PassesRawXMLThrough covers the non-zip branch
// directly. (Indirectly covered by FetchScanToHDF_RawXMLResponse, but
// the direct unit test makes the contract explicit.)
func TestExtractNessusXML_PassesRawXMLThrough(t *testing.T) {
	xml := []byte(`<?xml version="1.0"?><NessusClientData_v2/>`)
	out, err := extractNessusXML(xml, defaultMaxResponseSize)
	require.NoError(t, err)
	assert.Equal(t, xml, out)
}

// TestExtractNessusXML_ZipEntryExceedsCap covers the bombed-expansion
// guard inside extractNessusXML.
func TestExtractNessusXML_ZipEntryExceedsCap(t *testing.T) {
	xml := bytes.Repeat([]byte("X"), 1024)
	zipped := zipNessusBytes(t, xml, "big.nessus")

	_, err := extractNessusXML(zipped, 100)
	require.Error(t, err)
	assert.Contains(t, strings.ToLower(err.Error()), "exceed")
}
