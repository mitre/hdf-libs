// Package defectdojo fetches findings from a DefectDojo instance via its REST
// API (/api/v2/findings/) and returns the assembled response bytes, ready for
// the defectdojo-to-hdf converter. Findings are requested with
// ?related_fields=true so the underlying scanner (test_type) and the nested
// risk-acceptance provenance are available to the converter.
package defectdojo

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"time"

	shared "github.com/mitre/hdf-libs/hdf-converters/v3/fetchers/shared/go"
)

const (
	// defectDojoFetchTimeout is applied when the caller has not set a deadline.
	defectDojoFetchTimeout = 5 * time.Minute
	// defectDojoMaxResponseSize caps each page body to prevent memory exhaustion.
	defectDojoMaxResponseSize = 25 * 1024 * 1024
	// defectDojoMaxPages bounds the pagination loop.
	defectDojoMaxPages = 200
	// defectDojoPageSize is the per-page limit requested from the API.
	defectDojoPageSize = 100
	// defectDojoTokenEnv is the default environment variable holding the API token.
	defectDojoTokenEnv = "DEFECTDOJO_API_TOKEN" //nolint:gosec // env var name, not a credential
)

// DefectDojoParams holds parameters for a live DefectDojo findings fetch.
type DefectDojoParams struct {
	// URL is the DefectDojo instance base URL (required).
	URL string
	// ProductName filters findings to a product by name (optional).
	ProductName string
	// EngagementID filters findings to an engagement by id (optional).
	EngagementID string
	// TestID filters findings to a single test by id (optional).
	TestID string
	// TokenEnv overrides the environment variable read for the API token
	// (default: DEFECTDOJO_API_TOKEN). The token is never accepted as a value.
	TokenEnv string
	// MaxResponseSize overrides the default per-page response size limit.
	// 0 uses the default; -1 disables the limit.
	MaxResponseSize int64
	// MaxPages overrides the default pagination cap. 0 uses the default.
	MaxPages int
}

// DefectDojoFetcher fetches DefectDojo findings.
type DefectDojoFetcher struct {
	client *http.Client
	params DefectDojoParams
}

// NewDefectDojoFetcher creates a fetcher after validating the server URL. The
// token is resolved at Fetch time from the environment, never handled here.
func NewDefectDojoFetcher(params DefectDojoParams, tlsOpts shared.TLSOptions) (*DefectDojoFetcher, error) {
	if err := validateDefectDojoURL(params.URL); err != nil {
		return nil, err
	}
	client, err := shared.NewHTTPClient(tlsOpts)
	if err != nil {
		return nil, fmt.Errorf("defectdojo: failed to configure TLS: %w", err)
	}
	return &DefectDojoFetcher{client: client, params: params}, nil
}

// NewDefectDojoFetcherWithClient creates a fetcher with an injected HTTP client.
// Use this when the caller controls TLS/auth/transport (proxies, MFA, vaults,
// mocked clients in tests).
func NewDefectDojoFetcherWithClient(params DefectDojoParams, client *http.Client) (*DefectDojoFetcher, error) {
	if err := validateDefectDojoURL(params.URL); err != nil {
		return nil, err
	}
	return &DefectDojoFetcher{client: client, params: params}, nil
}

func validateDefectDojoURL(rawURL string) error {
	if rawURL == "" {
		return fmt.Errorf("defectdojo: URL is required")
	}
	if _, err := shared.ValidateAndBuildAPIURL(rawURL, "/", "DefectDojo"); err != nil {
		return fmt.Errorf("defectdojo: %w", err)
	}
	return nil
}

func (f *DefectDojoFetcher) tokenEnv() string {
	if f.params.TokenEnv != "" {
		return f.params.TokenEnv
	}
	return defectDojoTokenEnv
}

func (f *DefectDojoFetcher) resolveToken() (string, error) {
	token := os.Getenv(f.tokenEnv())
	if token == "" {
		return "", fmt.Errorf("defectdojo: API token not found in environment variable %s", f.tokenEnv())
	}
	return token, nil
}

func (f *DefectDojoFetcher) maxResponseSize() int64 {
	if f.params.MaxResponseSize != 0 {
		return f.params.MaxResponseSize
	}
	return defectDojoMaxResponseSize
}

func (f *DefectDojoFetcher) maxPages() int {
	if f.params.MaxPages > 0 {
		return f.params.MaxPages
	}
	return defectDojoMaxPages
}

func (f *DefectDojoFetcher) setAuth(req *http.Request, token string) {
	req.Header.Set("Authorization", "Token "+token)
	req.Header.Set("Accept", "application/json")
}

// findingsPage is the DRF pagination envelope for /api/v2/findings/.
type findingsPage struct {
	Next    *string           `json:"next"`
	Results []json.RawMessage `json:"results"`
}

// firstURL builds the initial findings request URL with filters and
// related_fields expansion.
func (f *DefectDojoFetcher) firstURL() (string, error) {
	apiURL, err := shared.ValidateAndBuildAPIURL(f.params.URL, "/api/v2/findings/", "DefectDojo")
	if err != nil {
		return "", fmt.Errorf("defectdojo: %w", err)
	}
	q := apiURL.Query()
	q.Set("related_fields", "true")
	q.Set("limit", strconv.Itoa(defectDojoPageSize))
	if f.params.ProductName != "" {
		q.Set("product_name", f.params.ProductName)
	}
	if f.params.EngagementID != "" {
		q.Set("test__engagement", f.params.EngagementID)
	}
	if f.params.TestID != "" {
		q.Set("test", f.params.TestID)
	}
	apiURL.RawQuery = q.Encode()
	return apiURL.String(), nil
}

// sameHost guards against a malicious `next` link pointing off-host (SSRF).
func (f *DefectDojoFetcher) sameHost(next string) bool {
	base, err := url.Parse(f.params.URL)
	if err != nil {
		return false
	}
	n, err := url.Parse(next)
	if err != nil {
		return false
	}
	return n.Scheme == base.Scheme && n.Host == base.Host
}

// Fetch pulls every page of findings and returns an assembled
// {"results": [...]} document — the exact shape defectdojo-to-hdf consumes.
func (f *DefectDojoFetcher) Fetch(ctx context.Context) ([]byte, error) {
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, defectDojoFetchTimeout)
		defer cancel()
	}
	token, err := f.resolveToken()
	if err != nil {
		return nil, err
	}

	nextURL, err := f.firstURL()
	if err != nil {
		return nil, err
	}

	var results []json.RawMessage
	for page := 0; nextURL != ""; page++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if page >= f.maxPages() {
			return nil, fmt.Errorf("defectdojo: exceeded maximum page limit (%d)", f.maxPages())
		}
		if page > 0 && !f.sameHost(nextURL) {
			return nil, fmt.Errorf("defectdojo: pagination link points to an unexpected host")
		}
		pageData, err := f.fetchPage(ctx, token, nextURL)
		if err != nil {
			return nil, err
		}
		results = append(results, pageData.Results...)
		if pageData.Next == nil {
			break
		}
		nextURL = *pageData.Next
	}

	assembled := map[string]interface{}{"results": results}
	out, err := json.Marshal(assembled)
	if err != nil {
		return nil, fmt.Errorf("defectdojo: failed to assemble findings: %w", err)
	}
	return out, nil
}

func (f *DefectDojoFetcher) fetchPage(ctx context.Context, token, pageURL string) (*findingsPage, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, pageURL, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("defectdojo: failed to build request: %w", err)
	}
	f.setAuth(req, token)

	resp, err := f.client.Do(req) //#nosec G704 -- host is user-configured DefectDojo server; scheme/host validated
	if err != nil {
		return nil, fmt.Errorf("defectdojo: request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("defectdojo: unexpected status %d", resp.StatusCode)
	}

	body, err := shared.ReadLimitedBody(resp.Body, f.maxResponseSize())
	if err != nil {
		return nil, fmt.Errorf("defectdojo: %w", err)
	}
	var pageData findingsPage
	if err := json.Unmarshal(body, &pageData); err != nil {
		return nil, fmt.Errorf("defectdojo: invalid findings response: %w", err)
	}
	return &pageData, nil
}

// Verify checks the API token with a single lightweight request, without
// downloading findings — backs the CLI `--check` flag.
func (f *DefectDojoFetcher) Verify(ctx context.Context) error {
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, defectDojoFetchTimeout)
		defer cancel()
	}
	token, err := f.resolveToken()
	if err != nil {
		return err
	}
	apiURL, err := shared.ValidateAndBuildAPIURL(f.params.URL, "/api/v2/user_profile/", "DefectDojo")
	if err != nil {
		return fmt.Errorf("defectdojo: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL.String(), http.NoBody)
	if err != nil {
		return fmt.Errorf("defectdojo: failed to build request: %w", err)
	}
	f.setAuth(req, token)
	resp, err := f.client.Do(req) //#nosec G704 -- host is user-configured DefectDojo server; scheme validated
	if err != nil {
		return fmt.Errorf("defectdojo: verification request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("defectdojo: credential verification failed (status %d)", resp.StatusCode)
	}
	return nil
}
