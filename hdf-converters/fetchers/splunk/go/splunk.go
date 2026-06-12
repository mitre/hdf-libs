// Package splunk fetches HDF events from a live Splunk instance and returns
// them as a JSON array of parsed events, ready for ConvertSplunkToHDF.
package splunk

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	hdftosplunk "github.com/mitre/hdf-libs/hdf-converters/v3/converters/hdf-to-splunk/go"
	shared "github.com/mitre/hdf-libs/hdf-converters/v3/fetchers/shared/go"
)

const (
	// splunkFetchTimeout is applied when the caller has not set a deadline.
	splunkFetchTimeout = 5 * time.Minute

	// splunkMaxResponseSize limits each HTTP response body to 10MB to prevent
	// memory exhaustion from malicious or misconfigured servers.
	splunkMaxResponseSize = 10 * 1024 * 1024

	// splunkMaxResults caps the number of results returned by a single search.
	// Prevents unbounded memory consumption from very large result sets.
	splunkMaxResults = 100000
)

// splunkSafeIdentifier validates that identifiers (SID, index name, GUID)
// contain only safe characters to prevent SPL injection and path traversal.
// Allows alphanumeric characters, underscores, dots, and hyphens.
var splunkSafeIdentifier = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.\-]*$`)

// SplunkParams holds parameters for a live Splunk fetch.
type SplunkParams struct {
	// URL is the Splunk server base URL (http or https only).
	URL string
	// Index is the Splunk index to search.
	Index string
	// GUID is the evaluation GUID to search for.
	GUID string
}

// SplunkFetcher fetches HDF events from a Splunk instance and returns them
// as a JSON array of parsed events, ready for ConvertSplunkToHDF.
type SplunkFetcher struct {
	client *http.Client
	params SplunkParams
}

// NewSplunkFetcher creates a fetcher after validating the server URL and parameters.
// The token is read from the SPLUNK_TOKEN environment variable at Fetch time.
func NewSplunkFetcher(params SplunkParams, tlsOpts shared.TLSOptions) (*SplunkFetcher, error) {
	if err := validateSplunkParams(params); err != nil {
		return nil, err
	}
	client, err := shared.NewHTTPClient(tlsOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to configure TLS: %w", err)
	}
	return &SplunkFetcher{
		client: client,
		params: params,
	}, nil
}

// NewSplunkFetcherWithClient creates a fetcher with an injected HTTP client.
// Use this constructor when the caller wants to handle TLS/auth/transport
// configuration in the application layer rather than relying on default
// discovery via TLSOptions.
func NewSplunkFetcherWithClient(params SplunkParams, client *http.Client) (*SplunkFetcher, error) {
	if err := validateSplunkParams(params); err != nil {
		return nil, err
	}
	return &SplunkFetcher{
		client: client,
		params: params,
	}, nil
}

// validateSplunkParams runs at construction time. Only URL is required at
// construction; Index and GUID are validated per-method (Fetch needs both,
// PushHDF needs only Index, VerifyCredentials needs neither). This keeps a
// single Params struct usable across all three methods without forcing
// callers to supply fields the method they're about to call won't use.
func validateSplunkParams(params SplunkParams) error {
	return validateSplunkURL(params.URL)
}

// validateSplunkURL ensures the URL parses and uses only http or https.
func validateSplunkURL(rawURL string) error {
	if rawURL == "" {
		return fmt.Errorf("splunk URL is required")
	}
	if _, err := buildSplunkAPIURL(rawURL, "/"); err != nil {
		return err
	}
	return nil
}

// validateSplunkIdentifier checks that a user-supplied identifier contains only
// safe characters to prevent SPL injection and path traversal.
func validateSplunkIdentifier(name, value string) error {
	if value == "" {
		return fmt.Errorf("splunk %s is required", name)
	}
	if !splunkSafeIdentifier.MatchString(value) {
		return fmt.Errorf("splunk %s contains invalid characters: only alphanumeric, underscore, dot, and hyphen are allowed", name)
	}
	return nil
}

// buildSplunkAPIURL validates the base URL and constructs a safe API endpoint URL.
func buildSplunkAPIURL(rawURL, path string) (*url.URL, error) {
	return shared.ValidateAndBuildAPIURL(rawURL, path, "splunk")
}

// splunkSearchResponse represents the JSON response from a Splunk search job creation.
type splunkSearchResponse struct {
	SID string `json:"sid"`
}

// splunkResultsResponse represents the JSON response from the Splunk search results endpoint.
type splunkResultsResponse struct {
	Fields []splunkField `json:"fields"`
	Rows   [][]string    `json:"rows"`
}

// splunkField represents a field descriptor in the Splunk JSON rows response.
type splunkField struct {
	Name string `json:"name"`
}

// Fetch retrieves HDF events from a Splunk index by GUID and returns them as
// a JSON array of parsed event objects. The SPLUNK_TOKEN environment variable must be set.
func (f *SplunkFetcher) Fetch(ctx context.Context) ([]byte, error) {
	if err := validateSplunkIdentifier("index", f.params.Index); err != nil {
		return nil, err
	}
	if err := validateSplunkIdentifier("GUID", f.params.GUID); err != nil {
		return nil, err
	}
	token := os.Getenv("SPLUNK_TOKEN")
	if token == "" {
		return nil, fmt.Errorf(
			"SPLUNK_TOKEN environment variable is not set; " +
				"set it to your Splunk Bearer token before running this command",
		)
	}

	// Apply a default deadline when the caller has not set one.
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, splunkFetchTimeout)
		defer cancel()
	}

	// Step 1: Create a blocking search job
	sid, err := f.createSearchJob(ctx, token)
	if err != nil {
		return nil, fmt.Errorf("splunk: creating search job: %w", err)
	}

	// Step 2: Retrieve results
	events, err := f.fetchResults(ctx, token, sid)
	if err != nil {
		return nil, fmt.Errorf("splunk: fetching results: %w", err)
	}

	return json.Marshal(events)
}

// createSearchJob submits a blocking search to the Splunk REST API and returns the SID.
func (f *SplunkFetcher) createSearchJob(ctx context.Context, token string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}

	apiURL, err := buildSplunkAPIURL(f.params.URL, "/services/search/jobs")
	if err != nil {
		return "", err
	}

	// Build the search query body. Index and GUID are pre-validated by
	// validateSplunkIdentifier to contain only safe characters, so %q quoting
	// is sufficient here without risk of SPL injection.
	searchQuery := fmt.Sprintf("search index=%q meta.guid=%q | fields _raw", f.params.Index, f.params.GUID)
	formData := url.Values{}
	formData.Set("exec_mode", "blocking")
	formData.Set("search", searchQuery)
	formData.Set("output_mode", "json")

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, apiURL.String(), strings.NewReader(formData.Encode()))
	if err != nil {
		return "", fmt.Errorf("building search request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := f.client.Do(req) //#nosec G704 -- host is user-configured Splunk server; scheme validated in buildSplunkAPIURL
	if err != nil {
		return "", fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return "", fmt.Errorf("splunk API returned HTTP %d", resp.StatusCode)
	}

	body, err := shared.ReadLimitedBody(resp.Body, splunkMaxResponseSize)
	if err != nil {
		return "", fmt.Errorf("reading search response body: %w", err)
	}

	var searchResp splunkSearchResponse
	if err := json.Unmarshal(body, &searchResp); err != nil {
		return "", fmt.Errorf("parsing search response: %w", err)
	}

	if searchResp.SID == "" {
		return "", fmt.Errorf("splunk API returned empty SID")
	}

	// Validate SID before using it in URL path construction to prevent
	// path traversal from a malicious or compromised Splunk server.
	if err := validateSplunkIdentifier("SID", searchResp.SID); err != nil {
		return "", fmt.Errorf("splunk API returned unsafe SID: %w", err)
	}

	return searchResp.SID, nil
}

// fetchResults retrieves the search results for the given SID and extracts _raw events.
func (f *SplunkFetcher) fetchResults(ctx context.Context, token, sid string) ([]json.RawMessage, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	resultsPath := fmt.Sprintf("/services/search/v2/jobs/%s/results", sid)
	apiURL, err := buildSplunkAPIURL(f.params.URL, resultsPath)
	if err != nil {
		return nil, err
	}

	q := url.Values{}
	q.Set("output_mode", "json_rows")
	q.Set("count", fmt.Sprintf("%d", splunkMaxResults))
	apiURL.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL.String(), http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("building results request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")

	resp, err := f.client.Do(req) //#nosec G704 -- host is user-configured Splunk server; scheme validated in buildSplunkAPIURL
	if err != nil {
		return nil, fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("splunk results API returned HTTP %d", resp.StatusCode)
	}

	body, err := shared.ReadLimitedBody(resp.Body, splunkMaxResponseSize)
	if err != nil {
		return nil, fmt.Errorf("reading results response body: %w", err)
	}

	var resultsResp splunkResultsResponse
	if err := json.Unmarshal(body, &resultsResp); err != nil {
		return nil, fmt.Errorf("parsing results response: %w", err)
	}

	// Warn if the result count hits the cap — data may have been silently truncated.
	if len(resultsResp.Rows) >= splunkMaxResults {
		log.Printf("WARNING: Splunk returned %d results (the configured maximum); "+
			"some events may have been truncated. Consider narrowing the search.", splunkMaxResults)
	}

	// Find the _raw field index
	rawIdx := -1
	for i, field := range resultsResp.Fields {
		if field.Name == "_raw" {
			rawIdx = i
			break
		}
	}
	if rawIdx == -1 {
		return nil, fmt.Errorf("splunk results missing _raw field")
	}

	// Extract and parse _raw values into JSON objects
	events := make([]json.RawMessage, 0, len(resultsResp.Rows))
	for _, row := range resultsResp.Rows {
		if rawIdx >= len(row) {
			continue
		}
		rawStr := row[rawIdx]
		// Validate that _raw is valid JSON before including it
		if !json.Valid([]byte(rawStr)) {
			continue
		}
		events = append(events, json.RawMessage(rawStr))
	}

	return events, nil
}

// =============================================================================
// PushHDF — convert HDF Results to Splunk records and upload them.
// =============================================================================

const (
	// pushSourcetype matches the heimdall2 hdf2splunk sourcetype so existing
	// Splunk dashboards and saved searches keep working.
	pushSourcetype = "HDF2Splunk"

	// pushReceiverPath is Splunk's simple HTTP receiver endpoint. We choose
	// it over HEC (`/services/collector`) because HEC uses a separate token
	// type (HEC tokens, not user tokens), which would require changing the
	// auth model we share with Fetch / Verify.
	pushReceiverPath = "/services/receivers/simple"

	// pushChunkSize bounds how many control records we ship in one HTTP
	// POST. Matches heimdall2's UPLOAD_CHUNK_SIZE.
	pushChunkSize = 100
)

// PushHDF converts the provided HDF Results JSON into Splunk records (via
// the hdf-to-splunk converter) and uploads them to the configured index.
// SPLUNK_TOKEN must be set. Returns an error if the index doesn't exist on
// the target Splunk instance, if any upload POST fails, or if the input
// isn't valid HDF.
func (f *SplunkFetcher) PushHDF(ctx context.Context, hdfBytes []byte) error {
	if err := validateSplunkIdentifier("index", f.params.Index); err != nil {
		return err
	}
	token := os.Getenv("SPLUNK_TOKEN")
	if token == "" {
		return fmt.Errorf(
			"SPLUNK_TOKEN environment variable is not set; " +
				"set it to your Splunk Bearer token before running this command",
		)
	}

	// Apply a default deadline when the caller has not set one.
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, splunkFetchTimeout)
		defer cancel()
	}

	// Convert HDF -> Splunk records BEFORE the network preflight so a
	// malformed input fails fast.
	splunkBytes, err := hdftosplunk.ConvertHDFToSplunk(hdfBytes)
	if err != nil {
		return fmt.Errorf("splunk: converting HDF for push: %w", err)
	}
	var data hdftosplunk.SplunkData
	if err := json.Unmarshal(splunkBytes, &data); err != nil {
		return fmt.Errorf("splunk: parsing converted records: %w", err)
	}

	// Pre-flight: confirm the target index exists.
	if err := f.checkIndexExists(ctx, token); err != nil {
		return err
	}

	// Report (one per HDF doc) → one POST.
	for _, rec := range data.Reports {
		if err := f.postRecords(ctx, token, []any{rec}); err != nil {
			return fmt.Errorf("splunk: uploading report: %w", err)
		}
	}

	// Profiles → one POST as NDJSON.
	if len(data.Profiles) > 0 {
		batch := make([]any, 0, len(data.Profiles))
		for _, p := range data.Profiles {
			batch = append(batch, p)
		}
		if err := f.postRecords(ctx, token, batch); err != nil {
			return fmt.Errorf("splunk: uploading profiles: %w", err)
		}
	}

	// Controls → N POSTs in chunks of pushChunkSize.
	for i := 0; i < len(data.Controls); i += pushChunkSize {
		if err := ctx.Err(); err != nil {
			return err
		}
		end := i + pushChunkSize
		if end > len(data.Controls) {
			end = len(data.Controls)
		}
		batch := make([]any, 0, end-i)
		for _, c := range data.Controls[i:end] {
			batch = append(batch, c)
		}
		if err := f.postRecords(ctx, token, batch); err != nil {
			return fmt.Errorf("splunk: uploading control chunk %d-%d: %w", i, end, err)
		}
	}
	return nil
}

// checkIndexExists confirms the target index is present on the Splunk
// instance. If not, surface a clear "index <name> not found" error instead
// of letting the upload fail with a cryptic message.
func (f *SplunkFetcher) checkIndexExists(ctx context.Context, token string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	apiURL, err := buildSplunkAPIURL(f.params.URL, "/services/data/indexes/"+f.params.Index)
	if err != nil {
		return err
	}
	q := url.Values{}
	q.Set("output_mode", "json")
	apiURL.RawQuery = q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL.String(), http.NoBody)
	if err != nil {
		return fmt.Errorf("building index preflight request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	resp, err := f.client.Do(req) //#nosec G704 -- host validated in buildSplunkAPIURL
	if err != nil {
		return fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck
	switch resp.StatusCode {
	case http.StatusOK:
		return nil
	case http.StatusNotFound:
		return fmt.Errorf("splunk: index %q does not exist on the target Splunk instance", f.params.Index)
	default:
		return fmt.Errorf("splunk: index preflight returned HTTP %d", resp.StatusCode)
	}
}

// postRecords serializes records as NDJSON (one JSON object per line) and
// POSTs them to /services/receivers/simple. One-element batches are sent as
// a single JSON object rather than NDJSON (heimdall2 parity).
func (f *SplunkFetcher) postRecords(ctx context.Context, token string, records []any) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if len(records) == 0 {
		return nil
	}
	apiURL, err := buildSplunkAPIURL(f.params.URL, pushReceiverPath)
	if err != nil {
		return err
	}
	q := url.Values{}
	q.Set("sourcetype", pushSourcetype)
	q.Set("index", f.params.Index)
	q.Set("output_mode", "json")
	apiURL.RawQuery = q.Encode()

	var body strings.Builder
	for i, rec := range records {
		if i > 0 {
			body.WriteByte('\n')
		}
		encoded, err := json.Marshal(rec)
		if err != nil {
			return fmt.Errorf("marshaling record %d: %w", i, err)
		}
		body.Write(encoded)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, apiURL.String(), strings.NewReader(body.String()))
	if err != nil {
		return fmt.Errorf("building upload request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := f.client.Do(req) //#nosec G704 -- host validated in buildSplunkAPIURL
	if err != nil {
		return fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("splunk receivers/simple returned HTTP %d", resp.StatusCode)
	}
	return nil
}

// =============================================================================
// VerifyCredentials — confirm SPLUNK_TOKEN authenticates against the server.
// =============================================================================

// VerifyCredentials hits /services/server/info with the configured token. A
// 200 response means the token authenticates; anything else returns an
// error (without leaking the token value).
func (f *SplunkFetcher) VerifyCredentials(ctx context.Context) error {
	token := os.Getenv("SPLUNK_TOKEN")
	if token == "" {
		return fmt.Errorf(
			"SPLUNK_TOKEN environment variable is not set; " +
				"set it to your Splunk Bearer token before running this command",
		)
	}
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, splunkFetchTimeout)
		defer cancel()
	}

	apiURL, err := buildSplunkAPIURL(f.params.URL, "/services/server/info")
	if err != nil {
		return err
	}
	q := url.Values{}
	q.Set("output_mode", "json")
	apiURL.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL.String(), http.NoBody)
	if err != nil {
		return fmt.Errorf("building verify request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")

	resp, err := f.client.Do(req) //#nosec G704 -- host validated in buildSplunkAPIURL
	if err != nil {
		return fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck
	switch resp.StatusCode {
	case http.StatusOK:
		return nil
	case http.StatusUnauthorized, http.StatusForbidden:
		return fmt.Errorf("splunk: credential verification failed (HTTP %d)", resp.StatusCode)
	default:
		return fmt.Errorf("splunk: server/info returned HTTP %d", resp.StatusCode)
	}
}
