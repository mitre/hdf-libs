package fetchers

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
func NewSplunkFetcher(params SplunkParams, tlsOpts TLSOptions) (*SplunkFetcher, error) {
	if err := validateSplunkParams(params); err != nil {
		return nil, err
	}
	client, err := NewHTTPClient(tlsOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to configure TLS: %w", err)
	}
	return &SplunkFetcher{
		client: client,
		params: params,
	}, nil
}

// newSplunkFetcherWithClient creates a fetcher with an injected HTTP client.
// Intended for testing only.
func newSplunkFetcherWithClient(params SplunkParams, client *http.Client) (*SplunkFetcher, error) {
	if err := validateSplunkParams(params); err != nil {
		return nil, err
	}
	return &SplunkFetcher{
		client: client,
		params: params,
	}, nil
}

// validateSplunkParams validates the URL, index, and GUID.
func validateSplunkParams(params SplunkParams) error {
	if err := validateSplunkURL(params.URL); err != nil {
		return err
	}
	if err := validateSplunkIdentifier("index", params.Index); err != nil {
		return err
	}
	return validateSplunkIdentifier("GUID", params.GUID)
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
	return ValidateAndBuildAPIURL(rawURL, path, "splunk")
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

	body, err := readLimitedBody(resp.Body, splunkMaxResponseSize)
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

	body, err := readLimitedBody(resp.Body, splunkMaxResponseSize)
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
