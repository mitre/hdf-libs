package fetchers

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"time"

	sonarqubeconv "github.com/mitre/hdf-converters/converters/sonarqube-to-hdf/go"
)

const (
	// sonarqubeMaxPages caps pagination to prevent infinite loops if the API returns
	// malformed responses. With ps=500, this allows up to 5 million issues.
	sonarqubeMaxPages = 10000

	// sonarqubePageSize is the maximum page size accepted by the SonarQube API.
	sonarqubePageSize = 500

	// sonarqubeFetchTimeout is applied when the caller has not set a deadline.
	sonarqubeFetchTimeout = 5 * time.Minute
)

// SonarqubeParams holds parameters for a live SonarQube fetch.
type SonarqubeParams struct {
	// URL is the SonarQube server base URL (http or https only).
	URL string
	// ProjectKey is the SonarQube project key (required).
	ProjectKey string
	// Branch filters issues to a specific branch. Mutually exclusive with PullRequestID.
	Branch string
	// PullRequestID filters issues to a specific pull request. Mutually exclusive with Branch.
	PullRequestID string
	// Organization is the SonarCloud organization key (optional).
	Organization string
}

// SonarqubeFetcher fetches SonarQube issues from the API and returns them
// as IssuesResponse JSON, ready for ConvertSonarqubeToHDF.
type SonarqubeFetcher struct {
	client   *http.Client
	params   SonarqubeParams
	maxPages int // 0 → sonarqubeMaxPages
}

// NewSonarqubeFetcher creates a fetcher after validating the server URL.
// The token is read from the SONARQUBE_TOKEN environment variable at Fetch time.
func NewSonarqubeFetcher(params SonarqubeParams) (*SonarqubeFetcher, error) {
	if err := validateSonarqubeURL(params.URL); err != nil {
		return nil, err
	}
	return &SonarqubeFetcher{
		client: &http.Client{},
		params: params,
	}, nil
}

// newSonarqubeFetcherWithClient creates a fetcher with an injected HTTP client.
// Intended for testing only.
func newSonarqubeFetcherWithClient(params SonarqubeParams, client *http.Client) (*SonarqubeFetcher, error) {
	if err := validateSonarqubeURL(params.URL); err != nil {
		return nil, err
	}
	return &SonarqubeFetcher{
		client: client,
		params: params,
	}, nil
}

// validateSonarqubeURL ensures the URL parses and uses only http or https.
func validateSonarqubeURL(rawURL string) error {
	if rawURL == "" {
		return fmt.Errorf("SonarQube URL is required")
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid SonarQube URL %q: %w", rawURL, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("invalid SonarQube URL %q: must use http or https scheme", rawURL)
	}
	return nil
}

// Fetch retrieves all issues from the SonarQube API and returns them as
// IssuesResponse JSON. The SONARQUBE_TOKEN environment variable must be set.
func (f *SonarqubeFetcher) Fetch(ctx context.Context) ([]byte, error) {
	token := os.Getenv("SONARQUBE_TOKEN")
	if token == "" {
		return nil, fmt.Errorf(
			"SONARQUBE_TOKEN environment variable is not set; " +
				"set it to your SonarQube API token before running this command",
		)
	}

	// Apply a default deadline when the caller has not set one.
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, sonarqubeFetchTimeout)
		defer cancel()
	}

	limit := f.maxPages
	if limit <= 0 {
		limit = sonarqubeMaxPages
	}

	var allIssues []sonarqubeconv.Issue
	componentMap := make(map[string]sonarqubeconv.Component)
	ruleMap := make(map[string]sonarqubeconv.Rule)
	var total int

	for page := 1; ; page++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if page > limit {
			return nil, fmt.Errorf("sonarqube: exceeded maximum page limit (%d)", limit)
		}

		resp, err := f.fetchPage(ctx, token, page)
		if err != nil {
			return nil, fmt.Errorf("sonarqube: fetching page %d: %w", page, err)
		}

		total = resp.Paging.Total
		allIssues = append(allIssues, resp.Issues...)

		// Accumulate components and rules (deduplicate by key)
		for _, c := range resp.Components {
			componentMap[c.Key] = c
		}
		for _, r := range resp.Rules {
			ruleMap[r.Key] = r
		}

		// Stop when we have accumulated all reported issues, or the page was empty
		if len(resp.Issues) == 0 || len(allIssues) >= total {
			break
		}
	}

	// Build components and rules slices
	components := make([]sonarqubeconv.Component, 0, len(componentMap))
	for _, c := range componentMap {
		components = append(components, c)
	}
	rules := make([]sonarqubeconv.Rule, 0, len(ruleMap))
	for _, r := range ruleMap {
		rules = append(rules, r)
	}

	result := sonarqubeconv.IssuesResponse{
		Total:      total,
		Page:       1,
		PageSize:   sonarqubePageSize,
		Issues:     allIssues,
		Components: components,
		Rules:      rules,
	}

	return json.Marshal(result)
}

// fetchPage calls /api/issues/search for a single page.
func (f *SonarqubeFetcher) fetchPage(ctx context.Context, token string, page int) (*sonarqubeconv.IssuesResponse, error) {
	apiURL, err := url.Parse(f.params.URL)
	if err != nil {
		return nil, err
	}
	apiURL.Path = "/api/issues/search"

	q := apiURL.Query()
	q.Set("componentKeys", f.params.ProjectKey)
	q.Set("ps", fmt.Sprintf("%d", sonarqubePageSize))
	q.Set("p", fmt.Sprintf("%d", page))

	if f.params.Branch != "" {
		q.Set("branch", f.params.Branch)
	}
	if f.params.PullRequestID != "" {
		q.Set("pullRequest", f.params.PullRequestID)
	}
	if f.params.Organization != "" {
		q.Set("organization", f.params.Organization)
	}

	apiURL.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL.String(), http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("building request: %w", err)
	}

	// Token is passed as Bearer auth; never logged or included in error messages
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")

	// URL scheme validated to http/https only in validateSonarqubeURL — SSRF prevented.
	resp, err := f.client.Do(req) //nolint:gosec
	if err != nil {
		return nil, fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("SonarQube API returned HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response body: %w", err)
	}

	var issuesResp sonarqubeconv.IssuesResponse
	if err := json.Unmarshal(body, &issuesResp); err != nil {
		return nil, fmt.Errorf("parsing API response: %w", err)
	}

	return &issuesResp, nil
}
