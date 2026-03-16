package fetchers

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
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
func NewSonarqubeFetcher(params SonarqubeParams, tlsOpts TLSOptions) (*SonarqubeFetcher, error) {
	if err := validateSonarqubeURL(params.URL); err != nil {
		return nil, err
	}
	client, err := NewHTTPClient(tlsOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to configure TLS: %w", err)
	}
	return &SonarqubeFetcher{
		client: client,
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
	// Reuse ValidateAndBuildAPIURL for scheme validation (single source of truth)
	if _, err := ValidateAndBuildAPIURL(rawURL, "/", "SonarQube"); err != nil {
		return err
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

	// Enrich rules with details from /api/rules/show (SQ 26+ compatibility).
	// This fetches descriptionSections, sysTags, htmlDesc, and mdDesc that
	// are no longer included in the /api/issues/search response.
	f.enrichRulesWithDetails(ctx, token, ruleMap)

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

func (f *SonarqubeFetcher) fetchPage(ctx context.Context, token string, page int) (*sonarqubeconv.IssuesResponse, error) {
	apiURL, err := ValidateAndBuildAPIURL(f.params.URL, "/api/issues/search", "SonarQube")
	if err != nil {
		return nil, err
	}

	q := url.Values{}
	q.Set("componentKeys", f.params.ProjectKey)
	q.Set("additionalFields", "rules")
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

	resp, err := f.client.Do(req) //#nosec G704 -- host is user-configured SonarQube server; scheme validated in ValidateAndBuildAPIURL
	if err != nil {
		return nil, fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("SonarQube API returned HTTP %d", resp.StatusCode)
	}

	// Limit response body to 10MB to prevent memory exhaustion from malicious servers.
	// Uses readLimitedBody (shared with Splunk fetcher) which reads maxSize+1 bytes
	// and returns an explicit error on overflow, rather than silently truncating.
	const maxResponseSize = 10 * 1024 * 1024
	body, err := readLimitedBody(resp.Body, maxResponseSize)
	if err != nil {
		return nil, fmt.Errorf("reading response body: %w", err)
	}

	var issuesResp sonarqubeconv.IssuesResponse
	if err := json.Unmarshal(body, &issuesResp); err != nil {
		return nil, fmt.Errorf("parsing API response: %w", err)
	}

	return &issuesResp, nil
}

// ruleShowResponse wraps the /api/rules/show response.
type ruleShowResponse struct {
	Rule sonarqubeconv.Rule `json:"rule"`
}

// enrichRulesWithDetails fetches detailed rule information from /api/rules/show
// for each rule in the map. This adds descriptionSections, sysTags, htmlDesc,
// and mdDesc that SonarQube 26+ no longer returns in /api/issues/search.
// Failures on individual rules are logged and skipped (graceful degradation).
func (f *SonarqubeFetcher) enrichRulesWithDetails(ctx context.Context, token string, ruleMap map[string]sonarqubeconv.Rule) {
	for ruleKey, existing := range ruleMap {
		if err := ctx.Err(); err != nil {
			return
		}

		detail, err := f.fetchRuleDetail(ctx, token, ruleKey)
		if err != nil {
			log.Printf("WARNING: failed to enrich rule %s: %v", ruleKey, err)
			continue
		}

		// Merge fields from the detailed response into the existing rule
		if len(detail.DescriptionSections) > 0 && len(existing.DescriptionSections) == 0 {
			existing.DescriptionSections = detail.DescriptionSections
		}
		if detail.HTMLDesc != "" && existing.HTMLDesc == "" {
			existing.HTMLDesc = detail.HTMLDesc
		}
		if detail.MDDesc != "" && existing.MDDesc == "" {
			existing.MDDesc = detail.MDDesc
		}
		if len(detail.SysTags) > 0 && len(existing.SysTags) == 0 {
			existing.SysTags = detail.SysTags
		}
		if len(detail.Tags) > 0 && len(existing.Tags) == 0 {
			existing.Tags = detail.Tags
		}

		ruleMap[ruleKey] = existing
	}
}

// fetchRuleDetail fetches a single rule's details from /api/rules/show.
func (f *SonarqubeFetcher) fetchRuleDetail(ctx context.Context, token, ruleKey string) (*sonarqubeconv.Rule, error) {
	apiURL, err := ValidateAndBuildAPIURL(f.params.URL, "/api/rules/show", "SonarQube")
	if err != nil {
		return nil, err
	}

	q := url.Values{}
	q.Set("key", ruleKey)
	apiURL.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL.String(), http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("building request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")

	resp, err := f.client.Do(req) //#nosec G704 -- host is user-configured SonarQube server
	if err != nil {
		return nil, fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("rules/show API returned HTTP %d for %s", resp.StatusCode, ruleKey)
	}

	const maxRuleResponseSize = 1 * 1024 * 1024
	body, err := readLimitedBody(resp.Body, maxRuleResponseSize)
	if err != nil {
		return nil, fmt.Errorf("reading rule response: %w", err)
	}

	var ruleResp ruleShowResponse
	if err := json.Unmarshal(body, &ruleResp); err != nil {
		return nil, fmt.Errorf("parsing rule response: %w", err)
	}

	return &ruleResp.Rule, nil
}
