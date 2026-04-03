package fetchers

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
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

	// sonarqubeESLimit is the Elasticsearch result cap enforced by SonarQube.
	// When p*ps exceeds this, the API returns HTTP 400. We detect this and
	// fall back to component-tree-partitioned fetching.
	sonarqubeESLimit = 10000
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
	client        *http.Client
	params        SonarqubeParams
	maxPages      int    // 0 → sonarqubeMaxPages
	serverVersion string // set externally to skip /api/server/version probe
	useBearer     bool   // determined from server version at Fetch time
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

// SetServerVersion overrides the auto-detected server version.
// Use this when the user explicitly specifies the SonarQube version.
func (f *SonarqubeFetcher) SetServerVersion(v string) {
	f.serverVersion = v
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

// sonarqubeUseBearerAuth returns true if the server version requires Bearer
// token auth (SonarQube 10+). Older versions use the token as HTTP Basic
// username with empty password. Returns true for unrecognized versions as
// a safe default (Bearer is the modern standard).
func sonarqubeUseBearerAuth(serverVersion string) bool {
	major := sonarqubeMajorVersion(serverVersion)
	// SQ 10+ supports Bearer, SQ 25+ requires it.
	// Versions <10 use token-as-username Basic auth.
	return major == 0 || major >= 10
}

// sonarqubeMajorVersion extracts the major version number from a version
// string like "10.8.1" or "2025.1.0". Returns 0 if unparseable.
func sonarqubeMajorVersion(version string) int {
	version = strings.TrimSpace(version)
	if version == "" {
		return 0
	}
	parts := strings.SplitN(version, ".", 2)
	major, err := strconv.Atoi(parts[0])
	if err != nil {
		return 0
	}
	return major
}

// fetchServerVersion calls /api/server/version to determine the SonarQube
// server version. Returns empty string on failure (non-fatal — version
// detection is best-effort).
func (f *SonarqubeFetcher) fetchServerVersion(ctx context.Context, token string) string {
	apiURL, err := ValidateAndBuildAPIURL(f.params.URL, "/api/server/version", "SonarQube")
	if err != nil {
		return ""
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL.String(), http.NoBody)
	if err != nil {
		return ""
	}
	// Try Bearer first; /api/server/version is often unauthenticated but
	// some installations lock it down.
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := f.client.Do(req) //#nosec G704 -- host is user-configured SonarQube server
	if err != nil {
		return ""
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		return ""
	}

	// Version is returned as plain text (e.g. "10.8.1")
	body, err := io.ReadAll(io.LimitReader(resp.Body, 256))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(body))
}

// setAuthHeader sets the appropriate auth header based on server version.
func (f *SonarqubeFetcher) setAuthHeader(req *http.Request, token string) {
	if f.useBearer {
		req.Header.Set("Authorization", "Bearer "+token)
	} else {
		req.SetBasicAuth(token, "")
	}
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

	// Detect server version and set auth method accordingly
	serverVersion := f.serverVersion
	if serverVersion == "" {
		serverVersion = f.fetchServerVersion(ctx, token)
		if serverVersion != "" {
			log.Printf("SonarQube server version: %s", serverVersion)
		}
	}
	f.useBearer = sonarqubeUseBearerAuth(serverVersion)
	if !f.useBearer {
		log.Printf("Using Basic auth (token-as-username) for SonarQube %s", serverVersion)
	}

	limit := f.maxPages
	if limit <= 0 {
		limit = sonarqubeMaxPages
	}

	componentMap := make(map[string]sonarqubeconv.Component)
	ruleMap := make(map[string]sonarqubeconv.Rule)

	// First attempt: fetch issues for the whole project
	allIssues, total, err := f.fetchIssuesForComponent(ctx, token, limit, f.params.ProjectKey, componentMap, ruleMap)
	if err != nil {
		return nil, err
	}

	// Detect the Elasticsearch 10K limit: if total exceeds the cap and we
	// couldn't fetch everything, fall back to component-tree traversal.
	// This fetches issues per sub-component (directory/file) instead of
	// per whole project, recursing deeper if a sub-component also exceeds 10K.
	if total > sonarqubeESLimit && len(allIssues) < total {
		log.Printf("WARNING: Project has %d issues (exceeds Elasticsearch 10K limit). "+ //nolint:gosec // total is from API response integer
			"Fetching by component tree — this may take longer.", total)

		allIssues, err = f.fetchByComponentTree(ctx, token, limit, componentMap, ruleMap)
		if err != nil {
			return nil, err
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
		Total:         len(allIssues),
		Page:          1,
		PageSize:      sonarqubePageSize,
		Issues:        allIssues,
		Components:    components,
		Rules:         rules,
		ServerVersion: serverVersion,
	}

	return json.Marshal(result)
}

// fetchIssuesForComponent paginates through /api/issues/search for a specific
// component key. Returns collected issues, the reported total, and any error.
// Stops early if it hits the Elasticsearch 10K cap (HTTP 400) and returns
// what was collected so the caller can fall back to sub-component traversal.
func (f *SonarqubeFetcher) fetchIssuesForComponent(
	ctx context.Context, token string, maxPages int, componentKey string,
	componentMap map[string]sonarqubeconv.Component, ruleMap map[string]sonarqubeconv.Rule,
) ([]sonarqubeconv.Issue, int, error) {
	var allIssues []sonarqubeconv.Issue
	var total int

	for page := 1; ; page++ {
		if err := ctx.Err(); err != nil {
			return nil, 0, err
		}
		if page > maxPages {
			return nil, 0, fmt.Errorf("sonarqube: exceeded maximum page limit (%d)", maxPages)
		}

		resp, err := f.fetchIssuePage(ctx, token, page, componentKey)
		if err != nil {
			// Detect the 10K Elasticsearch limit (HTTP 400 on high page numbers).
			// Return what we have so the caller can fall back to component tree.
			if page > 1 && strings.Contains(err.Error(), "HTTP 400") {
				return allIssues, total, nil
			}
			return nil, 0, fmt.Errorf("sonarqube: fetching page %d: %w", page, err)
		}

		total = resp.Paging.Total
		allIssues = append(allIssues, resp.Issues...)

		for _, c := range resp.Components {
			componentMap[c.Key] = c
		}
		for _, r := range resp.Rules {
			ruleMap[r.Key] = r
		}

		if len(resp.Issues) == 0 || len(allIssues) >= total {
			break
		}
	}

	return allIssues, total, nil
}

// fetchByComponentTree fetches issues by traversing the project's component
// tree. When the project exceeds the Elasticsearch 10K result limit, this
// fetches child components (directories/files) and queries each individually.
// If a child also exceeds 10K, it recurses into that child's children.
// Results are deduplicated by issue key.
func (f *SonarqubeFetcher) fetchByComponentTree(
	ctx context.Context, token string, maxPages int,
	componentMap map[string]sonarqubeconv.Component, ruleMap map[string]sonarqubeconv.Rule,
) ([]sonarqubeconv.Issue, error) {
	seen := make(map[string]bool)
	var allIssues []sonarqubeconv.Issue

	// BFS queue of component keys to process
	queue := []string{f.params.ProjectKey}

	for len(queue) > 0 {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		component := queue[0]
		queue = queue[1:]

		// First check: how many issues does this component have?
		issues, total, err := f.fetchIssuesForComponent(ctx, token, maxPages, component, componentMap, ruleMap)
		if err != nil {
			return nil, fmt.Errorf("sonarqube: fetching component %s: %w", component, err)
		}

		if total > sonarqubeESLimit && len(issues) < total {
			// This component exceeds the 10K limit — drill into children
			log.Printf("Component %s has %d issues (exceeds 10K limit), fetching children", component, total)
			children, err := f.fetchChildComponents(ctx, token, component, maxPages)
			if err != nil {
				log.Printf("WARNING: failed to fetch children of %s: %v; using %d partial issues", component, err, len(issues))
				// Fall through to use partial results
			} else if len(children) > 0 {
				queue = append(queue, children...)
				continue // Don't add partial results — children will cover them
			}
			// No children found or fetch failed — use what we got
		}

		for _, issue := range issues {
			if !seen[issue.Key] {
				seen[issue.Key] = true
				allIssues = append(allIssues, issue)
			}
		}
	}

	return allIssues, nil
}

// componentTreeResponse wraps the /api/components/tree response.
type componentTreeResponse struct {
	Paging     sonarqubeconv.Paging `json:"paging"`
	Components []struct {
		Key       string `json:"key"`
		Name      string `json:"name"`
		Qualifier string `json:"qualifier"`
		Path      string `json:"path"`
	} `json:"components"`
}

// fetchChildComponents retrieves direct child components (directories/files)
// of a given component via /api/components/tree with strategy=children.
func (f *SonarqubeFetcher) fetchChildComponents(ctx context.Context, token, componentKey string, maxPages int) ([]string, error) {
	var children []string

	for page := 1; ; page++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if page > maxPages {
			break
		}

		apiURL, err := ValidateAndBuildAPIURL(f.params.URL, "/api/components/tree", "SonarQube")
		if err != nil {
			return nil, err
		}

		q := url.Values{}
		q.Set("component", componentKey)
		q.Set("strategy", "children")
		q.Set("ps", fmt.Sprintf("%d", sonarqubePageSize))
		q.Set("p", fmt.Sprintf("%d", page))
		if f.params.Branch != "" {
			q.Set("branch", f.params.Branch)
		}
		if f.params.PullRequestID != "" {
			q.Set("pullRequest", f.params.PullRequestID)
		}
		apiURL.RawQuery = q.Encode()

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL.String(), http.NoBody)
		if err != nil {
			return nil, err
		}
		f.setAuthHeader(req, token)
		req.Header.Set("Accept", "application/json")

		resp, err := f.client.Do(req) //#nosec G704 -- host is user-configured
		if err != nil {
			return nil, err
		}

		const maxSize = 10 * 1024 * 1024
		body, err := readLimitedBody(resp.Body, maxSize)
		resp.Body.Close() //nolint:errcheck
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("components/tree API returned HTTP %d", resp.StatusCode)
		}
		if err != nil {
			return nil, err
		}

		var treeResp componentTreeResponse
		if err := json.Unmarshal(body, &treeResp); err != nil {
			return nil, fmt.Errorf("parsing components/tree response: %w", err)
		}

		for _, c := range treeResp.Components {
			children = append(children, c.Key)
		}

		if len(treeResp.Components) == 0 || len(children) >= treeResp.Paging.Total {
			break
		}
	}

	return children, nil
}

func (f *SonarqubeFetcher) fetchIssuePage(ctx context.Context, token string, page int, componentKey string) (*sonarqubeconv.IssuesResponse, error) {
	apiURL, err := ValidateAndBuildAPIURL(f.params.URL, "/api/issues/search", "SonarQube")
	if err != nil {
		return nil, err
	}

	q := url.Values{}
	q.Set("componentKeys", componentKey)
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

	f.setAuthHeader(req, token)
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

	f.setAuthHeader(req, token)
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
