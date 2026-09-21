// Package gitlabvulnerabilities reads a project's GitLab Vulnerability Report
// over GraphQL — the deduplicated, persisted, triaged view GitLab Ultimate
// maintains — and assembles the envelope the gitlab-vulnerabilities-to-hdf
// converter consumes. It can also iterate every project in a group, yielding
// one envelope per project.
//
// The fetcher never accepts a credential as a value; the token is resolved at
// fetch time through the same chain as the artifact fetcher (GITLAB_TOKEN,
// GLAB_TOKEN, then the glab CLI config).
package gitlabvulnerabilities

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	converter "github.com/mitre/hdf-libs/hdf-converters/v3/converters/gitlab-vulnerabilities-to-hdf/go"
	gitlab "github.com/mitre/hdf-libs/hdf-converters/v3/fetchers/gitlab/go"
	shared "github.com/mitre/hdf-libs/hdf-converters/v3/fetchers/shared/go"
)

const (
	// fetchTimeout is applied when the caller has not set a deadline.
	fetchTimeout = 10 * time.Minute
	// maxResponseSize caps each GraphQL response body.
	maxResponseSize = 25 * 1024 * 1024
	// maxPages bounds every pagination loop (vulnerabilities, projects and
	// nested histories). At the default page size it admits 12500 findings.
	maxPages = 500
	// pageSize is the default `first:` argument. GitLab caps GraphQL query
	// complexity at 250 for authenticated requests and the full Vulnerability
	// node selection costs roughly 1.1 per finding, so 25 scores 214 and keeps
	// headroom for the next field the converter needs. Fields are never dropped
	// to fit — the page shrinks instead.
	pageSize = 25
	// historyPageSize is the `first:` argument for the follow-up query that
	// completes a truncated nested history. That query selects one finding, so
	// it can afford a page the hot query cannot.
	historyPageSize = 100
	// graphqlPath is GitLab's GraphQL endpoint.
	graphqlPath = "/api/graphql"
	toolName    = "GitLab"
	errPrefix   = "gitlab-vulnerabilities"
)

//go:embed queries/probe.graphql
var probeQuery string

//go:embed queries/page.graphql
var pageQuery string

//go:embed queries/group.graphql
var groupQuery string

//go:embed queries/history.graphql
var historyQuery string

// GitLabVulnerabilitiesParams holds parameters for a Vulnerability Report
// fetch. Exactly one of
// Project or Group is required.
type GitLabVulnerabilitiesParams struct {
	// URL is the GitLab instance base URL (required).
	URL string
	// Project is the full path of one project (namespace/project).
	Project string
	// Group is the full path of a group; every non-archived project in it is
	// fetched, subgroups included unless ExcludeSubgroups is set.
	Group string
	// ExcludeSubgroups limits Group mode to the group's direct projects.
	ExcludeSubgroups bool
	// States filters vulnerabilities by VulnerabilityState (DETECTED,
	// CONFIRMED, DISMISSED, RESOLVED). Empty means every state.
	States []string
	// ReportTypes filters vulnerabilities by VulnerabilityReportType (SAST,
	// DAST, …). Empty means every type.
	ReportTypes []string
	// PageSize overrides the per-page `first:` argument. 0 uses the default.
	PageSize int
	// MaxPages overrides the pagination cap. 0 uses the default.
	MaxPages int
	// MaxResponseSize overrides the per-response body limit. 0 uses the
	// default; -1 disables the limit.
	MaxResponseSize int64
	// Clock supplies the envelope's fetchedAt. nil means the wall clock; tests
	// inject a fixed time so envelopes are reproducible.
	Clock func() time.Time
}

// Fetcher reads the Vulnerability Report for one project or a whole group.
type GitLabVulnerabilitiesFetcher struct {
	client *http.Client
	params GitLabVulnerabilitiesParams
}

// NewGitLabVulnerabilitiesFetcher creates a fetcher after validating the
// server URL and the
// project/group selection. The token is resolved at fetch time.
func NewGitLabVulnerabilitiesFetcher(params GitLabVulnerabilitiesParams, tlsOpts shared.TLSOptions) (*GitLabVulnerabilitiesFetcher, error) {
	if err := validateParams(params); err != nil {
		return nil, err
	}
	client, err := shared.NewHTTPClient(tlsOpts)
	if err != nil {
		return nil, fmt.Errorf("%s: failed to configure TLS: %w", errPrefix, err)
	}
	// A GraphQL endpoint never legitimately redirects, and Go copies custom
	// headers such as PRIVATE-TOKEN across hosts on a redirect. Refusing to
	// follow one keeps the token on the host the user named; the 3xx then
	// fails as a non-200 response.
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &GitLabVulnerabilitiesFetcher{client: client, params: params}, nil
}

// NewGitLabVulnerabilitiesFetcherWithClient creates a fetcher with an injected
// HTTP client, for callers that own TLS, auth and transport. Refusing redirects
// so the token never follows one to another host becomes their job too.
func NewGitLabVulnerabilitiesFetcherWithClient(params GitLabVulnerabilitiesParams, client *http.Client) (*GitLabVulnerabilitiesFetcher, error) {
	if err := validateParams(params); err != nil {
		return nil, err
	}
	return &GitLabVulnerabilitiesFetcher{client: client, params: params}, nil
}

func validateParams(p GitLabVulnerabilitiesParams) error {
	if p.URL == "" {
		return fmt.Errorf("%s: URL is required", errPrefix)
	}
	if _, err := shared.ValidateAndBuildAPIURL(p.URL, graphqlPath, toolName); err != nil {
		return fmt.Errorf("%s: %w", errPrefix, err)
	}
	switch {
	case p.Project == "" && p.Group == "":
		return fmt.Errorf("%s: a project or a group full path is required", errPrefix)
	case p.Project != "" && p.Group != "":
		return fmt.Errorf("%s: project and group are mutually exclusive", errPrefix)
	}
	if p.PageSize < 0 || p.MaxPages < 0 {
		return fmt.Errorf("%s: page size and page cap must not be negative", errPrefix)
	}
	return nil
}

func (f *GitLabVulnerabilitiesFetcher) pageSize() int {
	if f.params.PageSize > 0 {
		return f.params.PageSize
	}
	return pageSize
}

func (f *GitLabVulnerabilitiesFetcher) maxPages() int {
	if f.params.MaxPages > 0 {
		return f.params.MaxPages
	}
	return maxPages
}

func (f *GitLabVulnerabilitiesFetcher) maxResponseSize() int64 {
	if f.params.MaxResponseSize != 0 {
		return f.params.MaxResponseSize
	}
	return maxResponseSize
}

// filters reports the selection this fetch narrowed to, or nil when it asked
// for everything.
func (f *GitLabVulnerabilitiesFetcher) filters() *converter.Filters {
	if len(f.params.States) == 0 && len(f.params.ReportTypes) == 0 {
		return nil
	}
	return &converter.Filters{States: f.params.States, ReportTypes: f.params.ReportTypes}
}

func (f *GitLabVulnerabilitiesFetcher) now() time.Time {
	if f.params.Clock != nil {
		return f.params.Clock().UTC()
	}
	return time.Now().UTC()
}

// --- GraphQL transport ---

type graphqlRequest struct {
	Query     string         `json:"query"`
	Variables map[string]any `json:"variables"`
}

// graphqlError is one entry of a GraphQL errors[] array. Path segments are
// field names or list indices, so they are decoded loosely rather than as
// strings only.
type graphqlError struct {
	Message string `json:"message"`
	Path    []any  `json:"path"`
}

type graphqlResponse struct {
	Data   json.RawMessage `json:"data"`
	Errors []graphqlError  `json:"errors"`
}

// currentLicense is admin-only; a non-admin token gets a permission error on
// that one field and nothing else, which is expected and never fatal.
func (e graphqlError) tolerable() bool {
	if len(e.Path) != 1 {
		return false
	}
	field, ok := e.Path[0].(string)
	return ok && field == "currentLicense"
}

func (f *GitLabVulnerabilitiesFetcher) post(ctx context.Context, token, query string, variables map[string]any) (json.RawMessage, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	apiURL, err := shared.ValidateAndBuildAPIURL(f.params.URL, graphqlPath, toolName)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", errPrefix, err)
	}
	body, err := json.Marshal(graphqlRequest{Query: query, Variables: variables})
	if err != nil {
		return nil, fmt.Errorf("%s: failed to encode request: %w", errPrefix, err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, apiURL.String(), bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("%s: failed to build request: %w", errPrefix, err)
	}
	req.Header.Set("PRIVATE-TOKEN", token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := f.client.Do(req) //#nosec G704 -- host is the user-configured GitLab server; scheme validated above
	if err != nil {
		return nil, fmt.Errorf("%s: request failed: %w", errPrefix, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: GitLab GraphQL returned HTTP %d", errPrefix, resp.StatusCode)
	}

	var raw []byte
	if f.maxResponseSize() < 0 {
		raw, err = shared.ReadLimitedBody(resp.Body, 1<<62)
	} else {
		raw, err = shared.ReadLimitedBody(resp.Body, f.maxResponseSize())
	}
	if err != nil {
		return nil, fmt.Errorf("%s: %w", errPrefix, err)
	}
	var gql graphqlResponse
	if err := json.Unmarshal(raw, &gql); err != nil {
		return nil, fmt.Errorf("%s: invalid GraphQL response: %w", errPrefix, err)
	}
	for _, e := range gql.Errors {
		if !e.tolerable() {
			return nil, fmt.Errorf("%s: GraphQL error: %s", errPrefix, e.Message)
		}
	}
	if len(gql.Data) == 0 || string(gql.Data) == "null" {
		return nil, fmt.Errorf("%s: GraphQL response carried no data", errPrefix)
	}
	return gql.Data, nil
}

// --- Probe ---

// probeData is the probe query's data block.
type probeData struct {
	Metadata    converter.Metadata `json:"metadata"`
	CurrentUser *struct {
		Username string `json:"username"`
	} `json:"currentUser"`
	CurrentLicense *struct {
		Plan      string `json:"plan"`
		Trial     bool   `json:"trial"`
		ExpiresAt string `json:"expiresAt"`
	} `json:"currentLicense"`
	Project *converter.Project `json:"project"`
}

func (f *GitLabVulnerabilitiesFetcher) probe(ctx context.Context, token, fullPath string) (*probeData, error) {
	data, err := f.post(ctx, token, probeQuery, map[string]any{"fullPath": fullPath})
	if err != nil {
		return nil, err
	}
	var p probeData
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("%s: invalid probe response: %w", errPrefix, err)
	}
	if !p.Metadata.Enterprise {
		return nil, fmt.Errorf("%s: GitLab Community Edition has no Vulnerability Report; use `hdf fetch gitlab` for CI artifacts", errPrefix)
	}
	if p.Project == nil {
		return nil, fmt.Errorf("%s: project %q not found or not readable with this token", errPrefix, fullPath)
	}
	return &p, nil
}

// --- Pages ---

// pageData keeps Project a pointer so a null project is an error rather than a
// zero value that would read as "this project has no vulnerabilities".
type pageData struct {
	Project *struct {
		FullPath  string `json:"fullPath"`
		Pipelines *struct {
			Nodes []json.RawMessage `json:"nodes"`
		} `json:"pipelines"`
		Vulnerabilities struct {
			PageInfo struct {
				HasNextPage bool    `json:"hasNextPage"`
				EndCursor   *string `json:"endCursor"`
			} `json:"pageInfo"`
			Nodes []json.RawMessage `json:"nodes"`
		} `json:"vulnerabilities"`
	} `json:"project"`
}

// nestedConnection is one of a vulnerability's own connections as the page
// query returns it, with enough of pageInfo to tell a complete list from a
// truncated one.
type nestedConnection struct {
	PageInfo struct {
		HasNextPage bool    `json:"hasNextPage"`
		EndCursor   *string `json:"endCursor"`
	} `json:"pageInfo"`
	Nodes []json.RawMessage `json:"nodes"`
}

type nodeHistories struct {
	ID                string           `json:"id"`
	StateTransitions  nestedConnection `json:"stateTransitions"`
	SeverityOverrides nestedConnection `json:"severityOverrides"`
}

type historyData struct {
	Vulnerability *nodeHistories `json:"vulnerability"`
}

// completeHistories replaces every node whose nested history GitLab truncated
// with one carrying the whole connection. The page query keeps its nested
// pages small to stay inside the complexity limit, and both connections are
// oldest-first, so a truncated list hides the newest transition — the very one
// the converter reads as the governing decision.
func (f *GitLabVulnerabilitiesFetcher) completeHistories(ctx context.Context, token string, nodes []json.RawMessage) error {
	for i, raw := range nodes {
		var h nodeHistories
		if err := json.Unmarshal(raw, &h); err != nil {
			return fmt.Errorf("%s: invalid vulnerability node: %w", errPrefix, err)
		}
		if !h.StateTransitions.PageInfo.HasNextPage && !h.SeverityOverrides.PageInfo.HasNextPage {
			continue
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		transitions, err := f.drainHistory(ctx, token, h.ID, transitionsField, h.StateTransitions)
		if err != nil {
			return err
		}
		overrides, err := f.drainHistory(ctx, token, h.ID, overridesField, h.SeverityOverrides)
		if err != nil {
			return err
		}
		patched, err := patchHistories(raw, transitions, overrides)
		if err != nil {
			return err
		}
		nodes[i] = patched
	}
	return nil
}

const (
	transitionsField = "stateTransitions"
	overridesField   = "severityOverrides"
)

// drainHistory pages one connection to its end, starting from what the page
// query already returned.
func (f *GitLabVulnerabilitiesFetcher) drainHistory(ctx context.Context, token, id, field string, have nestedConnection) ([]json.RawMessage, error) {
	nodes := append([]json.RawMessage(nil), have.Nodes...)
	hasNext, after := have.PageInfo.HasNextPage, have.PageInfo.EndCursor
	for page := 0; hasNext; page++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if page >= f.maxPages() {
			return nil, fmt.Errorf("%s: the %s of %s exceeded the maximum page limit (%d); refusing to return a partial history", errPrefix, field, id, f.maxPages())
		}
		if after == nil || *after == "" {
			return nil, fmt.Errorf("%s: GitLab reported more %s for %s but no cursor to fetch them", errPrefix, field, id)
		}
		vars := map[string]any{
			"id":               id,
			"first":            historyPageSize,
			"transitionsAfter": nil,
			"overridesAfter":   nil,
			"withTransitions":  field == transitionsField,
			"withOverrides":    field == overridesField,
		}
		if field == transitionsField {
			vars["transitionsAfter"] = after
		} else {
			vars["overridesAfter"] = after
		}
		data, err := f.post(ctx, token, historyQuery, vars)
		if err != nil {
			return nil, err
		}
		var hd historyData
		if err := json.Unmarshal(data, &hd); err != nil {
			return nil, fmt.Errorf("%s: invalid %s response: %w", errPrefix, field, err)
		}
		if hd.Vulnerability == nil {
			return nil, fmt.Errorf("%s: asked for the %s of %s and GitLab returned no vulnerability", errPrefix, field, id)
		}
		conn := hd.Vulnerability.StateTransitions
		if field == overridesField {
			conn = hd.Vulnerability.SeverityOverrides
		}
		nodes = append(nodes, conn.Nodes...)
		hasNext, after = conn.PageInfo.HasNextPage, conn.PageInfo.EndCursor
	}
	return nodes, nil
}

// patchHistories rewrites the two connections with their complete node lists.
// The node is re-marshalled from a map, so a repaired node's keys come out
// sorted rather than in GitLab's order; only the ordering differs.
func patchHistories(raw json.RawMessage, transitions, overrides []json.RawMessage) (json.RawMessage, error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return nil, fmt.Errorf("%s: invalid vulnerability node: %w", errPrefix, err)
	}
	for field, complete := range map[string][]json.RawMessage{transitionsField: transitions, overridesField: overrides} {
		body, err := json.Marshal(map[string][]json.RawMessage{"nodes": complete})
		if err != nil {
			return nil, fmt.Errorf("%s: failed to reassemble %s: %w", errPrefix, field, err)
		}
		fields[field] = body
	}
	out, err := json.Marshal(fields)
	if err != nil {
		return nil, fmt.Errorf("%s: failed to reassemble vulnerability node: %w", errPrefix, err)
	}
	return out, nil
}

func (f *GitLabVulnerabilitiesFetcher) pageVariables(fullPath, ref string, after *string, withPipeline bool) map[string]any {
	vars := map[string]any{
		"fullPath":     fullPath,
		"ref":          ref,
		"first":        f.pageSize(),
		"after":        after,
		"withPipeline": withPipeline,
		"state":        nil,
		"reportType":   nil,
	}
	if len(f.params.States) > 0 {
		vars["state"] = f.params.States
	}
	if len(f.params.ReportTypes) > 0 {
		vars["reportType"] = f.params.ReportTypes
	}
	return vars
}

// envelope is the document handed to the converter, mirroring
// converter.Envelope with the vulnerability nodes kept as raw JSON so
// nothing GitLab returned is re-shaped in transit.
type envelope struct {
	Metadata converter.Metadata `json:"metadata"`
	Project  projectBlock       `json:"project"`
	// Filters records the selection this fetch asked for. Without it a zero-row
	// filtered result is indistinguishable from a project with no findings,
	// because the ingestion signals it would be judged against are unfiltered.
	Filters         *converter.Filters `json:"filters,omitempty"`
	Vulnerabilities []json.RawMessage  `json:"vulnerabilities"`
	FetchedAt       string             `json:"fetchedAt"`
}

// projectBlock is the probe's project block plus the latest default-branch
// pipeline lifted from the first page.
type projectBlock struct {
	converter.Project
	LatestDefaultBranchPipeline json.RawMessage `json:"latestDefaultBranchPipeline"`
}

func (f *GitLabVulnerabilitiesFetcher) fetchProject(ctx context.Context, token, fullPath string) ([]byte, error) {
	p, err := f.probe(ctx, token, fullPath)
	if err != nil {
		return nil, err
	}
	ref := ""
	if p.Project.Repository != nil {
		ref = p.Project.Repository.RootRef
	}

	env := envelope{
		Metadata:        p.Metadata,
		Project:         projectBlock{Project: *p.Project, LatestDefaultBranchPipeline: json.RawMessage("null")},
		Filters:         f.filters(),
		Vulnerabilities: make([]json.RawMessage, 0),
		FetchedAt:       f.now().Format(time.RFC3339),
	}

	var after *string
	for page := 0; ; page++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if page >= f.maxPages() {
			return nil, fmt.Errorf("%s: %s exceeded the maximum page limit (%d); refusing to return a partial report", errPrefix, fullPath, f.maxPages())
		}
		data, err := f.post(ctx, token, pageQuery, f.pageVariables(fullPath, ref, after, page == 0))
		if err != nil {
			return nil, err
		}
		var pd pageData
		if err := json.Unmarshal(data, &pd); err != nil {
			return nil, fmt.Errorf("%s: invalid page response: %w", errPrefix, err)
		}
		if pd.Project == nil {
			return nil, fmt.Errorf("%s: page %d of %s came back with no project; access may have changed mid-fetch", errPrefix, page+1, fullPath)
		}
		if pd.Project.FullPath != fullPath {
			return nil, fmt.Errorf("%s: asked for %s but page %d described %s", errPrefix, fullPath, page+1, pd.Project.FullPath)
		}
		if page == 0 && pd.Project.Pipelines != nil && len(pd.Project.Pipelines.Nodes) > 0 {
			env.Project.LatestDefaultBranchPipeline = pd.Project.Pipelines.Nodes[0]
		}
		env.Vulnerabilities = append(env.Vulnerabilities, pd.Project.Vulnerabilities.Nodes...)
		if !pd.Project.Vulnerabilities.PageInfo.HasNextPage {
			break
		}
		if pd.Project.Vulnerabilities.PageInfo.EndCursor == nil || *pd.Project.Vulnerabilities.PageInfo.EndCursor == "" {
			return nil, fmt.Errorf("%s: GitLab reported another page of %s but no cursor to fetch it", errPrefix, fullPath)
		}
		after = pd.Project.Vulnerabilities.PageInfo.EndCursor
	}

	if err := f.completeHistories(ctx, token, env.Vulnerabilities); err != nil {
		return nil, err
	}

	out, err := json.Marshal(env)
	if err != nil {
		return nil, fmt.Errorf("%s: failed to assemble envelope: %w", errPrefix, err)
	}
	// Refuse the never-ingested cases here, before anything is written, with
	// the converter's own classification so both doors agree.
	if len(env.Vulnerabilities) == 0 {
		var typed converter.Envelope
		if err := json.Unmarshal(out, &typed); err != nil {
			return nil, fmt.Errorf("%s: assembled envelope did not round-trip: %w", errPrefix, err)
		}
		if err := converter.IngestionError(&typed); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// Fetch reads one project's Vulnerability Report and returns the assembled
// envelope. In group mode use FetchGroup.
func (f *GitLabVulnerabilitiesFetcher) Fetch(ctx context.Context) ([]byte, error) {
	if f.params.Project == "" {
		return nil, fmt.Errorf("%s: Fetch needs a project; use FetchGroup for a group", errPrefix)
	}
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, fetchTimeout)
		defer cancel()
	}
	token, err := f.token()
	if err != nil {
		return nil, err
	}
	return f.fetchProject(ctx, token, f.params.Project)
}

// GroupResult is one project's outcome in a group fetch. Err is set when that
// project could not be fetched; the others are still returned so the caller
// can report exactly which repositories are missing.
type GroupResult struct {
	FullPath string
	Envelope []byte
	Err      error
}

// FetchGroup reads the Vulnerability Report of every non-archived project in
// the group (subgroups included unless excluded) and returns one result per
// project, in the order GitLab listed them.
func (f *GitLabVulnerabilitiesFetcher) FetchGroup(ctx context.Context) ([]GroupResult, error) {
	if f.params.Group == "" {
		return nil, fmt.Errorf("%s: FetchGroup needs a group; use Fetch for a project", errPrefix)
	}
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, fetchTimeout)
		defer cancel()
	}
	token, err := f.token()
	if err != nil {
		return nil, err
	}
	paths, err := f.listProjects(ctx, token)
	if err != nil {
		return nil, err
	}
	results := make([]GroupResult, 0, len(paths))
	for _, fullPath := range paths {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		env, err := f.fetchProject(ctx, token, fullPath)
		results = append(results, GroupResult{FullPath: fullPath, Envelope: env, Err: err})
	}
	return results, nil
}

type groupData struct {
	Group *struct {
		FullPath string `json:"fullPath"`
		Projects struct {
			PageInfo struct {
				HasNextPage bool    `json:"hasNextPage"`
				EndCursor   *string `json:"endCursor"`
			} `json:"pageInfo"`
			Nodes []struct {
				FullPath string `json:"fullPath"`
				Archived bool   `json:"archived"`
			} `json:"nodes"`
		} `json:"projects"`
	} `json:"group"`
}

func (f *GitLabVulnerabilitiesFetcher) listProjects(ctx context.Context, token string) ([]string, error) {
	var paths []string
	var after *string
	for page := 0; ; page++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if page >= f.maxPages() {
			return nil, fmt.Errorf("%s: group %s exceeded the maximum page limit (%d) while listing projects", errPrefix, f.params.Group, f.maxPages())
		}
		data, err := f.post(ctx, token, groupQuery, map[string]any{
			"fullPath":         f.params.Group,
			"first":            f.pageSize(),
			"after":            after,
			"includeSubgroups": !f.params.ExcludeSubgroups,
		})
		if err != nil {
			return nil, err
		}
		var gd groupData
		if err := json.Unmarshal(data, &gd); err != nil {
			return nil, fmt.Errorf("%s: invalid group response: %w", errPrefix, err)
		}
		if gd.Group == nil {
			return nil, fmt.Errorf("%s: group %q not found or not readable with this token", errPrefix, f.params.Group)
		}
		for _, n := range gd.Group.Projects.Nodes {
			if !n.Archived && n.FullPath != "" {
				paths = append(paths, n.FullPath)
			}
		}
		if !gd.Group.Projects.PageInfo.HasNextPage {
			break
		}
		if gd.Group.Projects.PageInfo.EndCursor == nil || *gd.Group.Projects.PageInfo.EndCursor == "" {
			return nil, fmt.Errorf("%s: GitLab reported another page of projects but no cursor to fetch it", errPrefix)
		}
		after = gd.Group.Projects.PageInfo.EndCursor
	}
	if len(paths) == 0 {
		return nil, fmt.Errorf("%s: group %s has no non-archived projects", errPrefix, f.params.Group)
	}
	return paths, nil
}

// --- Verify ---

// Diagnosis is what Verify learned from one probe: enough to tell a user why
// a fetch would or would not yield a report, without downloading one.
type Diagnosis struct {
	Username   string
	Version    string
	Enterprise bool
	// Plan and Trial are set only when the token can read the license.
	Plan  string
	Trial bool
	// Project is set in project mode.
	Project *ProjectDiagnosis
}

// ProjectDiagnosis summarizes a project's ingestion signals.
type ProjectDiagnosis struct {
	FullPath string
	// Ingested is true when the Vulnerability Report has been populated at
	// least once (a vulnerability statistic exists).
	Ingested bool
	Total    int
	Enabled  []string
}

// Verify performs the probe only — no vulnerabilities are downloaded — and
// reports the tier and ingestion diagnosis. It backs the CLI --check flag.
func (f *GitLabVulnerabilitiesFetcher) Verify(ctx context.Context) (*Diagnosis, error) {
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, fetchTimeout)
		defer cancel()
	}
	token, err := f.token()
	if err != nil {
		return nil, err
	}
	fullPath := f.params.Project
	if fullPath == "" {
		paths, err := f.listProjects(ctx, token)
		if err != nil {
			return nil, err
		}
		fullPath = paths[0]
	}
	p, err := f.probe(ctx, token, fullPath)
	if err != nil {
		return nil, err
	}
	d := &Diagnosis{Version: p.Metadata.Version, Enterprise: p.Metadata.Enterprise}
	if p.CurrentUser != nil {
		d.Username = p.CurrentUser.Username
	}
	if p.CurrentLicense != nil {
		d.Plan = p.CurrentLicense.Plan
		d.Trial = p.CurrentLicense.Trial
	}
	pd := &ProjectDiagnosis{FullPath: p.Project.FullPath, Ingested: p.Project.VulnerabilityStatistic != nil}
	if p.Project.VulnerabilityStatistic != nil {
		pd.Total = p.Project.VulnerabilityStatistic.Total
	}
	if p.Project.SecurityScanners != nil {
		pd.Enabled = p.Project.SecurityScanners.Enabled
	}
	d.Project = pd
	return d, nil
}

// String renders the diagnosis for a terminal.
func (d *Diagnosis) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "GitLab %s (%s) as %s", d.Version, map[bool]string{true: "EE", false: "CE"}[d.Enterprise], d.Username)
	if d.Plan != "" {
		fmt.Fprintf(&b, ", plan %s", d.Plan)
		if d.Trial {
			b.WriteString(" (trial)")
		}
	}
	if d.Project != nil {
		fmt.Fprintf(&b, "\n%s: ", d.Project.FullPath)
		if d.Project.Ingested {
			fmt.Fprintf(&b, "Vulnerability Report populated (%d open)", d.Project.Total)
		} else {
			b.WriteString("Vulnerability Report never populated")
		}
		if len(d.Project.Enabled) > 0 {
			fmt.Fprintf(&b, "; scanners on the latest default-branch pipeline: %s", strings.Join(d.Project.Enabled, ", "))
		}
	}
	return b.String()
}

func (f *GitLabVulnerabilitiesFetcher) token() (string, error) {
	apiURL, err := shared.ValidateAndBuildAPIURL(f.params.URL, graphqlPath, toolName)
	if err != nil {
		return "", fmt.Errorf("%s: %w", errPrefix, err)
	}
	token, err := gitlab.ResolveToken(apiURL.Host)
	if err != nil {
		return "", fmt.Errorf("%s: %w", errPrefix, err)
	}
	return token, nil
}
