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
	// maxPages bounds every pagination loop (vulnerabilities and projects).
	maxPages = 200
	// pageSize is the default `first:` argument. GitLab caps GraphQL query
	// complexity at 250 for authenticated requests; the full Vulnerability node
	// selection at first:100 scores 276 and is rejected, while 50 fits with
	// room to spare. Fields are never dropped to fit — the page shrinks instead.
	pageSize = 50
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

// Params holds parameters for a Vulnerability Report fetch. Exactly one of
// Project or Group is required.
type Params struct {
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
type Fetcher struct {
	client *http.Client
	params Params
}

// NewFetcher creates a fetcher after validating the server URL and the
// project/group selection. The token is resolved at fetch time.
func NewFetcher(params Params, tlsOpts shared.TLSOptions) (*Fetcher, error) {
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
	return &Fetcher{client: client, params: params}, nil
}

// NewFetcherWithClient creates a fetcher with an injected HTTP client. Use
// this when the caller controls TLS/auth/transport (proxies, MFA, vaults,
// mocked clients in tests). Redirect handling is the caller's responsibility
// too: the default constructor refuses redirects so the token never follows
// one to another host.
func NewFetcherWithClient(params Params, client *http.Client) (*Fetcher, error) {
	if err := validateParams(params); err != nil {
		return nil, err
	}
	return &Fetcher{client: client, params: params}, nil
}

func validateParams(p Params) error {
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

func (f *Fetcher) pageSize() int {
	if f.params.PageSize > 0 {
		return f.params.PageSize
	}
	return pageSize
}

func (f *Fetcher) maxPages() int {
	if f.params.MaxPages > 0 {
		return f.params.MaxPages
	}
	return maxPages
}

func (f *Fetcher) maxResponseSize() int64 {
	if f.params.MaxResponseSize != 0 {
		return f.params.MaxResponseSize
	}
	return maxResponseSize
}

func (f *Fetcher) now() time.Time {
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

func (f *Fetcher) post(ctx context.Context, token, query string, variables map[string]any) (json.RawMessage, error) {
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

func (f *Fetcher) probe(ctx context.Context, token, fullPath string) (*probeData, error) {
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

type pageData struct {
	Project struct {
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

func (f *Fetcher) pageVariables(fullPath, ref string, after *string, withPipeline bool) map[string]any {
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
	Metadata        converter.Metadata `json:"metadata"`
	Project         projectBlock       `json:"project"`
	Vulnerabilities []json.RawMessage  `json:"vulnerabilities"`
	FetchedAt       string             `json:"fetchedAt"`
}

// projectBlock is the probe's project block plus the latest default-branch
// pipeline lifted from the first page.
type projectBlock struct {
	converter.Project
	LatestDefaultBranchPipeline json.RawMessage `json:"latestDefaultBranchPipeline"`
}

func (f *Fetcher) fetchProject(ctx context.Context, token, fullPath string) ([]byte, error) {
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
		Vulnerabilities: make([]json.RawMessage, 0),
		FetchedAt:       f.now().Format("2006-01-02T15:04:05Z"),
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
func (f *Fetcher) Fetch(ctx context.Context) ([]byte, error) {
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
func (f *Fetcher) FetchGroup(ctx context.Context) ([]GroupResult, error) {
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

func (f *Fetcher) listProjects(ctx context.Context, token string) ([]string, error) {
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
func (f *Fetcher) Verify(ctx context.Context) (*Diagnosis, error) {
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

func (f *Fetcher) token() (string, error) {
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
