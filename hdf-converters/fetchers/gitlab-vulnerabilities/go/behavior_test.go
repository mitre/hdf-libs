package gitlabvulnerabilities

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	converter "github.com/mitre/hdf-libs/hdf-converters/v3/converters/gitlab-vulnerabilities-to-hdf/go"
	shared "github.com/mitre/hdf-libs/hdf-converters/v3/fetchers/shared/go"
)

// handlerFor builds a GraphQL replay handler from a map of operation name to
// response producer; the producer sees the decoded variables.
func handlerFor(t *testing.T, responses map[string]func(vars map[string]any) []byte) http.HandlerFunc {
	t.Helper()
	return func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, testToken, r.Header.Get("PRIVATE-TOKEN"))
		var req wireRequest
		require.NoError(t, json.NewDecoder(r.Body).Decode(&req))
		produce, ok := responses[operationName(req.Query)]
		if !ok {
			t.Errorf("unexpected operation %q", operationName(req.Query))
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(produce(req.Variables))
	}
}

// projectReplay replays a project's recorded probe and first page.
func projectReplay(t *testing.T, name string) map[string]func(map[string]any) []byte {
	t.Helper()
	return map[string]func(map[string]any) []byte{
		"VulnerabilityReportProbe": func(map[string]any) []byte { return testdata(t, "probe-"+name+".json") },
		"VulnerabilityReportPage":  func(map[string]any) []byte { return testdata(t, "pages-"+name+"-1.json") },
	}
}

func newTestFetcher(t *testing.T, url string, mutate func(*GitLabVulnerabilitiesParams)) *GitLabVulnerabilitiesFetcher {
	t.Helper()
	t.Setenv("GITLAB_TOKEN", testToken)
	p := GitLabVulnerabilitiesParams{URL: url, Project: "security-demo/web-goat", Clock: fixedClock}
	if mutate != nil {
		mutate(&p)
	}
	f, err := NewGitLabVulnerabilitiesFetcher(p, shared.TLSOptions{})
	require.NoError(t, err)
	return f
}

// --- Empty-report disambiguation (every row of the table) ---

func TestFetch_CleanIngestedProject_YieldsEnvelope(t *testing.T) {
	srv := httptest.NewServer(handlerFor(t, projectReplay(t, "web-goat")))
	defer srv.Close()
	f := newTestFetcher(t, srv.URL, nil)

	data, err := f.Fetch(context.Background())
	require.NoError(t, err)
	var env converter.Envelope
	require.NoError(t, json.Unmarshal(data, &env))
	assert.Empty(t, env.Vulnerabilities)
	assert.NotNil(t, env.Vulnerabilities, "empty must serialize as [] not null")
	require.NotNil(t, env.Project.VulnerabilityStatistic)
	assert.Equal(t, 0, env.Project.VulnerabilityStatistic.Total)
	result, err := converter.ConvertGitlabVulnerabilitiesToHDF(data, "test")
	require.NoError(t, err)
	assert.Equal(t, "gitlab-vulnerability-report-no-findings-secret_detection", result.Baselines[0].Requirements[0].ID)
}

func TestFetch_ReportErrorProject_IsRefusedBeforeWriting(t *testing.T) {
	srv := httptest.NewServer(handlerFor(t, projectReplay(t, "unscanned-app")))
	defer srv.Close()
	f := newTestFetcher(t, srv.URL, func(p *GitLabVulnerabilitiesParams) { p.Project = "security-demo/unscanned-app" })

	_, err := f.Fetch(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "sast: REPORT_ERROR")
	assert.Contains(t, err.Error(), "security-demo/unscanned-app")
}

func TestFetch_ProjectWithoutPipeline_IsRefused(t *testing.T) {
	srv := httptest.NewServer(handlerFor(t, projectReplay(t, "empty-app")))
	defer srv.Close()
	f := newTestFetcher(t, srv.URL, func(p *GitLabVulnerabilitiesParams) { p.Project = "security-demo/empty-app" })

	_, err := f.Fetch(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no default-branch pipeline")
}

// The Free-tier signature: the recorded pre-Ultimate pipeline whose scans
// never left CREATED, paired with a never-ingested probe.
func TestFetch_ReportsNeverIngested_NamesTheUltimateRequirement(t *testing.T) {
	// The recorded page was captured with first:1 and so reports further pages;
	// this test needs only its pipeline block, so the node list is emptied and
	// the paging flag cleared before replay.
	var page map[string]any
	require.NoError(t, json.Unmarshal(testdata(t, "pages-juice-shop-notingested-1.json"), &page))
	vulns := page["data"].(map[string]any)["project"].(map[string]any)["vulnerabilities"].(map[string]any)
	vulns["nodes"] = []any{}
	vulns["pageInfo"] = map[string]any{"hasNextPage": false, "endCursor": nil}
	// The page was recorded against a different project and the fetcher checks
	// that a page describes the project it asked for.
	page["data"].(map[string]any)["project"].(map[string]any)["fullPath"] = "security-demo/unscanned-app"
	notIngested, err := json.Marshal(page)
	require.NoError(t, err)
	responses := projectReplay(t, "unscanned-app")
	responses["VulnerabilityReportPage"] = func(map[string]any) []byte { return notIngested }
	srv := httptest.NewServer(handlerFor(t, responses))
	defer srv.Close()
	f := newTestFetcher(t, srv.URL, func(p *GitLabVulnerabilitiesParams) { p.Project = "security-demo/unscanned-app" })

	_, err = f.Fetch(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "never ingested")
	assert.Contains(t, err.Error(), "GitLab Ultimate")
}

func TestFetch_CommunityEdition_IsRefusedAtTheProbe(t *testing.T) {
	pages := 0
	srv := httptest.NewServer(handlerFor(t, map[string]func(map[string]any) []byte{
		"VulnerabilityReportProbe": func(map[string]any) []byte {
			return []byte(`{"data":{"metadata":{"enterprise":false,"version":"18.9.1"},"currentUser":{"username":"u"},"currentLicense":null,"project":{"fullPath":"g/p"}}}`)
		},
		"VulnerabilityReportPage": func(map[string]any) []byte { pages++; return nil },
	}))
	defer srv.Close()
	f := newTestFetcher(t, srv.URL, func(p *GitLabVulnerabilitiesParams) { p.Project = "g/p" })

	_, err := f.Fetch(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "Community Edition")
	assert.Equal(t, 0, pages, "no page is requested once the edition rules the report out")
}

func TestFetch_ToleratesOnlyTheLicensePermissionError(t *testing.T) {
	// Every recorded probe carries the non-admin currentLicense error.
	var probe struct {
		Errors []struct {
			Path []string `json:"path"`
		} `json:"errors"`
	}
	require.NoError(t, json.Unmarshal(testdata(t, "probe-web-goat.json"), &probe))
	require.Len(t, probe.Errors, 1)
	assert.Equal(t, []string{"currentLicense"}, probe.Errors[0].Path)

	responses := projectReplay(t, "web-goat")
	responses["VulnerabilityReportPage"] = func(map[string]any) []byte {
		return []byte(`{"errors":[{"message":"Field 'foo' doesn't exist on type 'Project'","path":["query","project","foo"]}],"data":null}`)
	}
	srv := httptest.NewServer(handlerFor(t, responses))
	defer srv.Close()
	f := newTestFetcher(t, srv.URL, nil)

	_, err := f.Fetch(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "GraphQL error: Field 'foo' doesn't exist")
}

func TestFetch_UnreadableProject_IsAnError(t *testing.T) {
	srv := httptest.NewServer(handlerFor(t, map[string]func(map[string]any) []byte{
		"VulnerabilityReportProbe": func(map[string]any) []byte {
			return []byte(`{"data":{"metadata":{"enterprise":true,"version":"18.9.1-ee"},"currentUser":{"username":"u"},"currentLicense":null,"project":null}}`)
		},
	}))
	defer srv.Close()
	f := newTestFetcher(t, srv.URL, func(p *GitLabVulnerabilitiesParams) { p.Project = "g/missing" })

	_, err := f.Fetch(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), `project "g/missing" not found or not readable`)
}

// --- Filters and pagination guards ---

func TestFetch_PassesStateAndReportTypeFilters(t *testing.T) {
	var got map[string]any
	responses := projectReplay(t, "web-goat")
	page := responses["VulnerabilityReportPage"]
	responses["VulnerabilityReportPage"] = func(vars map[string]any) []byte { got = vars; return page(vars) }
	srv := httptest.NewServer(handlerFor(t, responses))
	defer srv.Close()
	f := newTestFetcher(t, srv.URL, func(p *GitLabVulnerabilitiesParams) {
		p.States = []string{"DETECTED", "CONFIRMED"}
		p.ReportTypes = []string{"SAST"}
	})

	_, err := f.Fetch(context.Background())
	require.NoError(t, err)
	assert.Equal(t, []any{"DETECTED", "CONFIRMED"}, got["state"])
	assert.Equal(t, []any{"SAST"}, got["reportType"])
	assert.Equal(t, float64(25), got["first"], "default page size stays under GitLab's query complexity limit")
}

// An instance with a higher complexity cap can ask for bigger pages.
func TestFetch_PageSizeOverride(t *testing.T) {
	var got map[string]any
	responses := projectReplay(t, "web-goat")
	page := responses["VulnerabilityReportPage"]
	responses["VulnerabilityReportPage"] = func(vars map[string]any) []byte { got = vars; return page(vars) }
	srv := httptest.NewServer(handlerFor(t, responses))
	defer srv.Close()
	f := newTestFetcher(t, srv.URL, func(p *GitLabVulnerabilitiesParams) { p.PageSize = 75 })

	_, err := f.Fetch(context.Background())
	require.NoError(t, err)
	assert.Equal(t, float64(75), got["first"])
}

func TestFetch_UnfilteredRequestSendsNullFilters(t *testing.T) {
	var got map[string]any
	responses := projectReplay(t, "web-goat")
	page := responses["VulnerabilityReportPage"]
	responses["VulnerabilityReportPage"] = func(vars map[string]any) []byte { got = vars; return page(vars) }
	srv := httptest.NewServer(handlerFor(t, responses))
	defer srv.Close()
	f := newTestFetcher(t, srv.URL, nil)

	_, err := f.Fetch(context.Background())
	require.NoError(t, err)
	_, hasState := got["state"]
	assert.True(t, hasState, "the variable is declared so the query stays valid")
	assert.Nil(t, got["state"])
	assert.Nil(t, got["reportType"])
}

func TestFetch_PageCap_FailsLoudlyWithoutPartialEnvelope(t *testing.T) {
	// A server that always claims another page.
	responses := projectReplay(t, "juice-shop")
	responses["VulnerabilityReportPage"] = func(map[string]any) []byte {
		return []byte(`{"data":{"project":{"fullPath":"security-demo/juice-shop","pipelines":{"nodes":[]},"vulnerabilities":{"pageInfo":{"hasNextPage":true,"endCursor":"c"},"nodes":[{"uuid":"x","state":"DETECTED"}]}}}}`)
	}
	srv := httptest.NewServer(handlerFor(t, responses))
	defer srv.Close()
	f := newTestFetcher(t, srv.URL, func(p *GitLabVulnerabilitiesParams) { p.Project = "security-demo/juice-shop"; p.MaxPages = 3 })

	data, err := f.Fetch(context.Background())
	require.Error(t, err)
	assert.Nil(t, data, "no partial envelope on a capped fetch")
	assert.Contains(t, err.Error(), "maximum page limit (3)")
}

func TestFetch_NextPageWithoutCursor_IsAnError(t *testing.T) {
	responses := projectReplay(t, "juice-shop")
	responses["VulnerabilityReportPage"] = func(map[string]any) []byte {
		return []byte(`{"data":{"project":{"fullPath":"security-demo/juice-shop","vulnerabilities":{"pageInfo":{"hasNextPage":true,"endCursor":null},"nodes":[]}}}}`)
	}
	srv := httptest.NewServer(handlerFor(t, responses))
	defer srv.Close()
	f := newTestFetcher(t, srv.URL, func(p *GitLabVulnerabilitiesParams) { p.Project = "security-demo/juice-shop" })

	_, err := f.Fetch(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no cursor")
}

func TestFetch_ContextCancelled(t *testing.T) {
	srv := httptest.NewServer(handlerFor(t, projectReplay(t, "web-goat")))
	defer srv.Close()
	f := newTestFetcher(t, srv.URL, nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := f.Fetch(ctx)
	require.ErrorIs(t, err, context.Canceled)
}

func TestFetch_ResponseSizeLimit(t *testing.T) {
	srv := httptest.NewServer(handlerFor(t, projectReplay(t, "juice-shop")))
	defer srv.Close()
	f := newTestFetcher(t, srv.URL, func(p *GitLabVulnerabilitiesParams) { p.Project = "security-demo/juice-shop"; p.MaxResponseSize = 1024 })

	_, err := f.Fetch(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "exceeded 1024 byte limit")

	single := httptest.NewServer(handlerFor(t, projectReplay(t, "web-goat")))
	defer single.Close()
	unlimited := newTestFetcher(t, single.URL, func(p *GitLabVulnerabilitiesParams) { p.MaxResponseSize = -1 })
	_, err = unlimited.Fetch(context.Background())
	require.NoError(t, err)
}

func TestFetch_HTTPErrorAndBadJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusForbidden) }))
	defer srv.Close()
	f := newTestFetcher(t, srv.URL, nil)
	_, err := f.Fetch(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "HTTP 403")

	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("<html>")) }))
	defer bad.Close()
	f = newTestFetcher(t, bad.URL, nil)
	_, err = f.Fetch(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid GraphQL response")

	empty := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(`{"data":null}`)) }))
	defer empty.Close()
	f = newTestFetcher(t, empty.URL, nil)
	_, err = f.Fetch(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no data")
}

// deadlineCapture records the deadline on each outgoing request's context.
type deadlineCapture struct {
	deadlines []time.Time
	set       []bool
	inner     http.RoundTripper
}

func (d *deadlineCapture) RoundTrip(r *http.Request) (*http.Response, error) {
	deadline, ok := r.Context().Deadline()
	d.deadlines = append(d.deadlines, deadline)
	d.set = append(d.set, ok)
	return d.inner.RoundTrip(r)
}

func TestFetch_DefaultDeadlineApplied(t *testing.T) {
	srv := httptest.NewServer(handlerFor(t, projectReplay(t, "web-goat")))
	defer srv.Close()
	t.Setenv("GITLAB_TOKEN", testToken)
	capture := &deadlineCapture{inner: http.DefaultTransport}
	f, err := NewGitLabVulnerabilitiesFetcherWithClient(GitLabVulnerabilitiesParams{URL: srv.URL, Project: "security-demo/web-goat", Clock: fixedClock}, &http.Client{Transport: capture})
	require.NoError(t, err)

	_, err = f.Fetch(context.Background())
	require.NoError(t, err)
	require.NotEmpty(t, capture.set)
	for i, ok := range capture.set {
		assert.True(t, ok, "request %d carried no deadline", i)
		assert.WithinDuration(t, time.Now().Add(fetchTimeout), capture.deadlines[i], 10*time.Second)
	}

	// A caller-supplied deadline is kept, not replaced.
	capture.set, capture.deadlines = nil, nil
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	_, err = f.Fetch(ctx)
	require.NoError(t, err)
	assert.WithinDuration(t, time.Now().Add(time.Minute), capture.deadlines[0], 10*time.Second)
}

// --- Credentials and validation ---

func TestFetch_MissingToken_IsClearAndNeverLeaksAValue(t *testing.T) {
	srv := httptest.NewServer(handlerFor(t, projectReplay(t, "web-goat")))
	defer srv.Close()
	t.Setenv("GITLAB_TOKEN", "")
	t.Setenv("GLAB_TOKEN", "")
	t.Setenv("GLAB_CONFIG_DIR", t.TempDir())
	f, err := NewGitLabVulnerabilitiesFetcher(GitLabVulnerabilitiesParams{URL: srv.URL, Project: "security-demo/web-goat"}, shared.TLSOptions{})
	require.NoError(t, err)

	_, err = f.Fetch(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no GitLab API token found")
}

func TestFetch_TokenNeverAppearsInErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusUnauthorized) }))
	defer srv.Close()
	f := newTestFetcher(t, srv.URL, nil)
	_, err := f.Fetch(context.Background())
	require.Error(t, err)
	assert.NotContains(t, err.Error(), testToken)
}

func TestNewFetcher_Validation(t *testing.T) {
	cases := map[string]GitLabVulnerabilitiesParams{
		"empty URL":              {Project: "g/p"},
		"ftp scheme":             {URL: "ftp://gitlab.example.com", Project: "g/p"},
		"no project or group":    {URL: "https://gitlab.example.com"},
		"both project and group": {URL: "https://gitlab.example.com", Project: "g/p", Group: "g"},
		"negative page size":     {URL: "https://gitlab.example.com", Project: "g/p", PageSize: -1},
	}
	for name, p := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := NewGitLabVulnerabilitiesFetcher(p, shared.TLSOptions{})
			assert.Error(t, err)
			_, err = NewGitLabVulnerabilitiesFetcherWithClient(p, http.DefaultClient)
			assert.Error(t, err)
		})
	}
	f, err := NewGitLabVulnerabilitiesFetcherWithClient(GitLabVulnerabilitiesParams{URL: "https://gitlab.example.com", Group: "g"}, http.DefaultClient)
	require.NoError(t, err)
	_, err = f.Fetch(context.Background())
	assert.ErrorContains(t, err, "use FetchGroup")
	f, err = NewGitLabVulnerabilitiesFetcherWithClient(GitLabVulnerabilitiesParams{URL: "https://gitlab.example.com", Project: "g/p"}, http.DefaultClient)
	require.NoError(t, err)
	_, err = f.FetchGroup(context.Background())
	assert.ErrorContains(t, err, "use Fetch")
}

// --- Group mode ---

func groupReplay(t *testing.T) map[string]func(map[string]any) []byte {
	t.Helper()
	return map[string]func(map[string]any) []byte{
		"GroupProjects": func(vars map[string]any) []byte {
			assert.Equal(t, "security-demo", vars["fullPath"])
			return testdata(t, "group-projects.json")
		},
		"VulnerabilityReportProbe": func(vars map[string]any) []byte {
			return testdata(t, "probe-"+strings.TrimPrefix(vars["fullPath"].(string), "security-demo/")+".json")
		},
		"VulnerabilityReportPage": func(vars map[string]any) []byte {
			name := strings.TrimPrefix(vars["fullPath"].(string), "security-demo/")
			after, _ := vars["after"].(string)
			return pageAfter(t, name, after)
		},
	}
}

// pageAfter serves the recorded page whose predecessor ended at the given
// cursor, so a replay walks the same chain the live fetch did however many
// pages were recorded.
func pageAfter(t *testing.T, name, after string) []byte {
	t.Helper()
	if after == "" {
		return testdata(t, fmt.Sprintf("pages-%s-1.json", name))
	}
	for i := 1; ; i++ {
		data, err := os.ReadFile(filepath.Join("testdata", fmt.Sprintf("pages-%s-%d.json", name, i)))
		if err != nil {
			t.Fatalf("no recorded page for %s follows cursor %q", name, after)
		}
		if endCursorOf(t, data) == after {
			return testdata(t, fmt.Sprintf("pages-%s-%d.json", name, i+1))
		}
	}
}

func endCursorOf(t *testing.T, page []byte) string {
	t.Helper()
	var p struct {
		Data struct {
			Project struct {
				Vulnerabilities struct {
					PageInfo struct {
						EndCursor string `json:"endCursor"`
					} `json:"pageInfo"`
				} `json:"vulnerabilities"`
			} `json:"project"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(page, &p))
	return p.Data.Project.Vulnerabilities.PageInfo.EndCursor
}

func TestFetchGroup_OneResultPerProjectWithPerProjectErrors(t *testing.T) {
	var subgroups any
	responses := groupReplay(t)
	list := responses["GroupProjects"]
	responses["GroupProjects"] = func(vars map[string]any) []byte { subgroups = vars["includeSubgroups"]; return list(vars) }
	srv := httptest.NewServer(handlerFor(t, responses))
	defer srv.Close()
	t.Setenv("GITLAB_TOKEN", testToken)
	f, err := NewGitLabVulnerabilitiesFetcher(GitLabVulnerabilitiesParams{URL: srv.URL, Group: "security-demo", PageSize: 50, Clock: fixedClock}, shared.TLSOptions{})
	require.NoError(t, err)

	results, err := f.FetchGroup(context.Background())
	require.NoError(t, err)
	assert.Equal(t, true, subgroups)
	require.Len(t, results, 4, "the recorded group lists four projects")
	byPath := map[string]GroupResult{}
	for _, r := range results {
		byPath[r.FullPath] = r
	}
	assert.NoError(t, byPath["security-demo/juice-shop"].Err)
	assert.NoError(t, byPath["security-demo/web-goat"].Err)
	assert.ErrorContains(t, byPath["security-demo/unscanned-app"].Err, "REPORT_ERROR")
	assert.ErrorContains(t, byPath["security-demo/empty-app"].Err, "no default-branch pipeline")
	assert.Nil(t, byPath["security-demo/empty-app"].Envelope)

	var env converter.Envelope
	require.NoError(t, json.Unmarshal(byPath["security-demo/juice-shop"].Envelope, &env))
	assert.Len(t, env.Vulnerabilities, 100)
}

func TestFetchGroup_ExcludeSubgroupsAndUnknownGroup(t *testing.T) {
	var subgroups any
	responses := groupReplay(t)
	list := responses["GroupProjects"]
	responses["GroupProjects"] = func(vars map[string]any) []byte { subgroups = vars["includeSubgroups"]; return list(vars) }
	srv := httptest.NewServer(handlerFor(t, responses))
	defer srv.Close()
	t.Setenv("GITLAB_TOKEN", testToken)
	f, err := NewGitLabVulnerabilitiesFetcher(GitLabVulnerabilitiesParams{URL: srv.URL, Group: "security-demo", ExcludeSubgroups: true, Clock: fixedClock}, shared.TLSOptions{})
	require.NoError(t, err)
	_, err = f.FetchGroup(context.Background())
	require.NoError(t, err)
	assert.Equal(t, false, subgroups)

	missing := httptest.NewServer(handlerFor(t, map[string]func(map[string]any) []byte{
		"GroupProjects": func(map[string]any) []byte { return []byte(`{"data":{"group":null}}`) },
	}))
	defer missing.Close()
	f, err = NewGitLabVulnerabilitiesFetcher(GitLabVulnerabilitiesParams{URL: missing.URL, Group: "nope"}, shared.TLSOptions{})
	require.NoError(t, err)
	_, err = f.FetchGroup(context.Background())
	assert.ErrorContains(t, err, `group "nope" not found`)

	archivedOnly := httptest.NewServer(handlerFor(t, map[string]func(map[string]any) []byte{
		"GroupProjects": func(map[string]any) []byte {
			return []byte(`{"data":{"group":{"fullPath":"g","projects":{"pageInfo":{"hasNextPage":false,"endCursor":null},"nodes":[{"fullPath":"g/old","archived":true}]}}}}`)
		},
	}))
	defer archivedOnly.Close()
	f, err = NewGitLabVulnerabilitiesFetcher(GitLabVulnerabilitiesParams{URL: archivedOnly.URL, Group: "g"}, shared.TLSOptions{})
	require.NoError(t, err)
	_, err = f.FetchGroup(context.Background())
	assert.ErrorContains(t, err, "no non-archived projects")
}

func TestFetchGroup_ProjectListPagination(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(handlerFor(t, map[string]func(map[string]any) []byte{
		"GroupProjects": func(vars map[string]any) []byte {
			calls++
			if after, _ := vars["after"].(string); after == "" {
				return []byte(`{"data":{"group":{"fullPath":"g","projects":{"pageInfo":{"hasNextPage":true,"endCursor":"p2"},"nodes":[{"fullPath":"g/a","archived":false}]}}}}`)
			}
			assert.Equal(t, "p2", vars["after"])
			return []byte(`{"data":{"group":{"fullPath":"g","projects":{"pageInfo":{"hasNextPage":false,"endCursor":null},"nodes":[{"fullPath":"g/b","archived":false}]}}}}`)
		},
		"VulnerabilityReportProbe": func(map[string]any) []byte { return testdata(t, "probe-web-goat.json") },
		"VulnerabilityReportPage":  func(map[string]any) []byte { return testdata(t, "pages-web-goat-1.json") },
	}))
	defer srv.Close()
	t.Setenv("GITLAB_TOKEN", testToken)
	f, err := NewGitLabVulnerabilitiesFetcher(GitLabVulnerabilitiesParams{URL: srv.URL, Group: "g", Clock: fixedClock}, shared.TLSOptions{})
	require.NoError(t, err)
	results, err := f.FetchGroup(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 2, calls)
	assert.Equal(t, []string{"g/a", "g/b"}, []string{results[0].FullPath, results[1].FullPath})

	capped, err := NewGitLabVulnerabilitiesFetcher(GitLabVulnerabilitiesParams{URL: srv.URL, Group: "g", MaxPages: 1}, shared.TLSOptions{})
	require.NoError(t, err)
	_, err = capped.FetchGroup(context.Background())
	assert.ErrorContains(t, err, "maximum page limit (1) while listing projects")
}

// --- Verify ---

func TestVerify_ProbeOnlyDiagnosis(t *testing.T) {
	pages := 0
	responses := projectReplay(t, "juice-shop")
	responses["VulnerabilityReportPage"] = func(map[string]any) []byte { pages++; return nil }
	srv := httptest.NewServer(handlerFor(t, responses))
	defer srv.Close()
	f := newTestFetcher(t, srv.URL, func(p *GitLabVulnerabilitiesParams) { p.Project = "security-demo/juice-shop" })

	d, err := f.Verify(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 0, pages, "verify never downloads vulnerabilities")
	assert.Equal(t, "sec-reviewer", d.Username)
	assert.Equal(t, "18.9.1-ee", d.Version)
	assert.True(t, d.Enterprise)
	assert.Equal(t, "", d.Plan, "the recorded token cannot read the license")
	require.NotNil(t, d.Project)
	assert.True(t, d.Project.Ingested)
	assert.Equal(t, 177, d.Project.Total)
	assert.Equal(t, []string{"SAST", "DEPENDENCY_SCANNING", "SECRET_DETECTION"}, d.Project.Enabled)
	assert.Equal(t, "GitLab 18.9.1-ee (EE) as sec-reviewer\nsecurity-demo/juice-shop: Vulnerability Report populated (177 open); scanners on the latest default-branch pipeline: SAST, DEPENDENCY_SCANNING, SECRET_DETECTION", d.String())
}

func TestVerify_NeverIngestedProjectAndGroupMode(t *testing.T) {
	srv := httptest.NewServer(handlerFor(t, projectReplay(t, "empty-app")))
	defer srv.Close()
	f := newTestFetcher(t, srv.URL, func(p *GitLabVulnerabilitiesParams) { p.Project = "security-demo/empty-app" })
	d, err := f.Verify(context.Background())
	require.NoError(t, err)
	assert.False(t, d.Project.Ingested)
	assert.Contains(t, d.String(), "Vulnerability Report never populated")

	// Group mode verifies against the first listed project.
	group := httptest.NewServer(handlerFor(t, groupReplay(t)))
	defer group.Close()
	t.Setenv("GITLAB_TOKEN", testToken)
	g, err := NewGitLabVulnerabilitiesFetcher(GitLabVulnerabilitiesParams{URL: group.URL, Group: "security-demo"}, shared.TLSOptions{})
	require.NoError(t, err)
	d, err = g.Verify(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "security-demo/unscanned-app", d.Project.FullPath, "the recorded listing puts unscanned-app first")

	// A license-readable probe surfaces the plan.
	licensed := httptest.NewServer(handlerFor(t, map[string]func(map[string]any) []byte{
		"VulnerabilityReportProbe": func(map[string]any) []byte {
			return []byte(`{"data":{"metadata":{"enterprise":true,"version":"18.9.1-ee"},"currentUser":{"username":"root"},"currentLicense":{"plan":"ultimate","trial":true,"expiresAt":"2026-10-18"},"project":{"fullPath":"g/p","vulnerabilityStatistic":null}}}`)
		},
	}))
	defer licensed.Close()
	f = newTestFetcher(t, licensed.URL, func(p *GitLabVulnerabilitiesParams) { p.Project = "g/p" })
	d, err = f.Verify(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "ultimate", d.Plan)
	assert.True(t, d.Trial)
	assert.Contains(t, d.String(), "plan ultimate (trial)")
}

func TestFetch_ClockDefaultsToWallClock(t *testing.T) {
	srv := httptest.NewServer(handlerFor(t, projectReplay(t, "web-goat")))
	defer srv.Close()
	f := newTestFetcher(t, srv.URL, func(p *GitLabVulnerabilitiesParams) { p.Clock = nil })
	before := time.Now().UTC().Truncate(time.Second)
	data, err := f.Fetch(context.Background())
	require.NoError(t, err)
	var env converter.Envelope
	require.NoError(t, json.Unmarshal(data, &env))
	fetched, err := time.Parse("2006-01-02T15:04:05Z", env.FetchedAt)
	require.NoError(t, err)
	assert.False(t, fetched.Before(before), fmt.Sprintf("fetchedAt %s should not precede %s", fetched, before))
}

// A redirect from the named host is refused, so the token never travels to
// wherever the redirect points.
func TestFetch_RefusesRedirectsSoTheTokenStaysHome(t *testing.T) {
	var leaked int32
	elsewhere := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("PRIVATE-TOKEN") != "" {
			atomic.AddInt32(&leaked, 1)
		}
		_, _ = w.Write(testdata(t, "probe-web-goat.json"))
	}))
	defer elsewhere.Close()
	redirecting := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, elsewhere.URL+"/api/graphql", http.StatusTemporaryRedirect)
	}))
	defer redirecting.Close()
	f := newTestFetcher(t, redirecting.URL, nil)

	_, err := f.Fetch(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "HTTP 307")
	assert.Equal(t, int32(0), atomic.LoadInt32(&leaked), "the token must not be sent to the redirect target")
}

// GraphQL error paths may contain list indices; a node-level error must
// surface its own message, not a decoding failure.
func TestFetch_GraphQLErrorWithIndexedPath_SurfacesTheMessage(t *testing.T) {
	responses := projectReplay(t, "web-goat")
	responses["VulnerabilityReportPage"] = func(map[string]any) []byte {
		return []byte(`{"errors":[{"message":"Cannot return null for non-nullable field","path":["project","vulnerabilities","nodes",3,"cvss"]}],"data":null}`)
	}
	srv := httptest.NewServer(handlerFor(t, responses))
	defer srv.Close()
	f := newTestFetcher(t, srv.URL, nil)

	_, err := f.Fetch(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "GraphQL error: Cannot return null for non-nullable field")
	assert.False(t, graphqlError{Path: []any{float64(0)}}.tolerable(), "an index alone is never the license field")
}

// A finding whose triage history overflows the nested page is completed with a
// follow-up query. Both connections are oldest-first, so a short list would
// hide the newest transition, which is the one the converter reads as the
// governing decision.
func TestFetch_TruncatedHistory_IsCompletedByAFollowUpQuery(t *testing.T) {
	page := truncateOneHistory(t, "pages-web-goat-1.json")
	var historyCalls []map[string]any
	responses := projectReplay(t, "web-goat")
	responses["VulnerabilityReportPage"] = func(map[string]any) []byte { return page }
	responses["VulnerabilityHistory"] = func(vars map[string]any) []byte {
		historyCalls = append(historyCalls, vars)
		if vars["withTransitions"] == true {
			after, _ := vars["transitionsAfter"].(string)
			if after == "cursor-1" {
				return []byte(`{"data":{"vulnerability":{"id":"gid://gitlab/Vulnerability/1","stateTransitions":{"pageInfo":{"hasNextPage":true,"endCursor":"cursor-2"},"nodes":[{"toState":"DISMISSED"}]}}}}`)
			}
			return []byte(`{"data":{"vulnerability":{"id":"gid://gitlab/Vulnerability/1","stateTransitions":{"pageInfo":{"hasNextPage":false,"endCursor":null},"nodes":[{"toState":"DETECTED"}]}}}}`)
		}
		return []byte(`{"data":{"vulnerability":{"id":"gid://gitlab/Vulnerability/1","severityOverrides":{"pageInfo":{"hasNextPage":false,"endCursor":null},"nodes":[{"originalSeverity":"HIGH"}]}}}}`)
	}
	srv := httptest.NewServer(handlerFor(t, responses))
	defer srv.Close()
	f := newTestFetcher(t, srv.URL, func(p *GitLabVulnerabilitiesParams) { p.Project = "security-demo/web-goat" })

	data, err := f.Fetch(context.Background())
	require.NoError(t, err)

	require.Len(t, historyCalls, 3, "two pages of transitions, then one of severity overrides")
	assert.Equal(t, "gid://gitlab/Vulnerability/1", historyCalls[0]["id"])
	assert.Equal(t, "cursor-1", historyCalls[0]["transitionsAfter"])
	assert.Equal(t, "cursor-2", historyCalls[1]["transitionsAfter"])
	assert.Equal(t, true, historyCalls[2]["withOverrides"])

	var env struct {
		Vulnerabilities []struct {
			StateTransitions  struct{ Nodes []struct{ ToState string } }
			SeverityOverrides struct {
				Nodes []struct{ OriginalSeverity string }
			}
		}
	}
	require.NoError(t, json.Unmarshal(data, &env))
	require.Len(t, env.Vulnerabilities, 1)
	assert.Equal(t, []string{"CONFIRMED", "DISMISSED", "DETECTED"},
		[]string{env.Vulnerabilities[0].StateTransitions.Nodes[0].ToState, env.Vulnerabilities[0].StateTransitions.Nodes[1].ToState, env.Vulnerabilities[0].StateTransitions.Nodes[2].ToState},
		"the page's node is kept and the follow-up pages are appended in order")
	require.Len(t, env.Vulnerabilities[0].SeverityOverrides.Nodes, 1)
	assert.Equal(t, "HIGH", env.Vulnerabilities[0].SeverityOverrides.Nodes[0].OriginalSeverity)
}

func TestFetch_TruncatedHistoryWithoutACursor_Fails(t *testing.T) {
	page := truncateOneHistory(t, "pages-web-goat-1.json")
	page = []byte(strings.Replace(string(page), `"endCursor":"cursor-1"`, `"endCursor":null`, 1))
	responses := projectReplay(t, "web-goat")
	responses["VulnerabilityReportPage"] = func(map[string]any) []byte { return page }
	srv := httptest.NewServer(handlerFor(t, responses))
	defer srv.Close()
	f := newTestFetcher(t, srv.URL, func(p *GitLabVulnerabilitiesParams) { p.Project = "security-demo/web-goat" })

	_, err := f.Fetch(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no cursor to fetch them")
}

// truncateOneHistory replaces a recorded empty page with a single node whose
// stateTransitions connection reports another page, which is the shape the
// completion path exists for and which the corpus has no natural example of.
func truncateOneHistory(t *testing.T, name string) []byte {
	t.Helper()
	var page map[string]any
	require.NoError(t, json.Unmarshal(testdata(t, name), &page))
	project := page["data"].(map[string]any)["project"].(map[string]any)
	project["vulnerabilities"] = map[string]any{
		"pageInfo": map[string]any{"hasNextPage": false, "endCursor": nil},
		"nodes": []any{map[string]any{
			"id":    "gid://gitlab/Vulnerability/1",
			"uuid":  "3f1cf4a5-0cf9-5b28-9c60-6a0e2d1a5d11",
			"state": "DETECTED",
			"stateTransitions": map[string]any{
				"pageInfo": map[string]any{"hasNextPage": true, "endCursor": "cursor-1"},
				"nodes":    []any{map[string]any{"toState": "CONFIRMED"}},
			},
			"severityOverrides": map[string]any{
				"pageInfo": map[string]any{"hasNextPage": true, "endCursor": "sev-1"},
				"nodes":    []any{},
			},
		}},
	}
	out, err := json.Marshal(page)
	require.NoError(t, err)
	return out
}
