package gitlabvulnerabilities

import (
	"context"
	"encoding/json"
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

const testToken = "test-token" //nolint:gosec // test-only credential

var fixedClock = func() time.Time { return time.Date(2026, 9, 20, 19, 50, 18, 0, time.UTC) }

func testdata(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	require.NoError(t, err)
	return data
}

// graphqlRequest is the wire shape the fetcher must send.
type wireRequest struct {
	Query     string         `json:"query"`
	Variables map[string]any `json:"variables"`
}

type recordedRequest struct {
	operation string
	variables map[string]any
}

// replayServer serves recorded GraphQL responses keyed by operation name and,
// for pages, by the after cursor. Every request is asserted to carry the
// PRIVATE-TOKEN header and a JSON body with a query and variables.
func replayServer(t *testing.T, project string, pages []string, calls *[]recordedRequest, hits *int32) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(hits, 1)
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "/api/graphql", r.URL.Path)
		assert.Equal(t, testToken, r.Header.Get("PRIVATE-TOKEN"), "token must be sent on every request")
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))

		var req wireRequest
		require.NoError(t, json.NewDecoder(r.Body).Decode(&req))
		op := operationName(req.Query)
		*calls = append(*calls, recordedRequest{operation: op, variables: req.Variables})

		w.Header().Set("Content-Type", "application/json")
		switch op {
		case "VulnerabilityReportProbe":
			assert.Equal(t, project, req.Variables["fullPath"])
			_, _ = w.Write(testdata(t, "probe-"+strings.TrimPrefix(project, "security-demo/")+".json"))
		case "VulnerabilityReportPage":
			assert.Equal(t, project, req.Variables["fullPath"])
			idx := 0
			if after, _ := req.Variables["after"].(string); after != "" {
				for i, name := range pages {
					if endCursorOf(t, testdata(t, name)) == after {
						idx = i + 1
						break
					}
				}
			}
			require.Less(t, idx, len(pages), "unexpected extra page request")
			_, _ = w.Write(testdata(t, pages[idx]))
		case "GroupProjects":
			_, _ = w.Write(testdata(t, "group-projects.json"))
		default:
			t.Errorf("unexpected operation %q", op)
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
}

func operationName(query string) string {
	q := strings.TrimSpace(query)
	q = strings.TrimPrefix(q, "query")
	q = strings.TrimSpace(q)
	end := strings.IndexAny(q, "( {")
	if end < 0 {
		return q
	}
	return q[:end]
}

func TestFetch_PaginatesAndAssemblesEnvelope(t *testing.T) {
	var calls []recordedRequest
	var hits int32
	srv := replayServer(t, "security-demo/juice-shop", []string{"pages-juice-shop-1.json", "pages-juice-shop-2.json", "pages-juice-shop-3.json", "pages-juice-shop-4.json"}, &calls, &hits)
	defer srv.Close()
	t.Setenv("GITLAB_TOKEN", testToken)

	f, err := NewGitLabVulnerabilitiesFetcher(GitLabVulnerabilitiesParams{URL: srv.URL, Project: "security-demo/juice-shop", PageSize: 50, Clock: fixedClock}, shared.TLSOptions{})
	require.NoError(t, err)

	data, err := f.Fetch(context.Background())
	require.NoError(t, err)

	require.Len(t, calls, 5, "one probe, then one request per page")
	assert.Equal(t, "VulnerabilityReportProbe", calls[0].operation)
	assert.Equal(t, "VulnerabilityReportPage", calls[1].operation)
	assert.Equal(t, "master", calls[1].variables["ref"], "the default branch from the probe drives the pipeline lookup")
	assert.Equal(t, true, calls[1].variables["withPipeline"])
	assert.Equal(t, float64(50), calls[1].variables["first"])
	assert.Nil(t, calls[1].variables["after"])
	assert.Equal(t, "VulnerabilityReportPage", calls[2].operation)
	var page1 struct {
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
	require.NoError(t, json.Unmarshal(testdata(t, "pages-juice-shop-1.json"), &page1))
	assert.Equal(t, page1.Data.Project.Vulnerabilities.PageInfo.EndCursor, calls[2].variables["after"], "page 2 is requested with page 1's end cursor")
	assert.Equal(t, false, calls[2].variables["withPipeline"])

	var env converter.Envelope
	require.NoError(t, json.Unmarshal(data, &env))
	assert.Len(t, env.Vulnerabilities, 100, "every page concatenated")
	assert.Equal(t, "security-demo/juice-shop", env.Project.FullPath)
	assert.Equal(t, "gid://gitlab/Project/1", env.Project.ID)
	assert.True(t, env.Metadata.Enterprise)
	assert.Equal(t, "18.9.1-ee", env.Metadata.Version)
	require.NotNil(t, env.Project.VulnerabilityStatistic)
	assert.Equal(t, 177, env.Project.VulnerabilityStatistic.Total)
	require.NotNil(t, env.Project.LatestDefaultBranchPipeline, "page 1 carries the latest default-branch pipeline")
	assert.Equal(t, "8", env.Project.LatestDefaultBranchPipeline.IID)
	assert.Equal(t, "2026-09-20T19:50:18Z", env.FetchedAt)

	// The assembled bytes are exactly what the converter consumes.
	result, err := converter.ConvertGitlabVulnerabilitiesToHDF(data, "test")
	require.NoError(t, err)
	assert.Len(t, result.Baselines, 2)
	assert.Equal(t, "security-demo/juice-shop", result.Components[0].Name)
}
