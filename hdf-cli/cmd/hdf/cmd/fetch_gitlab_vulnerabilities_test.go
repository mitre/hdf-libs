package cmd

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// gvTestdata reads a recorded GraphQL response from the fetcher's corpus.
func gvTestdata(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "hdf-converters", "fetchers", "gitlab-vulnerabilities", "go", "testdata", name))
	require.NoError(t, err)
	return data
}

// gvServer replays the recorded probe, page and group responses for the
// security-demo group, keyed by GraphQL operation name and the fullPath /
// after variables.
func gvServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "tok", r.Header.Get("PRIVATE-TOKEN"))
		var req struct {
			Query     string         `json:"query"`
			Variables map[string]any `json:"variables"`
		}
		require.NoError(t, json.NewDecoder(r.Body).Decode(&req))
		fullPath, _ := req.Variables["fullPath"].(string)
		name := strings.TrimPrefix(fullPath, "security-demo/")
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.Contains(req.Query, "query GroupProjects"):
			_, _ = w.Write(gvTestdata(t, "group-projects.json"))
		case strings.Contains(req.Query, "query VulnerabilityReportProbe"):
			_, _ = w.Write(gvTestdata(t, "probe-"+name+".json"))
		case strings.Contains(req.Query, "query VulnerabilityReportPage"):
			if after, _ := req.Variables["after"].(string); after != "" {
				_, _ = w.Write(gvTestdata(t, "pages-"+name+"-2.json"))
				return
			}
			_, _ = w.Write(gvTestdata(t, "pages-"+name+"-1.json"))
		default:
			t.Errorf("unexpected query: %.60s", req.Query)
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
}

func runFetchGV(t *testing.T, args ...string) (string, error) {
	t.Helper()
	cmd := NewFetchCmd()
	var out, errOut bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errOut)
	cmd.SetArgs(append([]string{"gitlab-vulnerabilities"}, args...))
	err := cmd.Execute()
	return out.String() + errOut.String(), err
}

func TestFetchGitlabVulnerabilitiesCmd_IsSubcommand(t *testing.T) {
	root := NewRootCmd()
	found, _, err := root.Find([]string{"fetch", "gitlab-vulnerabilities"})
	require.NoError(t, err)
	assert.Equal(t, "gitlab-vulnerabilities", found.Name())
}

func TestFetchCmd_Help_ListsGitlabVulnerabilities(t *testing.T) {
	root := NewRootCmd()
	root.SetArgs([]string{"fetch", "--help"})
	var out bytes.Buffer
	root.SetOut(&out)
	_ = root.Execute()
	assert.Contains(t, out.String(), "gitlab-vulnerabilities")
}

func TestFetchGitlabVulnerabilitiesCmd_GroupWritesOneFilePerProject(t *testing.T) {
	t.Setenv("GITLAB_TOKEN", "tok")
	srv := gvServer(t)
	defer srv.Close()
	outDir := filepath.Join(t.TempDir(), "hdf")

	out, err := runFetchGV(t, "--url", srv.URL, "--group", "security-demo", "--out-dir", outDir)
	require.Error(t, err, "two of the four recorded projects cannot be fetched, so the run must not exit clean")
	assert.Contains(t, err.Error(), "2 of 4 projects failed")
	assert.Contains(t, out, "security-demo/unscanned-app")
	assert.Contains(t, out, "REPORT_ERROR")
	assert.Contains(t, out, "security-demo/empty-app")

	entries, readErr := os.ReadDir(outDir)
	require.NoError(t, readErr)
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	assert.ElementsMatch(t, []string{"security-demo__juice-shop.hdf.json", "security-demo__web-goat.hdf.json"}, names)

	for _, name := range names {
		data, err := os.ReadFile(filepath.Join(outDir, name))
		require.NoError(t, err)
		assertHDFOutput(t, data)
	}
	juice, err := os.ReadFile(filepath.Join(outDir, "security-demo__juice-shop.hdf.json"))
	require.NoError(t, err)
	var doc struct {
		Components []struct {
			Name   string `json:"name"`
			Commit string `json:"commit"`
		} `json:"components"`
		Baselines []struct {
			Requirements []json.RawMessage `json:"requirements"`
		} `json:"baselines"`
	}
	require.NoError(t, json.Unmarshal(juice, &doc))
	assert.Equal(t, "security-demo/juice-shop", doc.Components[0].Name)
	assert.Equal(t, "556a44e4001434ea7a242f29ede789565066082d", doc.Components[0].Commit)
	assert.Equal(t, 97, len(doc.Baselines[0].Requirements)+len(doc.Baselines[1].Requirements))
}

func TestFetchGitlabVulnerabilitiesCmd_GroupAllSucceedExitsClean(t *testing.T) {
	t.Setenv("GITLAB_TOKEN", "tok")
	// A group listing that names only the two fetchable projects.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Query     string         `json:"query"`
			Variables map[string]any `json:"variables"`
		}
		require.NoError(t, json.NewDecoder(r.Body).Decode(&req))
		name := strings.TrimPrefix(req.Variables["fullPath"].(string), "security-demo/")
		switch {
		case strings.Contains(req.Query, "query GroupProjects"):
			_, _ = w.Write([]byte(`{"data":{"group":{"fullPath":"security-demo","projects":{"pageInfo":{"hasNextPage":false,"endCursor":null},"nodes":[{"fullPath":"security-demo/web-goat","archived":false},{"fullPath":"security-demo/juice-shop","archived":false}]}}}}`))
		case strings.Contains(req.Query, "query VulnerabilityReportProbe"):
			_, _ = w.Write(gvTestdata(t, "probe-"+name+".json"))
		default:
			if after, _ := req.Variables["after"].(string); after != "" {
				_, _ = w.Write(gvTestdata(t, "pages-"+name+"-2.json"))
				return
			}
			_, _ = w.Write(gvTestdata(t, "pages-"+name+"-1.json"))
		}
	}))
	defer srv.Close()
	outDir := filepath.Join(t.TempDir(), "hdf")

	_, err := runFetchGV(t, "--url", srv.URL, "--group", "security-demo", "--out-dir", outDir)
	require.NoError(t, err)
	entries, err := os.ReadDir(outDir)
	require.NoError(t, err)
	assert.Len(t, entries, 2)
}

func TestFetchGitlabVulnerabilitiesCmd_ProjectSuccessAndRaw(t *testing.T) {
	t.Setenv("GITLAB_TOKEN", "tok")
	srv := gvServer(t)
	defer srv.Close()

	outFile := filepath.Join(t.TempDir(), "out.json")
	_, err := runFetchGV(t, "--url", srv.URL, "--project", "security-demo/juice-shop", outFile)
	require.NoError(t, err)
	data, err := os.ReadFile(outFile)
	require.NoError(t, err)
	assertHDFOutput(t, data)
	assert.Contains(t, string(data), "gitlab-vulnerabilities-to-hdf")

	rawFile := filepath.Join(t.TempDir(), "raw.json")
	_, err = runFetchGV(t, "--url", srv.URL, "--project", "security-demo/juice-shop", "--format", "raw", "-o", rawFile)
	require.NoError(t, err)
	raw, err := os.ReadFile(rawFile)
	require.NoError(t, err)
	var env map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(raw, &env))
	assert.Contains(t, env, "vulnerabilities")
	assert.Contains(t, env, "fetchedAt")
	assert.NotContains(t, env, "baselines")
}

func TestFetchGitlabVulnerabilitiesCmd_StateAndReportTypeFilters(t *testing.T) {
	t.Setenv("GITLAB_TOKEN", "tok")
	var got map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Query     string         `json:"query"`
			Variables map[string]any `json:"variables"`
		}
		require.NoError(t, json.NewDecoder(r.Body).Decode(&req))
		if strings.Contains(req.Query, "query VulnerabilityReportPage") {
			got = req.Variables
			_, _ = w.Write(gvTestdata(t, "pages-web-goat-1.json"))
			return
		}
		_, _ = w.Write(gvTestdata(t, "probe-web-goat.json"))
	}))
	defer srv.Close()

	_, err := runFetchGV(t, "--url", srv.URL, "--project", "security-demo/web-goat", "--state", "DETECTED,CONFIRMED", "--report-type", "SAST,DAST", "-o", filepath.Join(t.TempDir(), "o.json"))
	require.NoError(t, err)
	assert.Equal(t, []any{"DETECTED", "CONFIRMED"}, got["state"])
	assert.Equal(t, []any{"SAST", "DAST"}, got["reportType"])
}

func TestFetchGitlabVulnerabilitiesCmd_EnumFiltersAreCaseInsensitive(t *testing.T) {
	t.Setenv("GITLAB_TOKEN", "tok")
	var got map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Query     string         `json:"query"`
			Variables map[string]any `json:"variables"`
		}
		require.NoError(t, json.NewDecoder(r.Body).Decode(&req))
		if strings.Contains(req.Query, "query VulnerabilityReportPage") {
			got = req.Variables
			_, _ = w.Write(gvTestdata(t, "pages-web-goat-1.json"))
			return
		}
		_, _ = w.Write(gvTestdata(t, "probe-web-goat.json"))
	}))
	defer srv.Close()

	_, err := runFetchGV(t, "--url", srv.URL, "--project", "security-demo/web-goat", "--state", "dismissed, resolved", "--report-type", "secret_detection", "-o", filepath.Join(t.TempDir(), "o.json"))
	require.NoError(t, err)
	assert.Equal(t, []any{"DISMISSED", "RESOLVED"}, got["state"], "values are upper-cased and trimmed before they are sent")
	assert.Equal(t, []any{"SECRET_DETECTION"}, got["reportType"])
}

func TestFetchGitlabVulnerabilitiesCmd_CheckGroupNeedsNoOutDir(t *testing.T) {
	t.Setenv("GITLAB_TOKEN", "tok")
	srv := gvServer(t)
	defer srv.Close()

	out, err := runFetchGV(t, "--url", srv.URL, "--group", "security-demo", "--check")
	require.NoError(t, err, "--check is a probe; it neither needs nor writes an output directory")
	assert.Contains(t, out, "security-demo/unscanned-app: Vulnerability Report never populated", "the first listed project is diagnosed")
}

func TestFetchGitlabVulnerabilitiesCmd_Check(t *testing.T) {
	t.Setenv("GITLAB_TOKEN", "tok")
	srv := gvServer(t)
	defer srv.Close()

	out, err := runFetchGV(t, "--url", srv.URL, "--project", "security-demo/juice-shop", "--check")
	require.NoError(t, err)
	assert.Contains(t, out, "Vulnerability Report populated (89 open)")

	out, err = runFetchGV(t, "--url", srv.URL, "--project", "security-demo/empty-app", "--check")
	require.NoError(t, err, "--check reports the diagnosis; it does not fail on a never-populated report")
	assert.Contains(t, out, "never populated")
}

func TestFetchGitlabVulnerabilitiesCmd_NeverIngestedErrorReachesTheUser(t *testing.T) {
	t.Setenv("GITLAB_TOKEN", "tok")
	srv := gvServer(t)
	defer srv.Close()

	_, err := runFetchGV(t, "--url", srv.URL, "--project", "security-demo/unscanned-app", "-o", filepath.Join(t.TempDir(), "o.json"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "sast: REPORT_ERROR")

	_, err = runFetchGV(t, "--url", srv.URL, "--project", "security-demo/empty-app", "-o", filepath.Join(t.TempDir(), "o.json"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no default-branch pipeline")
}

func TestFetchGitlabVulnerabilitiesCmd_FlagValidation(t *testing.T) {
	t.Setenv("GITLAB_TOKEN", "tok")
	cases := []struct {
		name string
		args []string
		want string
	}{
		{"neither project nor group", []string{"--url", "https://gitlab.example.com"}, "--project or --group"},
		{"both project and group", []string{"--url", "https://gitlab.example.com", "--project", "g/p", "--group", "g"}, "mutually exclusive"},
		{"group without out-dir", []string{"--url", "https://gitlab.example.com", "--group", "g"}, "--out-dir is required"},
		{"project with out-dir", []string{"--url", "https://gitlab.example.com", "--project", "g/p", "--out-dir", "x"}, "--out-dir applies to --group"},
		{"bad format", []string{"--url", "https://gitlab.example.com", "--project", "g/p", "--format", "xml"}, "invalid --format"},
		{"bad scheme", []string{"--url", "ftp://gitlab.example.com", "--project", "g/p"}, "must use http or https"},
		{"bad state", []string{"--url", "https://gitlab.example.com", "--project", "g/p", "--state", "OPEN"}, "invalid --state value"},
		{"bad report type", []string{"--url", "https://gitlab.example.com", "--project", "g/p", "--report-type", "IAST"}, "invalid --report-type value"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := runFetchGV(t, tc.args...)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.want)
		})
	}
}

func TestFetchGitlabVulnerabilitiesCmd_NoTokenFlagAndHelp(t *testing.T) {
	cmd := newFetchGitlabVulnerabilitiesCmd()
	assert.Nil(t, cmd.Flags().Lookup("token"), "credentials are never accepted as a flag")
	assert.NotNil(t, cmd.Flags().Lookup("check"))
	assert.Equal(t, "true", cmd.Flags().Lookup("include-subgroups").DefValue)
	assert.Contains(t, cmd.Long, "GITLAB_TOKEN")
	assert.Contains(t, cmd.Long, "Ultimate")

	t.Setenv("GITLAB_TOKEN", "")
	t.Setenv("GLAB_TOKEN", "")
	t.Setenv("GLAB_CONFIG_DIR", t.TempDir())
	_, err := runFetchGV(t, "--url", "https://gitlab.example.com", "--project", "g/p", "-o", filepath.Join(t.TempDir(), "o.json"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no GitLab API token found")
}
