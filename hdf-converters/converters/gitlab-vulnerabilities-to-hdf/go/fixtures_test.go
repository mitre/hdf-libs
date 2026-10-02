package gitlab_vulnerabilities_to_hdf

import (
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fixtureEnvelope is the minimal view of the fetcher's assembled document that
// these fixture-contract tests need; the converter's full input type lives in
// converter.go.
type fixtureEnvelope struct {
	FetchedAt string `json:"fetchedAt"`
	Metadata  struct {
		Enterprise bool `json:"enterprise"`
	} `json:"metadata"`
	Project struct {
		FullPath         string `json:"fullPath"`
		WebURL           string `json:"webUrl"`
		SecurityScanners struct {
			Enabled     []string `json:"enabled"`
			PipelineRun []string `json:"pipelineRun"`
		} `json:"securityScanners"`
		VulnerabilityStatistic *struct {
			Total int `json:"total"`
		} `json:"vulnerabilityStatistic"`
		LatestDefaultBranchPipeline *struct {
			IID                   string                     `json:"iid"`
			SecurityReportSummary map[string]*summarySection `json:"securityReportSummary"`
		} `json:"latestDefaultBranchPipeline"`
	} `json:"project"`
	Vulnerabilities []fixtureVulnerability `json:"vulnerabilities"`
}

type fixtureVulnerability struct {
	ID               string       `json:"id"`
	State            string       `json:"state"`
	DismissalReason  *string      `json:"dismissalReason"`
	StateComment     *string      `json:"stateComment"`
	WebURL           string       `json:"webUrl"`
	ConfirmedBy      *fixtureUser `json:"confirmedBy"`
	DismissedBy      *fixtureUser `json:"dismissedBy"`
	ResolvedBy       *fixtureUser `json:"resolvedBy"`
	StateTransitions struct {
		Nodes []struct {
			ToState string       `json:"toState"`
			Comment *string      `json:"comment"`
			Author  *fixtureUser `json:"author"`
		} `json:"nodes"`
	} `json:"stateTransitions"`
	SeverityOverrides struct {
		Nodes []struct {
			Author *fixtureUser `json:"author"`
		} `json:"nodes"`
	} `json:"severityOverrides"`
}

type fixtureUser struct {
	Username    string  `json:"username"`
	Name        string  `json:"name"`
	PublicEmail *string `json:"publicEmail"`
}

type summarySection struct {
	VulnerabilitiesCount int `json:"vulnerabilitiesCount"`
	Scans                struct {
		Nodes []struct {
			Status string `json:"status"`
		} `json:"nodes"`
	} `json:"scans"`
}

// The identity every recorded reviewer was scrubbed to, and the only host any
// recorded URL may point at.
const (
	scrubbedUsername = "sec-reviewer"
	fixtureHost      = "gitlab.example.com"
)

func loadFixture(t *testing.T, name string) fixtureEnvelope {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "fixtures", "input", name))
	require.NoError(t, err)
	var env fixtureEnvelope
	require.NoError(t, json.Unmarshal(data, &env), name)
	return env
}

func scanStatuses(env fixtureEnvelope) []string {
	var out []string
	if env.Project.LatestDefaultBranchPipeline == nil {
		return out
	}
	for _, section := range env.Project.LatestDefaultBranchPipeline.SecurityReportSummary {
		if section == nil {
			continue
		}
		for _, s := range section.Scans.Nodes {
			out = append(out, s.Status)
		}
	}
	sort.Strings(out)
	return out
}

func TestFixtures_TriagedCoversEveryStateAndDismissalReason(t *testing.T) {
	env := loadFixture(t, "triaged.json")
	require.NotEmpty(t, env.Vulnerabilities)

	got := map[string]bool{}
	multiTransition, severityOverride := false, false
	for _, v := range env.Vulnerabilities {
		key := v.State
		if v.DismissalReason != nil {
			key += "/" + *v.DismissalReason
		}
		got[key] = true
		if len(v.StateTransitions.Nodes) >= 3 {
			multiTransition = true
		}
		if len(v.SeverityOverrides.Nodes) > 0 {
			severityOverride = true
		}
	}

	want := []string{
		"DETECTED", "CONFIRMED", "RESOLVED",
		"DISMISSED/FALSE_POSITIVE", "DISMISSED/ACCEPTABLE_RISK", "DISMISSED/MITIGATING_CONTROL",
		"DISMISSED/USED_IN_TESTS", "DISMISSED/NOT_APPLICABLE",
	}
	keys := make([]string, 0, len(got))
	for k := range got {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, w := range want {
		assert.True(t, got[w], "triaged.json lacks %s (have %v)", w, keys)
	}
	assert.True(t, multiTransition, "triaged.json needs a vulnerability with a revert-and-re-dismiss history (3+ transitions)")
	assert.True(t, severityOverride, "triaged.json needs a vulnerability with a severity override")
	require.NotNil(t, env.Project.VulnerabilityStatistic, "an ingested project carries a vulnerability statistic")
	assert.Equal(t, []string{"SUCCEEDED", "SUCCEEDED", "SUCCEEDED"}, scanStatuses(env))
	assert.True(t, env.Metadata.Enterprise)
	assert.NotEmpty(t, env.FetchedAt)
}

// Each finding's current decision (its latest transition into CONFIRMED,
// DISMISSED or RESOLVED) carries its own statement, so the governing override
// reasons in the goldens are distinguishable and no decision silently inherits
// another's text. Earlier, superseded transitions are real history and may
// repeat wording.
func TestFixtures_TriagedDecisionsCarryDistinctComments(t *testing.T) {
	env := loadFixture(t, "triaged.json")
	seen := map[string]string{}
	decisions := 0
	for _, v := range env.Vulnerabilities {
		if v.State == "DETECTED" {
			continue
		}
		nodes := v.StateTransitions.Nodes
		require.NotEmpty(t, nodes, "%s: state %s but no transitions recorded", v.ID, v.State)
		last := nodes[len(nodes)-1]
		require.Equal(t, v.State, last.ToState, "%s: latest transition disagrees with state", v.ID)
		require.NotNil(t, last.Comment, "%s: decision to %s has no comment", v.ID, v.State)
		require.NotEmpty(t, *last.Comment, "%s: decision to %s has an empty comment", v.ID, v.State)
		if prev, dup := seen[*last.Comment]; dup {
			t.Errorf("%s and %s share the decision comment %q", prev, v.ID, *last.Comment)
		}
		seen[*last.Comment] = v.ID
		decisions++
	}
	assert.GreaterOrEqual(t, decisions, 11, "the recorded triage pass holds 11 current decisions: 3 confirmed, 2 resolved, 6 dismissed")
}

// The three zero-vulnerability fixtures are distinguishable only by the
// ingestion-backed signals, never by securityScanners alone.
func TestFixtures_ZeroVulnerabilityShapes(t *testing.T) {
	clean := loadFixture(t, "clean.json")
	assert.Empty(t, clean.Vulnerabilities)
	require.NotNil(t, clean.Project.VulnerabilityStatistic, "clean.json must be an ingested project")
	assert.Equal(t, 0, clean.Project.VulnerabilityStatistic.Total)
	assert.Equal(t, []string{"SUCCEEDED"}, scanStatuses(clean))

	reportError := loadFixture(t, "report-error.json")
	assert.Empty(t, reportError.Vulnerabilities)
	assert.Nil(t, reportError.Project.VulnerabilityStatistic, "report-error.json must never have been ingested")
	assert.NotEmpty(t, reportError.Project.SecurityScanners.PipelineRun, "securityScanners alone would mislabel this as clean")
	assert.Equal(t, []string{"REPORT_ERROR"}, scanStatuses(reportError))

	empty := loadFixture(t, "empty.json")
	assert.Empty(t, empty.Vulnerabilities)
	assert.Nil(t, empty.Project.VulnerabilityStatistic)
	assert.Nil(t, empty.Project.LatestDefaultBranchPipeline, "empty.json must have no default-branch pipeline")
	assert.Empty(t, empty.Project.SecurityScanners.Enabled)
}

// Fixtures are recorded from a live instance; anything tying them to the
// machine or account that recorded them must have been scrubbed. Checked two
// ways: a denylist over the raw bytes of every fixture and testdata file, and
// the positive invariant that every identity and URL in the envelopes is the
// scrubbed one.
func TestFixtures_NoLocalDetails(t *testing.T) {
	forbidden := regexp.MustCompile(`(?i)/Users/|/home/|glpat-[A-Za-z0-9_-]+|https?://(127\.0\.0\.1|localhost|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+)|\.svc\.cluster\.local|\.local[/"]|\.internal[/"]|"username":\s*"(?:wdower|root)"|"publicEmail":\s*"[^"]+"`)
	dirs := []string{
		filepath.Join("..", "fixtures", "input"),
		filepath.Join("..", "fixtures", "expected"),
		filepath.Join("..", "..", "..", "fetchers", "gitlab-vulnerabilities", "go", "testdata"),
	}
	checked := 0
	for _, dir := range dirs {
		entries, err := os.ReadDir(dir)
		if os.IsNotExist(err) {
			continue
		}
		require.NoError(t, err)
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
				continue
			}
			data, err := os.ReadFile(filepath.Join(dir, e.Name()))
			require.NoError(t, err)
			if m := forbidden.Find(data); m != nil {
				t.Errorf("%s/%s contains machine-local or account detail: %q", dir, e.Name(), m)
			}
			checked++
		}
	}
	require.Positive(t, checked, "no fixtures found to check")

	for _, name := range []string{"triaged.json", "clean.json", "report-error.json", "empty.json"} {
		env := loadFixture(t, name)
		assertFixtureHost(t, name, env.Project.WebURL)
		for _, v := range env.Vulnerabilities {
			assertFixtureHost(t, name, v.WebURL)
			for _, u := range []*fixtureUser{v.ConfirmedBy, v.DismissedBy, v.ResolvedBy} {
				assertScrubbedUser(t, name, v.ID, u)
			}
			for _, tr := range v.StateTransitions.Nodes {
				assertScrubbedUser(t, name, v.ID, tr.Author)
			}
			for _, so := range v.SeverityOverrides.Nodes {
				assertScrubbedUser(t, name, v.ID, so.Author)
			}
		}
	}
}

func assertScrubbedUser(t *testing.T, fixture, vulnID string, u *fixtureUser) {
	t.Helper()
	if u == nil {
		return
	}
	assert.Equal(t, scrubbedUsername, u.Username, "%s %s: reviewer identity not scrubbed", fixture, vulnID)
	assert.Nil(t, u.PublicEmail, "%s %s: reviewer email must not be recorded", fixture, vulnID)
}

func assertFixtureHost(t *testing.T, fixture, raw string) {
	t.Helper()
	if raw == "" {
		return
	}
	u, err := url.Parse(raw)
	require.NoError(t, err, "%s: %q", fixture, raw)
	assert.Equal(t, "https", u.Scheme, "%s: %q", fixture, raw)
	assert.Equal(t, fixtureHost, u.Host, "%s: %q", fixture, raw)
}
