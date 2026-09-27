package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	hdfengine "github.com/mitre/hdf-libs/hdf-engine/go/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// richResults is a fixture with multiple targets (FQDN, IP, neither) and
// multiple baselines with various requirement statuses for full branch coverage.
const richResults = `{
  "baselines": [
    {
      "name": "baseline-a",
      "title": "Baseline Alpha",
      "version": "1.0",
      "status": "loaded",
      "checksum": {"algorithm": "sha256", "value": "aaa"},
      "depends": [],
      "groups": [],
      "inspecVersion": "5.0.0",
      "supports": [],
      "requirements": [
        {
          "id": "AC-1", "impact": 0.7, "title": "Access Control Policy",
          "descriptions": [{"label": "default", "data": "test"}],
          "results": [{"status": "failed", "codeDesc": "x", "startTime": "2026-01-01T00:00:00Z", "backtrace": []}],
          "tags": {}, "code": "", "refs": [],
          "sourceLocation": {"line": 1, "ref": "test.rb"},
          "statusOverrides": [], "evidence": [], "poams": []
        },
        {
          "id": "AC-2", "impact": 0.5,
          "descriptions": [{"label": "default", "data": "test"}],
          "results": [{"status": "passed", "codeDesc": "x", "startTime": "2026-01-01T00:00:00Z", "backtrace": []}],
          "tags": {}, "code": "", "refs": [],
          "sourceLocation": {"line": 2, "ref": "test.rb"},
          "statusOverrides": [], "evidence": [], "poams": []
        },
        {
          "id": "AC-3", "impact": 0.0,
          "descriptions": [{"label": "default", "data": "test"}],
          "results": [{"status": "notApplicable", "codeDesc": "x", "startTime": "2026-01-01T00:00:00Z", "backtrace": []}],
          "tags": {}, "code": "", "refs": [],
          "sourceLocation": {"line": 3, "ref": "test.rb"},
          "statusOverrides": [], "evidence": [], "poams": []
        },
        {
          "id": "AC-4", "impact": 0.9,
          "descriptions": [{"label": "default", "data": "test"}],
          "results": [{"status": "error", "codeDesc": "x", "startTime": "2026-01-01T00:00:00Z", "backtrace": []}],
          "tags": {}, "code": "", "refs": [],
          "sourceLocation": {"line": 4, "ref": "test.rb"},
          "statusOverrides": [], "evidence": [], "poams": []
        }
      ]
    },
    {
      "name": "baseline-b",
      "checksum": {"algorithm": "sha256", "value": "bbb"},
      "depends": [],
      "groups": [],
      "inspecVersion": "5.0.0",
      "supports": [],
      "requirements": [
        {
          "id": "CM-1", "impact": 0.5,
          "descriptions": [{"label": "default", "data": "test"}],
          "results": [{"status": "passed", "codeDesc": "x", "startTime": "2026-01-01T00:00:00Z", "backtrace": []}],
          "tags": {}, "code": "", "refs": [],
          "sourceLocation": {"line": 1, "ref": "test.rb"},
          "statusOverrides": [], "evidence": [], "poams": []
        }
      ]
    }
  ],
  "components": [
    {"type": "host", "name": "web-server", "fqdn": "web.example.com"},
    {"type": "host", "name": "db-server", "ipAddress": "10.0.0.5"},
    {"type": "application", "name": "portal-app"}
  ],
  "statistics": {"duration": 1.5}
}`

func writeRichFixture(t *testing.T) string {
	t.Helper()
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "rich-results.json")
	require.NoError(t, os.WriteFile(path, []byte(richResults), 0o600))
	return path
}

func TestListSummary(t *testing.T) {
	fixture := writeRichFixture(t)

	t.Run("human summary shows counts and status breakdown", func(t *testing.T) {
		stdout, _, err := executeCommand("list", fixture)
		require.NoError(t, err)
		assert.Contains(t, stdout, "Baselines:    2")
		assert.Contains(t, stdout, "Requirements: 5")
		assert.Contains(t, stdout, "Components:   3")
		assert.Contains(t, stdout, "passed")
		assert.Contains(t, stdout, "failed")
		assert.Contains(t, stdout, "error")
		assert.Contains(t, stdout, "not_applicable")
	})

	t.Run("JSON summary includes all fields", func(t *testing.T) {
		stdout, _, err := executeCommand("list", fixture, "--json")
		require.NoError(t, err)

		var summary map[string]interface{}
		require.NoError(t, json.Unmarshal([]byte(stdout), &summary))
		assert.Equal(t, float64(2), summary["baselines"])
		assert.Equal(t, float64(5), summary["requirements"])
		assert.Equal(t, float64(3), summary["components"])
		assert.Equal(t, float64(2), summary["passed"])
		assert.Equal(t, float64(1), summary["failed"])
		assert.Equal(t, float64(1), summary["error"])
		assert.Equal(t, float64(1), summary["not_applicable"])
	})
}

func TestListComponentsDetail(t *testing.T) {
	fixture := writeRichFixture(t)

	t.Run("human output shows target details with FQDN and IP", func(t *testing.T) {
		stdout, _, err := executeCommand("list", fixture, "--detail", "components")
		require.NoError(t, err)
		assert.Contains(t, stdout, "Components: 3")
		assert.Contains(t, stdout, "web-server")
		assert.Contains(t, stdout, "web.example.com")
		assert.Contains(t, stdout, "db-server")
		assert.Contains(t, stdout, "10.0.0.5")
		assert.Contains(t, stdout, "portal-app")
	})

	t.Run("JSON output includes FQDN and IP", func(t *testing.T) {
		stdout, _, err := executeCommand("list", fixture, "--detail", "components", "--json")
		require.NoError(t, err)

		var targets []map[string]interface{}
		require.NoError(t, json.Unmarshal([]byte(stdout), &targets))
		require.Len(t, targets, 3)

		assert.Equal(t, "web.example.com", targets[0]["fqdn"])
		assert.Equal(t, "10.0.0.5", targets[1]["ip_address"])
		// Third target has neither FQDN nor IP — fields should be omitted
		_, hasFQDN := targets[2]["fqdn"]
		_, hasIP := targets[2]["ip_address"]
		assert.False(t, hasFQDN)
		assert.False(t, hasIP)
	})
}

func TestListComponentsEmpty(t *testing.T) {
	// Create fixture with no targets
	noTargets := `{"baselines": [{"name": "b", "checksum": {"algorithm": "sha256", "value": "x"}, "depends": [], "groups": [], "inspecVersion": "5", "supports": [], "requirements": [{"id": "SV-1", "impact": 0.5, "tags": {}, "descriptions": [{"label": "default", "data": "Test"}], "results": [{"status": "passed", "codeDesc": "Test", "startTime": "2025-01-01T00:00:00Z"}]}]}], "statistics": {"duration": 0}}`
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "no-targets.json")
	require.NoError(t, os.WriteFile(path, []byte(noTargets), 0o600))

	t.Run("human output says no targets", func(t *testing.T) {
		stdout, _, err := executeCommand("list", path, "--detail", "components")
		require.NoError(t, err)
		assert.Contains(t, stdout, "No components defined")
	})

	t.Run("JSON output returns empty array", func(t *testing.T) {
		stdout, _, err := executeCommand("list", path, "--detail", "components", "--json")
		require.NoError(t, err)
		assert.Contains(t, stdout, "[]")
	})
}

func TestListRequirementsAllFlag(t *testing.T) {
	fixture := writeRichFixture(t)

	t.Run("--all shows flat list with status symbols", func(t *testing.T) {
		stdout, _, err := executeCommand("list", fixture, "--detail", "requirements", "--all")
		require.NoError(t, err)
		// Should use status symbols (✓, ✗, !, ○, ?)
		assert.Contains(t, stdout, "AC-1")
		assert.Contains(t, stdout, "AC-2")
	})
}

func TestListErrorCases(t *testing.T) {
	t.Run("nonexistent file", func(t *testing.T) {
		_, _, err := executeCommand("list", "/nonexistent/file.json")
		require.Error(t, err)
	})

	t.Run("invalid JSON", func(t *testing.T) {
		tmpDir := t.TempDir()
		path := filepath.Join(tmpDir, "bad.json")
		require.NoError(t, os.WriteFile(path, []byte("not json"), 0o600))
		_, _, err := executeCommand("list", path)
		require.Error(t, err)
	})
}

func TestListSystemDataFlows(t *testing.T) {
	// componentId / dataFlows.from / dataFlows.to are UUID-formatted per
	// the hdf-system schema; using non-UUID literals fails the input gate.
	const (
		webUUID = "11111111-1111-1111-1111-111111111111"
		dbUUID  = "22222222-2222-2222-2222-222222222222"
	)
	sysJSON := `{
		"name": "Portal-Prod",
		"components": [
			{"name": "WebTier", "type": "application", "componentId": "` + webUUID + `"},
			{"name": "DB", "type": "database", "componentId": "` + dbUUID + `"}
		],
		"dataFlows": [
			{"from": "` + webUUID + `", "to": "` + dbUUID + `", "protocol": "JDBC", "port": 5432, "description": "Web to database"},
			{"from": "` + dbUUID + `", "to": "` + webUUID + `", "protocol": "JDBC", "description": "Query results"}
		]
	}`
	path := filepath.Join(t.TempDir(), "system.json")
	require.NoError(t, os.WriteFile(path, []byte(sysJSON), 0o600))

	t.Run("detail dataFlows shows flows", func(t *testing.T) {
		stdout, _, err := executeCommand("list", path, "--detail", "dataFlows")
		require.NoError(t, err)
		assert.Contains(t, stdout, "Data Flows: 2")
		assert.Contains(t, stdout, webUUID)
		assert.Contains(t, stdout, dbUUID)
		assert.Contains(t, stdout, "JDBC")
	})

	t.Run("detail dataFlows JSON output", func(t *testing.T) {
		stdout, _, err := executeCommand("list", path, "--detail", "dataFlows", "--json")
		require.NoError(t, err)
		assert.Contains(t, stdout, webUUID)
	})

	t.Run("alias d maps to dataFlows", func(t *testing.T) {
		stdout, _, err := executeCommand("list", path, "--detail", "d")
		require.NoError(t, err)
		assert.Contains(t, stdout, "Data Flows: 2")
	})

	t.Run("detail components on system doc", func(t *testing.T) {
		stdout, _, err := executeCommand("list", path, "--detail", "components")
		require.NoError(t, err)
		assert.Contains(t, stdout, "WebTier")
		assert.Contains(t, stdout, "DB")
	})

	t.Run("system summary without detail", func(t *testing.T) {
		stdout, _, err := executeCommand("list", path)
		require.NoError(t, err)
		assert.Contains(t, stdout, "Portal-Prod")
		assert.Contains(t, stdout, "Components")
		assert.Contains(t, stdout, "Data Flows")
	})
}

func TestResolveDetailAlias(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"r", "requirements"},
		{"requirement", "requirements"},
		{"b", "baselines"},
		{"baseline", "baselines"},
		{"t", "components"},
		{"c", "components"},
		{"component", "components"},
		{"g", "groups"},
		{"group", "groups"},
		{"a", "assessments"},
		{"assessment", "assessments"},
		{"o", "amendments"},
		{"override", "amendments"},
		{"d", "dataFlows"},
		{"dataflow", "dataFlows"},
		{"dataflows", "dataFlows"},
		{"p", "baselines"}, // legacy alias
		{"unknown", "unknown"},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			assert.Equal(t, tt.want, resolveDetailAlias(tt.input))
		})
	}
}

func TestTruncateTitle(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		maxLen int
		want   string
	}{
		{"short title", "Hello", 50, "Hello"},
		{"exact length", "12345", 5, "12345"},
		{"long title truncated", "This is a very long title that exceeds the max", 20, "This is a very lo..."},
		{"empty title placeholder", "", 50, "(no title)"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, truncateTitle(tt.input, tt.maxLen))
		})
	}
}

// hdf list resolved STATUS through the shared effective-status ladder and
// reported the requirement's RAW impact in the same row — the same
// pre/post-adjudication split hdf query carried, on a surface that emits both
// fields together in --json. A risk-adjusted requirement is the only document
// shape that can tell them apart.
func TestListRequirements_ImpactResolvesOverrides(t *testing.T) {
	resultsPath := writeRiskAdjustedResults(t)

	stdout, _, err := executeCommand("list", resultsPath, "--detail", "requirements", "--json")
	require.NoError(t, err)

	var rows []struct {
		ID     string  `json:"id"`
		Status string  `json:"status"`
		Impact float64 `json:"impact"`
	}
	require.NoError(t, json.Unmarshal([]byte(stdout), &rows), "stdout: %s", stdout)

	byID := map[string]float64{}
	status := map[string]string{}
	for _, r := range rows {
		byID[r.ID] = r.Impact
		status[r.ID] = r.Status
	}
	require.Equal(t, "failed", status["SV-ADJUSTED"],
		"the status column is post-adjudication, which is what makes a raw impact beside it incoherent")
	require.Contains(t, byID, "SV-ADJUSTED")
	require.Contains(t, byID, "SV-PLAIN")

	assert.InDelta(t, 0.3, byID["SV-ADJUSTED"], 1e-9,
		"the row reports the impact the governing riskAdjustment re-scored it to, since its status column is already post-adjudication")
	assert.InDelta(t, 0.9, byID["SV-PLAIN"], 1e-9,
		"and a requirement nobody adjudicated is unchanged")
}

// `hdf query --status` refuses a value outside its vocabulary and normalizes the
// aliases, because a typo that matches nothing is indistinguishable from a clean
// run. `hdf list --status` did neither: it compared the flag string to the
// DISPLAY status, so the schema spelling every other surface accepts selected
// nothing, and an outright typo reported an empty result with exit 0.
//
// Each case names a requirement the filter must EXCLUDE. An absent filter returns
// everything, so an inclusion-only assertion would pass against a filter that
// never ran.
func TestListStatusFilter_AcceptsEveryFormAndRefusesATypo(t *testing.T) {
	fixture := writeRichFixture(t)

	// AC-3 is the fixture's only notApplicable requirement; AC-1 is failed.
	for _, form := range []string{"not_applicable", "notApplicable", "NOTAPPLICABLE"} {
		t.Run("accepts "+form, func(t *testing.T) {
			stdout, _, err := executeCommand("list", fixture, "--detail", "requirements", "--status", form)
			require.NoError(t, err, "%q must be accepted", form)
			assert.Contains(t, stdout, "AC-3", "%q must select the notApplicable requirement", form)
			assert.NotContains(t, stdout, "AC-1", "%q must exclude the failed requirement", form)
		})
	}

	for _, bad := range []string{"bogus_value", "not_aplicable", "faild"} {
		t.Run("refuses "+bad, func(t *testing.T) {
			_, _, err := executeCommand("list", fixture, "--detail", "requirements", "--status", bad)
			require.Error(t, err, "%q must be refused, not reported as an empty result", bad)
			assert.Contains(t, err.Error(), "unknown --status value")
		})
	}
}

// The filter is refused in the command's run step rather than where it filters,
// so a typo cannot ride along on an invocation that happens to ignore the flag.
// The summary view ignores --status entirely, which made a typo there silently
// harmless — and a flag that is sometimes validated is not validated.
func TestListStatusFilter_RefusedEvenWhereTheFlagIsIgnored(t *testing.T) {
	fixture := writeRichFixture(t)

	_, _, err := executeCommand("list", fixture, "--status", "bogus_value")
	require.Error(t, err, "an unknown status must be refused even without --detail")
	assert.Contains(t, err.Error(), "unknown --status value")
}

// Every flag help naming a closed vocabulary is BUILT from the engine, so it
// cannot drift from what the refusal names. This asserts the derivation actually
// reaches each flag: a help string hand-typed back would stop matching.
func TestFilterFlagHelpIsDerivedFromTheEngine(t *testing.T) {
	query := NewQueryCmd()
	for _, c := range []struct {
		name  string
		field string
		usage string
	}{
		{"list --status", "status", NewListCmd().Flags().Lookup("status").Usage},
		{"query --status", "status", query.Flags().Lookup("status").Usage},
		{"query --severity", "severity", query.Flags().Lookup("severity").Usage},
		{"query --disposition", "disposition", query.Flags().Lookup("disposition").Usage},
		{"amend draft --status", "status", amendDraftStatusUsage(t)},
	} {
		t.Run(c.name, func(t *testing.T) {
			vocab := FilterHelpVocabulary(c.field)
			require.NotEmpty(t, vocab, "the engine must supply a vocabulary for %q", c.field)
			assert.Contains(t, c.usage, vocab,
				"help must carry the engine-built vocabulary verbatim, not a hand-typed copy")

			// And every advertised form is actually named, so a shrinking
			// vocabulary cannot pass by matching a shorter string.
			for _, form := range hdfengine.AdvertisedFilterValues(c.field) {
				assert.Contains(t, c.usage, form, "help must name %q", form)
			}
		})
	}
}

// A retired name is accepted and never advertised. Nothing a user reads may teach
// it, or we hand a newcomer the name a release replaced.
//
// retiredForms is enumerated, NOT derived from the Advertise flag. Deriving it
// made an earlier version of this test vacuous in both directions: it skipped
// every entry whose flag said "advertised", so flipping the flag — the exact
// regression it is named for — silenced it instead of failing it.
func TestRetiredFormsAreAcceptedButNeverAdvertised(t *testing.T) {
	retiredForms := map[string][]string{
		"severity": {"none"}, // informational replaced it in 3.7.0
	}

	query := NewQueryCmd()
	helpFor := map[string][]string{
		"status":      {NewListCmd().Flags().Lookup("status").Usage, query.Flags().Lookup("status").Usage, amendDraftStatusUsage(t)},
		"severity":    {query.Flags().Lookup("severity").Usage},
		"disposition": {query.Flags().Lookup("disposition").Usage},
	}

	for field, forms := range retiredForms {
		for _, form := range forms {
			t.Run(field+"/"+form, func(t *testing.T) {
				assert.True(t, hdfengine.ValidStatus(form) || hdfengine.ValidSeverity(form) || hdfengine.ValidDisposition(form),
					"%q must still be accepted", form)
				assert.NotContains(t, hdfengine.AdvertisedFilterValues(field), form,
					"the engine must not advertise the retired %q", form)
				assert.NotContains(t, FilterHelpVocabulary(field), form,
					"the built help clause must not name the retired %q", form)
				for _, usage := range helpFor[field] {
					assert.NotContains(t, usage, form, "no %s help may teach the retired %q", field, form)
				}
			})
		}
	}
}

// The refusal names the canonical vocabulary, and the help names it too — the two
// cannot disagree because both come from the engine. Pinned because a refusal
// naming values the help never showed is what sent a user hunting.
func TestStatusRefusalAndHelpAgree(t *testing.T) {
	refusal := ValidateStatusFilter("definitely-not-a-status")
	require.Error(t, refusal)
	for _, form := range hdfengine.StatusValues {
		assert.Contains(t, refusal.Error(), form, "the refusal must name %q", form)
		assert.Contains(t, FilterHelpVocabulary("status"), form, "the help vocabulary must name %q", form)
	}
}

// amendDraftStatusUsage reaches the draft subcommand's --status help. It is a
// subcommand rather than a top-level flag, so it cannot be looked up the way the
// other two are.
func amendDraftStatusUsage(t *testing.T) string {
	t.Helper()
	for _, sub := range NewAmendCmd().Commands() {
		if sub.Name() == "draft" {
			flag := sub.Flags().Lookup("status")
			require.NotNil(t, flag, "amend draft must still take --status")
			return flag.Usage
		}
	}
	t.Fatal("amend draft subcommand not found")
	return ""
}
