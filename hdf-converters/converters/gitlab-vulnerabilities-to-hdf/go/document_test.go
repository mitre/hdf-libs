package gitlab_vulnerabilities_to_hdf

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	shared "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go"
	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
)

const testVersion = "1.0.0"

func TestConverterContract(t *testing.T) {
	shared.RunConverterContractTests(t, shared.ConverterContractSpec{
		ConverterName:  "gitlab-vulnerabilities-to-hdf",
		ConvertFn:      func(input []byte) (interface{}, error) { return ConvertGitlabVulnerabilitiesToHDF(input, testVersion) },
		MinimalFixture: "clean.json",
	})
}

func TestSnapshots(t *testing.T) {
	shared.RunSnapshotTests(t, "gitlab-vulnerabilities-to-hdf", func(input []byte) (interface{}, error) {
		return ConvertGitlabVulnerabilitiesToHDF(input, testVersion)
	})
}

func TestConvert_Document_BaselinesPerReportTypeAndProvenance(t *testing.T) {
	result := convertFixture(t, "triaged.json")

	require.Len(t, result.Baselines, 2)
	sast, secrets := result.Baselines[0], result.Baselines[1]
	assert.Equal(t, "GitLab Vulnerability Report: SAST", sast.Name)
	assert.Equal(t, "Scanner: Semgrep", *sast.Summary)
	assert.Len(t, sast.Requirements, 94)
	assert.Equal(t, "GitLab Vulnerability Report: Secret Detection", secrets.Name)
	assert.Equal(t, "Scanner: Gitleaks", *secrets.Summary)
	assert.Len(t, secrets.Requirements, 3)
	require.NotNil(t, sast.ResultsChecksum)
	assert.Equal(t, sast.ResultsChecksum, secrets.ResultsChecksum, "one input, one checksum")

	assert.Equal(t, "gitlab-vulnerabilities-to-hdf", result.Generator.Name)
	assert.Equal(t, testVersion, result.Generator.Version)
	require.NotNil(t, result.Tool)
	require.NotNil(t, result.Tool.Name)
	assert.Equal(t, "GitLab Vulnerability Report", *result.Tool.Name)
	require.NotNil(t, result.Tool.Version)
	assert.Equal(t, "18.9.1-ee", *result.Tool.Version)
	require.NotNil(t, result.Timestamp)
	assert.Equal(t, "2026-09-20T19:50:18Z", stamp(*result.Timestamp), "document timestamp is the fetch time")

	require.Len(t, result.Components, 1)
	c := result.Components[0]
	assert.Equal(t, hdf.Repository, c.Type)
	assert.Equal(t, "security-demo/juice-shop", c.Name)
	assert.Equal(t, "https://gitlab.example.com/security-demo/juice-shop", *c.URL)
	assert.Equal(t, "master", *c.Branch)
	assert.Equal(t, "556a44e4001434ea7a242f29ede789565066082d", *c.Commit)
	assert.Equal(t, map[string]string{"gitlab/project-id": "gid://gitlab/Project/1", "gitlab/full-path": "security-demo/juice-shop"}, c.Labels)
}

func TestConvert_Requirement_IdentityCodeLocationAndTags(t *testing.T) {
	input := readInput(t, "triaged.json")
	result, err := ConvertGitlabVulnerabilitiesToHDF(input, testVersion)
	require.NoError(t, err)
	req := requirementByGID(t, result, "50")

	assert.Equal(t, req.Tags["gitlab/uuid"], req.ID, "requirement id is the GitLab uuid")
	assert.Equal(t, "Use of hard-coded credentials", *req.Title)
	require.NotEmpty(t, req.Descriptions)
	assert.Equal(t, "default", req.Descriptions[0].Label)
	assert.True(t, strings.HasPrefix(req.Descriptions[0].Data, "Hardcoded JWT secret"), req.Descriptions[0].Data[:40])
	assert.InDelta(t, 0.7, req.Impact, 1e-9, "HIGH")

	// code is the raw node, re-indented, so nothing the typed view drops is lost.
	var env struct {
		Vulnerabilities []json.RawMessage `json:"vulnerabilities"`
	}
	require.NoError(t, json.Unmarshal(input, &env))
	var want bytes.Buffer
	for _, raw := range env.Vulnerabilities {
		if strings.Contains(string(raw), `"gid://gitlab/Vulnerability/50"`) {
			require.NoError(t, json.Indent(&want, raw, "", "  "))
			break
		}
	}
	require.NotNil(t, req.Code)
	assert.Equal(t, want.String(), *req.Code)
	require.NotNil(t, req.VerificationMethod)
	assert.Equal(t, hdf.VerificationMethodEnumAutomated, *req.VerificationMethod)

	require.NotNil(t, req.SourceLocation)
	assert.Equal(t, "lib/insecurity.ts", *req.SourceLocation.Ref)
	assert.InDelta(t, 54, *req.SourceLocation.Line, 0)
	assert.Equal(t, "File: lib/insecurity.ts | Line: 54", req.Results[0].CodeDesc)
	assert.Equal(t, "2026-09-19T20:47:38Z", stamp(req.Results[0].StartTime), "result time is the latest detecting pipeline's")

	// CWE-798 has no NIST mapping in the table, so the static-analysis default applies.
	assert.Equal(t, []any{"SA-11", "RA-5"}, req.Tags["nist"])
	assert.Equal(t, []any{"798"}, req.Tags["cwe"])
	xss := requirementByGID(t, result, "43")
	assert.Equal(t, []any{"SI-10"}, xss.Tags["nist"], "CWE-79 maps to SI-10")
	assert.Equal(t, []any{"79"}, xss.Tags["cwe"])
	assert.Equal(t, "SAST", req.Tags["gitlab/reportType"])
	assert.Equal(t, map[string]interface{}{"name": "Semgrep", "vendor": "GitLab", "externalId": "semgrep"}, req.Tags["gitlab/scanner"])
	assert.Equal(t, map[string]interface{}{"iid": "5", "sha": "556a44e4001434ea7a242f29ede789565066082d", "ref": "master", "createdAt": "2026-09-19T20:47:38Z"}, req.Tags["gitlab/latestDetectedPipeline"])
	assert.Equal(t, "security-demo/juice-shop", req.Tags["gitlab/project"])
	assert.Equal(t, "2026-09-19T21:20:50Z", req.Tags["gitlab/detectedAt"])
	assert.Equal(t, "2026-09-20T19:27:19Z", req.Tags["gitlab/dismissedAt"])
	assert.Equal(t, "sec-reviewer", req.Tags["gitlab/dismissedBy"])
	assert.Nil(t, req.Tags["gitlab/confirmedBy"])
	assert.Nil(t, req.Tags["gitlab/resolvedAt"])
	assert.Equal(t, 1, req.Tags["gitlab/stateTransitionCount"])

	require.NotEmpty(t, req.Refs)
	assert.Equal(t, "https://gitlab.example.com/security-demo/juice-shop/-/security/vulnerabilities/50", *req.Refs[0].URL, "the finding's own page is the first ref")
}

func TestConvert_EveryTriageTagIsPresentOnEveryRequirement(t *testing.T) {
	result := convertFixture(t, "triaged.json")
	keys := []string{
		"gitlab/id", "gitlab/uuid", "gitlab/webUrl", "gitlab/project", "gitlab/reportType", "gitlab/severity",
		"gitlab/originalSeverity", "gitlab/state", "gitlab/dismissalReason", "gitlab/stateComment",
		"gitlab/falsePositive", "gitlab/presentOnDefaultBranch", "gitlab/resolvedOnDefaultBranch",
		"gitlab/detectedAt", "gitlab/updatedAt", "gitlab/confirmedAt", "gitlab/confirmedBy",
		"gitlab/dismissedAt", "gitlab/dismissedBy", "gitlab/resolvedAt", "gitlab/resolvedBy",
		"gitlab/initialDetectedPipeline", "gitlab/latestDetectedPipeline", "gitlab/scanner",
		"gitlab/stateTransitionCount",
	}
	for _, b := range result.Baselines {
		for _, r := range b.Requirements {
			for _, k := range keys {
				_, present := r.Tags[k]
				assert.True(t, present, "%s lacks tag %s", r.ID, k)
			}
		}
	}
}

func TestConvert_CleanReport_OneNoFindingsRequirementPerIngestedType(t *testing.T) {
	result := convertFixture(t, "clean.json")
	require.Len(t, result.Baselines, 1)
	b := result.Baselines[0]
	assert.Equal(t, "GitLab Vulnerability Report", b.Name)
	assert.Equal(t, "Ingested scanner types: secretDetection", *b.Summary)
	require.Len(t, b.Requirements, 1)
	r := b.Requirements[0]
	assert.Equal(t, "gitlab-vulnerability-report-no-findings-secret_detection", r.ID)
	assert.Equal(t, hdf.Passed, r.Results[0].Status)
	assert.Equal(t, "GitLab Vulnerability Report for security-demo/web-goat lists zero Secret Detection vulnerabilities after a successful scan ingestion.", r.Results[0].CodeDesc)
	assert.Equal(t, "2026-09-20T19:42:17Z", stamp(r.Results[0].StartTime), "no-findings time is the fetch time")
	assert.Equal(t, "security-demo/web-goat", result.Components[0].Name)
	assert.Equal(t, "main", *result.Components[0].Branch)
}

func TestConvert_NeverIngested_IsAnErrorNotADocument(t *testing.T) {
	_, err := ConvertGitlabVulnerabilitiesToHDF(readInput(t, "report-error.json"), testVersion)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "security-demo/unscanned-app")
	assert.Contains(t, err.Error(), "sast: REPORT_ERROR")

	_, err = ConvertGitlabVulnerabilitiesToHDF(readInput(t, "empty.json"), testVersion)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no default-branch pipeline")
}

// The Free-tier signature: scans exist but stay CREATED because nothing
// ingests them. Composed from the recorded report-error envelope and the
// recorded pre-Ultimate pipeline page, since a Free instance was not
// available to record whole.
func TestConvert_ReportsNeverIngested_NamesTheUltimateRequirement(t *testing.T) {
	var env map[string]any
	require.NoError(t, json.Unmarshal(readInput(t, "report-error.json"), &env))
	page := loadJSON(t, "../../../fetchers/gitlab-vulnerabilities/go/testdata/pages-juice-shop-notingested-1.json").(map[string]any)
	pipeline := page["data"].(map[string]any)["project"].(map[string]any)["pipelines"].(map[string]any)["nodes"].([]any)[0]
	env["project"].(map[string]any)["latestDefaultBranchPipeline"] = pipeline
	modified, err := json.Marshal(env)
	require.NoError(t, err)

	_, err = ConvertGitlabVulnerabilitiesToHDF(modified, testVersion)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "never ingested")
	assert.Contains(t, err.Error(), "GitLab Ultimate")
	assert.Contains(t, err.Error(), "sast, secretDetection")
}

func TestConvert_CommunityEdition_IsRejected(t *testing.T) {
	var env map[string]any
	require.NoError(t, json.Unmarshal(readInput(t, "clean.json"), &env))
	env["metadata"].(map[string]any)["enterprise"] = false
	modified, err := json.Marshal(env)
	require.NoError(t, err)
	_, err = ConvertGitlabVulnerabilitiesToHDF(modified, testVersion)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "Community Edition")
}

func TestConvert_RejectsNonEnvelopes(t *testing.T) {
	for name, bad := range map[string][]byte{
		"nil": nil, "empty": []byte(""), "object": []byte("{}"), "garbage": []byte("garbage"), "array": []byte("[]"),
		"no project":    []byte(`{"vulnerabilities":[]}`),
		"bad fetchedAt": []byte(`{"metadata":{"enterprise":true},"project":{"fullPath":"g/p","vulnerabilityStatistic":{"total":0}},"vulnerabilities":[],"fetchedAt":"yesterday"}`),
		"ci artifact":   readInput(t, "../../../gitlab-to-hdf/fixtures/input/minimal-sast.json"),
	} {
		_, err := ConvertGitlabVulnerabilitiesToHDF(bad, testVersion)
		assert.Error(t, err, name)
	}
}

func TestExpectedRequirementCount_MatchesConversionForEveryFixture(t *testing.T) {
	for _, name := range []string{"triaged.json", "clean.json", "report-error.json", "empty.json"} {
		data := readInput(t, name)
		result, convErr := ConvertGitlabVulnerabilitiesToHDF(data, testVersion)
		expected, unit, expErr := ExpectedRequirementCount(data)
		require.Equal(t, "GitLab vulnerabilities", unit)
		require.Equal(t, convErr != nil, expErr != nil, "%s: converter and expectation must agree on rejection", name)
		if convErr != nil {
			continue
		}
		produced := 0
		for _, b := range result.Baselines {
			produced += len(b.Requirements)
		}
		assert.Equal(t, expected, produced, name)
	}
	assert.Equal(t, 97, mustCount(t, readInput(t, "triaged.json")))
	assert.Equal(t, 1, mustCount(t, readInput(t, "clean.json")))
}

func mustCount(t *testing.T, data []byte) int {
	t.Helper()
	n, _, err := ExpectedRequirementCount(data)
	require.NoError(t, err)
	return n
}
