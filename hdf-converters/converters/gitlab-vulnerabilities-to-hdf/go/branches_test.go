package gitlab_vulnerabilities_to_hdf

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
)

func str(s string) *string { return &s }

// Location union members the recorded corpus does not contain (only SAST and
// secret detection ran) are rendered from the GraphQL shapes GitLab documents
// for them.
func TestBuildCodeDesc_EveryLocationVariant(t *testing.T) {
	dep := &Dependency{Version: "4.17.20"}
	dep.Package.Name = "lodash"
	cases := []struct {
		name string
		v    Vulnerability
		want string
	}{
		{"no location", Vulnerability{ReportType: "GENERIC"}, "Report type: GENERIC"},
		{"sast line range and class", Vulnerability{Location: &Location{Typename: "VulnerabilityLocationSast", File: "a.go", StartLine: str("3"), EndLine: str("9"), VulnerableClass: str("Handler"), VulnerableMethod: str("Serve")}}, "File: a.go | Line: 3-9 | Class: Handler | Method: Serve"},
		{"sast same start and end", Vulnerability{Location: &Location{Typename: "VulnerabilityLocationSast", File: "a.go", StartLine: str("3"), EndLine: str("3")}}, "File: a.go | Line: 3"},
		{"secret detection", Vulnerability{Location: &Location{Typename: "VulnerabilityLocationSecretDetection", File: ".env", StartLine: str("1")}}, "File: .env | Line: 1"},
		{"dependency scanning", Vulnerability{Location: &Location{Typename: "VulnerabilityLocationDependencyScanning", File: "package-lock.json", Dependency: dep}}, "File: package-lock.json | Package: lodash@4.17.20"},
		{"container scanning", Vulnerability{Location: &Location{Typename: "VulnerabilityLocationContainerScanning", Image: "registry/app:1.0", OperatingSystem: "debian:12", Dependency: &Dependency{Package: struct {
			Name string `json:"name"`
		}{Name: "openssl"}}}}, "Image: registry/app:1.0 | OS: debian:12 | Package: openssl"},
		{"dast", Vulnerability{Location: &Location{Typename: "VulnerabilityLocationDast", Hostname: "https://app.example.com", Path: "/login", RequestMethod: "POST", Param: "user"}}, "URL: https://app.example.com/login | Method: POST | Param: user"},
		{"unknown variant falls back to JSON", Vulnerability{Location: &Location{Typename: "VulnerabilityLocationFuture", File: "x"}}, `Location: {"__typename":"VulnerabilityLocationFuture","file":"x","startLine":null,"endLine":null,"blobPath":null,"vulnerableClass":null,"vulnerableMethod":null,"dependency":null,"image":"","operatingSystem":"","hostname":"","path":"","param":"","requestMethod":""}`},
		{"known variant with nothing to say", Vulnerability{ReportType: "SAST", Location: &Location{Typename: "VulnerabilityLocationSast"}}, "Report type: SAST"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, buildCodeDesc(&tc.v))
		})
	}
}

func TestPackageLabel(t *testing.T) {
	assert.Equal(t, "", packageLabel(nil))
	assert.Equal(t, "", packageLabel(&Dependency{Version: "1"}))
	d := &Dependency{}
	d.Package.Name = "zlib"
	assert.Equal(t, "zlib", packageLabel(d))
}

func TestBuildSourceLocation_LineFallbacks(t *testing.T) {
	assert.Nil(t, buildSourceLocation(nil))
	assert.Nil(t, buildSourceLocation(&Location{Typename: "VulnerabilityLocationDast", Hostname: "h"}), "no file, no location")

	sl := buildSourceLocation(&Location{File: "f.go", EndLine: str("12")})
	require.NotNil(t, sl)
	assert.Equal(t, "f.go", *sl.Ref)
	assert.InDelta(t, 12, *sl.Line, 0, "endLine stands in when startLine is absent")

	sl = buildSourceLocation(&Location{File: "f.go", StartLine: str("not-a-number")})
	require.NotNil(t, sl)
	assert.Nil(t, sl.Line, "an unparseable line is omitted, not fabricated")
	assert.Nil(t, parseLine(str("")))
}

func TestBuildVulnCode_WithoutRawBytes(t *testing.T) {
	assert.Equal(t, "{}", buildVulnCode(&Vulnerability{}))
	v := &Vulnerability{raw: json.RawMessage(`{"uuid":"u","state":"DETECTED"}`)}
	assert.Equal(t, "{\n  \"uuid\": \"u\",\n  \"state\": \"DETECTED\"\n}", buildVulnCode(v))
	bad := &Vulnerability{raw: json.RawMessage(`{not json`)}
	assert.Equal(t, "{}", buildVulnCode(bad))
}

func TestVulnerability_UnmarshalJSON_RejectsWrongShape(t *testing.T) {
	var v Vulnerability
	assert.Error(t, json.Unmarshal([]byte(`{"uuid": 42}`), &v))
}

func TestResultStartTime_Fallbacks(t *testing.T) {
	fetched := time.Date(2026, 9, 20, 19, 50, 18, 0, time.UTC)
	assert.Equal(t, "2026-09-19T20:47:38Z", stamp(resultStartTime(&Vulnerability{LatestDetectedPipeline: &PipelineRef{CreatedAt: "2026-09-19T20:47:38Z"}, DetectedAt: "2026-09-19T21:20:50Z"}, fetched)))
	assert.Equal(t, "2026-09-19T21:20:50Z", stamp(resultStartTime(&Vulnerability{LatestDetectedPipeline: &PipelineRef{CreatedAt: "bogus"}, DetectedAt: "2026-09-19T21:20:50Z"}, fetched)))
	assert.Equal(t, "2026-09-20T19:50:18Z", stamp(resultStartTime(&Vulnerability{}, fetched)), "never omit startTime: the fetch time is the last resort")
}

func TestBuildDescriptions_FallsBackToTitleAndOmitsEmptySolution(t *testing.T) {
	d := buildDescriptions(&Vulnerability{Title: "Only a title", Solution: str("")})
	require.Len(t, d, 1)
	assert.Equal(t, "Only a title", d[0].Data)

	d = buildDescriptions(&Vulnerability{Title: "T", Description: "D", Solution: str("Fix it")})
	require.Len(t, d, 2)
	assert.Equal(t, hdf.Description{Label: "fix", Data: "Fix it"}, d[1])
}

func TestTagHelpers_NilInputs(t *testing.T) {
	assert.Nil(t, pipelineTag(nil))
	assert.Nil(t, scannerTag(nil))
	assert.Nil(t, userTag(nil))
	assert.Nil(t, nullableString(nil))
	assert.Equal(t, "", derefString(nil))
	assert.Equal(t, "x", derefString(str("x")))
	fetched := time.Date(2026, 9, 20, 19, 50, 18, 0, time.UTC)
	assert.Equal(t, fetched, firstTime(fetched, "", "bogus"), "no source time falls back to the fetch time, never a zero or epoch date")
}

func TestReportTypeLabel_UnknownPassesThrough(t *testing.T) {
	assert.Equal(t, "Dependency Scanning", reportTypeLabel("DEPENDENCY_SCANNING"))
	assert.Equal(t, "SOMETHING_NEW", reportTypeLabel("SOMETHING_NEW"))
	assert.Equal(t, "SECRET_DETECTION", summaryKeyToReportType("secretDetection"))
	assert.Equal(t, "CONTAINER_SCANNING_FOR_REGISTRY", summaryKeyToReportType("containerScanningForRegistry"))
}

func TestIdentityFor_PrefersPublicEmailAndCarriesDisplayName(t *testing.T) {
	id := identityFor(&User{Username: "u", Name: "U Name", PublicEmail: str("u@example.com")})
	assert.Equal(t, hdf.Identity{Type: hdf.Email, Identifier: "u@example.com", Description: str("U Name")}, id)
	id = identityFor(&User{Username: "u"})
	assert.Equal(t, hdf.Identity{Type: hdf.Username, Identifier: "u"}, id)
	id = identityFor(&User{})
	assert.Equal(t, hdf.IdentityTypeSystem, id.Type, "a user record with no handle is not a person we can name")
}

func TestCurrentDecisionProvenance_EveryState(t *testing.T) {
	fetched := time.Date(2026, 9, 20, 19, 50, 18, 0, time.UTC)
	at, by := currentDecisionProvenance(&Vulnerability{State: "DISMISSED", DismissedAt: str("2026-01-02T03:04:05Z"), DismissedBy: &User{Username: "d"}}, fetched)
	assert.Equal(t, "2026-01-02T03:04:05Z", stamp(at))
	assert.Equal(t, "d", by.Username)
	at, by = currentDecisionProvenance(&Vulnerability{State: "CONFIRMED", UpdatedAt: "2026-01-02T03:04:05Z"}, fetched)
	assert.Equal(t, "2026-01-02T03:04:05Z", stamp(at))
	assert.Nil(t, by)
	at, _ = currentDecisionProvenance(&Vulnerability{State: "RESOLVED", DetectedAt: "2026-01-01T00:00:00Z"}, fetched)
	assert.Equal(t, "2026-01-01T00:00:00Z", stamp(at), "detectedAt is the last dated fallback")
	at, _ = currentDecisionProvenance(&Vulnerability{State: "RESOLVED"}, fetched)
	assert.Equal(t, fetched, at, "with no source time at all, the fetch time stands in")
}

func TestDecisionFor_UnknownStatesAndReasons(t *testing.T) {
	_, ok := decisionFor("SOMETHING_ELSE", nil, false)
	assert.False(t, ok)
	_, ok = decisionFor("CONFIRMED", nil, false)
	assert.False(t, ok)
	_, ok = decisionFor("RESOLVED", nil, true)
	assert.False(t, ok, "scanner-confirmed resolution needs no attestation")
	d, ok := dismissalDecision("FUTURE_REASON")
	require.True(t, ok)
	assert.Equal(t, hdf.OverrideTypeWaiver, d.overrideType)
	assert.Equal(t, hdf.NotApplicable, d.status)
	assert.Equal(t, "Dismissed as FUTURE_REASON in GitLab", d.defaultReason)
	d, _ = dismissalDecision("")
	assert.Equal(t, "Dismissed as NOT_APPLICABLE in GitLab", d.defaultReason, "a dismissal with no reason is treated as not applicable")
}

func TestIngestionError_ScanStatusBranches(t *testing.T) {
	env := func(scans ...Scan) *Envelope {
		p := &Pipeline{SecurityReportSummary: map[string]*SummarySection{"sast": {}, "dast": nil}}
		p.SecurityReportSummary["sast"].Scans.Nodes = scans
		return &Envelope{Project: Project{FullPath: "g/p", LatestDefaultBranchPipeline: p}}
	}
	assert.NoError(t, IngestionError(&Envelope{Project: Project{VulnerabilityStatistic: &Statistic{}}}))
	assert.NoError(t, IngestionError(env(Scan{Status: "SUCCEEDED"})), "a succeeded scan without a statistic row still counts as populated")
	assert.ErrorContains(t, IngestionError(env(Scan{Status: "PREPARING"})), "never ingested")
	assert.ErrorContains(t, IngestionError(env(Scan{Status: ""})), "status unknown")
	assert.ErrorContains(t, IngestionError(env(Scan{Status: "JOB_FAILED", Errors: []string{"exit 1"}})), "sast: JOB_FAILED (exit 1)")
	assert.ErrorContains(t, IngestionError(env()), "no security scanner has run")
	assert.Empty(t, ingestedReportTypes(nil))
}

func TestExpectedRequirementCount_EmptyReportWithoutSections(t *testing.T) {
	input := []byte(`{"metadata":{"enterprise":true},"project":{"fullPath":"g/p","vulnerabilityStatistic":{"total":0}},"vulnerabilities":[],"fetchedAt":"2026-09-20T19:50:18Z"}`)
	n, _, err := ExpectedRequirementCount(input)
	require.NoError(t, err)
	assert.Equal(t, 1, n, "a populated report with no summary still gets one no-findings requirement")
	result, err := ConvertGitlabVulnerabilitiesToHDF(input, testVersion)
	require.NoError(t, err)
	assert.Equal(t, "gitlab-vulnerability-report-no-findings-generic", result.Baselines[0].Requirements[0].ID)
	assert.Nil(t, result.Components[0].Commit, "no pipeline, no commit to name")
}

func TestConvert_GenericReportTypeAndScannerlessFinding(t *testing.T) {
	input := []byte(`{"metadata":{"enterprise":true,"version":"18.9.1-ee"},"project":{"fullPath":"g/p","webUrl":"https://gitlab.example.com/g/p"},"vulnerabilities":[{"id":"gid://gitlab/Vulnerability/1","uuid":"u1","title":"T","severity":"UNKNOWN","state":"DETECTED","detectedAt":"2026-09-01T00:00:00Z","updatedAt":"2026-09-01T00:00:00Z","identifiers":[{"externalType":"","externalId":""}]}],"fetchedAt":"2026-09-20T19:50:18Z"}`)
	result, err := ConvertGitlabVulnerabilitiesToHDF(input, testVersion)
	require.NoError(t, err)
	require.Len(t, result.Baselines, 1)
	assert.Equal(t, "GitLab Vulnerability Report: Generic", result.Baselines[0].Name)
	assert.Equal(t, "Scanner: unknown", *result.Baselines[0].Summary)
	req := result.Baselines[0].Requirements[0]
	assert.InDelta(t, 0.5, req.Impact, 1e-9, "UNKNOWN severity takes the default")
	assert.Equal(t, "unrated", req.Tags["severity_rating"])
	assert.Equal(t, "2026-09-01T00:00:00Z", stamp(req.Results[0].StartTime))
	assert.Nil(t, req.SourceLocation)
	assert.Nil(t, req.Tags["gitlab/scanner"])
}
