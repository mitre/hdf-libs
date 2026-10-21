package nexusiq

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	shared "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go"
	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	validators "github.com/mitre/hdf-libs/hdf-validators/go/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testVersion = "1.0.0"

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "fixtures", "input", name))
	require.NoError(t, err)
	return b
}

func convert(t *testing.T, name string) *hdf.HDFResults {
	t.Helper()
	out, err := ConvertNexusIQToHDF(fixture(t, name), testVersion)
	require.NoError(t, err)
	require.NotNil(t, out)
	return out
}

func requirementByID(t *testing.T, out *hdf.HDFResults, id string) hdf.EvaluatedRequirement {
	t.Helper()
	for _, r := range out.Baselines[0].Requirements {
		if r.ID == id {
			return r
		}
	}
	require.FailNow(t, "requirement not found", id)
	return hdf.EvaluatedRequirement{}
}

// ---- Contract ----

func TestRejectsEmptyInput(t *testing.T) {
	_, err := ConvertNexusIQToHDF([]byte("  "), testVersion)
	require.Error(t, err)
}

func TestRejectsInvalidJSON(t *testing.T) {
	_, err := ConvertNexusIQToHDF([]byte("not json"), testVersion)
	require.Error(t, err)
}

func TestRejectsNonNexusIQDocument(t *testing.T) {
	for _, in := range []string{
		`{"foo":1}`,
		`[]`,
		`{"applicationId":"a","scanId":"s"}`,
		`{"applicationId":"a","policyEvaluationResult":{"alerts":[]}}`,
		`{"scanId":"s","policyEvaluationResult":{"alerts":[]}}`,
		`{"applicationId":5,"scanId":"s","policyEvaluationResult":{"alerts":[]}}`,
		`{"applicationId":"a","scanId":"s","policyEvaluationResult":[]}`,
		`{"applicationId":"a","scanId":"s","policyEvaluationResult":{"alerts":{}}}`,
	} {
		_, err := ConvertNexusIQToHDF([]byte(in), testVersion)
		assert.Error(t, err, in)
	}
}

func TestRejectsOversizedInput(t *testing.T) {
	big := make([]byte, shared.DefaultMaxJSONSize+1)
	_, err := ConvertNexusIQToHDF(big, testVersion)
	require.Error(t, err)
}

// ---- Document level ----

func TestOneRequirementPerAlertInSourceOrder(t *testing.T) {
	out := convert(t, "policy-evaluation.json")
	var report struct {
		PolicyEvaluationResult struct {
			Alerts []struct {
				Trigger struct {
					PolicyViolationID string `json:"policyViolationId"`
				} `json:"trigger"`
			} `json:"alerts"`
		} `json:"policyEvaluationResult"`
	}
	require.NoError(t, json.Unmarshal(fixture(t, "policy-evaluation.json"), &report))

	reqs := out.Baselines[0].Requirements
	require.Len(t, reqs, 15)
	for i, a := range report.PolicyEvaluationResult.Alerts {
		assert.Equal(t, a.Trigger.PolicyViolationID, reqs[i].ID)
	}
}

func TestDocumentIdentity(t *testing.T) {
	out := convert(t, "policy-evaluation.json")

	require.NotNil(t, out.Generator)
	assert.Equal(t, "nexusiq-to-hdf", out.Generator.Name)
	assert.Equal(t, testVersion, out.Generator.Version)
	require.NotNil(t, out.Tool)
	require.NotNil(t, out.Tool.Name)
	assert.Equal(t, "Nexus IQ Server", *out.Tool.Name)
	assert.Nil(t, out.Tool.Version, "the result file carries no IQ version")

	require.Len(t, out.Components, 1)
	c := out.Components[0]
	assert.Equal(t, hdf.Application, c.Type)
	assert.Equal(t, "example-org_example-app_dev", c.Name)
	assert.Equal(t, map[string]string{"nexus-iq": "example-org_example-app_dev"}, c.ExternalIDS)
}

func TestReportLinksBecomeRootExternalReferences(t *testing.T) {
	out := convert(t, "policy-evaluation.json")
	require.Len(t, out.ExternalReferences, 3)
	media := map[string]string{}
	for _, r := range out.ExternalReferences {
		assert.Equal(t, "nexus-iq", r.SourceName)
		require.NotNil(t, r.Href)
		require.NotNil(t, r.MediaType)
		media[*r.Href] = *r.MediaType
	}
	base := "https://lifecycle.example.com/ui/links/application/example-org_example-app_dev/report/0a1b2c3d4e5f60718293a4b5c6d7e8f9"
	assert.Equal(t, "text/html", media[base])
	assert.Equal(t, "application/pdf", media[base+"/pdf"])
	assert.Equal(t, "application/json",
		media["https://lifecycle.example.com/api/v2/applications/example-org_example-app_dev/reports/0a1b2c3d4e5f60718293a4b5c6d7e8f9/raw"])
}

func TestBaselineCarriesScanContext(t *testing.T) {
	out := convert(t, "policy-evaluation.json")
	b := out.Baselines[0]
	assert.Equal(t, "Nexus IQ Policy Evaluation", b.Name)
	require.NotNil(t, b.Title)
	assert.Equal(t, "Nexus IQ policy evaluation of example-org_example-app_dev (build stage)", *b.Title)
	require.NotNil(t, b.ResultsChecksum)
	assert.Nil(t, b.StatusMessage)

	require.NotNil(t, b.Extensions)
	ctx, ok := b.Extensions.Passthrough["nexusiq"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "0a1b2c3d4e5f60718293a4b5c6d7e8f9", ctx["scanId"])
	assert.Equal(t, "build", ctx["stage"])
	assert.Equal(t, "Warning", ctx["policyAction"])
	summary, ok := ctx["summary"].(map[string]any)
	require.True(t, ok)
	assert.EqualValues(t, 7, summary["criticalPolicyViolationCount"])
	assert.EqualValues(t, 150, summary["totalComponentCount"])
	assert.NotContains(t, summary, "alerts")
	assert.NotContains(t, summary, "sastAlerts")
}

// ---- A security policy violation (CVE) ----

func TestSecurityViolation(t *testing.T) {
	out := convert(t, "policy-evaluation.json")
	r := requirementByID(t, out, "e27fb118b0d940248ae27e451b1e9314")

	require.NotNil(t, r.Title)
	assert.Equal(t, "urllib3 2.7.0 (whl) — Security-High", *r.Title)
	assert.InDelta(t, 0.9, r.Impact, 1e-9)

	require.Len(t, r.ExternalReferences, 1)
	ref := r.ExternalReferences[0]
	assert.Equal(t, "cve", ref.SourceName)
	require.NotNil(t, ref.ExternalID)
	assert.Equal(t, "CVE-2026-97687", *ref.ExternalID)
	require.NotNil(t, ref.Rel)
	assert.Equal(t, "definition", *ref.Rel)

	require.Len(t, r.Refs, 1)
	require.NotNil(t, r.Refs[0].URL)
	assert.Equal(t, "https://nvd.nist.gov/vuln/detail/CVE-2026-97687", *r.Refs[0].URL)

	require.Len(t, r.AffectedPackages, 1)
	p := r.AffectedPackages[0]
	assert.Equal(t, "urllib3", *p.Name)
	assert.Equal(t, "2.7.0", *p.Version)
	assert.Equal(t, hdf.Pypi, *p.Ecosystem)
	assert.Equal(t, "pkg:pypi/urllib3@2.7.0", *p.Purl)

	assert.Equal(t, []any{"SI-2", "RA-5"}, r.Tags["nist"])
	assert.NotEmpty(t, r.Tags["cci"])
	assert.Equal(t, "Security-High", r.Tags["policyName"])
	assert.Equal(t, "269898a7af3840a7a925368807d79556", r.Tags["policyId"])
	assert.Equal(t, 9, r.Tags["threatLevel"])
	assert.Equal(t, "critical", r.Tags["threatCategory"])
	assert.Equal(t, []string{"warn"}, r.Tags["actions"])
	assert.Equal(t, []string{"CVSS >=7 and <10"}, r.Tags["constraints"])
	assert.Equal(t, []string{"SecurityVulnerabilitySeverity", "SecurityVulnerabilityStatus"}, r.Tags["conditionTypes"])
	assert.Equal(t, []string{"bd774de92f860e8e0cc6"}, r.Tags["componentHash"])
	assert.InDelta(t, 8.1, r.Tags["cvssScore"], 1e-9)
	// The requirement id is IQ's opaque violation id, so a CVE gate needs the tag.
	assert.Equal(t, []string{"CVE-2026-97687"}, r.Tags["cve"])

	require.Len(t, r.Results, 1)
	res := r.Results[0]
	assert.Equal(t, hdf.Failed, res.Status)
	assert.Contains(t, res.CodeDesc, "with severity >= 7 (severity = 8.1)")
	assert.Contains(t, res.CodeDesc, "with status 'Open', not 'Not Applicable'")
	require.NotNil(t, res.Message)
	assert.Equal(t,
		"dependency:/./app/module-a.zip/requirements.txt/urllib3==2.7.0\ndependency:/./app/requirements.txt/urllib3==2.7.0",
		*res.Message)
	require.NotNil(t, res.Resource)
	assert.Equal(t, "package", *res.Resource)
	assert.Equal(t, "pkg:pypi/urllib3@2.7.0", *res.ResourceID)
}

func TestWheelAndSdistStayDistinct(t *testing.T) {
	out := convert(t, "policy-evaluation.json")
	whl := requirementByID(t, out, "e27fb118b0d940248ae27e451b1e9314")
	sdist := requirementByID(t, out, "dda0346a9a71412890af075da3a50c60")
	assert.Equal(t, "urllib3 2.7.0 (tar.gz) — Security-High", *sdist.Title)
	assert.NotEqual(t, whl.Tags["componentHash"], sdist.Tags["componentHash"])
}

func TestDescriptions(t *testing.T) {
	out := convert(t, "policy-evaluation.json")
	r := requirementByID(t, out, "e27fb118b0d940248ae27e451b1e9314")
	byLabel := map[string]string{}
	for _, d := range r.Descriptions {
		byLabel[d.Label] = d.Data
	}
	assert.Equal(t, "Nexus IQ policy Security-High (threat level 9, critical) was violated by urllib3 2.7.0 (whl).", byLabel["default"])
	assert.Equal(t, "CVSS >=7 and <10:\nSecurity Vulnerability Severity >= 7\nSecurity Vulnerability Severity < 10\nSecurity Vulnerability Status is not NOT_APPLICABLE", byLabel["check"])
	assert.NotContains(t, byLabel, "fix", "the result file carries no remediation")
}

func TestRawSourceRecordIsTheAlert(t *testing.T) {
	out := convert(t, "policy-evaluation.json")
	var report struct {
		PolicyEvaluationResult struct {
			Alerts []json.RawMessage `json:"alerts"`
		} `json:"policyEvaluationResult"`
	}
	require.NoError(t, json.Unmarshal(fixture(t, "policy-evaluation.json"), &report))

	for i, r := range out.Baselines[0].Requirements {
		rec := r.Results[0].RawSourceRecord
		require.NotNil(t, rec, r.ID)
		assert.Equal(t, "application/json", rec.MediaType)
		assert.Equal(t, hdf.UTF8, rec.Encoding)
		require.NotNil(t, rec.Pointer)
		assert.Equal(t, "/policyEvaluationResult/alerts/"+itoa(i), *rec.Pointer)
		assert.JSONEq(t, string(report.PolicyEvaluationResult.Alerts[i]), rec.Content)
		assert.True(t, strings.HasPrefix(rec.Content, "{\n  \"trigger\": {"), "re-indented, not the source spacing")
	}
}

// ---- Non-security policies ----

func TestQualityViolationWithoutCVE(t *testing.T) {
	out := convert(t, "policy-evaluation.json")
	r := requirementByID(t, out, "63fd0bc6f1764894a1259b87ba3da80a")

	assert.Equal(t, "defusedxml 0.7.1 (tar.gz) — Quality-Architecture-Age GT 5 Years", *r.Title)
	assert.InDelta(t, 0.3, r.Impact, 1e-9)
	assert.Equal(t, "moderate", r.Tags["threatCategory"])
	assert.Equal(t, []any{"CM-8"}, r.Tags["nist"])
	assert.NotContains(t, r.Tags, "actions", "IQ attached no action to this alert")
	assert.NotContains(t, r.Tags, "cvssScore")
	assert.NotContains(t, r.Tags, "cve")
	assert.Empty(t, r.ExternalReferences)
	assert.Empty(t, r.Refs)
	assert.Equal(t, hdf.Failed, r.Results[0].Status)
	assert.Equal(t, "Found component older than 5 years\nFound component younger than 10 years", r.Results[0].CodeDesc)
}

func TestUnknownComponentHasNoPackageIdentity(t *testing.T) {
	out := convert(t, "policy-evaluation.json")
	r := requirementByID(t, out, "23b1b964c6544fae9b48d92f121b13e8")

	assert.Equal(t, "Unknown component ./app/module-a.zip — Other-Component-Unknown", *r.Title)
	assert.InDelta(t, 1.0, r.Impact, 1e-9)
	assert.Equal(t, []any{"CM-8"}, r.Tags["nist"])
	assert.Empty(t, r.AffectedPackages)
	assert.Nil(t, r.Results[0].Resource)
	assert.Nil(t, r.Results[0].ResourceID)
	assert.NotContains(t, r.Tags, "componentIdentifier")
	assert.Equal(t, []string{"20f1efaefeae4a001d46"}, r.Tags["componentHash"])
}

func TestComponentIdentifierCarriedVerbatim(t *testing.T) {
	out := convert(t, "policy-evaluation.json")
	r := requirementByID(t, out, "dda0346a9a71412890af075da3a50c60")
	ids, ok := r.Tags["componentIdentifier"].([]map[string]any)
	require.True(t, ok)
	require.Len(t, ids, 1)
	assert.Equal(t, "pypi", ids[0]["format"])
	assert.Equal(t, map[string]any{"extension": "tar.gz", "name": "urllib3", "qualifier": "", "version": "2.7.0"}, ids[0]["coordinates"])
}

// ---- Threat level ----

func TestThreatCategoryBands(t *testing.T) {
	for level, want := range map[int]string{
		0: "none", 1: "low", 2: "moderate", 3: "moderate", 4: "severe",
		7: "severe", 8: "critical", 10: "critical",
	} {
		assert.Equal(t, want, threatCategory(level), level)
	}
}

func TestImpactClampsOutOfRangeThreatLevels(t *testing.T) {
	assert.InDelta(t, 0.0, impactFor(-3), 1e-9)
	assert.InDelta(t, 1.0, impactFor(12), 1e-9)
}

// ---- Package identity by format ----

func TestPackageForNonPypiFormat(t *testing.T) {
	p, ok := affectedPackage(ComponentFact{
		ComponentIdentifier: &ComponentIdentifier{Format: "npm", Coordinates: map[string]any{"packageId": "lodash", "version": "4.17.20"}},
		DisplayName:         &DisplayName{Name: "lodash"},
	})
	require.True(t, ok)
	assert.Equal(t, "lodash", *p.Name)
	assert.Equal(t, "4.17.20", *p.Version)
	assert.Equal(t, hdf.Npm, *p.Ecosystem)
	assert.Nil(t, p.Purl, "a purl is only built for formats a real fixture covers")

	p, ok = affectedPackage(ComponentFact{
		ComponentIdentifier: &ComponentIdentifier{Format: "a-name", Coordinates: map[string]any{"name": "openssl", "version": "1.0"}},
	})
	require.True(t, ok)
	assert.Equal(t, hdf.Generic, *p.Ecosystem)
}

func TestPypiPurlNormalizesTheName(t *testing.T) {
	p, ok := affectedPackage(ComponentFact{
		ComponentIdentifier: &ComponentIdentifier{Format: "pypi", Coordinates: map[string]any{"name": "Typing_Extensions", "version": "4.12.2"}},
	})
	require.True(t, ok)
	assert.Equal(t, "pkg:pypi/typing-extensions@4.12.2", *p.Purl)
	assert.Equal(t, "Typing_Extensions", *p.Name, "the package name itself is kept as IQ reported it")
}

func TestNonCVEReferenceIsNotACVE(t *testing.T) {
	refs := externalReferences(Trigger{ComponentFacts: []ComponentFact{{ConstraintFacts: []ConstraintFact{{
		ConditionFacts: []ConditionFact{{Reference: &Reference{Value: "sonatype-2024-0001", Type: "SECURITY_VULNERABILITY_REFID"}}},
	}}}}})
	require.Len(t, refs, 1)
	assert.Equal(t, "nexus-iq", refs[0].SourceName)
	assert.Equal(t, "sonatype-2024-0001", *refs[0].ExternalID)
}

// ---- No findings, and a report that only looks clean ----

func TestEmptyScanIsANoFindingsDocument(t *testing.T) {
	out := convert(t, "empty.json")
	reqs := out.Baselines[0].Requirements
	require.Len(t, reqs, 1)
	assert.Equal(t, "nexusiq-no-findings", reqs[0].ID)
	require.Len(t, reqs[0].Results, 1)
	assert.Equal(t, hdf.Passed, reqs[0].Results[0].Status)
	assert.Contains(t, reqs[0].Results[0].CodeDesc, "example-org_example-app_dev")
}

func TestNullOrMissingAlertsWithZeroCountsIsClean(t *testing.T) {
	for _, in := range []string{
		`{"applicationId":"a","scanId":"s","policyEvaluationResult":{"alerts":null,"criticalPolicyViolationCount":0}}`,
		`{"applicationId":"a","scanId":"s","policyEvaluationResult":{}}`,
	} {
		out, err := ConvertNexusIQToHDF([]byte(in), testVersion)
		require.NoError(t, err, in)
		assert.Equal(t, "nexusiq-no-findings", out.Baselines[0].Requirements[0].ID, in)
	}
}

func TestNullAlertsWithViolationCountsIsRejected(t *testing.T) {
	in := `{"applicationId":"a","scanId":"s","policyEvaluationResult":{"alerts":null,"criticalPolicyViolationCount":2,"severePolicyViolationCount":1}}`
	_, err := ConvertNexusIQToHDF([]byte(in), testVersion)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "3 policy violations")
}

func TestSastAlertsAreReportedNotDropped(t *testing.T) {
	in := `{"applicationId":"a","scanId":"s","policyEvaluationResult":{"alerts":[],"sastAlerts":[{},{}]}}`
	out, err := ConvertNexusIQToHDF([]byte(in), testVersion)
	require.NoError(t, err)
	b := out.Baselines[0]
	require.NotNil(t, b.StatusMessage)
	assert.Contains(t, *b.StatusMessage, "2 SAST alerts")
	ctx := b.Extensions.Passthrough["nexusiq"].(map[string]any)
	assert.EqualValues(t, 2, ctx["unconvertedSastAlerts"])
}

func TestAlertWithoutViolationIDGetsPositionalID(t *testing.T) {
	in := `{"applicationId":"a","scanId":"s","policyEvaluationResult":{"alerts":[{"trigger":{"policyName":"P","threatLevel":5,"componentFacts":[]},"actions":[]}]}}`
	out, err := ConvertNexusIQToHDF([]byte(in), testVersion)
	require.NoError(t, err)
	r := out.Baselines[0].Requirements[0]
	assert.Equal(t, "nexusiq-alert-0", r.ID)
	assert.Equal(t, "Unknown component — P", *r.Title)
	assert.Equal(t, "Unknown component", r.Results[0].CodeDesc[:len("Unknown component")])
}

// ---- Expected count ----

func TestExpectedRequirementCount(t *testing.T) {
	n, unit, err := ExpectedRequirementCount(fixture(t, "policy-evaluation.json"))
	require.NoError(t, err)
	assert.Equal(t, 15, n)
	assert.NotEmpty(t, unit)

	n, _, err = ExpectedRequirementCount(fixture(t, "empty.json"))
	require.NoError(t, err)
	assert.Equal(t, 1, n)

	_, _, err = ExpectedRequirementCount([]byte(`{}`))
	require.Error(t, err)
}

// ---- Schema and goldens ----

func TestOutputValidatesAgainstSchema(t *testing.T) {
	for _, name := range []string{"policy-evaluation.json", "empty.json"} {
		out := convert(t, name)
		data, err := json.Marshal(out)
		require.NoError(t, err)
		v := validators.ValidateResults(data)
		assert.Truef(t, v.Valid, "%s: %s", name, v.Error())
	}
}

func TestSnapshots(t *testing.T) {
	// The result file carries no scan time, so startTime has nothing to assert.
	shared.RunSnapshotTests(t, "nexusiq-to-hdf", func(input []byte) (interface{}, error) {
		return ConvertNexusIQToHDF(input, testVersion)
	}, "*")
}

func itoa(i int) string {
	b, _ := json.Marshal(i)
	return string(b)
}

// Every optional field absent or empty: the shapes a trimmed or older result
// file could carry. TypeScript asserts the same document in its sparse-input test.
const sparse = `{"applicationId":"app","scanId":"scan","policyEvaluationResult":{"alerts":[
	{},
	{"trigger":{"policyName":"P","componentFacts":[{"componentIdentifier":{"format":"maven"},"displayName":{"name":"shown"}}]}},
	{"trigger":{"componentFacts":[{"componentIdentifier":{"format":"npm","coordinates":{}}}]}},
	{"trigger":{"componentFacts":[{"componentIdentifier":null,"constraintFacts":[{"conditionFacts":[{"summary":"s"}]}]}]}},
	{"trigger":{"componentFacts":[{"componentIdentifier":{"format":"pypi","coordinates":{"name":"n"}},"constraintFacts":[{}]}]}}
]}}`

func TestSparseAlerts(t *testing.T) {
	out, err := ConvertNexusIQToHDF([]byte(sparse), testVersion)
	require.NoError(t, err)
	reqs := out.Baselines[0].Requirements
	require.Len(t, reqs, 5)

	var titles []string
	for i, r := range reqs {
		titles = append(titles, *r.Title)
		assert.Equal(t, "nexusiq-alert-"+itoa(i), r.ID)
	}
	assert.Equal(t, []string{
		"Unknown component — ", "shown — P", "Unknown component — ", "Unknown component — ", "n — ",
	}, titles)
	assert.InDelta(t, 0.0, reqs[0].Impact, 1e-9)
	assert.Equal(t, "none", reqs[0].Tags["threatCategory"])
	assert.Equal(t, "Unknown component violated ", reqs[0].Results[0].CodeDesc)
	assert.Empty(t, reqs[1].AffectedPackages)
	assert.Equal(t, ":\ns", reqs[3].Descriptions[1].Data)
	assert.Equal(t, ":", reqs[4].Descriptions[1].Data)

	assert.Equal(t, "Nexus IQ policy evaluation of app", *out.Baselines[0].Title)
	assert.Empty(t, out.ExternalReferences)
	assert.Equal(t, map[string]any{"applicationId": "app", "scanId": "scan", "summary": map[string]any{}},
		out.Baselines[0].Extensions.Passthrough["nexusiq"])

	data, err := json.Marshal(out)
	require.NoError(t, err)
	assert.Contains(t, string(data), `"componentIdentifier":[{"coordinates":{"name":"n"},"format":"pypi"}]`)
	v := validators.ValidateResults(data)
	assert.Truef(t, v.Valid, "%s", v.Error())
}
