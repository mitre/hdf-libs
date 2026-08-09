package junit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	shared "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go"
	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const converterVersion = "0.1.0"

func fixtureDir() string {
	return filepath.Join(shared.GetConvertersDir(), "junit-to-hdf", "fixtures", "input")
}

func loadFixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(fixtureDir(), name))
	require.NoError(t, err)
	return data
}

// Fixtures sourced from apache/maven-surefire test resources:
// https://github.com/apache/maven-surefire/tree/master/surefire-report-parser/src/test/resources/fixture/testsuitexmlparser

// --- Conversion basics ---

func TestConvertJUnitToHDF_SurefireFailing(t *testing.T) {
	result, err := ConvertJUnitToHDF(loadFixture(t, "surefire-failing.xml"), converterVersion)
	require.NoError(t, err)
	require.NotNil(t, result)

	require.NotNil(t, result.Generator)
	assert.Equal(t, "junit-to-hdf", result.Generator.Name)
	assert.Equal(t, converterVersion, result.Generator.Version)
	require.NotNil(t, result.Timestamp)
	assert.Len(t, result.Baselines, 1)
}

func TestConvertJUnitToHDF_Tool(t *testing.T) {
	result, err := ConvertJUnitToHDF(loadFixture(t, "surefire-failing.xml"), converterVersion)
	require.NoError(t, err)

	require.NotNil(t, result.Tool)
	require.NotNil(t, result.Tool.Name)
	assert.Equal(t, "JUnit XML", *result.Tool.Name)
	assert.Nil(t, result.Tool.Format, "serialization structures are not formats (kpvj)")
}

func TestConverterContract(t *testing.T) {
	shared.RunConverterContractTests(t, shared.ConverterContractSpec{
		ConverterName:  "junit-to-hdf",
		ConvertFn:      func(input []byte) (interface{}, error) { return ConvertJUnitToHDF(input, converterVersion) },
		MinimalFixture: "surefire-error.xml",
		InvalidInput:   "<not valid xml",
	})
}

func TestConvertJUnitToHDF_InvalidXML(t *testing.T) {
	_, err := ConvertJUnitToHDF([]byte("<unclosed"), converterVersion)
	assert.Error(t, err)
}

func TestConvertJUnitToHDF_NonJUnitXML(t *testing.T) {
	_, err := ConvertJUnitToHDF([]byte(`<?xml version="1.0"?><root><item/></root>`), converterVersion)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not a JUnit XML")
}

// --- Baseline structure ---

func TestBaselineName_SurefireFailing(t *testing.T) {
	result, err := ConvertJUnitToHDF(loadFixture(t, "surefire-failing.xml"), converterVersion)
	require.NoError(t, err)
	assert.Equal(t, "org.apache.maven.surefire.test.FailingTest", result.Baselines[0].Name)
}

func TestBaselineName_SurefireError(t *testing.T) {
	result, err := ConvertJUnitToHDF(loadFixture(t, "surefire-error.xml"), converterVersion)
	require.NoError(t, err)
	assert.Equal(t, "surefire.MyTest", result.Baselines[0].Name)
}

func TestBaselineChecksum(t *testing.T) {
	result, err := ConvertJUnitToHDF(loadFixture(t, "surefire-failing.xml"), converterVersion)
	require.NoError(t, err)
	checksum := result.Baselines[0].ResultsChecksum
	require.NotNil(t, checksum)
	assert.Equal(t, hdf.Sha256, checksum.Algorithm)
	assert.Regexp(t, `^[a-f0-9]{64}$`, checksum.Value)
}

// --- Requirements from test cases ---

func TestRequirementCount_Failing(t *testing.T) {
	result, err := ConvertJUnitToHDF(loadFixture(t, "surefire-failing.xml"), converterVersion)
	require.NoError(t, err)
	// surefire-failing.xml has 2 testcases
	assert.Len(t, result.Baselines[0].Requirements, 2)
}

func TestRequirementID(t *testing.T) {
	result, err := ConvertJUnitToHDF(loadFixture(t, "surefire-failing.xml"), converterVersion)
	require.NoError(t, err)

	ids := make([]string, len(result.Baselines[0].Requirements))
	for i, r := range result.Baselines[0].Requirements {
		ids[i] = r.ID
	}
	assert.Contains(t, ids, "org.apache.maven.surefire.test.FailingTest.defaultTestValueIs_Value")
	assert.Contains(t, ids, "org.apache.maven.surefire.test.FailingTest.setTestAndRetrieveValue")
}

func TestRequirementTitle(t *testing.T) {
	result, err := ConvertJUnitToHDF(loadFixture(t, "surefire-failing.xml"), converterVersion)
	require.NoError(t, err)

	req := shared.MustFindRequirement(t, result.Baselines[0].Requirements, "org.apache.maven.surefire.test.FailingTest.defaultTestValueIs_Value")
	require.NotNil(t, req.Title)
	assert.Equal(t, "defaultTestValueIs_Value", *req.Title)
}

func TestRequirementImpact(t *testing.T) {
	result, err := ConvertJUnitToHDF(loadFixture(t, "surefire-failing.xml"), converterVersion)
	require.NoError(t, err)

	for _, req := range result.Baselines[0].Requirements {
		assert.Equal(t, 0.5, req.Impact, "requirement %s should have impact 0.5", req.ID)
	}
}

// --- Status mapping ---

func TestStatusMapping_Failed(t *testing.T) {
	result, err := ConvertJUnitToHDF(loadFixture(t, "surefire-failing.xml"), converterVersion)
	require.NoError(t, err)

	for _, req := range result.Baselines[0].Requirements {
		assert.Equal(t, hdf.Failed, req.Results[0].Status, "requirement %s should be failed", req.ID)
	}
}

func TestStatusMapping_Error(t *testing.T) {
	result, err := ConvertJUnitToHDF(loadFixture(t, "surefire-error.xml"), converterVersion)
	require.NoError(t, err)

	req := shared.MustFindRequirement(t, result.Baselines[0].Requirements, "surefire.MyTest.test")
	assert.Equal(t, hdf.Error, req.Results[0].Status)
}

func TestStatusMapping_Passed(t *testing.T) {
	// surefire-flaky.xml has 2 test cases that ultimately passed
	result, err := ConvertJUnitToHDF(loadFixture(t, "surefire-flaky.xml"), converterVersion)
	require.NoError(t, err)

	for _, req := range result.Baselines[0].Requirements {
		assert.Equal(t, hdf.Passed, req.Results[0].Status, "requirement %s should be passed", req.ID)
	}
}

// --- Result details ---

func TestFailureMessage(t *testing.T) {
	result, err := ConvertJUnitToHDF(loadFixture(t, "surefire-failing.xml"), converterVersion)
	require.NoError(t, err)

	req := shared.MustFindRequirement(t, result.Baselines[0].Requirements, "org.apache.maven.surefire.test.FailingTest.defaultTestValueIs_Value")
	require.NotNil(t, req.Results[0].Message)
	assert.Contains(t, *req.Results[0].Message, "wrong")
	assert.Contains(t, *req.Results[0].Message, "value")
}

func TestErrorMessage(t *testing.T) {
	result, err := ConvertJUnitToHDF(loadFixture(t, "surefire-error.xml"), converterVersion)
	require.NoError(t, err)

	req := shared.MustFindRequirement(t, result.Baselines[0].Requirements, "surefire.MyTest.test")
	require.NotNil(t, req.Results[0].Message)
	assert.Contains(t, *req.Results[0].Message, "RuntimeException")
	assert.Contains(t, *req.Results[0].Message, "this is different message")
}

func TestCodeDesc(t *testing.T) {
	result, err := ConvertJUnitToHDF(loadFixture(t, "surefire-failing.xml"), converterVersion)
	require.NoError(t, err)

	req := shared.MustFindRequirement(t, result.Baselines[0].Requirements, "org.apache.maven.surefire.test.FailingTest.defaultTestValueIs_Value")
	assert.Contains(t, req.Results[0].CodeDesc, "org.apache.maven.surefire.test.FailingTest")
	assert.Contains(t, req.Results[0].CodeDesc, "defaultTestValueIs_Value")
}

func TestRunTime(t *testing.T) {
	result, err := ConvertJUnitToHDF(loadFixture(t, "surefire-failing.xml"), converterVersion)
	require.NoError(t, err)

	req := shared.MustFindRequirement(t, result.Baselines[0].Requirements, "org.apache.maven.surefire.test.FailingTest.defaultTestValueIs_Value")
	require.NotNil(t, req.Results[0].RunTime)
	assert.InDelta(t, 0.013, *req.Results[0].RunTime, 0.001)
}

func TestErrorStackTrace(t *testing.T) {
	result, err := ConvertJUnitToHDF(loadFixture(t, "surefire-error.xml"), converterVersion)
	require.NoError(t, err)

	req := shared.MustFindRequirement(t, result.Baselines[0].Requirements, "surefire.MyTest.test")
	require.NotNil(t, req.Results[0].Message)
	assert.Contains(t, *req.Results[0].Message, "IndexOutOfBoundsException")
	assert.Contains(t, *req.Results[0].Message, "MyTest.rethrownDelegate")
}

// --- NIST tags ---

func TestNISTTags(t *testing.T) {
	result, err := ConvertJUnitToHDF(loadFixture(t, "surefire-failing.xml"), converterVersion)
	require.NoError(t, err)

	for _, req := range result.Baselines[0].Requirements {
		nist, ok := req.Tags["nist"]
		require.True(t, ok, "requirement %s should have nist tag", req.ID)
		nistSlice, ok := nist.([]string)
		require.True(t, ok)
		assert.Contains(t, nistSlice, "SA-11")
	}
}

// --- Flaky test handling ---

func TestFlakyTestsPassedStatus(t *testing.T) {
	// flakyFailure and flakyError are Surefire extensions for tests that
	// failed on reruns but ultimately passed — they should map to passed.
	result, err := ConvertJUnitToHDF(loadFixture(t, "surefire-flaky.xml"), converterVersion)
	require.NoError(t, err)

	assert.Len(t, result.Baselines[0].Requirements, 2)
	req := shared.MustFindRequirement(t, result.Baselines[0].Requirements, "org.acme.FlakyTest.testFlaky")
	assert.Equal(t, hdf.Passed, req.Results[0].Status)
}

// --- Description ---

func TestDescription(t *testing.T) {
	result, err := ConvertJUnitToHDF(loadFixture(t, "surefire-error.xml"), converterVersion)
	require.NoError(t, err)

	req := shared.MustFindRequirement(t, result.Baselines[0].Requirements, "surefire.MyTest.test")

	var defaultDesc *hdf.Description
	for i := range req.Descriptions {
		if req.Descriptions[i].Label == "default" {
			defaultDesc = &req.Descriptions[i]
			break
		}
	}
	require.NotNil(t, defaultDesc)
	assert.Contains(t, defaultDesc.Data, "test")
	assert.Contains(t, defaultDesc.Data, "surefire.MyTest")
}

// --- system-out / system-err descriptions ---

func findDescription(descs []hdf.Description, label string) *hdf.Description {
	for i := range descs {
		if descs[i].Label == label {
			return &descs[i]
		}
	}
	return nil
}

// testFlaky's captured stdout/stderr live inside Surefire flakyFailure/flakyError
// retry elements in surefire-flaky.xml. They should surface as system-out /
// system-err descriptions on the requirement.
func TestSystemOutErrDescriptions_Flaky(t *testing.T) {
	result, err := ConvertJUnitToHDF(loadFixture(t, "surefire-flaky.xml"), converterVersion)
	require.NoError(t, err)

	req := shared.MustFindRequirement(t, result.Baselines[0].Requirements, "org.acme.FlakyTest.testFlaky")

	out := findDescription(req.Descriptions, "system-out")
	require.NotNil(t, out, "testFlaky should carry a system-out description")
	assert.Contains(t, out.Data, "code-with-quarkus 1.0.0-SNAPSHOT on JVM")
	assert.Contains(t, out.Data, "Installed features: [cdi, resteasy-reactive")

	errDesc := findDescription(req.Descriptions, "system-err")
	require.NotNil(t, errDesc, "testFlaky should carry a system-err description")
	assert.Equal(t, "Test system.err", errDesc.Data)
}

// testStable has no captured output — neither description should be emitted.
func TestSystemOutErrDescriptions_Absent(t *testing.T) {
	result, err := ConvertJUnitToHDF(loadFixture(t, "surefire-flaky.xml"), converterVersion)
	require.NoError(t, err)

	req := shared.MustFindRequirement(t, result.Baselines[0].Requirements, "org.acme.FlakyTest.testStable")
	assert.Nil(t, findDescription(req.Descriptions, "system-out"))
	assert.Nil(t, findDescription(req.Descriptions, "system-err"))
}

func TestCollectSystemStreams_DirectChildren(t *testing.T) {
	tc := junitTestCase{SystemOut: "  hello out\n", SystemErr: "\nhello err "}
	out, errs := collectSystemStreams(tc)
	assert.Equal(t, "hello out", out)
	assert.Equal(t, "hello err", errs)
}

func TestCollectSystemStreams_Empty(t *testing.T) {
	out, errs := collectSystemStreams(junitTestCase{Name: "x"})
	assert.Empty(t, out)
	assert.Empty(t, errs)
}

func TestCollectSystemStreams_JoinsRetriesInOrder(t *testing.T) {
	tc := junitTestCase{
		FlakyFailures: []junitFlaky{{SystemOut: "a"}, {SystemOut: "  b  "}},
		FlakyErrors:   []junitFlaky{{SystemOut: "c", SystemErr: "e"}},
	}
	out, errs := collectSystemStreams(tc)
	assert.Equal(t, "a\nb\nc", out)
	assert.Equal(t, "e", errs)
}

// --- Testsuites root with mixed statuses (schema-validated against Windyroad XSD) ---

func TestConvertJUnitToHDF_TestsuitesMixed(t *testing.T) {
	result, err := ConvertJUnitToHDF(loadFixture(t, "testsuites-mixed.xml"), converterVersion)
	require.NoError(t, err)
	require.NotNil(t, result)

	// testsuites has no name attr — should default
	assert.Equal(t, "JUnit Test Results", result.Baselines[0].Name)
}

func TestTestsuitesMixed_RequirementCount(t *testing.T) {
	result, err := ConvertJUnitToHDF(loadFixture(t, "testsuites-mixed.xml"), converterVersion)
	require.NoError(t, err)

	// 2 suites: MathTest (3 tests) + StringTest (2 tests) = 5 requirements
	assert.Len(t, result.Baselines[0].Requirements, 5)
}

func TestTestsuitesMixed_SkippedStatus(t *testing.T) {
	result, err := ConvertJUnitToHDF(loadFixture(t, "testsuites-mixed.xml"), converterVersion)
	require.NoError(t, err)

	req := shared.MustFindRequirement(t, result.Baselines[0].Requirements, "com.example.math.MathTest.testSquareRoot")
	assert.Equal(t, hdf.NotReviewed, req.Results[0].Status)
	require.NotNil(t, req.Results[0].Message)
	assert.Contains(t, *req.Results[0].Message, "Requires math library upgrade")
}

func TestTestsuitesMixed_PassedStatus(t *testing.T) {
	result, err := ConvertJUnitToHDF(loadFixture(t, "testsuites-mixed.xml"), converterVersion)
	require.NoError(t, err)

	req := shared.MustFindRequirement(t, result.Baselines[0].Requirements, "com.example.math.MathTest.testAddition")
	assert.Equal(t, hdf.Passed, req.Results[0].Status)
}

func TestTestsuitesMixed_FailedStatus(t *testing.T) {
	result, err := ConvertJUnitToHDF(loadFixture(t, "testsuites-mixed.xml"), converterVersion)
	require.NoError(t, err)

	req := shared.MustFindRequirement(t, result.Baselines[0].Requirements, "com.example.math.MathTest.testDivisionByZero")
	assert.Equal(t, hdf.Failed, req.Results[0].Status)
	require.NotNil(t, req.Results[0].Message)
	assert.Contains(t, *req.Results[0].Message, "Expected exception was not thrown")
}

func TestTestsuitesMixed_ErrorStatus(t *testing.T) {
	result, err := ConvertJUnitToHDF(loadFixture(t, "testsuites-mixed.xml"), converterVersion)
	require.NoError(t, err)

	req := shared.MustFindRequirement(t, result.Baselines[0].Requirements, "com.example.string.StringTest.testParseInt")
	assert.Equal(t, hdf.Error, req.Results[0].Status)
	require.NotNil(t, req.Results[0].Message)
	assert.Contains(t, *req.Results[0].Message, "NullPointerException")
}

func TestTestsuitesMixed_Timestamp(t *testing.T) {
	result, err := ConvertJUnitToHDF(loadFixture(t, "testsuites-mixed.xml"), converterVersion)
	require.NoError(t, err)

	// First suite has timestamp="2024-11-15T10:30:00" — should be parsed into startTime
	req := shared.MustFindRequirement(t, result.Baselines[0].Requirements, "com.example.math.MathTest.testAddition")
	assert.False(t, req.Results[0].StartTime.IsZero(), "startTime should be set from suite timestamp")
}

// --- Scan-target components ---

func findComponent(components []hdf.Component, t2 hdf.TargetType) *hdf.Component {
	for i := range components {
		if components[i].Type == t2 {
			return &components[i]
		}
	}
	return nil
}

// testsuites-mixed.xml carries hostname="ci-runner-01" on both suites; that
// machine identity surfaces as a single deduped host component alongside the
// application component.
func TestComponents_HostFromHostname(t *testing.T) {
	result, err := ConvertJUnitToHDF(loadFixture(t, "testsuites-mixed.xml"), converterVersion)
	require.NoError(t, err)

	host := findComponent(result.Components, hdf.Host)
	require.NotNil(t, host, "a host component should be emitted from testsuite @hostname")
	assert.Equal(t, hdf.Host, host.Type)
	assert.Equal(t, "ci-runner-01", host.Name)
	require.NotNil(t, host.Hostname)
	assert.Equal(t, "ci-runner-01", *host.Hostname)

	// Two suites share one hostname -> exactly one host component (deduped).
	var hostCount int
	for _, c := range result.Components {
		if c.Type == hdf.Host {
			hostCount++
		}
	}
	assert.Equal(t, 1, hostCount, "duplicate hostnames should be deduped")

	// The application component is still present.
	assert.NotNil(t, findComponent(result.Components, hdf.Application))
}

// Fixtures without any testsuite @hostname emit no host component.
func TestComponents_NoHostnameAbsent(t *testing.T) {
	result, err := ConvertJUnitToHDF(loadFixture(t, "surefire-failing.xml"), converterVersion)
	require.NoError(t, err)
	assert.Nil(t, findComponent(result.Components, hdf.Host),
		"no host component when no testsuite carries a hostname")
}

func TestHostComponents_DistinctAndDeduped(t *testing.T) {
	suites := []junitTestSuite{
		{Hostname: "alpha"},
		{Hostname: ""},
		{Hostname: "beta"},
		{Hostname: "  alpha  "},
		{Hostname: "beta"},
	}
	hosts := hostComponents(suites)
	require.Len(t, hosts, 2)
	assert.Equal(t, "alpha", hosts[0].Name)
	assert.Equal(t, "beta", hosts[1].Name)
	assert.Equal(t, hdf.Host, hosts[0].Type)
	require.NotNil(t, hosts[0].Hostname)
	assert.Equal(t, "alpha", *hosts[0].Hostname)
}

// --- JSON serialization round-trip ---

func TestJSONRoundTrip(t *testing.T) {
	result, err := ConvertJUnitToHDF(loadFixture(t, "surefire-failing.xml"), converterVersion)
	require.NoError(t, err)

	data, err := json.MarshalIndent(result, "", "  ")
	require.NoError(t, err)

	var roundTrip hdf.HDFResults
	err = json.Unmarshal(data, &roundTrip)
	require.NoError(t, err)

	require.NotNil(t, roundTrip.Generator)
	assert.Equal(t, result.Generator.Name, roundTrip.Generator.Name)
	assert.Len(t, roundTrip.Baselines, 1)
	assert.Len(t, roundTrip.Baselines[0].Requirements, 2)
}

// --- Helper function tests ---

func TestBuildID_WithClassname(t *testing.T) {
	tc := junitTestCase{ClassName: "com.example.Test", Name: "testFoo"}
	assert.Equal(t, "com.example.Test.testFoo", buildID(tc))
}

func TestBuildID_WithoutClassname(t *testing.T) {
	tc := junitTestCase{Name: "testFoo"}
	assert.Equal(t, "testFoo", buildID(tc))
}

func TestResolveStatus_Passed(t *testing.T) {
	tc := junitTestCase{Name: "test"}
	status, msg := resolveStatus(tc)
	assert.Equal(t, hdf.Passed, status)
	assert.Nil(t, msg)
}

func TestResolveStatus_Failed(t *testing.T) {
	tc := junitTestCase{Name: "test", Failure: &junitFailure{Message: "bad", Type: "AssertionError"}}
	status, msg := resolveStatus(tc)
	assert.Equal(t, hdf.Failed, status)
	require.NotNil(t, msg)
	assert.Contains(t, *msg, "AssertionError")
	assert.Contains(t, *msg, "bad")
}

func TestResolveStatus_Error(t *testing.T) {
	tc := junitTestCase{Name: "test", Error: &junitError{Message: "boom", Type: "RuntimeException"}}
	status, msg := resolveStatus(tc)
	assert.Equal(t, hdf.Error, status)
	require.NotNil(t, msg)
	assert.Contains(t, *msg, "RuntimeException")
}

func TestResolveStatus_SkippedWithMessage(t *testing.T) {
	tc := junitTestCase{Name: "test", Skipped: &junitSkipped{Message: "not ready"}}
	status, msg := resolveStatus(tc)
	assert.Equal(t, hdf.NotReviewed, status)
	require.NotNil(t, msg)
	assert.Contains(t, *msg, "not ready")
}

func TestResolveStatus_SkippedNoMessage(t *testing.T) {
	tc := junitTestCase{Name: "test", Skipped: &junitSkipped{}}
	status, msg := resolveStatus(tc)
	assert.Equal(t, hdf.NotReviewed, status)
	require.NotNil(t, msg)
	assert.Equal(t, "Skipped", *msg)
}

func TestBuildFailureMessage_Full(t *testing.T) {
	msg := buildFailureMessage("bad value", "AssertionError", "at Test.java:42")
	assert.Equal(t, "AssertionError: bad value\nat Test.java:42", msg)
}

func TestBuildFailureMessage_NoType(t *testing.T) {
	msg := buildFailureMessage("bad value", "", "")
	assert.Equal(t, "bad value", msg)
}

func TestBuildFailureMessage_NoBody(t *testing.T) {
	msg := buildFailureMessage("bad value", "AssertionError", "")
	assert.Equal(t, "AssertionError: bad value", msg)
}

func TestBuildCodeDesc_WithClassname(t *testing.T) {
	tc := junitTestCase{ClassName: "com.example.Test", Name: "testFoo"}
	assert.Equal(t, "com.example.Test :: testFoo", buildCodeDesc(tc))
}

func TestBuildCodeDesc_WithoutClassname(t *testing.T) {
	tc := junitTestCase{Name: "testFoo"}
	assert.Equal(t, "testFoo", buildCodeDesc(tc))
}

func TestConvertJUnitToHDF_EntityExpansion(t *testing.T) {
	input := []byte(`<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe "test">]><foo/>`)
	_, err := ConvertJUnitToHDF(input, converterVersion)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "entity declarations")
}

func TestSnapshots(t *testing.T) {
	// JUnit fixtures carry no suite timestamp; conversion-time fallback.
	shared.RunSnapshotTests(t, "junit-to-hdf", func(input []byte) (interface{}, error) {
		return ConvertJUnitToHDF(input, "1.0.0")
	}, "*")
}

func TestConvertJUnitToHDF_EmptyFindings(t *testing.T) {
	result, err := ConvertJUnitToHDF(loadFixture(t, "empty.xml"), converterVersion)
	require.NoError(t, err)
	require.Len(t, result.Baselines, 1)
	require.Len(t, result.Baselines[0].Requirements, 1)
	req := result.Baselines[0].Requirements[0]
	assert.Equal(t, "junit-no-findings", req.ID)
	require.Len(t, req.Results, 1)
	assert.Equal(t, hdf.Passed, req.Results[0].Status)
	assert.Contains(t, req.Results[0].CodeDesc, "JUnit")
	assert.Contains(t, req.Results[0].CodeDesc, "EmptySuite")
	assert.Contains(t, req.Results[0].CodeDesc, "zero findings")
}

func TestConvertJUnitToHDF_ControlType(t *testing.T) {
	result, err := ConvertJUnitToHDF(loadFixture(t, "surefire-failing.xml"), converterVersion)
	require.NoError(t, err)

	reqs := result.Baselines[0].Requirements
	require.NotEmpty(t, reqs)

	var sawDerivation bool
	for _, req := range reqs {
		if req.ControlType != nil {
			sawDerivation = true
			switch *req.ControlType {
			case hdf.Management, hdf.Operational, hdf.Technical, hdf.Policy, hdf.Procedure:
			default:
				t.Errorf("requirement %q has unrecognized controlType %q", req.ID, *req.ControlType)
			}
		}
	}
	assert.True(t, sawDerivation, "at least one requirement should derive controlType")
}

func TestConvertJUnitToHDF_VerificationMethod(t *testing.T) {
	result, err := ConvertJUnitToHDF(loadFixture(t, "surefire-failing.xml"), converterVersion)
	require.NoError(t, err)
	require.NotEmpty(t, result.Baselines)
	reqs := result.Baselines[0].Requirements
	require.NotEmpty(t, reqs)
	for _, req := range reqs {
		require.NotNil(t, req.VerificationMethod, "requirement %q missing verificationMethod", req.ID)
		assert.Equal(t, hdf.VerificationMethodEnumAutomated, *req.VerificationMethod,
			"requirement %q: JUnit reports come from automated CI test runs", req.ID)
	}
}

// Ground-truth anchor: JUnit emits one requirement per <testcase> element across
// every <testsuite>. The count is derived by a generic XML token walk of the raw
// input (shared/go/anchor.go), independent of the converter's structs, so a
// silent under-extraction fails even where TS/Go golden parity would agree.
func TestConvertJUnitToHDF_TestcaseAnchor(t *testing.T) {
	input := loadFixture(t, "testsuites-mixed.xml")
	result, err := ConvertJUnitToHDF(input, converterVersion)
	require.NoError(t, err)
	shared.AssertRequirementCount(t, result, shared.CountXMLElements(t, input, "testcase"),
		"testsuites-mixed.xml: one requirement per <testcase>")
}
