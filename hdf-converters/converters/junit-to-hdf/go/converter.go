package junit

import (
	"encoding/xml"
	"fmt"
	"strconv"
	"time"

	shared "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go"
	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	hdfutil "github.com/mitre/hdf-libs/hdf-utilities/go/v3"
)

// JUnit XML struct types

type junitTestSuites struct {
	XMLName    xml.Name         `xml:"testsuites"`
	Name       string           `xml:"name,attr"`
	TestSuites []junitTestSuite `xml:"testsuite"`
}

type junitTestSuite struct {
	XMLName   xml.Name        `xml:"testsuite"`
	Name      string          `xml:"name,attr"`
	Tests     int             `xml:"tests,attr"`
	Failures  int             `xml:"failures,attr"`
	Errors    int             `xml:"errors,attr"`
	Skipped   int             `xml:"skipped,attr"`
	Time      string          `xml:"time,attr"`
	Timestamp string          `xml:"timestamp,attr"`
	Hostname  string          `xml:"hostname,attr"`
	TestCases []junitTestCase `xml:"testcase"`
}

type junitTestCase struct {
	ClassName string        `xml:"classname,attr"`
	Name      string        `xml:"name,attr"`
	Time      string        `xml:"time,attr"`
	Failure   *junitFailure `xml:"failure"`
	Error     *junitError   `xml:"error"`
	Skipped   *junitSkipped `xml:"skipped"`
}

type junitFailure struct {
	Message string `xml:"message,attr"`
	Type    string `xml:"type,attr"`
	Body    string `xml:",chardata"`
}

type junitError struct {
	Message string `xml:"message,attr"`
	Type    string `xml:"type,attr"`
	Body    string `xml:",chardata"`
}

type junitSkipped struct {
	Message string `xml:"message,attr"`
}

// defaultNIST is the NIST 800-53 tag for test results.
// SA-11: Developer Security Testing and Evaluation.
var defaultNIST = []string{"SA-11"}

// ConvertJUnitToHDF converts JUnit XML test results to HDF format.
func ConvertJUnitToHDF(input []byte, converterVersion string) (*hdf.HDFResults, error) {
	if len(input) == 0 {
		return nil, fmt.Errorf("empty input")
	}
	if err := shared.ValidateXMLInput(input, 0); err != nil {
		return nil, fmt.Errorf("junit: %w", err)
	}

	suites, name, err := parseJUnitXML(input)
	if err != nil {
		return nil, err
	}

	requirements := buildRequirements(suites)

	now := time.Now().UTC()

	if len(requirements) == 0 {
		requirements = []hdf.EvaluatedRequirement{
			shared.BuildNoFindingsRequirement(
				"junit-no-findings",
				fmt.Sprintf("JUnit scanned %s and reported zero findings.", noFindingsTarget(name, suites)),
				now,
			),
		}
	}

	baseline := hdf.EvaluatedBaseline{
		Name:            name,
		Requirements:    requirements,
		ResultsChecksum: shared.InputChecksum(input),
	}

	target := hdf.Component{
		Name: name,
		Type: hdf.Application,
	}

	return shared.BuildHDFResults(shared.HDFResultsOptions{
		GeneratorName:    "junit-to-hdf",
		ConverterVersion: converterVersion,
		ToolName:         "JUnit XML",
		ToolFormat:       "XML",
		Baselines:        []hdf.EvaluatedBaseline{baseline},
		Components:       []hdf.Component{target},
		Timestamp:        &now,
	}), nil
}

// parseJUnitXML parses JUnit XML that may have <testsuites> or <testsuite> as root.
func parseJUnitXML(input []byte) ([]junitTestSuite, string, error) {
	var suites junitTestSuites
	if err := xml.Unmarshal(input, &suites); err == nil && suites.XMLName.Local == "testsuites" {
		name := suites.Name
		if name == "" {
			name = "JUnit Test Results"
		}
		return suites.TestSuites, name, nil
	}

	var suite junitTestSuite
	if err := xml.Unmarshal(input, &suite); err == nil && suite.XMLName.Local == "testsuite" {
		name := suite.Name
		if name == "" {
			name = "JUnit Test Results"
		}
		return []junitTestSuite{suite}, name, nil
	}

	return nil, "", fmt.Errorf("not a JUnit XML document: expected <testsuites> or <testsuite> root element")
}

func noFindingsTarget(baselineName string, suites []junitTestSuite) string {
	if baselineName != "" && baselineName != "JUnit Test Results" {
		return baselineName
	}
	for _, s := range suites {
		if s.Name != "" {
			return s.Name
		}
	}
	return "JUnit test suite"
}

// buildRequirements creates HDF requirements from all test cases across all suites.
func buildRequirements(suites []junitTestSuite) []hdf.EvaluatedRequirement {
	limitedSuites := shared.LimitSliceWithWarning(suites, 0, "test suite")
	var requirements []hdf.EvaluatedRequirement

	for _, suite := range limitedSuites {
		limitedTestCases := shared.LimitSliceWithWarning(suite.TestCases, 0, "test case")
		for _, tc := range limitedTestCases {
			requirements = append(requirements, testCaseToRequirement(tc, suite.Timestamp))
		}
	}

	return requirements
}

// testCaseToRequirement converts a single JUnit test case to an HDF requirement.
func testCaseToRequirement(tc junitTestCase, suiteTimestamp string) hdf.EvaluatedRequirement {
	id := buildID(tc)
	status, message := resolveStatus(tc)
	codeDesc := buildCodeDesc(tc)

	result := hdf.RequirementResult{
		Status:   status,
		CodeDesc: codeDesc,
		Message:  message,
	}

	if tc.Time != "" {
		if f, err := strconv.ParseFloat(tc.Time, 64); err == nil {
			result.RunTime = &f
		}
	}

	if suiteTimestamp != "" {
		if t := hdfutil.ParseTimestamp(suiteTimestamp); !t.IsZero() {
			result.StartTime = t
		}
	}

	tags := map[string]interface{}{
		"nist": defaultNIST,
	}

	descriptions := []hdf.Description{
		{
			Label: "default",
			Data:  fmt.Sprintf("JUnit test: %s in %s", tc.Name, tc.ClassName),
		},
	}

	return hdf.EvaluatedRequirement{
		ID:                 id,
		Title:              hdfutil.Ptr(tc.Name),
		Descriptions:       descriptions,
		Impact:             0.5,
		Tags:               tags,
		Results:            []hdf.RequirementResult{result},
		ControlType:        shared.DeriveControlTypeFromTags(defaultNIST),
		VerificationMethod: hdfutil.Ptr(hdf.VerificationMethodEnumAutomated),
	}
}

// buildID constructs a unique requirement ID from classname and test name.
func buildID(tc junitTestCase) string {
	if tc.ClassName != "" {
		return tc.ClassName + "." + tc.Name
	}
	return tc.Name
}

// resolveStatus determines HDF status and message from test case elements.
func resolveStatus(tc junitTestCase) (hdf.ResultStatus, *string) {
	if tc.Failure != nil {
		msg := buildFailureMessage(tc.Failure.Message, tc.Failure.Type, tc.Failure.Body)
		return hdf.Failed, &msg
	}
	if tc.Error != nil {
		msg := buildFailureMessage(tc.Error.Message, tc.Error.Type, tc.Error.Body)
		return hdf.Error, &msg
	}
	if tc.Skipped != nil {
		if tc.Skipped.Message != "" {
			msg := fmt.Sprintf("Skipped: %s", tc.Skipped.Message)
			return hdf.NotReviewed, &msg
		}
		msg := "Skipped"
		return hdf.NotReviewed, &msg
	}
	return hdf.Passed, nil
}

// buildFailureMessage constructs a message from failure/error attributes and body.
func buildFailureMessage(message, typeName, body string) string {
	result := ""
	if typeName != "" {
		result = typeName + ": "
	}
	result += message
	if body != "" {
		result += "\n" + body
	}
	return result
}

// buildCodeDesc creates a code description for the test case.
func buildCodeDesc(tc junitTestCase) string {
	if tc.ClassName != "" {
		return fmt.Sprintf("%s :: %s", tc.ClassName, tc.Name)
	}
	return tc.Name
}
