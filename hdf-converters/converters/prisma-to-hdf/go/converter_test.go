package prisma

import (
	"os"
	"path/filepath"
	"sort"
	"testing"

	shared "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go"
	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	hdfutil "github.com/mitre/hdf-libs/hdf-utilities/go/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testVersion = "test-0.1.0"

func loadFixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "fixtures", name))
	require.NoError(t, err, "failed to read fixture %s", name)
	return data
}

func findRequirement(reqs []hdf.EvaluatedRequirement, id string) *hdf.EvaluatedRequirement {
	for i := range reqs {
		if reqs[i].ID == id {
			return &reqs[i]
		}
	}
	return nil
}

func findBaseline(baselines []hdf.EvaluatedBaseline, titleSubstring string) *hdf.EvaluatedBaseline {
	for i := range baselines {
		if baselines[i].Title != nil && contains(*baselines[i].Title, titleSubstring) {
			return &baselines[i]
		}
	}
	return nil
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		(len(s) > 0 && len(substr) > 0 && searchString(s, substr)))
}

func searchString(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// ---- Input validation ----

func TestConvertPrisma_EmptyInput(t *testing.T) {
	_, err := ConvertPrismaToHDF([]byte(""), testVersion)
	assert.Error(t, err)
}

func TestConvertPrisma_InvalidCSV(t *testing.T) {
	_, err := ConvertPrismaToHDF([]byte("not,a,valid\ncsv,with,wrong,columns"), testVersion)
	assert.Error(t, err)
}

// ---- Minimal fixture: multi-host grouping ----

func TestConvertPrisma_Minimal_HostGrouping(t *testing.T) {
	input := loadFixture(t, "input/minimal.csv")
	result, err := ConvertPrismaToHDF(input, testVersion)
	require.NoError(t, err)

	// minimal.csv has 2 hosts: host-1.example.com and host-2.example.com
	assert.Len(t, result.Baselines, 2)
}

func TestConvertPrisma_Minimal_BaselineName(t *testing.T) {
	input := loadFixture(t, "input/minimal.csv")
	result, err := ConvertPrismaToHDF(input, testVersion)
	require.NoError(t, err)

	for _, baseline := range result.Baselines {
		assert.Equal(t, "Prisma Cloud Scan", baseline.Name)
	}
}

func TestConvertPrisma_Minimal_BaselineTitle(t *testing.T) {
	input := loadFixture(t, "input/minimal.csv")
	result, err := ConvertPrismaToHDF(input, testVersion)
	require.NoError(t, err)

	titles := make([]string, len(result.Baselines))
	for i, b := range result.Baselines {
		require.NotNil(t, b.Title)
		titles[i] = *b.Title
	}
	sort.Strings(titles)
	assert.Equal(t, "Prisma Cloud Scan (host-1.example.com)", titles[0])
	assert.Equal(t, "Prisma Cloud Scan (host-2.example.com)", titles[1])
}

func TestConvertPrisma_Minimal_Checksum(t *testing.T) {
	input := loadFixture(t, "input/minimal.csv")
	result, err := ConvertPrismaToHDF(input, testVersion)
	require.NoError(t, err)

	for _, baseline := range result.Baselines {
		require.NotNil(t, baseline.ResultsChecksum)
		assert.Equal(t, hdf.Sha256, baseline.ResultsChecksum.Algorithm)
		assert.NotEmpty(t, baseline.ResultsChecksum.Value)
	}
}

// ---- Generator ----

func TestConvertPrisma_Generator(t *testing.T) {
	input := loadFixture(t, "input/minimal.csv")
	result, err := ConvertPrismaToHDF(input, testVersion)
	require.NoError(t, err)

	require.NotNil(t, result.Generator)
	assert.Equal(t, "prisma-to-hdf", result.Generator.Name)
	assert.Equal(t, testVersion, result.Generator.Version)
}

// ---- Tool ----

func TestConvertPrisma_Tool(t *testing.T) {
	input := loadFixture(t, "input/minimal.csv")
	result, err := ConvertPrismaToHDF(input, testVersion)
	require.NoError(t, err)

	require.NotNil(t, result.Tool)
	require.NotNil(t, result.Tool.Name)
	assert.Equal(t, "Prisma Cloud", *result.Tool.Name)
	require.NotNil(t, result.Tool.Format)
	assert.Equal(t, "CSV", *result.Tool.Format)
}

// ---- Targets ----

func TestConvertPrisma_Targets(t *testing.T) {
	input := loadFixture(t, "input/minimal.csv")
	result, err := ConvertPrismaToHDF(input, testVersion)
	require.NoError(t, err)

	require.Len(t, result.Components, 2)
	names := []string{result.Components[0].Name, result.Components[1].Name}
	sort.Strings(names)
	assert.Equal(t, "host-1.example.com", names[0])
	assert.Equal(t, "host-2.example.com", names[1])
	for _, target := range result.Components {
		assert.Equal(t, hdf.Host, target.Type)
	}
}

// ---- Requirement IDs ----

func TestConvertPrisma_RequirementIDs(t *testing.T) {
	input := loadFixture(t, "input/minimal.csv")
	result, err := ConvertPrismaToHDF(input, testVersion)
	require.NoError(t, err)

	// host-1: 3 records (60522 linux no CVE, 46-CVE-2021-44142, 46-CVE-2016-2226)
	host1 := findBaseline(result.Baselines, "host-1.example.com")
	require.NotNil(t, host1)
	assert.Len(t, host1.Requirements, 3)

	// Compliance finding (no CVE): ID = ComplianceID-Distro-Severity
	req := findRequirement(host1.Requirements, "60522-redhat-RHEL7-high")
	require.NotNil(t, req, "expected compliance requirement with ID 60522-redhat-RHEL7-high")

	// CVE finding: ID = ComplianceID-CVEID
	req = findRequirement(host1.Requirements, "46-CVE-2021-44142")
	require.NotNil(t, req, "expected CVE requirement with ID 46-CVE-2021-44142")
}

// ---- Severity → Impact mapping ----

func TestConvertPrisma_SeverityMapping(t *testing.T) {
	tests := []struct {
		severity string
		expected float64
	}{
		{"critical", 0.9},
		{"high", 0.7},
		{"important", 0.9},
		{"moderate", 0.5},
		{"medium", 0.5},
		{"low", 0.3},
		{"", 0.5},
		{"unknown", 0.5},
	}
	for _, tc := range tests {
		t.Run(tc.severity, func(t *testing.T) {
			assert.InDelta(t, tc.expected, getImpact(tc.severity), 0.001)
		})
	}
}

func TestConvertPrisma_ImpactValues(t *testing.T) {
	input := loadFixture(t, "input/minimal.csv")
	result, err := ConvertPrismaToHDF(input, testVersion)
	require.NoError(t, err)

	host1 := findBaseline(result.Baselines, "host-1.example.com")
	require.NotNil(t, host1)

	// critical → 0.9
	req := findRequirement(host1.Requirements, "46-CVE-2021-44142")
	require.NotNil(t, req)
	assert.InDelta(t, 0.9, req.Impact, 0.001)

	// low → 0.3
	req = findRequirement(host1.Requirements, "46-CVE-2016-2226")
	require.NotNil(t, req)
	assert.InDelta(t, 0.3, req.Impact, 0.001)

	// high → 0.7
	req = findRequirement(host1.Requirements, "60522-redhat-RHEL7-high")
	require.NotNil(t, req)
	assert.InDelta(t, 0.7, req.Impact, 0.001)
}

// ---- NIST tags ----

func TestConvertPrisma_NistTags(t *testing.T) {
	input := loadFixture(t, "input/minimal.csv")
	result, err := ConvertPrismaToHDF(input, testVersion)
	require.NoError(t, err)

	host1 := findBaseline(result.Baselines, "host-1.example.com")
	require.NotNil(t, host1)

	// CVE finding should get remediation NIST tags (SI-2, RA-5)
	req := findRequirement(host1.Requirements, "46-CVE-2021-44142")
	require.NotNil(t, req)
	nist := hdfutil.SafeStringSlice(req.Tags["nist"])
	require.NotNil(t, nist)
	assert.Contains(t, nist, "SI-2")
	assert.Contains(t, nist, "RA-5")

	// Non-CVE compliance finding should get static analysis NIST tags (SA-11, RA-5)
	req = findRequirement(host1.Requirements, "60522-redhat-RHEL7-high")
	require.NotNil(t, req)
	nist = hdfutil.SafeStringSlice(req.Tags["nist"])
	require.NotNil(t, nist)
	assert.Contains(t, nist, "SA-11")
	assert.Contains(t, nist, "RA-5")
}

// ---- All results are Failed ----

func TestConvertPrisma_AllResultsFailed(t *testing.T) {
	input := loadFixture(t, "input/minimal.csv")
	result, err := ConvertPrismaToHDF(input, testVersion)
	require.NoError(t, err)

	for _, baseline := range result.Baselines {
		for _, req := range baseline.Requirements {
			for _, r := range req.Results {
				assert.Equal(t, hdf.Failed, r.Status,
					"all Prisma findings should be Failed (req %s)", req.ID)
			}
		}
	}
}

// ---- Code description ----

func TestConvertPrisma_CodeDesc(t *testing.T) {
	input := loadFixture(t, "input/minimal.csv")
	result, err := ConvertPrismaToHDF(input, testVersion)
	require.NoError(t, err)

	host1 := findBaseline(result.Baselines, "host-1.example.com")
	require.NotNil(t, host1)

	// image type with packages
	req := findRequirement(host1.Requirements, "46-CVE-2021-44142")
	require.NotNil(t, req)
	require.NotEmpty(t, req.Results)
	assert.Contains(t, req.Results[0].CodeDesc, "samba-common")

	// linux type
	req = findRequirement(host1.Requirements, "60522-redhat-RHEL7-high")
	require.NotNil(t, req)
	require.NotEmpty(t, req.Results)
	assert.Contains(t, req.Results[0].CodeDesc, "Configuration check")
}

// ---- Descriptions ----

func TestConvertPrisma_DefaultDescription(t *testing.T) {
	input := loadFixture(t, "input/minimal.csv")
	result, err := ConvertPrismaToHDF(input, testVersion)
	require.NoError(t, err)

	host1 := findBaseline(result.Baselines, "host-1.example.com")
	require.NotNil(t, host1)

	req := findRequirement(host1.Requirements, "46-CVE-2021-44142")
	require.NotNil(t, req)
	require.NotEmpty(t, req.Descriptions)
	assert.Equal(t, "default", req.Descriptions[0].Label)
	assert.Contains(t, req.Descriptions[0].Data, "Samba")
}

// ---- CVE tags ----

func TestConvertPrisma_CveTags(t *testing.T) {
	input := loadFixture(t, "input/minimal.csv")
	result, err := ConvertPrismaToHDF(input, testVersion)
	require.NoError(t, err)

	host1 := findBaseline(result.Baselines, "host-1.example.com")
	require.NotNil(t, host1)

	req := findRequirement(host1.Requirements, "46-CVE-2021-44142")
	require.NotNil(t, req)
	cve := hdfutil.SafeStringSlice(req.Tags["cve"])
	require.NotNil(t, cve)
	assert.Contains(t, cve, "CVE-2021-44142")
}

// ---- Full fixture smoke test ----

func TestConvertPrisma_FullFixture(t *testing.T) {
	input := loadFixture(t, "input/prismacloud_sample.csv")
	result, err := ConvertPrismaToHDF(input, testVersion)
	require.NoError(t, err)

	// The full fixture has 16 unique hostnames
	assert.Len(t, result.Baselines, 16)

	// Every baseline should have at least 1 requirement
	for _, baseline := range result.Baselines {
		assert.NotEmpty(t, baseline.Requirements,
			"baseline %s should have requirements", *baseline.Title)
	}
}

// ---- Message field ----

func TestConvertPrisma_MessageField(t *testing.T) {
	input := loadFixture(t, "input/minimal.csv")
	result, err := ConvertPrismaToHDF(input, testVersion)
	require.NoError(t, err)

	host1 := findBaseline(result.Baselines, "host-1.example.com")
	require.NotNil(t, host1)

	// Compliance finding with Cause should include it in message
	req := findRequirement(host1.Requirements, "60522-redhat-RHEL7-high")
	require.NotNil(t, req)
	require.NotEmpty(t, req.Results)
	msg := req.Results[0].Message
	require.NotNil(t, msg)
	assert.Contains(t, *msg, "File ownership is wrong")
}

// ---- Empty findings fixture (headers-only CSV) ----

func TestConvertPrisma_NoFindings(t *testing.T) {
	input := loadFixture(t, "input/empty.csv")
	result, err := ConvertPrismaToHDF(input, testVersion)
	require.NoError(t, err)

	require.Len(t, result.Baselines, 1)
	require.Len(t, result.Baselines[0].Requirements, 1)
	req := result.Baselines[0].Requirements[0]
	assert.Equal(t, "prisma-no-findings", req.ID)
	require.Len(t, req.Results, 1)
	assert.Equal(t, hdf.Passed, req.Results[0].Status)
	assert.Contains(t, req.Results[0].CodeDesc, "Prisma")
	assert.Contains(t, req.Results[0].CodeDesc, "scanned")
	assert.Contains(t, req.Results[0].CodeDesc, "vulnerable components")
}

func TestSnapshots(t *testing.T) {
	shared.RunSnapshotTests(t, "prisma-to-hdf", func(input []byte) (interface{}, error) {
		return ConvertPrismaToHDF(input, "0.1.0")
	})
}

func TestConvertPrisma_ControlType(t *testing.T) {
	input := loadFixture(t, "input/prismacloud_sample.csv")
	result, err := ConvertPrismaToHDF(input, testVersion)
	require.NoError(t, err)

	// Each baseline groups by hostname; at least one requirement across all
	// baselines should have a derived controlType (Prisma uses either
	// DefaultRemediationNIST for CVEs or DefaultStaticAnalysisNIST otherwise).
	var sawDerivation bool
	for _, baseline := range result.Baselines {
		for _, req := range baseline.Requirements {
			if req.ControlType != nil {
				sawDerivation = true
				switch *req.ControlType {
				case hdf.Management, hdf.Operational, hdf.Technical, hdf.Policy, hdf.Procedure:
				default:
					t.Errorf("requirement %q has unrecognized controlType %q", req.ID, *req.ControlType)
				}
			}
		}
	}
	assert.False(t, sawDerivation, "converter uses static-fallback NIST only; controlType must be omitted per helper gate")
}

// ---- VerificationMethod ----

func TestConvertPrisma_VerificationMethod(t *testing.T) {
	input := loadFixture(t, "input/minimal.csv")
	result, err := ConvertPrismaToHDF(input, testVersion)
	require.NoError(t, err)
	require.NotEmpty(t, result.Baselines)
	reqs := result.Baselines[0].Requirements
	require.NotEmpty(t, reqs)

	for _, req := range reqs {
		require.NotNil(t, req.VerificationMethod, "requirement %q missing verificationMethod", req.ID)
		assert.Equal(t, hdf.VerificationMethodEnumAutomated, *req.VerificationMethod,
			"requirement %q expected verificationMethod=automated", req.ID)
	}
}
