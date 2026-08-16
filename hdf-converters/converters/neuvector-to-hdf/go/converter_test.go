package neuvector

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
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

func findDescription(descs []hdf.Description, label string) *hdf.Description {
	for i := range descs {
		if descs[i].Label == label {
			return &descs[i]
		}
	}
	return nil
}

// ---- Input validation ----

func TestConverterContract(t *testing.T) {
	shared.RunConverterContractTests(t, shared.ConverterContractSpec{
		ConverterName:  "neuvector-to-hdf",
		ConvertFn:      func(input []byte) (interface{}, error) { return ConvertNeuVectorToHDF(input, testVersion) },
		MinimalFixture: "minimal.json",
	})
}

// ---- Minimal fixture: baseline structure ----

func TestConvertNeuVector_Minimal(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertNeuVectorToHDF(input, testVersion)
	require.NoError(t, err)

	require.Len(t, result.Baselines, 1)
	// minimal.json has 8 unique vulnerability IDs (name/package_name/package_version)
	assert.Len(t, result.Baselines[0].Requirements, 8)
}

func TestConvertNeuVector_BaselineName(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertNeuVectorToHDF(input, testVersion)
	require.NoError(t, err)

	assert.Equal(t, "NeuVector Scan", result.Baselines[0].Name)
}

func TestConvertNeuVector_BaselineTitle(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertNeuVectorToHDF(input, testVersion)
	require.NoError(t, err)

	require.NotNil(t, result.Baselines[0].Title)
	// Title should contain registry/repository:tag - Digest: ... - Image ID: ...
	assert.Contains(t, *result.Baselines[0].Title, "mitre/heimdall")
	assert.Contains(t, *result.Baselines[0].Title, "latest")
}

func TestConvertNeuVector_Checksum(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertNeuVectorToHDF(input, testVersion)
	require.NoError(t, err)

	require.NotNil(t, result.Baselines[0].ResultsChecksum)
	assert.Equal(t, hdf.Sha256, result.Baselines[0].ResultsChecksum.Algorithm)
	assert.NotEmpty(t, result.Baselines[0].ResultsChecksum.Value)
}

// ---- Generator ----

func TestConvertNeuVector_Generator(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertNeuVectorToHDF(input, testVersion)
	require.NoError(t, err)

	require.NotNil(t, result.Generator)
	assert.Equal(t, "neuvector-to-hdf", result.Generator.Name)
	assert.Equal(t, testVersion, result.Generator.Version)
}

// ---- Tool ----

func TestConvertNeuVector_Tool(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertNeuVectorToHDF(input, testVersion)
	require.NoError(t, err)

	require.NotNil(t, result.Tool)
	require.NotNil(t, result.Tool.Name)
	assert.Equal(t, "NeuVector", *result.Tool.Name)
	assert.Nil(t, result.Tool.Format, "serialization structures are not formats (kpvj)")
}

// ---- Impact: score_v3 / 10 ----

func TestConvertNeuVector_ImpactFromCVSSv3(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertNeuVectorToHDF(input, testVersion)
	require.NoError(t, err)

	reqs := result.Baselines[0].Requirements

	// CVE-2021-36159/apk-tools/2.10.5-r1 has score_v3=9.1 -> impact=0.91
	req := shared.MustFindRequirement(t, reqs, "CVE-2021-36159/apk-tools/2.10.5-r1")
	assert.Equal(t, 0.91, req.Impact)

	// CVE-2021-36217/avahi/0.8-r0 has score_v3=6.2 -> impact=0.62
	reqMedium := shared.MustFindRequirement(t, reqs, "CVE-2021-36217/avahi/0.8-r0")
	assert.Equal(t, 0.62, reqMedium.Impact)
}

func TestConvertNeuVector_ImpactFallbackToCVSSv2(t *testing.T) {
	// When score_v3 is 0, should fall back to score (v2) / 10
	input := []byte(`{
		"error_message": "",
		"report": {
			"image_id": "abc123",
			"registry": "https://registry.example.com",
			"repository": "test/image",
			"tag": "latest",
			"digest": "sha256:abc",
			"size": 100,
			"author": "",
			"base_os": "alpine:3.12",
			"created_at": "2024-01-01T00:00:00Z",
			"cvedb_version": "1.0",
			"cvedb_create_time": "2024-01-01T00:00:00Z",
			"layers": [],
			"vulnerabilities": [{
				"name": "CVE-2020-0001",
				"score": 7.5,
				"severity": "High",
				"vectors": "AV:N/AC:L/Au:N/C:P/I:P/A:P",
				"description": "Test vuln with only v2 score",
				"file_name": "",
				"package_name": "test-pkg",
				"package_version": "1.0.0",
				"fixed_version": "1.0.1",
				"link": "https://example.com",
				"score_v3": 0,
				"vectors_v3": "",
				"published_timestamp": 1700000000,
				"last_modified_timestamp": 1700000000,
				"feed_rating": "High"
			}]
		}
	}`)
	result, err := ConvertNeuVectorToHDF(input, testVersion)
	require.NoError(t, err)

	reqs := result.Baselines[0].Requirements
	require.Len(t, reqs, 1)
	// score=7.5 / 10 = 0.75
	assert.Equal(t, 0.75, reqs[0].Impact)
}

// ---- CWE extraction from description ----

func TestConvertNeuVector_CweExtraction(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertNeuVectorToHDF(input, testVersion)
	require.NoError(t, err)

	reqs := result.Baselines[0].Requirements

	// CVE-2020-25613/ruby:webrick/1.4.2 has CWE-444 in description
	req := shared.MustFindRequirement(t, reqs, "CVE-2020-25613/ruby:webrick/1.4.2")

	nist := hdfutil.SafeStringSlice(req.Tags["nist"])
	require.NotNil(t, nist, "nist tag should be present")
	assert.NotEmpty(t, nist)
}

func TestConvertNeuVector_CweToNist(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertNeuVectorToHDF(input, testVersion)
	require.NoError(t, err)

	reqs := result.Baselines[0].Requirements

	// CVE-2018-25032/ruby:nokogiri/1.10.9 has CWE-787 in description
	req := shared.MustFindRequirement(t, reqs, "CVE-2018-25032/ruby:nokogiri/1.10.9")

	nist := hdfutil.SafeStringSlice(req.Tags["nist"])
	require.NotNil(t, nist, "nist tag should be present")
	assert.NotEmpty(t, nist)

	// CWE is now first-class on the requirement (not a tag).
	assert.Contains(t, req.Cwe, "CWE-787")
	_, hasCweTag := req.Tags["cwe"]
	assert.False(t, hasCweTag, "cwe must no longer be emitted as a tag")
}

func TestConvertNeuVector_NistFallback(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertNeuVectorToHDF(input, testVersion)
	require.NoError(t, err)

	reqs := result.Baselines[0].Requirements

	// CVE-2021-36159/apk-tools/2.10.5-r1 has no CWE in description -> uses default remediation NIST
	req := shared.MustFindRequirement(t, reqs, "CVE-2021-36159/apk-tools/2.10.5-r1")

	nist := hdfutil.SafeStringSlice(req.Tags["nist"])
	require.NotNil(t, nist, "nist fallback should be present")
	assert.Contains(t, nist, "SI-2")
	assert.Contains(t, nist, "RA-5")
}

// ---- Structured CVSS ----

func TestConvertNeuVector_CvssV3FromVector(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertNeuVectorToHDF(input, testVersion)
	require.NoError(t, err)

	reqs := result.Baselines[0].Requirements
	// CVE-2021-36159/apk-tools carries a v3 vector + score_v3=9.1.
	req := shared.MustFindRequirement(t, reqs, "CVE-2021-36159/apk-tools/2.10.5-r1")
	require.Len(t, req.Cvss, 1)
	cv := req.Cvss[0]
	assert.Equal(t, hdf.The31, cv.Version)
	require.NotNil(t, cv.BaseScore)
	assert.InDelta(t, 9.1, *cv.BaseScore, 0.001)
	require.NotNil(t, cv.BaseVector)
	assert.Equal(t, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H", *cv.BaseVector)
	require.NotNil(t, cv.BaseSeverity)
	assert.Equal(t, hdf.CVSSSeverityCritical, *cv.BaseSeverity)
	require.NotNil(t, cv.Source)
	assert.Equal(t, "NeuVector", *cv.Source)
}

func TestConvertNeuVector_CvssV2Fallback(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertNeuVectorToHDF(input, testVersion)
	require.NoError(t, err)

	reqs := result.Baselines[0].Requirements
	// CVE-2018-25032/ruby:nokogiri has no v3 vector, so the prefix-less v2
	// vector + score (5) is used and forced to version 2.0.
	req := shared.MustFindRequirement(t, reqs, "CVE-2018-25032/ruby:nokogiri/1.10.9")
	require.Len(t, req.Cvss, 1)
	cv := req.Cvss[0]
	assert.Equal(t, hdf.The20, cv.Version)
	require.NotNil(t, cv.BaseScore)
	assert.InDelta(t, 5.0, *cv.BaseScore, 0.001)
	require.NotNil(t, cv.BaseVector)
	assert.Equal(t, "AV:N/AC:L/Au:N/C:N/I:N/A:P", *cv.BaseVector)
}

// buildCvssEntries branch coverage for the sub-branches fixtures don't exercise:
// a vector present with a zero score (score omitted), and no vector at all.
func TestBuildCvssEntries_Branches(t *testing.T) {
	t.Run("v3 vector, no score", func(t *testing.T) {
		out := buildCvssEntries(NeuVectorVuln{VectorsV3: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", ScoreV3: 0})
		require.Len(t, out, 1)
		assert.Equal(t, hdf.The30, out[0].Version)
		assert.Nil(t, out[0].BaseScore, "zero score_v3 must not be emitted")
		require.NotNil(t, out[0].BaseVector)
	})
	t.Run("v2 vector, no score", func(t *testing.T) {
		out := buildCvssEntries(NeuVectorVuln{Vectors: "AV:N/AC:L/Au:N/C:P/I:P/A:P", Score: 0})
		require.Len(t, out, 1)
		assert.Equal(t, hdf.The20, out[0].Version)
		assert.Nil(t, out[0].BaseScore, "zero score must not be emitted")
	})
	t.Run("no vector, no entry", func(t *testing.T) {
		assert.Empty(t, buildCvssEntries(NeuVectorVuln{ScoreV3: 9.8, Score: 5}),
			"a vulnerability with no vector contributes no cvss entry")
	})
}

// ---- External references (refs[]) ----

// Value-pins the mapped vulnerability.link -> refs[0].url. The link is read
// independently from the fixture so this catches a silent drop even if the
// golden churns.
func TestConvertNeuVector_RefsFromLink(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertNeuVectorToHDF(input, testVersion)
	require.NoError(t, err)

	reqs := result.Baselines[0].Requirements
	req := shared.MustFindRequirement(t, reqs, "CVE-2021-36159/apk-tools/2.10.5-r1")
	require.Len(t, req.Refs, 1, "one Reference per link")
	require.NotNil(t, req.Refs[0].URL)
	assert.Equal(t, "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-36159", *req.Refs[0].URL)
	assert.Nil(t, req.Refs[0].Ref, "external link maps to url, not ref")
	assert.Nil(t, req.Refs[0].URI, "external link maps to url, not uri")
}

// buildRefs branch coverage: no link -> no refs[].
func TestBuildRefs_Absent(t *testing.T) {
	assert.Nil(t, buildRefs(NeuVectorVuln{Link: ""}), "empty link contributes no refs")
	out := buildRefs(NeuVectorVuln{Link: "https://example.test/adv"})
	require.Len(t, out, 1)
	require.NotNil(t, out[0].URL)
	assert.Equal(t, "https://example.test/adv", *out[0].URL)
}

// ---- CVE tag (interim) ----

func TestConvertNeuVector_CveTag(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertNeuVectorToHDF(input, testVersion)
	require.NoError(t, err)

	reqs := result.Baselines[0].Requirements
	req := shared.MustFindRequirement(t, reqs, "CVE-2021-36159/apk-tools/2.10.5-r1")

	// requirement.id is a name/package/version composite, NOT the bare CVE.
	assert.NotEqual(t, "CVE-2021-36159", req.ID)
	cveTags := hdfutil.SafeStringSlice(req.Tags["cve"])
	require.NotNil(t, cveTags, "cve tag should be present")
	assert.Equal(t, []string{"CVE-2021-36159"}, cveTags)
}

func TestExtractCVEs_Dedup(t *testing.T) {
	out := extractCVEs(NeuVectorVuln{Cves: []string{"CVE-2021-1", "", "CVE-2021-1", "CVE-2021-2"}})
	assert.Equal(t, []string{"CVE-2021-1", "CVE-2021-2"}, out)
	assert.Nil(t, extractCVEs(NeuVectorVuln{Cves: nil}), "no cves -> no tag")
}

// ---- severity / status / source / timestamp tags (h2 parity) ----

// Value-pins vulnerability.severity -> tags["severity"] and the epoch
// published/last_modified timestamps -> their tags, read from minimal.json which
// carries no modules or cmds (so status/source are absent there).
func TestConvertNeuVector_SeverityAndTimestampTags(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertNeuVectorToHDF(input, testVersion)
	require.NoError(t, err)

	reqs := result.Baselines[0].Requirements
	req := shared.MustFindRequirement(t, reqs, "CVE-2021-36159/apk-tools/2.10.5-r1")
	assert.Equal(t, "Critical", req.Tags["severity"])
	assert.Equal(t, int64(1699328203), req.Tags["published_timestamp"])
	assert.Equal(t, int64(1699328203), req.Tags["last_modified_timestamp"])

	// minimal.json has no report.modules → those tags are absent.
	_, hasStatus := req.Tags["status"]
	assert.False(t, hasStatus, "no modules → no status tag")
	_, hasSource := req.Tags["source"]
	assert.False(t, hasSource, "no modules → no source tag")
}

// Value-pins the module cross-reference: status from report.modules[].cves[].status
// and source from report.modules[].source, matched by package_name.
func TestConvertNeuVector_StatusSourceTags(t *testing.T) {
	input := loadFixture(t, "input/neuvector-mitre-heimdall2.json")
	result, err := ConvertNeuVectorToHDF(input, testVersion)
	require.NoError(t, err)

	reqs := result.Baselines[0].Requirements
	req := shared.MustFindRequirement(t, reqs, "CVE-2019-12904/libgcrypt/1.8.5-7.el8_6")
	assert.Equal(t, "unpatched", req.Tags["status"])
	assert.Equal(t, "rhel:8.10", req.Tags["source"])
	assert.Equal(t, "Medium", req.Tags["severity"])
}

// report.cmds is scan-scope image build history → it lives once on
// baseline.extensions["neuvector"], never duplicated onto requirement tags.
func TestConvertNeuVector_CmdsOnBaselineExtensions(t *testing.T) {
	input := loadFixture(t, "input/neuvector-mitre-heimdall2.json")
	result, err := ConvertNeuVectorToHDF(input, testVersion)
	require.NoError(t, err)

	baseline := result.Baselines[0]
	ns, ok := baseline.Extensions["neuvector"].(map[string]interface{})
	require.True(t, ok, "baseline.extensions[neuvector] should be present")
	cmds := hdfutil.SafeStringSlice(ns["cmds"])
	require.NotNil(t, cmds, "cmds should be present")
	assert.Len(t, cmds, 66)
	assert.Equal(t, `CMD ["/usr/local/bin/cmd.sh"]`, cmds[0])

	// cmds must NOT be duplicated onto any requirement's tags.
	for _, req := range baseline.Requirements {
		_, has := req.Tags["cmds"]
		assert.False(t, has, "cmds must not appear on requirement tags")
	}
}

// Absent branch: a report with no report.cmds emits no baseline.extensions.
func TestConvertNeuVector_CmdsAbsent(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertNeuVectorToHDF(input, testVersion)
	require.NoError(t, err)

	baseline := result.Baselines[0]
	assert.Nil(t, baseline.Extensions, "no report.cmds → no baseline.extensions")
	for _, req := range baseline.Requirements {
		_, has := req.Tags["cmds"]
		assert.False(t, has, "cmds must not appear on requirement tags")
	}
}

// Absent branch: a vuln with no severity/timestamps and a report with no modules
// contributes none of the new tags.
func TestConvertNeuVector_NewTagsAbsent(t *testing.T) {
	input := []byte(`{
		"report": {
			"registry": "reg",
			"repository": "repo",
			"tag": "latest",
			"vulnerabilities": [
				{"name": "CVE-2020-0001", "package_name": "pkg", "package_version": "1.0"}
			]
		}
	}`)
	result, err := ConvertNeuVectorToHDF(input, testVersion)
	require.NoError(t, err)

	req := shared.MustFindRequirement(t, result.Baselines[0].Requirements, "CVE-2020-0001/pkg/1.0")
	for _, k := range []string{"severity", "status", "source", "published_timestamp", "last_modified_timestamp", "cmds"} {
		_, has := req.Tags[k]
		assert.Falsef(t, has, "absent source field must not emit tag %q", k)
	}
}

// buildModuleLookup unit branches: source first-wins, status matched by
// (module name, cve name), empty values skipped, and misses returning "".
func TestBuildModuleLookup(t *testing.T) {
	ml := buildModuleLookup([]NeuVectorScanModule{
		{Name: "openssl", Source: "rhel:8.10", Cves: []NeuVectorModuleCVE{
			{Name: "CVE-2023-1", Status: "unpatched"},
			{Name: "CVE-2023-2", Status: ""},
		}},
		{Name: "openssl", Source: "rhel:9", Cves: []NeuVectorModuleCVE{
			{Name: "CVE-2023-1", Status: "fix exists"},
		}},
		{Name: "empty", Source: ""},
	})

	assert.Equal(t, "rhel:8.10", ml.source(NeuVectorVuln{PackageName: "openssl"}), "first non-empty source wins")
	assert.Equal(t, "unpatched", ml.status(NeuVectorVuln{PackageName: "openssl", Name: "CVE-2023-1"}), "first status wins")
	assert.Empty(t, ml.status(NeuVectorVuln{PackageName: "openssl", Name: "CVE-2023-2"}), "empty status not indexed")
	assert.Empty(t, ml.source(NeuVectorVuln{PackageName: "empty"}), "empty source not indexed")
	assert.Empty(t, ml.source(NeuVectorVuln{PackageName: "missing"}), "no module → empty source")
	assert.Empty(t, ml.status(NeuVectorVuln{PackageName: "missing", Name: "CVE-X"}), "no module → empty status")
}

// ---- feed_rating tag ----

// Value-pins vulnerability.feed_rating -> tags["feed_rating"], read as a string.
func TestConvertNeuVector_FeedRatingTag(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertNeuVectorToHDF(input, testVersion)
	require.NoError(t, err)

	reqs := result.Baselines[0].Requirements
	req := shared.MustFindRequirement(t, reqs, "CVE-2021-36159/apk-tools/2.10.5-r1")
	assert.Equal(t, "Critical", req.Tags["feed_rating"])

	// Different vuln carries a different rating in the same fixture.
	medium := shared.MustFindRequirement(t, reqs, "CVE-2021-36217/avahi/0.8-r0")
	assert.Equal(t, "Medium", medium.Tags["feed_rating"])
}

// Absent branch: a vuln with no feed_rating contributes no feed_rating tag.
func TestConvertNeuVector_FeedRatingAbsent(t *testing.T) {
	input := []byte(`{
		"report": {
			"registry": "reg",
			"repository": "repo",
			"tag": "latest",
			"vulnerabilities": [
				{"name": "CVE-2020-0001", "package_name": "pkg", "package_version": "1.0"}
			]
		}
	}`)
	result, err := ConvertNeuVectorToHDF(input, testVersion)
	require.NoError(t, err)

	reqs := result.Baselines[0].Requirements
	req := shared.MustFindRequirement(t, reqs, "CVE-2020-0001/pkg/1.0")
	_, has := req.Tags["feed_rating"]
	assert.False(t, has, "no feed_rating in source -> no feed_rating tag")
}

// ---- Requirement ID and Title ----

func TestConvertNeuVector_RequirementID(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertNeuVectorToHDF(input, testVersion)
	require.NoError(t, err)

	reqs := result.Baselines[0].Requirements
	// ID format: name/package_name/package_version
	req := shared.MustFindRequirement(t, reqs, "CVE-2021-36159/apk-tools/2.10.5-r1")
	assert.Equal(t, "CVE-2021-36159/apk-tools/2.10.5-r1", req.ID)
}

func TestConvertNeuVector_RequirementTitle(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertNeuVectorToHDF(input, testVersion)
	require.NoError(t, err)

	reqs := result.Baselines[0].Requirements
	req := shared.MustFindRequirement(t, reqs, "CVE-2021-36159/apk-tools/2.10.5-r1")
	require.NotNil(t, req.Title)
	// Title: "NeuVector found a vulnerability to <name> in <package_name>/<package_version>."
	assert.Contains(t, *req.Title, "CVE-2021-36159")
	assert.Contains(t, *req.Title, "apk-tools")
	assert.Contains(t, *req.Title, "2.10.5-r1")
}

// ---- Description ----

func TestConvertNeuVector_Description(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertNeuVectorToHDF(input, testVersion)
	require.NoError(t, err)

	reqs := result.Baselines[0].Requirements
	req := shared.MustFindRequirement(t, reqs, "CVE-2021-36159/apk-tools/2.10.5-r1")

	desc := findDescription(req.Descriptions, "default")
	require.NotNil(t, desc, "expected a 'default' description")
	assert.Contains(t, desc.Data, "libfetch")
}

// ---- Results: all Failed ----

func TestConvertNeuVector_AllResultsFailed(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertNeuVectorToHDF(input, testVersion)
	require.NoError(t, err)

	for _, req := range result.Baselines[0].Requirements {
		for _, r := range req.Results {
			assert.Equal(t, hdf.Failed, r.Status,
				"all NeuVector vulnerabilities should be Failed (vuln %s)", req.ID)
		}
	}
}

// ---- Result message format ----

func TestConvertNeuVector_ResultMessage_WithFixedVersion(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertNeuVectorToHDF(input, testVersion)
	require.NoError(t, err)

	reqs := result.Baselines[0].Requirements
	// CVE-2021-36159/apk-tools/2.10.5-r1 has fixed_version "2.10.7-r0"
	req := shared.MustFindRequirement(t, reqs, "CVE-2021-36159/apk-tools/2.10.5-r1")
	require.NotEmpty(t, req.Results)

	msg := req.Results[0].Message
	require.NotNil(t, msg)
	assert.Contains(t, *msg, "apk-tools")
	assert.Contains(t, *msg, "2.10.5-r1")
	assert.Contains(t, *msg, "2.10.7-r0")
}

func TestConvertNeuVector_ResultMessage_NoFixedVersion(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertNeuVectorToHDF(input, testVersion)
	require.NoError(t, err)

	reqs := result.Baselines[0].Requirements
	// CVE-2023-37920/ca-certificates/... has no fixed_version
	req := shared.MustFindRequirement(t, reqs, "CVE-2023-37920/ca-certificates/2023.2.60_v7.0.306-80.0.el8_8")
	require.NotEmpty(t, req.Results)

	msg := req.Results[0].Message
	require.NotNil(t, msg)
	assert.Contains(t, *msg, "No fixed version")
}

// ---- Target ----

func TestConvertNeuVector_Target(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertNeuVectorToHDF(input, testVersion)
	require.NoError(t, err)

	require.NotEmpty(t, result.Components)
	// Target name should be the image reference
	assert.Contains(t, result.Components[0].Name, "mitre/heimdall")
	assert.Equal(t, hdf.ContainerImage, result.Components[0].Type)
}

// ---- Scan-target component identity ----

// Value-pins the enriched containerImage component: base_os → osName/osVersion,
// digest → Integrity (sha256, prefix stripped), image_id → ImageID, plus
// registry/repository/tag. Fields are read independently of the golden.
func TestConvertNeuVector_ComponentIdentity(t *testing.T) {
	input := loadFixture(t, "input/neuvector-mitre-heimdall.json")
	result, err := ConvertNeuVectorToHDF(input, testVersion)
	require.NoError(t, err)

	require.Len(t, result.Components, 1)
	comp := result.Components[0]
	assert.Equal(t, hdf.ContainerImage, comp.Type)
	assert.Equal(t, "https://registry.hub.docker.com/mitre/heimdall:latest", comp.Name)

	// base_os "alpine:3.12.1" → osName "alpine", osVersion "3.12.1"
	require.NotNil(t, comp.OSName)
	assert.Equal(t, "alpine", *comp.OSName)
	require.NotNil(t, comp.OSVersion)
	assert.Equal(t, "3.12.1", *comp.OSVersion)

	require.NotNil(t, comp.ImageID)
	assert.Equal(t, "65785cbf46647c77caf8d7c40485900b013fca1290d1a7ab06c9039c3b29761c", *comp.ImageID)
	require.NotNil(t, comp.Registry)
	assert.Equal(t, "https://registry.hub.docker.com", *comp.Registry)
	require.NotNil(t, comp.Repository)
	assert.Equal(t, "mitre/heimdall", *comp.Repository)
	require.NotNil(t, comp.Tag)
	assert.Equal(t, "latest", *comp.Tag)

	// digest "sha256:54cb..." → Integrity{sha256, <hex without prefix>}
	require.Len(t, comp.Integrity, 1)
	assert.Equal(t, hdf.Sha256, comp.Integrity[0].Algorithm)
	assert.Equal(t, "54cbfb34a9a8fe00c9a60d722aa1c12f25bec825c505139cfffaeabc91fb10e6", comp.Integrity[0].Value)
}

// The rhel fixture pins a different base_os split.
func TestConvertNeuVector_ComponentOSRhel(t *testing.T) {
	input := loadFixture(t, "input/neuvector-mitre-heimdall2.json")
	result, err := ConvertNeuVectorToHDF(input, testVersion)
	require.NoError(t, err)

	require.Len(t, result.Components, 1)
	comp := result.Components[0]
	require.NotNil(t, comp.OSName)
	assert.Equal(t, "rhel", *comp.OSName)
	require.NotNil(t, comp.OSVersion)
	assert.Equal(t, "8.10", *comp.OSVersion)
}

// Absent branch: a report carrying no base_os/digest/image_id yields a
// containerImage component with no OS, Integrity, or ImageID.
func TestConvertNeuVector_ComponentIdentityAbsent(t *testing.T) {
	input := []byte(`{
		"report": {
			"registry": "reg",
			"repository": "repo",
			"tag": "latest",
			"vulnerabilities": [
				{"name": "CVE-2020-0001", "package_name": "pkg", "package_version": "1.0"}
			]
		}
	}`)
	result, err := ConvertNeuVectorToHDF(input, testVersion)
	require.NoError(t, err)

	require.Len(t, result.Components, 1)
	comp := result.Components[0]
	assert.Equal(t, hdf.ContainerImage, comp.Type)
	assert.Nil(t, comp.OSName, "no base_os → no osName")
	assert.Nil(t, comp.OSVersion, "no base_os → no osVersion")
	assert.Nil(t, comp.ImageID, "no image_id → no imageId")
	assert.Nil(t, comp.Integrity, "no digest → no integrity")
	// registry/repository/tag are still present.
	require.NotNil(t, comp.Registry)
	assert.Equal(t, "reg", *comp.Registry)
}

// Unit branch coverage for the base_os split and digest algorithm folding.
func TestComponentHelpers_Branches(t *testing.T) {
	t.Run("splitBaseOS name only", func(t *testing.T) {
		name, version := splitBaseOS("scratch")
		assert.Equal(t, "scratch", name)
		assert.Empty(t, version)
	})
	t.Run("splitBaseOS empty", func(t *testing.T) {
		name, version := splitBaseOS("")
		assert.Empty(t, name)
		assert.Empty(t, version)
	})
	// Digest→checksum parsing now lives in shared.DigestToChecksums (tested in
	// shared/go/converterutil_test.go); the report-level integration is covered
	// by the full-conversion tests above.
}

// ---- Tags with extras ----

func TestConvertNeuVector_Tags(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertNeuVectorToHDF(input, testVersion)
	require.NoError(t, err)

	reqs := result.Baselines[0].Requirements
	req := shared.MustFindRequirement(t, reqs, "CVE-2021-36159/apk-tools/2.10.5-r1")

	// nist should be present
	nist := hdfutil.SafeStringSlice(req.Tags["nist"])
	require.NotNil(t, nist, "nist should be present")
	assert.NotEmpty(t, nist)

	// cci should be present
	cciSlice := hdfutil.SafeStringSlice(req.Tags["cci"])
	require.NotNil(t, cciSlice, "cci should be present")
	assert.NotEmpty(t, cciSlice)
}

// ---- Empty vulnerabilities ----

func TestConvertNeuVector_EmptyVulnerabilities(t *testing.T) {
	input := []byte(`{
		"error_message": "",
		"report": {
			"image_id": "abc123",
			"registry": "https://registry.example.com",
			"repository": "test/image",
			"tag": "latest",
			"digest": "sha256:abc",
			"size": 100,
			"author": "",
			"base_os": "alpine:3.12",
			"created_at": "2024-01-01T00:00:00Z",
			"cvedb_version": "1.0",
			"cvedb_create_time": "2024-01-01T00:00:00Z",
			"layers": [],
			"vulnerabilities": []
		}
	}`)
	result, err := ConvertNeuVectorToHDF(input, testVersion)
	require.NoError(t, err)
	require.Len(t, result.Baselines, 1)
	reqs := result.Baselines[0].Requirements
	require.Len(t, reqs, 1)
	assert.Equal(t, "neuvector-no-findings", reqs[0].ID)
	require.Len(t, reqs[0].Results, 1)
	assert.Equal(t, hdf.Passed, reqs[0].Results[0].Status)
	assert.Contains(t, reqs[0].Results[0].CodeDesc, "NeuVector")
	assert.Contains(t, reqs[0].Results[0].CodeDesc, "test/image")
}

func TestConvertNeuVector_EmptyFixtureSynthesizesPlaceholder(t *testing.T) {
	input := loadFixture(t, "input/empty.json")
	result, err := ConvertNeuVectorToHDF(input, testVersion)
	require.NoError(t, err)
	require.Len(t, result.Baselines, 1)
	reqs := result.Baselines[0].Requirements
	require.Len(t, reqs, 1)
	assert.Equal(t, "neuvector-no-findings", reqs[0].ID)
	require.Len(t, reqs[0].Results, 1)
	assert.Equal(t, hdf.Passed, reqs[0].Results[0].Status)
	if !strings.Contains(reqs[0].Results[0].CodeDesc, "NeuVector") {
		t.Errorf("Expected codeDesc to contain 'NeuVector', got %q", reqs[0].Results[0].CodeDesc)
	}
	if !strings.Contains(reqs[0].Results[0].CodeDesc, "mitre/heimdall") {
		t.Errorf("Expected codeDesc to contain target 'mitre/heimdall', got %q", reqs[0].Results[0].CodeDesc)
	}
}

// ---- Full fixture smoke tests ----

func TestConvertNeuVector_FullFixtureHeimdall(t *testing.T) {
	input := loadFixture(t, "input/neuvector-mitre-heimdall.json")
	result, err := ConvertNeuVectorToHDF(input, testVersion)
	require.NoError(t, err)

	reqs := result.Baselines[0].Requirements
	assert.NotEmpty(t, reqs)
	for _, req := range reqs {
		assert.NotEmpty(t, req.ID)
		assert.NotEmpty(t, req.Results)
	}
}

func TestConvertNeuVector_FullFixtureHeimdall2(t *testing.T) {
	input := loadFixture(t, "input/neuvector-mitre-heimdall2.json")
	result, err := ConvertNeuVectorToHDF(input, testVersion)
	require.NoError(t, err)

	reqs := result.Baselines[0].Requirements
	assert.NotEmpty(t, reqs)
	for _, req := range reqs {
		assert.NotEmpty(t, req.ID)
		assert.NotEmpty(t, req.Results)
	}
}

func TestSnapshots(t *testing.T) {
	// NeuVector scan JSON carries no scan time.
	shared.RunSnapshotTests(t, "neuvector-to-hdf", func(input []byte) (interface{}, error) {
		return ConvertNeuVectorToHDF(input, "1.0.0")
	}, "*")
}

func TestConvertNeuVector_ControlType(t *testing.T) {
	input := loadFixture(t, "input/neuvector-mitre-heimdall.json")
	result, err := ConvertNeuVectorToHDF(input, testVersion)
	require.NoError(t, err)

	reqs := result.Baselines[0].Requirements
	require.NotEmpty(t, reqs)

	// NeuVector resolves NIST tags via CWE→NIST mapping (with
	// DefaultRemediationNIST as fallback). At least one requirement should
	// have a derived controlType.
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
	assert.True(t, sawDerivation, "at least one NeuVector requirement should have a derived controlType")
}

func TestConvertNeuVector_VerificationMethod(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertNeuVectorToHDF(input, testVersion)
	require.NoError(t, err)
	require.NotEmpty(t, result.Baselines)
	reqs := result.Baselines[0].Requirements
	require.NotEmpty(t, reqs)
	for _, req := range reqs {
		require.NotNil(t, req.VerificationMethod, "requirement %q missing verificationMethod", req.ID)
		assert.Equal(t, hdf.VerificationMethodEnumAutomated, *req.VerificationMethod,
			"requirement %q: NeuVector is an automated container vulnerability scanner", req.ID)
	}
}

// countDistinctNeuVectorVulns unmarshals raw NeuVector JSON into a minimal local
// struct — deliberately NOT the converter's structs — and returns the number of
// vulnerabilities distinct by the composite ID name/package_name/package_version.
// The converter dedups on that key, so a plain array count over-counts; this
// mirrors the dedup independently to give the true ground-truth requirement count.
func countDistinctNeuVectorVulns(t *testing.T, input []byte) int {
	t.Helper()
	var doc struct {
		Report struct {
			Vulnerabilities []struct {
				Name           string `json:"name"`
				PackageName    string `json:"package_name"`
				PackageVersion string `json:"package_version"`
			} `json:"vulnerabilities"`
		} `json:"report"`
	}
	require.NoError(t, json.Unmarshal(input, &doc), "failed to parse NeuVector JSON for anchor count")
	distinct := make(map[string]struct{})
	for _, v := range doc.Report.Vulnerabilities {
		distinct[v.Name+"/"+v.PackageName+"/"+v.PackageVersion] = struct{}{}
	}
	return len(distinct)
}

// ---- CODE tab / code_desc fidelity ----

// The requirement's code carries the source vulnerability object serialized as
// indented JSON; it must round-trip back to the exact source vuln.
func TestConvertNeuVector_RequirementCodeRoundTrips(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	var scan NeuVectorScan
	require.NoError(t, json.Unmarshal(input, &scan))

	result, err := ConvertNeuVectorToHDF(input, testVersion)
	require.NoError(t, err)

	req := result.Baselines[0].Requirements[0]
	require.NotNil(t, req.Code, "requirement.code must be populated (CODE tab)")
	assert.NotEmpty(t, *req.Code)

	var back NeuVectorVuln
	require.NoError(t, json.Unmarshal([]byte(*req.Code), &back),
		"requirement.code must parse back to the source vuln object")
	assert.Equal(t, scan.Report.Vulnerabilities[0], back)
}

// code_desc is no longer hard-coded empty; it is a pipe-joined composite of the
// fields the vuln carries.
func TestConvertNeuVector_ResultCodeDescComposite(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertNeuVectorToHDF(input, testVersion)
	require.NoError(t, err)

	req := result.Baselines[0].Requirements[0]
	require.Len(t, req.Results, 1)
	cd := req.Results[0].CodeDesc
	assert.NotEmpty(t, cd, "code_desc must no longer be hard-coded empty")
	assert.Equal(t,
		"apk-tools@2.10.5-r1 | CVE-2021-36159 | CVSS 9.1 | libfetch before 2021-07-26, as used in apk-tools, xbps, and other products, mishandles numeric strin…",
		cd)
}

// Ground-truth anchor (input-derived count; see shared/go/anchor.go). Golden
// parity proves Go and TS agree, not that either is correct. NeuVector emits one
// requirement per vulnerability distinct by name/package_name/package_version
// (it dedups on that composite ID); assert that distinct count derived
// INDEPENDENTLY from the source, so a silent under-extraction fails even when
// both languages agree.
func TestConvertNeuVector_VulnerabilityAnchor(t *testing.T) {
	input := loadFixture(t, "input/neuvector-mitre-heimdall.json")
	result, err := ConvertNeuVectorToHDF(input, testVersion)
	require.NoError(t, err)

	want := countDistinctNeuVectorVulns(t, input)
	shared.AssertRequirementCount(t, result, want,
		"neuvector-mitre-heimdall.json: one requirement per distinct name/package_name/package_version vulnerability")
}
