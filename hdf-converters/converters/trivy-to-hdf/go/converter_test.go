package trivy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/mitre/hdf-libs/hdf-converters/v3/registry"
	shared "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go"
	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	validators "github.com/mitre/hdf-libs/hdf-validators/go/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const converterVersion = "0.1.0"

func loadFixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "fixtures", "input", name))
	require.NoError(t, err)
	return data
}

func convert(t *testing.T, name string) *hdf.HDFResults {
	t.Helper()
	res, err := ConvertTrivyToHDF(loadFixture(t, name), converterVersion)
	require.NoError(t, err)
	require.NotNil(t, res)
	return res
}

func assertSchemaValid(t *testing.T, res *hdf.HDFResults) {
	t.Helper()
	data, err := json.Marshal(res)
	require.NoError(t, err)
	vr := validators.ValidateResults(data)
	assert.True(t, vr.Valid, "output must pass HDF Results schema: %v", vr.Errors)
}

func findReq(res *hdf.HDFResults, id string) *hdf.EvaluatedRequirement {
	for i := range res.Baselines[0].Requirements {
		if res.Baselines[0].Requirements[i].ID == id {
			return &res.Baselines[0].Requirements[i]
		}
	}
	return nil
}

func TestConvert_Image_Vulnerabilities(t *testing.T) {
	res := convert(t, "image-webgoat.json")
	assertSchemaValid(t, res)

	require.Len(t, res.Baselines, 1)
	assert.Equal(t, "Trivy Scan", res.Baselines[0].Name)
	require.NotNil(t, res.Baselines[0].Title)
	assert.Equal(t, "webgoat/webgoat:latest", *res.Baselines[0].Title)
	require.NotNil(t, res.Tool)
	assert.Equal(t, "Trivy", *res.Tool.Name)
	assert.Equal(t, "0.74.0", *res.Tool.Version)
	require.NotNil(t, res.Timestamp)

	// Container-image component.
	require.Len(t, res.Components, 1)
	assert.Equal(t, hdf.ContainerImage, res.Components[0].Type)
	require.NotNil(t, res.Components[0].OSName)
	assert.Equal(t, "ubuntu", *res.Components[0].OSName)
	assert.Equal(t, "24.04", *res.Components[0].OSVersion)
	require.NotNil(t, res.Components[0].ImageID)

	// An OS-package vulnerability with rich fields.
	v := findReq(res, "Trivy/CVE-2025-6965")
	require.NotNil(t, v, "expected requirement Trivy/CVE-2025-6965")
	assert.Equal(t, 0.5, v.Impact) // MEDIUM
	require.Len(t, v.Results, 1)
	assert.Equal(t, hdf.Failed, v.Results[0].Status)
	assert.Equal(t, []string{"CWE-197"}, v.Cwe)
	require.NotNil(t, v.VerificationMethod)
	assert.Equal(t, hdf.VerificationMethodEnumAutomated, *v.VerificationMethod)
	require.NotNil(t, v.Code)
	assert.NotEmpty(t, v.Refs)

	// Multi-source CVSS: one entry per (provider, version); provider is the source.
	assert.GreaterOrEqual(t, len(v.Cvss), 2, "expected multiple CVSS entries across providers")
	sources := map[string]bool{}
	for _, c := range v.Cvss {
		if c.Source != nil {
			sources[*c.Source] = true
		}
	}
	assert.True(t, sources["nvd"], "expected an nvd-sourced CVSS entry, got %v", sources)

	// affectedPackages carries the PURL.
	require.Len(t, v.AffectedPackages, 1)
	require.NotNil(t, v.AffectedPackages[0].Purl)
	assert.Contains(t, *v.AffectedPackages[0].Purl, "pkg:deb/")
	require.NotNil(t, v.AffectedPackages[0].Ecosystem)
	assert.Equal(t, hdf.Deb, *v.AffectedPackages[0].Ecosystem)

	// NIST tags present (static fallback).
	assert.Contains(t, v.Tags, "nist")
}

func TestConvert_Image_Licenses(t *testing.T) {
	res := convert(t, "image-webgoat.json")
	var lic *hdf.EvaluatedRequirement
	for i := range res.Baselines[0].Requirements {
		r := &res.Baselines[0].Requirements[i]
		if len(r.ID) >= 13 && r.ID[:13] == "Trivy/license" {
			lic = r
			break
		}
	}
	require.NotNil(t, lic, "expected at least one license requirement")
	assert.Equal(t, hdf.Failed, lic.Results[0].Status)
	assert.Contains(t, lic.Tags, "package")
}

func TestConvert_FS_MisconfigAndSecret(t *testing.T) {
	res := convert(t, "fs-misconfig-secret.json")
	assertSchemaValid(t, res)

	// Filesystem → Artifact component.
	require.Len(t, res.Components, 1)
	assert.Equal(t, hdf.Artifact, res.Components[0].Type)
	assert.Equal(t, "testdata", res.Components[0].Name)

	// Misconfiguration.
	mc := findReq(res, "Trivy/DS-0001")
	require.NotNil(t, mc, "expected requirement Trivy/DS-0001")
	assert.Equal(t, hdf.Failed, mc.Results[0].Status)
	require.NotNil(t, mc.SourceLocation)
	require.NotNil(t, mc.SourceLocation.Ref)
	assert.Equal(t, "Dockerfile", *mc.SourceLocation.Ref)
	require.NotNil(t, mc.SourceLocation.Line)
	assert.Equal(t, float64(1), *mc.SourceLocation.Line)

	// Secret — redacted, located.
	sec := findReq(res, "Trivy/secret/aws-access-key-id@app.env:2")
	require.NotNil(t, sec, "expected the aws-access-key-id secret requirement")
	assert.Equal(t, hdf.Failed, sec.Results[0].Status)
	assert.Equal(t, 0.9, sec.Impact) // CRITICAL
	assert.Contains(t, sec.Results[0].CodeDesc, "****", "secret match must be redacted")
	require.NotNil(t, sec.SourceLocation)
	assert.Equal(t, "app.env", *sec.SourceLocation.Ref)
}

func TestConvert_Empty(t *testing.T) {
	res := convert(t, "empty.json")
	assertSchemaValid(t, res)
	require.Len(t, res.Baselines, 1)
	require.Len(t, res.Baselines[0].Requirements, 1)
	req := res.Baselines[0].Requirements[0]
	assert.Equal(t, "trivy-no-findings", req.ID)
	require.Len(t, req.Results, 1)
	assert.Equal(t, hdf.Passed, req.Results[0].Status)
	assert.Contains(t, req.Results[0].CodeDesc, "Trivy")
}

func TestConvert_VulnWithoutPurlOmitsAffectedPackages(t *testing.T) {
	// A vuln with name+version but no PURL lacks the ecosystem the schema
	// requires; emitting {name,version} would be schema-invalid, so omit it.
	input := []byte(`{"SchemaVersion":2,"ArtifactName":"x","ArtifactType":"filesystem","Results":[{"Class":"os-pkgs","Vulnerabilities":[{"VulnerabilityID":"CVE-Z","PkgName":"p","InstalledVersion":"1","Severity":"LOW"}]}]}`)
	res, err := ConvertTrivyToHDF(input, converterVersion)
	require.NoError(t, err)
	req := findReq(res, "Trivy/CVE-Z")
	require.NotNil(t, req)
	assert.Nil(t, req.AffectedPackages, "a vuln without a PURL must not emit a schema-invalid affectedPackage")
	assertSchemaValid(t, res)
}

func TestConvertMisconf_OmitsMisconfigTypeTagWhenTypeIsEmpty(t *testing.T) {
	// Tags are presence-based: an absent or empty Type must omit the key
	// entirely (the TS peer's behavior), never emit "misconfig_type": "".
	input := []byte(`{"SchemaVersion":2,"ArtifactName":"x","ArtifactType":"filesystem","Results":[{"Target":"Dockerfile","Class":"config","Misconfigurations":[{"ID":"M-TYPE-ABSENT","Title":"t","Severity":"LOW","Status":"FAIL"},{"ID":"M-TYPE-EMPTY","Title":"t","Severity":"LOW","Status":"FAIL","Type":""},{"ID":"M-TYPE-SET","Title":"t","Severity":"LOW","Status":"FAIL","Type":"Dockerfile Security Check"}]}]}`)
	res, err := ConvertTrivyToHDF(input, converterVersion)
	require.NoError(t, err)
	for _, id := range []string{"Trivy/M-TYPE-ABSENT", "Trivy/M-TYPE-EMPTY"} {
		req := findReq(res, id)
		require.NotNil(t, req)
		assert.NotContains(t, req.Tags, "misconfig_type", "%s must omit the tag, not emit an empty string", id)
	}
	set := findReq(res, "Trivy/M-TYPE-SET")
	require.NotNil(t, set)
	assert.Equal(t, "Dockerfile Security Check", set.Tags["misconfig_type"])
}

func TestConvertVuln_EmptySeverityMessageFallsBackToUnknown(t *testing.T) {
	// Absent, empty-string, and null Severity all render as UNKNOWN in the
	// result message; the TS peer must agree on all three.
	input := []byte(`{"SchemaVersion":2,"ArtifactName":"x","ArtifactType":"filesystem","Results":[{"Class":"os-pkgs","Vulnerabilities":[{"VulnerabilityID":"CVE-SEV-ABSENT","PkgName":"p","InstalledVersion":"1"},{"VulnerabilityID":"CVE-SEV-EMPTY","PkgName":"p","InstalledVersion":"1","Severity":""},{"VulnerabilityID":"CVE-SEV-NULL","PkgName":"p","InstalledVersion":"1","Severity":null}]}]}`)
	res, err := ConvertTrivyToHDF(input, converterVersion)
	require.NoError(t, err)
	for _, id := range []string{"Trivy/CVE-SEV-ABSENT", "Trivy/CVE-SEV-EMPTY", "Trivy/CVE-SEV-NULL"} {
		req := findReq(res, id)
		require.NotNil(t, req)
		require.NotNil(t, req.Results[0].Message)
		assert.Equal(t, "Severity: UNKNOWN", *req.Results[0].Message, id)
	}
}

func TestConvert_InvalidInput(t *testing.T) {
	_, err := ConvertTrivyToHDF([]byte("not json"), converterVersion)
	assert.Error(t, err)
}

func TestConvert_EmptyInput(t *testing.T) {
	_, err := ConvertTrivyToHDF([]byte(""), converterVersion)
	assert.Error(t, err)
}

func TestConvert_UnrecognizedShape(t *testing.T) {
	_, err := ConvertTrivyToHDF([]byte(`{"foo":"bar"}`), converterVersion)
	assert.Error(t, err)
}

// --- routing: delegate non-native Trivy formats to their converters ---------

func delegateFixture(t *testing.T, converter, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(shared.GetConvertersDir(), converter, "fixtures", "input", name))
	require.NoError(t, err)
	return data
}

func TestRouting_SARIF(t *testing.T) {
	res, err := ConvertTrivyToHDF(delegateFixture(t, "sarif-to-hdf", "gosec.sarif"), converterVersion)
	require.NoError(t, err)
	require.NotNil(t, res)
	require.NotEmpty(t, res.Baselines)
	// Delegated: the SARIF converter names the baseline after the run's driver,
	// not the native "Trivy Scan" label.
	assert.NotEqual(t, "Trivy Scan", res.Baselines[0].Name)
}

func TestRouting_CycloneDX(t *testing.T) {
	res, err := ConvertTrivyToHDF(delegateFixture(t, "cyclonedx-to-hdf", "minimal-vulns.json"), converterVersion)
	require.NoError(t, err)
	require.NotNil(t, res)
	require.NotEmpty(t, res.Baselines)
	assert.NotEqual(t, "Trivy Scan", res.Baselines[0].Name)
}

func TestRouting_ASFF(t *testing.T) {
	res, err := ConvertTrivyToHDF(delegateFixture(t, "asff-to-hdf", "trivy_sample.json"), converterVersion)
	require.NoError(t, err)
	require.NotEmpty(t, res.Baselines)
	assert.NotEqual(t, "Trivy Scan", res.Baselines[0].Name)
}

func TestRouting_GitLab(t *testing.T) {
	res, err := ConvertTrivyToHDF(delegateFixture(t, "gitlab-to-hdf", "minimal-sast.json"), converterVersion)
	require.NoError(t, err)
	require.NotEmpty(t, res.Baselines)
	assert.NotEqual(t, "Trivy Scan", res.Baselines[0].Name)
}

func TestFingerprint(t *testing.T) {
	fp := registry.GetFingerprint("trivy-to-hdf")
	require.NotNil(t, fp)
	native := map[string]any{"SchemaVersion": float64(2), "ArtifactName": "x", "ArtifactType": "container_image"}
	assert.Equal(t, 0.95, fp.Fingerprint(native))
	assert.Equal(t, "2", fp.DetectVersion(native))
	assert.Equal(t, float64(0), fp.Fingerprint(map[string]any{"SchemaVersion": float64(2)}))         // no name/type
	assert.Equal(t, float64(0), fp.Fingerprint(map[string]any{"version": "2.1.0", "runs": []any{}})) // sarif shape
	assert.Equal(t, float64(0), fp.Fingerprint("not a map"))
	assert.Equal(t, "", fp.DetectVersion("not a map"))
}

func TestMisconfStatus(t *testing.T) {
	assert.Equal(t, hdf.Passed, misconfStatus("PASS"))
	assert.Equal(t, hdf.NotApplicable, misconfStatus("EXCEPTION"))
	assert.Equal(t, hdf.Failed, misconfStatus("FAIL"))
	assert.Equal(t, hdf.Failed, misconfStatus(""))
}

func TestHelperEdges(t *testing.T) {
	assert.Equal(t, hdf.Maven, ecosystemFromPURL("pkg:maven/g/a@1"))
	assert.Equal(t, hdf.Ecosystem(""), ecosystemFromPURL("pkg:unknown/x"))
	assert.Equal(t, "sha256:abc", digestPart("img@sha256:abc"))
	assert.Equal(t, "bare", digestPart("bare"))
	assert.Equal(t, "n", pkgLabel("n", ""))
	assert.Equal(t, "n@1", pkgLabel("n", "1"))
	assert.Equal(t, "amd64", architecture(json.RawMessage(`{"architecture":"amd64"}`)))
	assert.Equal(t, "", architecture(json.RawMessage(``)))
	assert.Equal(t, "", architecture(json.RawMessage(`not json`)))
}

func TestUnratedSeverityMarker(t *testing.T) {
	// Unrated severities (UNKNOWN/absent) carry the shared severity_rating
	// marker on every finding class; rated severities never do.
	input := []byte(`{"SchemaVersion":2,"ArtifactName":"x","ArtifactType":"filesystem","Results":[
		{"Class":"os-pkgs","Vulnerabilities":[
			{"VulnerabilityID":"CVE-UNRATED","PkgName":"p","InstalledVersion":"1","Severity":"UNKNOWN"},
			{"VulnerabilityID":"CVE-RATED","PkgName":"p","InstalledVersion":"1","Severity":"LOW"}]},
		{"Target":"Dockerfile","Class":"config","Misconfigurations":[
			{"ID":"M-UNRATED","Title":"t","Status":"FAIL"},
			{"ID":"M-RATED","Title":"t","Severity":"LOW","Status":"FAIL"}]},
		{"Target":"f","Class":"secret","Secrets":[
			{"RuleID":"unrated-secret","StartLine":1},
			{"RuleID":"rated-secret","Severity":"HIGH","StartLine":2}]},
		{"Target":"L","Class":"license","Licenses":[
			{"PkgName":"pk","Name":"MIT"},
			{"PkgName":"pk2","Name":"MIT","Severity":"LOW"}]}]}`)
	res, err := ConvertTrivyToHDF(input, converterVersion)
	require.NoError(t, err)

	unrated := []string{"Trivy/CVE-UNRATED", "Trivy/M-UNRATED", "Trivy/secret/unrated-secret@f:1", "Trivy/license/pk/MIT"}
	rated := []string{"Trivy/CVE-RATED", "Trivy/M-RATED", "Trivy/secret/rated-secret@f:2", "Trivy/license/pk2/MIT"}
	for _, id := range unrated {
		req := findReq(res, id)
		require.NotNil(t, req, id)
		assert.Equal(t, "unrated", req.Tags["severity_rating"], id)
	}
	for _, id := range rated {
		req := findReq(res, id)
		require.NotNil(t, req, id)
		assert.NotContains(t, req.Tags, "severity_rating", id)
	}
}
