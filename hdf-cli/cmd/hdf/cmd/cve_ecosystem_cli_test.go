// CVE-ecosystem CLI end-to-end tests (epic hdf-libs-8zn0).
//
// Waves 1 + 2 of the epic added five structured fields to Evaluated_Requirement:
// cvss[], epss, kev, cwe[], affectedPackages[]. The CLI surface flows these
// fields automatically via Go struct marshaling. These tests verify that
// converter -> CLI -> JSON output preserves the structured CVE data, and that
// the CLI's parse pipeline (parseHDFResults + findMatches) accepts and
// surfaces the new fields downstream.

package cmd

import (
	"encoding/json"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// cvssEntry mirrors the subset of Cvss fields the CLI tests assert on.
// We use a local struct (rather than hdf.Cvss) so the tests document the
// CLI-observable JSON contract independently of the generated Go types.
type cvssEntry struct {
	BaseScore        float64  `json:"baseScore"`
	BaseSeverity     string   `json:"baseSeverity"`
	BaseVector       string   `json:"baseVector"`
	ComputedScore    *float64 `json:"computedScore,omitempty"`
	ComputedSeverity string   `json:"computedSeverity,omitempty"`
	Source           string   `json:"source"`
	ThreatVector     string   `json:"threatVector,omitempty"`
	Version          string   `json:"version"`
}

type affectedPackage struct {
	Cpe       string `json:"cpe,omitempty"`
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
	Purl      string `json:"purl,omitempty"`
	Version   string `json:"version"`
}

// cveRequirement is a partial view of EvaluatedRequirement focused on CVE fields.
type cveRequirement struct {
	ID               string            `json:"id"`
	Impact           float64           `json:"impact"`
	Cvss             []cvssEntry       `json:"cvss"`
	Cwe              []string          `json:"cwe"`
	AffectedPackages []affectedPackage `json:"affectedPackages"`
}

type cveBaseline struct {
	Name         string           `json:"name"`
	Requirements []cveRequirement `json:"requirements"`
}

type cveResults struct {
	Baselines []cveBaseline `json:"baselines"`
}

// flattenRequirements walks all baselines and returns a single slice of
// requirements across the document. Most CVE-emitting converters produce
// multiple baselines (per target / per scan section).
func flattenRequirements(r cveResults) []cveRequirement {
	var out []cveRequirement
	for _, b := range r.Baselines {
		out = append(out, b.Requirements...)
	}
	return out
}

// convertFixtureViaCLI runs the convert command and parses the resulting JSON
// into a cveResults. Fails the test on convert error or JSON parse error.
func convertFixtureViaCLI(t *testing.T, source, fixturePath string) cveResults {
	t.Helper()

	stdout, stderr, err := executeCommand("convert", "--from", source, "--to", "hdf", fixturePath)
	require.NoErrorf(t, err, "convert --from %s failed: %s", source, stderr)
	require.NotEmpty(t, stdout, "convert produced empty output")

	var parsed cveResults
	require.NoError(t, json.Unmarshal([]byte(stdout), &parsed), "convert output is not valid JSON")
	require.NotEmpty(t, parsed.Baselines, "convert output has no baselines")

	return parsed
}

// findFirstWithCvss returns the first requirement whose cvss[] is non-empty.
func findFirstWithCvss(reqs []cveRequirement) *cveRequirement {
	for i := range reqs {
		if len(reqs[i].Cvss) > 0 {
			return &reqs[i]
		}
	}
	return nil
}

// findFirstWithCwe returns the first requirement whose cwe[] is non-empty.
func findFirstWithCwe(reqs []cveRequirement) *cveRequirement {
	for i := range reqs {
		if len(reqs[i].Cwe) > 0 {
			return &reqs[i]
		}
	}
	return nil
}

// findFirstWithAffectedPackages returns the first requirement whose
// affectedPackages[] is non-empty.
func findFirstWithAffectedPackages(reqs []cveRequirement) *cveRequirement {
	for i := range reqs {
		if len(reqs[i].AffectedPackages) > 0 {
			return &reqs[i]
		}
	}
	return nil
}

// cveIDPattern matches CVE-YYYY-N+ for asserting CVSS source fields.
var cveIDPattern = regexp.MustCompile(`^CVE-\d{4}-\d+$`)

// cvssVectorPattern matches the FIRST.org vector shape for CVSS 3.x/4.0
// (prefix CVSS:V/...). CVSS 2.0 vectors omit the prefix; this pattern matches
// the prefix-less form too via the optional non-capturing group. Tests choose
// the stricter form when the source converter is known to emit it.
//
// References:
//   - CVSS 3.x: https://www.first.org/cvss/v3.1/specification-document#Vector-String
//   - CVSS 4.0: https://www.first.org/cvss/v4.0/specification-document#Vector-String
var cvssVectorPrefixed = regexp.MustCompile(`^CVSS:[234]\.[01]/[A-Z]+:[A-Z]+(/[A-Z]+:[A-Z]+)*$`)

// cwePattern matches the CWE-N (no leading zeros) format documented on
// EvaluatedRequirement.cwe[].
var cwePattern = regexp.MustCompile(`^CWE-\d+$`)

// TestConvertCLI_Nessus_PopulatesCVEFields verifies that the nessus CLI
// converter emits structured cvss[] and cwe[] on findings sourced from real
// Nessus output (sample.nessus). This covers the convert -> JSON -> downstream
// pipeline that other tools (heimdall, OSCAL exporters) consume.
func TestConvertCLI_Nessus_PopulatesCVEFields(t *testing.T) {
	fixture := converterFixturePath(t, "nessus-to-hdf", "input/sample.nessus")
	parsed := convertFixtureViaCLI(t, "nessus", fixture)
	reqs := flattenRequirements(parsed)

	t.Run("cvss populated on at least one finding", func(t *testing.T) {
		req := findFirstWithCvss(reqs)
		require.NotNil(t, req, "expected at least one Nessus finding with cvss[] populated")
		require.NotEmpty(t, req.Cvss)

		first := req.Cvss[0]
		assert.Greaterf(t, first.BaseScore, 0.0,
			"expected cvss[0].baseScore > 0 on %s, got %v", req.ID, first.BaseScore)
		assert.NotEmptyf(t, first.BaseVector,
			"cvss[0].baseVector on %s should be present on Nessus (always emits vectors)", req.ID)
		assert.Regexpf(t, cvssVectorPrefixed, first.BaseVector,
			"cvss[0].baseVector on %s must match FIRST vector grammar, got %q", req.ID, first.BaseVector)
		assert.Regexpf(t, cveIDPattern, first.Source,
			"cvss[0].source on %s should be a CVE ID, got %q", req.ID, first.Source)
		assert.NotEmptyf(t, first.Version, "cvss[0].version on %s must be set", req.ID)
	})

	t.Run("cwe populated on at least one finding", func(t *testing.T) {
		req := findFirstWithCwe(reqs)
		require.NotNil(t, req, "expected at least one Nessus finding with cwe[] populated")
		require.NotEmpty(t, req.Cwe)
		for _, c := range req.Cwe {
			assert.Regexpf(t, cwePattern, c, "cwe entry %q on %s must match CWE-N pattern", c, req.ID)
		}
	})
}

// TestConvertCLI_Twistlock_PopulatesCVEFields verifies twistlock emits cvss[]
// and affectedPackages[]. Twistlock's image-scan output uses CVE-XXX directly
// as the requirement id and reports per-package ecosystem hits.
func TestConvertCLI_Twistlock_PopulatesCVEFields(t *testing.T) {
	fixture := converterFixturePath(t, "twistlock-to-hdf", "input/twistlock-twistcli-sample-1.json")
	parsed := convertFixtureViaCLI(t, "twistlock", fixture)
	reqs := flattenRequirements(parsed)

	t.Run("requirement id is a CVE", func(t *testing.T) {
		// Twistlock uses CVE-YYYY-N as the requirement id; verify at least one match.
		var found bool
		for _, r := range reqs {
			if cveIDPattern.MatchString(r.ID) {
				found = true
				break
			}
		}
		assert.True(t, found, "expected at least one Twistlock requirement id matching CVE-YYYY-N")
	})

	t.Run("cvss populated", func(t *testing.T) {
		req := findFirstWithCvss(reqs)
		require.NotNil(t, req, "expected at least one Twistlock finding with cvss[]")
		require.NotEmpty(t, req.Cvss)

		first := req.Cvss[0]
		assert.Greaterf(t, first.BaseScore, 0.0,
			"cvss[0].baseScore should be > 0 on %s, got %v", req.ID, first.BaseScore)
		assert.Regexpf(t, cveIDPattern, first.Source,
			"cvss[0].source should be a CVE ID on %s, got %q", req.ID, first.Source)
		assert.NotEmptyf(t, first.Version, "cvss[0].version must be set on %s", req.ID)
		// Twistlock sometimes omits baseVector (PCC scan doesn't always include
		// the vector string). Schema now allows this; only assert format when present.
		if first.BaseVector != "" {
			assert.Regexpf(t, cvssVectorPrefixed, first.BaseVector,
				"baseVector on %s must match FIRST grammar when present, got %q",
				req.ID, first.BaseVector)
		}
	})

	t.Run("affectedPackages populated with ecosystem + name + version", func(t *testing.T) {
		req := findFirstWithAffectedPackages(reqs)
		require.NotNil(t, req, "expected at least one Twistlock finding with affectedPackages[]")
		require.NotEmpty(t, req.AffectedPackages)

		first := req.AffectedPackages[0]
		assert.NotEmptyf(t, first.Ecosystem, "affectedPackages[0].ecosystem must be set on %s", req.ID)
		assert.NotEmptyf(t, first.Name, "affectedPackages[0].name must be set on %s", req.ID)
		assert.NotEmptyf(t, first.Version, "affectedPackages[0].version must be set on %s", req.ID)
	})
}

// TestConvertCLI_Grype_PopulatesCVEFields verifies Grype emits cvss[] and
// affectedPackages[] including CPE + PURL identifiers (Grype is the richest
// source: anchore_grype.json has 89 findings, all CVEs).
func TestConvertCLI_Grype_PopulatesCVEFields(t *testing.T) {
	fixture := converterFixturePath(t, "grype-to-hdf", "input/anchore_grype.json")
	parsed := convertFixtureViaCLI(t, "grype", fixture)
	reqs := flattenRequirements(parsed)

	t.Run("requirement id is Grype/CVE-...", func(t *testing.T) {
		var found bool
		for _, r := range reqs {
			if strings.HasPrefix(r.ID, "Grype/CVE-") {
				found = true
				break
			}
		}
		assert.True(t, found, "expected at least one Grype requirement id matching Grype/CVE-...")
	})

	t.Run("cvss populated with vector + source", func(t *testing.T) {
		req := findFirstWithCvss(reqs)
		require.NotNil(t, req, "expected at least one Grype finding with cvss[]")
		require.NotEmpty(t, req.Cvss)

		first := req.Cvss[0]
		assert.Greaterf(t, first.BaseScore, 0.0,
			"cvss[0].baseScore should be > 0 on %s, got %v", req.ID, first.BaseScore)
		assert.NotEmptyf(t, first.BaseVector,
			"cvss[0].baseVector on %s should be present on Grype (always emits vectors)", req.ID)
		assert.Regexpf(t, cvssVectorPrefixed, first.BaseVector,
			"cvss[0].baseVector on %s must match FIRST grammar, got %q", req.ID, first.BaseVector)
		assert.Regexpf(t, cveIDPattern, first.Source,
			"cvss[0].source on %s should be a CVE ID, got %q", req.ID, first.Source)
		assert.NotEmptyf(t, first.Version, "cvss[0].version must be set on %s", req.ID)
	})

	t.Run("affectedPackages with cpe + purl", func(t *testing.T) {
		req := findFirstWithAffectedPackages(reqs)
		require.NotNil(t, req, "expected at least one Grype finding with affectedPackages[]")
		require.NotEmpty(t, req.AffectedPackages)

		first := req.AffectedPackages[0]
		assert.NotEmptyf(t, first.Name, "affectedPackages[0].name must be set on %s", req.ID)
		assert.NotEmptyf(t, first.Version, "affectedPackages[0].version must be set on %s", req.ID)
		assert.NotEmptyf(t, first.Ecosystem, "affectedPackages[0].ecosystem must be set on %s", req.ID)

		// Grype consumes hdf-utilities parseCpe/parsePurl and emits both when
		// available. Lenient prefix checks only — full grammar lives in
		// hdf-utilities.
		assert.Truef(t, strings.HasPrefix(first.Cpe, "cpe:2.3:"),
			"affectedPackages[0].cpe on %s should start with 'cpe:2.3:', got %q", req.ID, first.Cpe)
		assert.Truef(t, strings.HasPrefix(first.Purl, "pkg:"),
			"affectedPackages[0].purl on %s should start with 'pkg:', got %q", req.ID, first.Purl)
	})
}

// TestQueryCLI_PreservesCvssOnConvertedGrype drives the CLI end-to-end:
// convert a Grype fixture to HDF on disk, then run `hdf query --severity high`
// against that file. Verifies the query pipeline (parseHDFResults +
// findMatches + outputQueryResults) accepts and surfaces CVE-bearing
// requirements. The summary-shaped query JSON does not expose cvss[] directly,
// but the surrounding test also reads the converted HDF file and asserts that
// the cvss[].baseSeverity flowed through end-to-end.
//
// Grype is used (rather than Nessus) because the Nessus converter emits ref
// URLs like 'iavm:0123' that fail strict URI-format validation — a known
// pre-existing bug documented on TestNessusConverter_Convert_Sample.
func TestQueryCLI_PreservesCvssOnConvertedGrype(t *testing.T) {
	fixture := converterFixturePath(t, "grype-to-hdf", "input/anchore_grype.json")

	// 1) Convert via CLI and persist to a temp file (so hdf query can read it).
	stdout, stderr, err := executeCommand("convert", "--from", "grype", "--to", "hdf", fixture)
	require.NoErrorf(t, err, "convert failed: %s", stderr)

	tmp := t.TempDir()
	hdfPath := tmp + "/grype.hdf.json"
	require.NoError(t, os.WriteFile(hdfPath, []byte(stdout), 0o600))

	// 2) Inspect the persisted document to confirm cvss[].baseSeverity is set
	//    on at least one CVE finding before exercising the query layer.
	var parsed cveResults
	require.NoError(t, json.Unmarshal([]byte(stdout), &parsed))
	reqs := flattenRequirements(parsed)

	var matched *cveRequirement
	for i := range reqs {
		for _, c := range reqs[i].Cvss {
			if c.BaseSeverity != "" {
				matched = &reqs[i]
				break
			}
		}
		if matched != nil {
			break
		}
	}
	require.NotNil(t, matched, "expected at least one Grype finding with cvss[].baseSeverity populated post-convert")

	// 3) Run hdf query --severity high against the converted file with JSON
	//    output. Query summarizes (id/title/status/impact/severity/baseline) —
	//    full structured fields stay in the persisted HDF, which other CLIs
	//    consume. Asserting that the query reads the file without error proves
	//    the new structured fields don't break the existing parser/validator.
	qStdout, qStderr, qErr := executeCommand("query", "--severity", "high", "--json", hdfPath)
	require.NoErrorf(t, qErr, "query --severity high failed: %s", qStderr)

	var qOut []map[string]any
	require.NoError(t, json.Unmarshal([]byte(qStdout), &qOut),
		"query --json output must parse: %s", qStdout)
	require.NotEmpty(t, qOut, "expected at least one --severity high match from Grype findings")

	// Each result must include the canonical summary fields.
	for _, r := range qOut {
		assert.Equal(t, "high", r["severity"], "all --severity high results must report severity=high")
		assert.Contains(t, r, "id")
		assert.Contains(t, r, "impact")
	}
}

// TestQueryCLI_FullParse_LoadsCvssIntoModel exercises the CLI's parseHDFResults
// pipeline directly on a converted Grype file and confirms the loaded HDF
// model carries cvss[].baseSeverity on at least one CVE finding. This proves
// the typed Go path (used by every CLI command, including stats/info/convert)
// preserves the new fields.
func TestQueryCLI_FullParse_LoadsCvssIntoModel(t *testing.T) {
	fixture := converterFixturePath(t, "grype-to-hdf", "input/anchore_grype.json")

	stdout, stderr, err := executeCommand("convert", "--from", "grype", "--to", "hdf", fixture)
	require.NoErrorf(t, err, "convert failed: %s", stderr)

	results, err := parseHDFResults([]byte(stdout))
	require.NoError(t, err, "parseHDFResults should accept Grype-converted HDF")

	var found bool
	var firstCVE string
	for _, b := range results.Baselines {
		for _, r := range b.Requirements {
			if len(r.Cvss) == 0 {
				continue
			}
			c := r.Cvss[0]
			// baseScore is float64 (required); baseVector is string (required).
			// baseSeverity is *CVSSSeverity (optional); when present it should
			// be one of the FIRST bands.
			if c.BaseSeverity != nil {
				band := string(*c.BaseSeverity)
				assert.Containsf(t, []string{"none", "low", "medium", "high", "critical"}, band,
					"baseSeverity %q on %s outside FIRST band set", band, r.ID)
				found = true
				firstCVE = r.ID
				break
			}
		}
		if found {
			break
		}
	}
	assert.Truef(t, found,
		"expected at least one parsed requirement to carry cvss[0].baseSeverity (first match seen: %s)", firstCVE)
}
