package hdftohtml

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	corpus "github.com/mitre/hdf-libs/hdf-converters/v3/internal/corpus"
	shared "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go"
	fixtures "github.com/mitre/hdf-libs/hdf-fixtures/v3"
	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	validators "github.com/mitre/hdf-libs/hdf-validators/go/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var reportTypes = []ReportType{Executive, Manager, Administrator}

func fixturePath(parts ...string) string {
	return filepath.Join(append([]string{"..", "fixtures"}, parts...)...)
}

// assertGolden compares against a stored golden, or rewrites it under -update.
// Go owns regeneration; the TypeScript peer only verifies, which is what holds
// the two implementations to the same bytes.
func assertGolden(t *testing.T, path string, actual []byte) {
	t.Helper()
	if shared.UpdateSnapshots() {
		require.NoError(t, os.WriteFile(path, actual, 0o600))
		t.Logf("updated %s", path)
		return
	}
	expected, err := os.ReadFile(path)
	require.NoError(t, err, "missing golden; regenerate with: go test ./converters/hdf-to-html/go/ -update")
	require.Equal(t, string(expected), string(actual),
		"output changed; if intentional regenerate with: go test ./converters/hdf-to-html/go/ -update")
}

func richInput(t *testing.T) []byte {
	t.Helper()
	input, err := os.ReadFile(fixturePath("input", "rich.json"))
	require.NoError(t, err)
	return input
}

// rich.json is schema-confirmed, not real (see fixtures/provenance.txt), so the
// schema check that vouches for it is kept running here.
func TestRichFixture_IsValidHDFAndCarriesWhatItIsFor(t *testing.T) {
	input := richInput(t)
	result := validators.ValidateResults(input)
	require.True(t, result.Valid, "rich.json must validate as hdf-results: %s", result.Error())

	var doc hdf.HDFResults
	require.NoError(t, json.Unmarshal(input, &doc))
	require.NotNil(t, doc.SystemRef)
	require.NotNil(t, doc.Runner)
	require.Len(t, doc.Components, 2)
	for _, c := range doc.Components {
		require.NotEmpty(t, c.Labels, c.Name)
		require.NotEmpty(t, c.ExternalIDS, c.Name)
		require.NotNil(t, c.ComponentID, c.Name)
	}
	overrides := 0
	for _, b := range doc.Baselines {
		for _, r := range b.Requirements {
			overrides += len(r.StatusOverrides)
		}
	}
	require.Equal(t, 1, overrides)
}

func TestConvertHDFToHTML_RichGolden(t *testing.T) {
	input := richInput(t)
	for _, reportType := range reportTypes {
		t.Run(string(reportType), func(t *testing.T) {
			out, err := ConvertHDFToHTMLWithOptions(input, Options{ReportType: reportType})
			require.NoError(t, err)
			require.NoError(t, htmlStructureValidator{}.Validate(out))
			assertSelfContained(t, string(out), true)
			assertGolden(t, fixturePath("expected", "rich."+string(reportType)+".html"), out)
		})
	}
}

// The acceptance criteria, stated against the fixture built to carry them.
func TestConvertHDFToHTML_RichReportShowsWhatTheLegacyRouteDrops(t *testing.T) {
	out, err := ConvertHDFToHTML(richInput(t))
	require.NoError(t, err)
	html := string(out)

	for _, want := range []string{
		"systems/portal.hdf-system.json",
		"code.jquery.com", "mymac.com",
		"a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d", "b7c8d9e0-1a2b-4c3d-8e4f-5a6b7c8d9e0f",
		chip("system", "Portal"), chip("environment", "production"),
		chip("cmdb", "CI0012345"), chip("cmdb", "CI0067890"), chip("emass", "1234"),
		"zap-runner", "scanner01",
		"issm@example.gov", "governing",
	} {
		assert.Contains(t, html, want)
	}
	assert.Equal(t, 2, strings.Count(html, `<details class="fold component"`))
}

// corpusRejected marks a corpus case the converter refuses; the two languages
// phrase the error differently, so only the fact of refusing is compared.
const corpusRejected = "REJECTED"

func TestConvertHDFToHTML_CorpusOutputGolden(t *testing.T) {
	outputs := make(map[string]string, len(corpus.ResultsCorpus()))
	for _, c := range corpus.ResultsCorpus() {
		out, err := corpus.ConvertNoPanic(ConvertHDFToHTML, c.Input)
		if err != nil {
			outputs[c.Name] = corpusRejected
			continue
		}
		outputs[c.Name] = bodyOf(t, string(out))
	}

	actual, err := json.MarshalIndent(outputs, "", "  ")
	require.NoError(t, err)
	assertGolden(t, fixturePath("expected", "corpus-outputs.json"), append(actual, '\n'))
}

// bodyOf drops the document head, which is identical in every report and is
// already pinned whole by the rich goldens.
func bodyOf(t *testing.T, html string) string {
	t.Helper()
	i := strings.Index(html, "<body>")
	require.GreaterOrEqual(t, i, 0)
	return html[i:]
}

// Real data is where the two languages are most likely to part company, and a
// real report is too large to be worth keeping whole, so its digest is pinned.
func TestConvertHDFToHTML_RealDocumentDigests(t *testing.T) {
	digests := map[string]string{}
	for _, reportType := range reportTypes {
		out, err := ConvertHDFToHTMLWithOptions(fixtures.Results.MergeZap, Options{ReportType: reportType})
		require.NoError(t, err)
		require.NoError(t, htmlStructureValidator{}.Validate(out))
		assertSelfContained(t, string(out), true)
		sum := sha256.Sum256(out)
		digests["merge-zap."+string(reportType)] = hex.EncodeToString(sum[:])
	}

	// The enrich pass's own golden: results carrying STIX objects from a real
	// bundle, read in place from the fixtures that pass is tested against.
	enriched, err := os.ReadFile(filepath.Join("..", "..", "..", "shared", "enrich-fixtures", "results-enriched.golden.json"))
	require.NoError(t, err)
	out, err := ConvertHDFToHTML(enriched)
	require.NoError(t, err)
	require.NoError(t, htmlStructureValidator{}.Validate(out))
	assertSelfContained(t, string(out), true)
	require.Contains(t, string(out), `<details class="doc"><summary>Embedded document</summary>`,
		"the enriched document must exercise the embedded-object path")
	sum := sha256.Sum256(out)
	digests["results-enriched.administrator"] = hex.EncodeToString(sum[:])

	// The two real documents reported together.
	combined, err := ConvertHDFDocumentsToHTML([]Document{
		{Name: "merge-zap.json", Data: fixtures.Results.MergeZap},
		{Name: "results-enriched.golden.json", Data: enriched},
	}, Options{})
	require.NoError(t, err)
	require.NoError(t, htmlStructureValidator{}.Validate(combined))
	assertSelfContained(t, string(combined), true)
	sum = sha256.Sum256(combined)
	digests["aggregate.administrator"] = hex.EncodeToString(sum[:])

	actual, err := json.MarshalIndent(digests, "", "  ")
	require.NoError(t, err)
	assertGolden(t, fixturePath("expected", "real-digests.json"), append(actual, '\n'))
}

// The export-side ground-truth anchor: counts derived from the input, not from
// the converter. Every component gets one block and every requirement one entry.
func TestConvertHDFToHTML_OutputCountAnchor(t *testing.T) {
	var doc struct {
		Components []json.RawMessage `json:"components"`
		Baselines  []struct {
			Requirements []json.RawMessage `json:"requirements"`
		} `json:"baselines"`
	}
	require.NoError(t, json.Unmarshal(fixtures.Results.MergeZap, &doc))
	requirements := 0
	for _, b := range doc.Baselines {
		requirements += len(b.Requirements)
	}
	require.Positive(t, requirements)
	require.Greater(t, len(doc.Components), 1, "the anchor needs a multi-component document")

	out, err := ConvertHDFToHTML(fixtures.Results.MergeZap)
	require.NoError(t, err)
	html := string(out)
	assert.Equal(t, len(doc.Components), strings.Count(html, `<details class="fold component"`))
	assert.Equal(t, requirements, strings.Count(html, `<details class="requirement `))
	assert.Equal(t, len(doc.Baselines), strings.Count(html, `class="fold group baseline"`))

	executive, err := ConvertHDFToHTMLWithOptions(fixtures.Results.MergeZap, Options{ReportType: Executive})
	require.NoError(t, err)
	assert.Equal(t, len(doc.Components), strings.Count(string(executive), `<details class="fold component"`))
	assert.Zero(t, strings.Count(string(executive), `<details class="requirement `))
}

// aggregateInputs are two fixtures reported together, named as the CLI names them.
func aggregateInputs(t *testing.T) []Document {
	t.Helper()
	return []Document{
		{Name: "rich.json", Data: richInput(t)},
		{Name: "finding-detail.json", Data: findingDetail(t)},
	}
}

func TestConvertHDFDocumentsToHTML_Golden(t *testing.T) {
	for _, reportType := range reportTypes {
		t.Run(string(reportType), func(t *testing.T) {
			out, err := ConvertHDFDocumentsToHTML(aggregateInputs(t), Options{ReportType: reportType})
			require.NoError(t, err)
			require.NoError(t, htmlStructureValidator{}.Validate(out))
			assertSelfContained(t, string(out), true)
			assertGolden(t, fixturePath("expected", "aggregate."+string(reportType)+".html"), out)
		})
	}
}

// Several documents become one report: combined counts, then each document's
// context, components and results under its own name.
func TestConvertHDFDocumentsToHTML_AggregatesAcrossSources(t *testing.T) {
	out, err := ConvertHDFDocumentsToHTML(aggregateInputs(t), Options{})
	require.NoError(t, err)
	html := string(out)

	for _, want := range []string{
		`<a href="#sources">Sources</a>`,
		`<h2 id="sources-heading">Sources (2)</h2>`,
		"<details class=\"fold\" id=\"source-1\">\n<summary><h3>rich.json</h3>",
		// two facts only, so this one is shown open
		"<details class=\"fold\" id=\"source-2\" open=\"open\">\n<summary><h3>finding-detail.json</h3>",
		`<table class="summary" aria-label="Status by source">`,
		// rich.json: 1 passed (waived), 3 failed; finding-detail.json: 1 not applicable (false positive)
		`<tr><th scope="row"><a href="#source-1">rich.json</a></th><td>1</td><td>3</td><td>0</td><td>0</td><td>0</td><td>4</td><td>25.00%</td></tr>`,
		`<tr><th scope="row"><a href="#source-2">finding-detail.json</a></th><td>0</td><td>0</td><td>0</td><td>1</td><td>0</td><td>1</td><td>0.00%</td></tr>`,
		wantSummaryRow("All sources", "1", "3", "0", "1", "0", "5", "25.00%"),
		wantSummaryRow("rich.json \u203a OWASP ZAP Scan: mymac.com", "1", "2", "0", "0", "0", "3", "33.33%"),
		wantSummaryRow("finding-detail.json \u203a sast", "0", "0", "0", "1", "0", "1", "0.00%"),
		wantSummaryRow("All baselines", "1", "3", "0", "1", "0", "5", "25.00%"),
		`<h2 id="components-heading">Components (2)</h2>`,
		"<dt>Source</dt><dd>rich.json</dd>",
		`<summary><h3>rich.json</h3><span class="count">4</span></summary>`,
		`<summary><h3>finding-detail.json</h3><span class="count">1</span></summary>`,
		`<summary><h4>sast</h4><span class="count">1</span></summary>`,
		"<h5>Result Details</h5>", "<h5>Test Results</h5>", "<h5>Overrides</h5>", "<h5>Code</h5>",
		"Effective status evaluated for each source as of its own assessment time.",
	} {
		assert.Contains(t, html, want)
	}
	assert.NotContains(t, html, `id="assessment"`, "the aggregated layout lists sources instead")
	assert.Equal(t, 5, strings.Count(html, `<details class="requirement `))
	assert.Equal(t, 1, strings.Count(html, "<h1"))
}

// Each document's overrides are judged at that document's own assessment time,
// so the same waiver can be in force in one source and expired in another.
func TestConvertHDFDocumentsToHTML_EachSourceHasItsOwnAssessmentTime(t *testing.T) {
	early := waived(t, "2020-06-01T00:00:00Z") // assessed 2020-01-01: waiver in force
	late := waived(t, "2020-06-01T00:00:00Z")
	lateTime := mustTime(t, "2021-01-01T00:00:00Z") // assessed after the waiver lapsed
	late.Timestamp = &lateTime
	marshal := func(doc hdf.HDFResults) []byte {
		data, err := json.Marshal(doc)
		require.NoError(t, err)
		return data
	}

	out, err := ConvertHDFDocumentsToHTML([]Document{{Name: "early.json", Data: marshal(early)}, {Name: "late.json", Data: marshal(late)}}, Options{})
	require.NoError(t, err)
	html := string(out)
	assert.Contains(t, html, `<a href="#source-1">early.json</a></th><td>1</td><td>0</td>`)
	assert.Contains(t, html, `<a href="#source-2">late.json</a></th><td>0</td><td>1</td>`)
	assert.Contains(t, html, "<td>governing</td>")
	assert.Contains(t, html, "<td>expired</td>")
}

func TestConvertHDFDocumentsToHTML_Errors(t *testing.T) {
	_, err := ConvertHDFDocumentsToHTML(nil, Options{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no documents")

	_, err = ConvertHDFDocumentsToHTML([]Document{{Name: "ok.json", Data: richInput(t)}, {Name: "bad.json", Data: []byte(`{"overrides":[]}`)}}, Options{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "bad.json", "the error names the document that is not results")

	_, err = ConvertHDFDocumentsToHTML(aggregateInputs(t), Options{ReportType: "auditor"})
	require.Error(t, err)
}

// A single named document still gets the aggregated layout, so a directory that
// happens to hold one file reports the same way as one that holds ten.
func TestConvertHDFDocumentsToHTML_OneDocument(t *testing.T) {
	out, err := ConvertHDFDocumentsToHTML([]Document{{Name: "only.json", Data: []byte(`{"baselines":[]}`)}}, Options{})
	require.NoError(t, err)
	html := string(out)
	assert.Contains(t, html, `<h2 id="sources-heading">Sources (1)</h2>`)
	assert.Contains(t, html, "The documents name no components.")
	assert.NotContains(t, html, "evaluated for each source")
}
