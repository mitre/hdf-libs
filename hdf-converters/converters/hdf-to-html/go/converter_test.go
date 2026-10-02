package hdftohtml

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	corpus "github.com/mitre/hdf-libs/hdf-converters/v3/internal/corpus"
	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	testhdf "github.com/mitre/hdf-libs/hdf-schema/testhdf/go/v3"
	hdfutil "github.com/mitre/hdf-libs/hdf-utilities/go/v3"
	validators "github.com/mitre/hdf-libs/hdf-validators/go/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const farFuture = "2099-12-31T00:00:00Z"

func mustTime(t *testing.T, s string) time.Time {
	t.Helper()
	parsed, err := time.Parse(time.RFC3339, s)
	require.NoError(t, err)
	return parsed
}

// renderDoc marshals a builder document, checks it is valid HDF, and converts it.
func renderDoc(t *testing.T, doc hdf.HDFResults, reportType ReportType) string {
	t.Helper()
	input, err := json.Marshal(doc)
	require.NoError(t, err)
	require.True(t, validators.ValidateResults(input).Valid, "the test document must be valid HDF: %s",
		validators.ValidateResults(input).Error())

	out, err := ConvertHDFToHTMLWithOptions(input, Options{ReportType: reportType})
	require.NoError(t, err)
	return string(out)
}

func richDoc(t *testing.T) hdf.HDFResults {
	t.Helper()
	doc := testhdf.Doc(testhdf.Baseline("rhel9-stig",
		testhdf.Req("SV-257777", testhdf.Title("Vendor support"), testhdf.Impact(0.7),
			testhdf.Status(hdf.Failed), testhdf.Code("describe file('/etc/x') do\n  it { should exist }\nend"),
			testhdf.Tag("nist", []string{"CM-6", "SI-2"}), testhdf.Tag("cci", []string{"CCI-000366"})),
		testhdf.Req("SV-257778", testhdf.Title("Banner"), testhdf.Impact(0.5), testhdf.Status(hdf.Passed)),
	))
	ts := testhdf.DefaultStartTime
	doc.Timestamp = &ts
	doc.SystemRef = hdfutil.Ptr("systems/portal.hdf-system.json")
	doc.PlanRef = hdfutil.Ptr("plans/q3.hdf-plan.json")
	doc.Tool = &hdf.Tool{Name: hdfutil.Ptr("InSpec"), Version: hdfutil.Ptr("5.22.3")}
	doc.Generator = &hdf.Generator{Name: "hdf-converters", Version: "3.7.1"}
	doc.Runner = &hdf.Runner{Name: "ci-runner-07", Hostname: hdfutil.Ptr("runner07"), Architecture: hdfutil.Ptr("x86_64")}
	doc.Components = []hdf.Component{
		testhdf.Component("web01", hdf.Host, func(c *hdf.Component) {
			c.ComponentID = hdfutil.Ptr("3f2504e0-4f89-11d3-9a0c-0305e82c3301")
			c.FQDN = hdfutil.Ptr("web01.prod.example.com")
			c.Labels = map[string]string{"system": "Portal", "environment": "production"}
			c.ExternalIDS = map[string]string{"cmdb": "CI0012345", "aws": "i-0abc123def456789"}
		}),
		testhdf.Component("db01", hdf.Host, func(c *hdf.Component) {
			c.ComponentID = hdfutil.Ptr("a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d")
			c.ExternalIDS = map[string]string{"emass": "1234"}
		}),
		testhdf.Component("registry.example.com/portal:1.4", hdf.ContainerImage),
	}
	return doc
}

func TestConvertHDFToHTML_ShowsEveryComponent(t *testing.T) {
	out := renderDoc(t, richDoc(t), Administrator)

	assert.Equal(t, 3, strings.Count(out, `<details class="fold component"`), "one block per component")
	for _, want := range []string{
		"web01", "db01", "registry.example.com/portal:1.4",
		"host", "containerImage",
		"3f2504e0-4f89-11d3-9a0c-0305e82c3301", "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d",
		"web01.prod.example.com",
		chip("environment", "production"), chip("system", "Portal"),
		chip("aws", "i-0abc123def456789"), chip("cmdb", "CI0012345"), chip("emass", "1234"),
	} {
		assert.Contains(t, out, want)
	}
	assert.Less(t, strings.Index(out, `<span class="k">aws</span>`), strings.Index(out, `<span class="k">cmdb</span>`), "map keys render sorted")
}

// chip is how a label or external id is rendered.
func chip(key, value string) string {
	return `<li><span class="k">` + key + `</span><span class="v">` + value + "</span></li>"
}

// detail is one row of a requirement's Result Details table.
func detail(heading, value string) string {
	return `<tr><th scope="row">` + heading + "</th><td>" + value + "</td></tr>"
}

func badge(class, label string) string {
	return `<span class="status c-` + class + `">` + label + "</span>"
}

func TestConvertHDFToHTML_ShowsDocumentContext(t *testing.T) {
	out := renderDoc(t, richDoc(t), Executive)
	for _, want := range []string{
		"systems/portal.hdf-system.json", "plans/q3.hdf-plan.json",
		"InSpec 5.22.3", "hdf-converters 3.7.1", "2020-01-01T00:00:00Z",
		"ci-runner-07", "runner07", "x86_64",
	} {
		assert.Contains(t, out, want)
	}
}

func TestConvertHDFToHTML_ReportTypes(t *testing.T) {
	doc := richDoc(t)
	executive := renderDoc(t, doc, Executive)
	manager := renderDoc(t, doc, Manager)
	administrator := renderDoc(t, doc, Administrator)

	for name, out := range map[string]string{"executive": executive, "manager": manager, "administrator": administrator} {
		assert.Contains(t, out, "rhel9-stig", name+" names the baseline")
		assert.Contains(t, out, "50.00%", name+" shows compliance")
	}

	assert.NotContains(t, executive, "SV-257777", "executive stops at the summary")
	assert.Contains(t, manager, "SV-257777")
	assert.Contains(t, manager, "Vendor support")
	assert.NotContains(t, manager, "should exist", "manager omits test code")
	assert.Contains(t, administrator, "describe file(&#39;/etc/x&#39;) do\n  it { should exist }\nend")

	assert.Contains(t, executive, "Report type: Executive")
	assert.Contains(t, manager, "Report type: Manager")
	assert.Contains(t, administrator, "Report type: Administrator")
}

func TestConvertHDFToHTML_DefaultIsAdministrator(t *testing.T) {
	input, err := json.Marshal(richDoc(t))
	require.NoError(t, err)

	byDefault, err := ConvertHDFToHTML(input)
	require.NoError(t, err)
	explicit, err := ConvertHDFToHTMLWithOptions(input, Options{ReportType: Administrator})
	require.NoError(t, err)
	assert.Equal(t, string(explicit), string(byDefault))
}

func TestParseReportType(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want ReportType
	}{
		{"", Administrator}, {"executive", Executive}, {"Manager", Manager}, {"ADMINISTRATOR", Administrator}, {" manager ", Manager},
	} {
		got, err := ParseReportType(tc.in)
		require.NoError(t, err, tc.in)
		assert.Equal(t, tc.want, got, tc.in)
	}

	_, err := ParseReportType("auditor")
	require.Error(t, err)
	assert.Contains(t, err.Error(), `"auditor"`)
	assert.Contains(t, err.Error(), "executive, manager, administrator")

	_, err = ConvertHDFToHTMLWithOptions([]byte(`{"baselines":[]}`), Options{ReportType: "auditor"})
	require.Error(t, err)
}

// waived builds a document whose one failed requirement carries a waiver to
// passed, expiring at expiresAt, assessed at the builder's fixed 2020-01-01.
func waived(t *testing.T, expiresAt string) hdf.HDFResults {
	t.Helper()
	passed := hdf.Passed
	req := testhdf.Req("V-1", testhdf.Title("Waived control"), testhdf.Impact(0.7), testhdf.Status(hdf.Failed))
	req.StatusOverrides = []hdf.StatusOverride{{
		Type:      hdf.OverrideTypeWaiver,
		Status:    &passed,
		Reason:    "Compensating control in place",
		AppliedBy: hdf.Identity{Type: hdf.Email, Identifier: "issm@example.gov"},
		AppliedAt: mustTime(t, "2019-06-01T00:00:00Z"),
		ExpiresAt: mustTime(t, expiresAt),
	}}
	doc := testhdf.Results(req)
	ts := testhdf.DefaultStartTime
	doc.Timestamp = &ts
	return doc
}

func TestConvertHDFToHTML_EffectiveStatusBesideOriginal(t *testing.T) {
	out := renderDoc(t, waived(t, farFuture), Manager)

	assert.Contains(t, out, detail("Effective status", badge("passed", "Passed")))
	assert.Contains(t, out, detail("Assessed status", badge("failed", "Failed")))
	for _, want := range []string{"waiver", "Compensating control in place", "issm@example.gov", "2019-06-01T00:00:00Z", farFuture, "governing"} {
		assert.Contains(t, out, want)
	}
	assert.Contains(t, out, "100.00%", "the summary counts the effective status")
	assert.Contains(t, out, `<span class="lbl">Passed</span><span class="sub">0 individual checks passed</span>`,
		"a requirement passed by a waiver does not turn its failed check into a passed one")
	assert.Contains(t, out, "Effective status evaluated as of 2020-01-01T00:00:00Z")
}

// An override is judged against the document's own assessment time, never the
// wall clock, so a report rendered next year is the report rendered today.
func TestConvertHDFToHTML_OverrideExpiryIsJudgedAtAssessmentTime(t *testing.T) {
	expired := renderDoc(t, waived(t, "2019-12-31T00:00:00Z"), Manager)
	assert.Contains(t, expired, detail("Effective status", badge("failed", "Failed")))
	assert.Contains(t, expired, "0.00%")
	assert.Contains(t, expired, "<td>expired</td>")

	// Expired by the wall clock, still in force when the assessment ran.
	inForceThen := renderDoc(t, waived(t, "2020-06-01T00:00:00Z"), Manager)
	assert.Contains(t, inForceThen, detail("Effective status", badge("passed", "Passed")))
}

func TestConvertHDFToHTML_AssessmentTimeFallsBackToLatestResult(t *testing.T) {
	doc := waived(t, "2019-12-31T00:00:00Z")
	doc.Timestamp = nil
	out := renderDoc(t, doc, Manager)
	assert.Contains(t, out, "Effective status evaluated as of 2020-01-01T00:00:00Z")
	assert.Contains(t, out, detail("Effective status", badge("failed", "Failed")))
}

func TestConvertHDFToHTML_Deterministic(t *testing.T) {
	input, err := json.Marshal(richDoc(t))
	require.NoError(t, err)
	first, err := ConvertHDFToHTML(input)
	require.NoError(t, err)
	for range 5 {
		again, err := ConvertHDFToHTML(input)
		require.NoError(t, err)
		require.Equal(t, string(first), string(again))
	}
}

// elementsThatLoad are the tags that make a browser fetch something or leave the page.
var elementsThatLoad = []string{"<link", "<img", "<iframe", "<object", "<embed", "<video", "<audio", "<source",
	"<form", "<base", "<svg", "<meta http-equiv=\"refresh\""}

var (
	// attributeInTag finds one attribute inside a tag. Document text is escaped,
	// so it can never sit inside one.
	loadingAttribute = regexp.MustCompile(`<[^>]*\s(src|srcset|data|action|formaction|poster|background|on[a-z]+)\s*=`)
	hrefAttribute    = regexp.MustCompile(`<[^>]*\shref\s*=\s*"([^"]*)"`)
	styleAttribute   = regexp.MustCompile(`<[^>]*\sstyle\s*=\s*"([^"]*)"`)
	// The only inline styles are numbers handed to the stylesheet as custom properties.
	numericStyle = regexp.MustCompile(`^--(n|pct):[0-9]+(\.[0-9]+)?$`)
	scriptBlock  = regexp.MustCompile(`(?s)<script>(.*?)</script>`)
)

// assertSelfContained checks the report can neither fetch anything nor run
// anything but its own static script, which the content security policy pins by
// hash.
func assertSelfContained(t *testing.T, out string, wantScript bool) {
	t.Helper()
	lower := strings.ToLower(out)
	for _, forbidden := range elementsThatLoad {
		assert.NotContains(t, lower, forbidden, "the report must not contain %q", forbidden)
	}
	assert.NotRegexp(t, loadingAttribute, lower)
	for _, m := range hrefAttribute.FindAllStringSubmatch(out, -1) {
		assert.True(t, strings.HasPrefix(m[1], "#"), "href %q must stay inside the page", m[1])
	}
	for _, m := range styleAttribute.FindAllStringSubmatch(out, -1) {
		assert.Regexp(t, numericStyle, m[1], "an inline style may only carry a number")
	}

	require.Equal(t, 1, strings.Count(lower, "<style>"), "exactly one stylesheet, inline")
	css := lower[strings.Index(lower, "<style>"):strings.Index(lower, "</style>")]
	assert.NotContains(t, css, "url(")
	assert.NotContains(t, css, "@import")
	assert.NotContains(t, css, "http")

	policy := "default-src 'none'; style-src 'unsafe-inline'"
	scripts := scriptBlock.FindAllStringSubmatch(out, -1)
	assert.Equal(t, strings.Count(lower, "<script"), len(scripts), "every script is inline and attribute-free")
	if wantScript {
		require.Len(t, scripts, 1)
		sum := sha256.Sum256([]byte(scripts[0][1]))
		policy += "; script-src 'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) + "'"
	} else {
		require.Empty(t, scripts)
	}
	assert.Contains(t, out, `<meta http-equiv="Content-Security-Policy" content="`+policy+`" />`,
		"the policy must admit exactly the script the report carries, by hash")
}

func TestAssertSelfContained_PatternsCanMatch(t *testing.T) {
	assert.Regexp(t, loadingAttribute, `<p onclick="x">`)
	assert.Regexp(t, loadingAttribute, `<img alt="" src="x">`)
	assert.NotRegexp(t, loadingAttribute, `&lt;img src=x onerror=alert(1)&gt;`)
	assert.NotRegexp(t, loadingAttribute, `<button type="button" data-status="all">`)
	assert.Equal(t, "https://x", hrefAttribute.FindStringSubmatch(`<a href="https://x">`)[1])
	assert.NotRegexp(t, numericStyle, "--n:1;background:red")
	assert.Regexp(t, numericStyle, "--pct:33.33")
}

func TestScriptHashMatchesScript(t *testing.T) {
	// The element's content is the newline after <script> plus the script itself.
	sum := sha256.Sum256([]byte("\n" + script))
	assert.Equal(t, "sha256-"+base64.StdEncoding.EncodeToString(sum[:]), scriptHash)
	assert.NotContains(t, script, "<", "the script must stay valid inside well-formed markup")
	assert.NotContains(t, script, "&")
}

func TestConvertHDFToHTML_SelfContained(t *testing.T) {
	for _, reportType := range []ReportType{Executive, Manager, Administrator} {
		assertSelfContained(t, renderDoc(t, richDoc(t), reportType), true)
	}
}

const hostile = `</pre></dd><script>alert(1)</script><img src=x onerror=alert(1)>"'&`

func hostileDoc(t *testing.T) hdf.HDFResults {
	t.Helper()
	passed := hdf.Passed
	req := testhdf.Req(hostile+"id", testhdf.Title(hostile+"title"), testhdf.Impact(0.5), testhdf.Status(hdf.Failed),
		testhdf.Desc(hostile+"desc"), testhdf.AddDesc(hostile+"label", hostile+"data"), testhdf.Code(hostile+"code"),
		testhdf.Tag("nist", []string{hostile + "nist"}), testhdf.Tag("cci", []string{hostile + "cci"}))
	req.Results[0].CodeDesc = hostile + "codeDesc"
	req.Results[0].Message = hdfutil.Ptr(hostile + "message")
	req.StatusOverrides = []hdf.StatusOverride{{
		Type: hdf.OverrideTypeWaiver, Status: &passed, Reason: hostile + "reason",
		AppliedBy: hdf.Identity{Type: hdf.Email, Identifier: hostile + "identifier"},
		AppliedAt: mustTime(t, "2019-06-01T00:00:00Z"), ExpiresAt: mustTime(t, farFuture),
	}}
	baseline := testhdf.Baseline(hostile+"baseline", req)
	baseline.Title = hdfutil.Ptr(hostile + "baselineTitle")
	baseline.Version = hdfutil.Ptr(hostile + "baselineVersion")
	doc := testhdf.Doc(baseline)
	doc.SystemRef = hdfutil.Ptr("ref" + hostile)
	doc.Tool = &hdf.Tool{Name: hdfutil.Ptr(hostile + "tool"), Version: hdfutil.Ptr(hostile + "toolVersion")}
	doc.Generator = &hdf.Generator{Name: hostile + "generator", Version: hostile + "generatorVersion"}
	doc.Runner = &hdf.Runner{Name: hostile + "runner", Hostname: hdfutil.Ptr(hostile + "runnerHost")}
	doc.Components = []hdf.Component{testhdf.Component(hostile+"component", hdf.Host, func(c *hdf.Component) {
		c.Description = hdfutil.Ptr(hostile + "componentDescription")
		c.Labels = map[string]string{hostile + "labelKey": hostile + "labelValue"}
		c.ExternalIDS = map[string]string{hostile + "scheme": hostile + "externalValue"}
	})}
	return doc
}

func TestConvertHDFToHTML_EscapesEveryRenderedField(t *testing.T) {
	// systemRef is a uri-reference, so this document is built for the converter
	// rather than held to the schema: a report must be safe on input no
	// validator has seen.
	input, err := json.Marshal(hostileDoc(t))
	require.NoError(t, err)
	out, err := ConvertHDFToHTML(input)
	require.NoError(t, err)
	html := string(out)

	assert.NotContains(t, html, "<script>alert", "no document string may open a tag")
	assert.Equal(t, 1, strings.Count(html, "<script"), "the report's own script is the only one")
	assert.NotContains(t, html, "<img", "no document string may open a tag")
	assert.NotContains(t, html, hostile)
	assertSelfContained(t, html, true)

	escaped := `&lt;/pre&gt;&lt;/dd&gt;&lt;script&gt;alert(1)&lt;/script&gt;&lt;img src=x onerror=alert(1)&gt;&quot;&#39;&amp;`
	for _, field := range []string{
		"id", "title", "desc", "label", "data", "code", "nist", "cci", "codeDesc", "message", "reason", "identifier",
		"baseline", "baselineTitle", "baselineVersion", "tool", "toolVersion", "generator", "generatorVersion",
		"runner", "runnerHost", "component", "componentDescription", "labelKey", "labelValue", "scheme", "externalValue",
	} {
		assert.Contains(t, html, escaped+field, "%s must be rendered, escaped", field)
	}
	require.NoError(t, htmlStructureValidator{}.Validate(out), "hostile text must not unbalance the markup")
}

func TestConvertHDFToHTML_ControlCharactersAreReplaced(t *testing.T) {
	doc := testhdf.Results(testhdf.Req("V-1", testhdf.Title("a\x00b\x0bc\x7fd\te\nf")))
	input, err := json.Marshal(doc)
	require.NoError(t, err)
	out, err := ConvertHDFToHTML(input)
	require.NoError(t, err)
	assert.Contains(t, string(out), "a�b�c�d\te\nf", "tab and newline survive; other control characters cannot appear in HTML")
	require.NoError(t, htmlStructureValidator{}.Validate(out))
}

// HDF prose is carried verbatim: a description's line structure and edge
// whitespace reach the report unchanged. The newline after <pre> is the one an
// HTML parser discards, so content starting with a newline keeps it.
func TestConvertHDFToHTML_ProseIsCarriedVerbatim(t *testing.T) {
	prose := "\n  Verify the setting:\r\n\n    $ sysctl kernel.dmesg_restrict\n\tkernel.dmesg_restrict = 1  \n"
	out := renderDoc(t, testhdf.Results(testhdf.Req("V-1", testhdf.Desc(prose), testhdf.Impact(0.5))), Manager)
	assert.Contains(t, out, "<pre class=\"prose\">\n"+strings.ReplaceAll(prose, "\r", "&#13;")+"</pre>",
		"a carriage return is written as a reference so the parser cannot fold it away")
}

func TestConvertHDFToHTML_SummaryCountsAndCompliance(t *testing.T) {
	doc := testhdf.Doc(
		testhdf.Baseline("one",
			testhdf.Req("A", testhdf.Impact(0.5), testhdf.Status(hdf.Passed)),
			testhdf.Req("B", testhdf.Impact(0.5), testhdf.Status(hdf.Passed)),
			testhdf.Req("C", testhdf.Impact(0.5), testhdf.Status(hdf.Failed)),
			testhdf.Req("D", testhdf.Impact(0), testhdf.Status(hdf.Passed)),
		),
		testhdf.Baseline("two",
			testhdf.Req("E", testhdf.Impact(0.5), testhdf.Status(hdf.NotReviewed)),
			testhdf.Req("F", testhdf.Impact(0.5), testhdf.Status(hdf.Error)),
		),
	)
	out := renderDoc(t, doc, Executive)

	// passed, failed, notReviewed, notApplicable, error, total, compliance
	assert.Contains(t, out, wantSummaryRow("one", "2", "1", "0", "1", "0", "4", "66.67%"))
	assert.Contains(t, out, wantSummaryRow("two", "0", "0", "1", "0", "1", "2", "0.00%"))
	assert.Contains(t, out, wantSummaryRow("All baselines", "2", "1", "1", "1", "1", "6", "40.00%"))
}

func wantSummaryRow(name string, cells ...string) string {
	var b strings.Builder
	b.WriteString("<tr><th scope=\"row\">" + name + "</th>")
	for _, c := range cells {
		b.WriteString("<td>" + c + "</td>")
	}
	b.WriteString("</tr>")
	return b.String()
}

func TestCompliance(t *testing.T) {
	for _, tc := range []struct {
		counts statusCounts
		want   string
	}{
		{statusCounts{}, "0.00%"},
		{statusCounts{notApplicable: 4}, "0.00%"},
		{statusCounts{passed: 1}, "100.00%"},
		{statusCounts{passed: 1, failed: 2}, "33.33%"},
		{statusCounts{passed: 2, failed: 1}, "66.67%"},
		{statusCounts{passed: 1, failed: 7}, "12.50%"},
		{statusCounts{passed: 1, notReviewed: 1, errored: 1, notApplicable: 9}, "33.33%"},
	} {
		assert.Equal(t, tc.want, tc.counts.compliance(), fmt.Sprintf("%+v", tc.counts))
	}
}

func TestConvertHDFToHTML_RejectsWhatIsNotResults(t *testing.T) {
	for name, input := range map[string]string{
		"empty":             "",
		"not json":          "not json",
		"missing baselines": `{"generator":{"name":"t","version":"0"}}`,
		"null baselines":    `{"baselines":null}`,
		"top-level array":   `[]`,
	} {
		t.Run(name, func(t *testing.T) {
			out, err := ConvertHDFToHTML([]byte(input))
			require.Error(t, err)
			assert.Nil(t, out)
			assert.Contains(t, err.Error(), "hdf-to-html")
		})
	}
}

func TestConvertHDFToHTML_ZeroBaselinesStillReports(t *testing.T) {
	out, err := ConvertHDFToHTML([]byte(`{"baselines":[]}`))
	require.NoError(t, err)
	assert.Contains(t, string(out), wantSummaryRow("All baselines", "0", "0", "0", "0", "0", "0", "0.00%"))
	assert.NotContains(t, string(out), "Effective status evaluated as of", "nothing was evaluated")
}

// htmlStructureValidator checks the report the only way a document with no
// schema can be checked: every tag opened is closed, in order. The report is
// written as XML-well-formed HTML so a strict XML parse is that check.
type htmlStructureValidator struct{}

func (htmlStructureValidator) Validate(doc []byte) error {
	if !strings.HasPrefix(string(doc), "<!DOCTYPE html>\n<html lang=\"en\">") {
		return errors.New("output does not start with the HTML doctype and root element")
	}
	d := xml.NewDecoder(strings.NewReader(string(doc)))
	d.Strict = true
	for {
		_, err := d.Token()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("output is not well-formed: %w", err)
		}
	}
}

func TestHTMLStructureValidator_CanFail(t *testing.T) {
	v := htmlStructureValidator{}
	require.Error(t, v.Validate([]byte("<p>no doctype</p>")))
	require.Error(t, v.Validate([]byte("<!DOCTYPE html>\n<html lang=\"en\"><body><p>unclosed</body></html>")))
	require.NoError(t, v.Validate([]byte("<!DOCTYPE html>\n<html lang=\"en\"><body><p>ok</p></body></html>")))
}

func TestConvertHDFToHTML_AdversarialCorpus(t *testing.T) {
	corpus.RunSchemaCorpus(t, htmlStructureValidator{}, corpus.ResultsCorpus(), ConvertHDFToHTML)
}

func TestConvertHDFToHTML_OptionalDetailBranches(t *testing.T) {
	impact := 0.3
	disposition := hdf.OverrideTypeWaiver
	severity := hdf.Severity("critical")
	req := testhdf.Req("V-1", testhdf.Impact(0.7), testhdf.Status(hdf.Failed), testhdf.Tag("nist", "AC-1"),
		testhdf.Tag("cci", []any{"CCI-1", 7, "CCI-2"}))
	req.Severity = &severity
	req.EffectiveImpact = &impact
	req.Disposition = &disposition
	req.StatusOverrides = []hdf.StatusOverride{{
		Type: hdf.OperationalRequirement, Reason: "documentation only",
		AppliedBy: hdf.Identity{Type: hdf.Email, Identifier: "a@example.gov"},
		AppliedAt: mustTime(t, "2019-06-01T00:00:00Z"),
	}}
	doc := testhdf.Results(req)
	port := int64(5432)
	provider := hdf.CloudProvider("aws")
	doc.Components = []hdf.Component{testhdf.Component("db", hdf.TargetType("database"), func(c *hdf.Component) {
		c.Port = &port
		c.Provider = &provider
		c.Owner = &hdf.Identity{Type: hdf.Email, Identifier: "dba@example.gov"}
	})}
	doc.Runner = &hdf.Runner{Name: "r", Operator: &hdf.Identity{Identifier: "ops"}}
	duration := 12.345
	doc.Statistics = &hdf.Statistics{Duration: &duration}

	input, err := json.Marshal(doc)
	require.NoError(t, err)
	out, err := ConvertHDFToHTML(input)
	require.NoError(t, err)
	html := string(out)

	for _, want := range []string{
		"<dt>Port</dt><dd>5432</dd>", "<dt>Provider</dt><dd>aws</dd>", "<dt>Owner</dt><dd>dba@example.gov (email)</dd>",
		"<dt>Operator</dt><dd>ops</dd>",
		"<dt>Duration</dt><dd>12.35 s</dd>",
		detail("Severity", "critical"), detail("Impact", "0.70"), detail("Effective impact", "0.30"),
		detail("Disposition", "waiver"), detail("NIST Controls", "AC-1"), detail("CCI Controls", "CCI-1, CCI-2"),
		`<span class="sev c-critical"><span class="vh">Severity: </span>Critical</span>`,
		`<span class="tags"><span class="vh">Controls: </span><span class="tag">AC-1</span><span class="tag">CCI-1</span><span class="tag">CCI-2</span></span>`,
		"<td>operationalRequirement</td><td></td>",
	} {
		assert.Contains(t, html, want)
	}
	assert.NotContains(t, html, "governing", "an override with no status governs nothing")
	assert.NotContains(t, html, "0001-01-01", "an absent expiry is blank, not the zero time")
}

func TestStatusBadge(t *testing.T) {
	for status, want := range map[string]string{
		"passed":        badge("passed", "Passed"),
		"failed":        badge("failed", "Failed"),
		"notReviewed":   badge("not-reviewed", "Not Reviewed"),
		"notApplicable": badge("not-applicable", "Not Applicable"),
		"error":         badge("error", "Error"),
		`"><script>`:    badge("unknown", "&quot;&gt;&lt;script&gt;"),
	} {
		assert.Equal(t, want, statusBadge(status))
	}
}

func TestTagItems(t *testing.T) {
	assert.Empty(t, tagItems(nil, "nist"))
	assert.Empty(t, tagItems(map[string]interface{}{"nist": 7}, "nist"))
	assert.Equal(t, []string{"AC-1"}, tagItems(map[string]interface{}{"nist": "AC-1"}, "nist"))
	assert.Equal(t, []string{"AC-1", "AC-2"}, tagItems(map[string]interface{}{"nist": []interface{}{"AC-1", nil, "AC-2"}}, "nist"))
}

func TestSeverityPresentation(t *testing.T) {
	for severity, want := range map[string][2]string{
		"critical": {"critical", "Critical"}, "high": {"high", "High"}, "medium": {"medium", "Medium"}, "low": {"low", "Low"},
		"informational": {"none", "None"}, "none": {"none", "None"}, "": {"none", "None"}, "Sev<1>": {"none", "Sev<1>"},
	} {
		assert.Equal(t, want[0], severityClass(severity), severity)
		assert.Equal(t, want[1], severityLabel(severity), severity)
	}
}

func TestDescriptionHeading(t *testing.T) {
	for label, want := range map[string]string{
		"default": "Description", "check": "Check Text", "fix": "Fix Text", "rationale": "Rationale", "caveat": "Caveat", "solution": "solution",
	} {
		assert.Equal(t, want, descriptionHeading(label))
	}
}

// The dashboard words its counts the way the Heimdall report does: requirements
// by status with the individual checks beneath them, requirements by severity,
// and a compliance level banded at 90 and 60.
func TestConvertHDFToHTML_Dashboard(t *testing.T) {
	failing := testhdf.Req("F", testhdf.Impact(0.9), testhdf.Status(hdf.Failed))
	failing.Results = append(failing.Results,
		hdf.RequirementResult{Status: hdf.Passed, CodeDesc: "ok", StartTime: testhdf.DefaultStartTime},
		hdf.RequirementResult{Status: hdf.Failed, CodeDesc: "bad", StartTime: testhdf.DefaultStartTime})
	doc := testhdf.Results(
		testhdf.Req("P1", testhdf.Impact(0.7), testhdf.Status(hdf.Passed)),
		testhdf.Req("P2", testhdf.Impact(0.5), testhdf.Status(hdf.Passed)),
		failing,
		testhdf.Req("N", testhdf.Impact(0), testhdf.Status(hdf.Passed)),
	)
	out := renderDoc(t, doc, Executive)

	for _, want := range []string{
		`<li class="stat c-passed"><span class="num">2</span><span class="lbl">Passed</span><span class="sub">2 individual checks passed</span></li>`,
		`<li class="stat c-failed"><span class="num">1</span><span class="lbl">Failed</span><span class="sub">1 individual check passed, 2 failed out of 6 total checks</span></li>`,
		`<li class="stat c-not-applicable"><span class="num">1</span><span class="lbl">Not Applicable</span></li>`,
		`<li class="stat stat-total"><span class="num">4</span><span class="lbl">Total</span></li>`,
		`<li class="stat c-critical"><span class="num">1</span><span class="lbl">Critical</span></li>`,
		`<li class="stat c-high"><span class="num">1</span><span class="lbl">High</span></li>`,
		`<li class="stat c-medium"><span class="num">1</span><span class="lbl">Medium</span></li>`,
		`<li class="stat c-none"><span class="num">1</span><span class="lbl">None</span></li>`,
		`<div class="bar" role="img" aria-label="Requirements by status: 2 passed, 1 failed, 1 not applicable, 0 not reviewed, 0 error">` +
			`<span class="seg c-passed" style="--n:2"></span><span class="seg c-failed" style="--n:1"></span><span class="seg c-not-applicable" style="--n:1"></span></div>`,
		`aria-label="Requirements by severity: 1 critical, 1 high, 1 medium, 0 low, 1 none"`,
		`<div class="panel compliance compliance-medium">`,
		`<div class="gauge" style="--pct:66.67"><span class="pct">66.67%</span></div>`,
		`<p class="level">Medium compliance</p>`,
	} {
		assert.Contains(t, out, want)
	}
	assert.NotContains(t, out, `class="seg c-error"`, "a zero count draws no segment")
}

func TestConvertHDFToHTML_ComplianceLevels(t *testing.T) {
	reqs := func(passed, failed int) hdf.HDFResults {
		var all []hdf.EvaluatedRequirement
		for i := range passed + failed {
			status := hdf.Failed
			if i < passed {
				status = hdf.Passed
			}
			all = append(all, testhdf.Req(fmt.Sprintf("R-%d", i), testhdf.Impact(0.5), testhdf.Status(status)))
		}
		return testhdf.Results(all...)
	}
	assert.Contains(t, renderDoc(t, reqs(9, 1), Executive), `compliance-high">`)
	assert.Contains(t, renderDoc(t, reqs(9, 1), Executive), "High compliance")
	assert.Contains(t, renderDoc(t, reqs(6, 4), Executive), `compliance-medium">`)
	assert.Contains(t, renderDoc(t, reqs(5, 5), Executive), `compliance-low">`)
	assert.Contains(t, renderDoc(t, reqs(5, 5), Executive), "Low compliance")
}

func TestAssessmentTime_NoUsableTime(t *testing.T) {
	_, ok := assessmentTime(&hdf.HDFResults{})
	assert.False(t, ok)

	out, err := ConvertHDFToHTML([]byte(`{"baselines":[{"name":"b","requirements":[{"id":"V-1","impact":0.5,"tags":{},"descriptions":[],"results":[]}]}]}`))
	require.NoError(t, err)
	assert.NotContains(t, string(out), "evaluated as of", "no time in the document, so none is claimed")
	assert.Contains(t, string(out), wantSummaryRow("b", "0", "0", "1", "0", "0", "1", "0.00%"))
}

// A report is read by people using a keyboard or a screen reader: it needs a way
// past the navigation, named landmarks, labelled controls and tables, and text
// wherever colour carries meaning.
func TestConvertHDFToHTML_AccessibleStructure(t *testing.T) {
	out := renderDoc(t, richDoc(t), Administrator)
	for _, want := range []string{
		`<html lang="en">`,
		`<a class="skip" href="#main">Skip to content</a>`,
		`<nav aria-label="Sections">`,
		`<main id="main">`,
		`<section id="status" class="card" aria-labelledby="status-heading">`, `<h2 id="status-heading">Status</h2>`,
		`<section id="results" class="card" aria-labelledby="results-heading">`,
		`<table class="summary" aria-label="Status by baseline">`,
		`<table aria-label="Test results">`, `<table class="details" aria-label="Result details">`,
		`aria-label="Filter requirements by ID, title or control"`,
		`<div class="filters" role="group" aria-label="Filter by status">`,
		`<button type="button" class="filter" data-status="all" aria-pressed="true">All</button>`,
		`<span id="filter-count" class="shown" aria-live="polite"></span>`,
		`<button type="button" id="theme-toggle" class="theme-toggle" aria-label="Switch to dark mode">Dark mode</button>`,
		`<a class="page-top" href="#top">Top</a>`,
		`<span class="vh">Severity: </span>`,
	} {
		assert.Contains(t, out, want)
	}
	assert.Equal(t, 1, strings.Count(out, "<h1"), "one top-level heading")
	for _, th := range regexp.MustCompile(`<th[ >][^>]*>`).FindAllString(out, -1) {
		assert.Contains(t, th, "scope=", "every header cell states its scope: %s", th)
	}
	// The results header row is decoration for sighted users; each summary states its own cells.
	assert.Contains(t, out, `<div class="req-head" aria-hidden="true">`)
}

// colourTokens reads the `--name: #rrggbb` declarations of one palette block.
func colourTokens(t *testing.T, css string) map[string]string {
	t.Helper()
	tokens := map[string]string{}
	for _, m := range regexp.MustCompile(`--([a-z0-9-]+):\s*(#[0-9a-fA-F]{6})`).FindAllStringSubmatch(css, -1) {
		tokens[m[1]] = m[2]
	}
	require.NotEmpty(t, tokens)
	return tokens
}

// relativeLuminance and contrast follow WCAG 2.x, "contrast ratio".
func relativeLuminance(t *testing.T, hex string) float64 {
	t.Helper()
	channel := func(s string) float64 {
		v, err := strconv.ParseUint(s, 16, 8)
		require.NoError(t, err)
		c := float64(v) / 255
		if c <= 0.03928 {
			return c / 12.92
		}
		return math.Pow((c+0.055)/1.055, 2.4)
	}
	return 0.2126*channel(hex[1:3]) + 0.7152*channel(hex[3:5]) + 0.0722*channel(hex[5:7])
}

func contrast(t *testing.T, a, b string) float64 {
	t.Helper()
	la, lb := relativeLuminance(t, a), relativeLuminance(t, b)
	if la < lb {
		la, lb = lb, la
	}
	return (la + 0.05) / (lb + 0.05)
}

// Every colour the report uses is a named token, in a light and a dark palette.
// Text pairs must meet WCAG 2.2 AA (1.4.3, 4.5:1) and the graphics and control
// boundaries that carry meaning must meet 1.4.11 (3:1), in both.
func TestStylesheet_PalettesMeetWCAGContrast(t *testing.T) {
	// Light is the default. Dark is declared twice: for a reader whose system
	// asks for it and who has not chosen light, and for one who chose dark.
	const systemDark = `:root:not([data-theme="light"]) {`
	const chosenDark = `:root[data-theme="dark"] {`
	mediaStart := strings.Index(stylesheet, "@media (prefers-color-scheme: dark)")
	darkStart := strings.Index(stylesheet, chosenDark)
	classesStart := strings.Index(stylesheet, ".c-passed {")
	require.Positive(t, mediaStart)
	require.Greater(t, darkStart, mediaStart)
	require.Greater(t, classesStart, darkStart)
	require.Contains(t, stylesheet[mediaStart:darkStart], systemDark)
	assert.Equal(t, colourTokens(t, stylesheet[mediaStart:darkStart]), colourTokens(t, stylesheet[darkStart:classesStart]),
		"the system-dark and chosen-dark palettes must be the same palette")

	type pair struct {
		fg, bg string
		min    float64
	}
	pairs := []pair{
		{"ink", "bg", 4.5}, {"ink", "surface", 4.5}, {"ink", "surface-2", 4.5},
		{"muted", "bg", 4.5}, {"muted", "surface", 4.5}, {"muted", "surface-2", 4.5},
		{"on-brand", "brand-1", 4.5}, {"on-brand", "brand-2", 4.5}, {"on-accent", "accent", 4.5},
		{"code-ink", "code-bg", 4.5},
		{"focus", "surface", 3}, {"focus", "bg", 3},
		{"control-line", "surface", 3}, {"control-line", "surface-2", 3},
		{"accent", "surface", 4.5}, {"accent", "surface-2", 4.5}, // link text, and the accent edges
	}
	for _, name := range []string{"passed", "failed", "not-applicable", "not-reviewed", "error", "unknown",
		"critical", "high", "medium", "low", "none"} {
		pairs = append(pairs,
			pair{"s-" + name + "-on", "s-" + name, 4.5}, // pill text
			pair{"t-" + name + "-on", "t-" + name, 4.5}, // tile text
			pair{"s-" + name, "surface", 3},             // requirement edge, severity dot
			pair{"s-" + name, "surface-2", 3},           // bar segment and gauge ring on a panel
			pair{"s-" + name, "t-" + name, 3},           // tile edge, severity dot on its tint
		)
	}

	for label, css := range map[string]string{
		"light": stylesheet[:mediaStart],
		"dark":  stylesheet[darkStart:classesStart],
	} {
		tokens := colourTokens(t, css)
		for _, p := range pairs {
			fg, okFg := tokens[p.fg]
			bg, okBg := tokens[p.bg]
			require.True(t, okFg && okBg, "%s palette must define --%s and --%s", label, p.fg, p.bg)
			assert.GreaterOrEqual(t, contrast(t, fg, bg), p.min, "%s: --%s on --%s", label, p.fg, p.bg)
		}
	}

	// A colour written outside the two palettes would escape the check above.
	rest := stylesheet[classesStart:]
	for _, m := range regexp.MustCompile(`#[0-9a-fA-F]{3,8}\b`).FindAllString(rest, -1) {
		assert.Equal(t, "#ffffff", m, "rules must use palette tokens; only the print background is literal")
	}
}

func TestContrast_KnownValues(t *testing.T) {
	assert.InDelta(t, 21.0, contrast(t, "#000000", "#ffffff"), 0.01)
	assert.InDelta(t, 1.0, contrast(t, "#777777", "#777777"), 0.001)
	assert.Less(t, contrast(t, "#999999", "#ffffff"), 4.5)
}

// findingDetail reads the fixture that carries every requirement, result,
// override and baseline field the report renders beyond the basics. It is a file
// because both languages must run on the same bytes to share its golden.
func findingDetail(t *testing.T) []byte {
	t.Helper()
	input, err := os.ReadFile(filepath.Join("..", "fixtures", "input", "finding-detail.json"))
	require.NoError(t, err)
	return input
}

// A SAST finding is only actionable with the file and line it was found at, and
// a vulnerability with its scores and packages; the report shows every such
// field the document carries.
func TestConvertHDFToHTML_FindingDetail(t *testing.T) {
	input := findingDetail(t)
	require.True(t, validators.ValidateResults(input).Valid,
		"finding-detail.json must be valid HDF: %s", validators.ValidateResults(input).Error())
	out, err := ConvertHDFToHTML(input)
	require.NoError(t, err)
	html := string(out)
	assertGolden(t, filepath.Join("..", "fixtures", "expected", "finding-detail.administrator.html"), out)
	require.NoError(t, htmlStructureValidator{}.Validate(out))
	assertSelfContained(t, html, true)

	sub := func(label, value string) string {
		return `<span class="sub"><span class="k">` + label + `</span> ` + value + "</span>"
	}
	for _, want := range []string{
		`<p class="location"><span class="k">Location</span><code>app/controllers/attestations_controller.rb:35</code></p>`,
		detail("Source location", "app/controllers/attestations_controller.rb:35"),
		detail("Control type", "technical"), detail("Verification method", "automated"), detail("Applicability", "required"),
		detail("CWE", "CWE-915, CWE-20"),
		detail("CVSS", "v3.1 7.3 high CVSS:3.1/AV:N (nvd); v4.0 9.8 critical"),
		detail("EPSS", "score 0.00123, percentile 0.50000, as of 2020-01-01"),
		detail("KEV", "Listed, added 2020-01-02, due 2020-02-01, ransomware use"),
		detail("Affected packages", "rails 6.1.0 (fixed in 6.1.7); pkg:gem/rack@2.0.0 cpe:2.3:a:rack"),
		detail("Evidence", "url: scan log"),
		detail("References", "<pre class=\"prose\">\nBrakeman docs\nhttps://brakemanscanner.org/docs/warning_types/mass_assignment/\n"+
			"urn:example:rule:105\nhttps://a.example/adv\nhttps://z.example/tracker</pre>"),
		detail("Fix Text", "<pre class=\"prose\">\nPermit fewer keys.</pre>"),
		"<summary><h4>Tags</h4><span class=\"count\">3</span></summary>\n<div class=\"fold-body\">\n<ul class=\"chips\">\n" +
			chip("owasp", "A04, A08") + "\n" + chip("reviewed", "true") + "\n" + chip("wascid", "15") + "\n</ul>",
		`attestations_controller.rb line 35` + sub("Resource", "File · app/controllers/attestations_controller.rb"),
		"permit(:role)" + sub("Exception", "RuntimeError") + sub("Backtrace", "a.rb:1\nb.rb:2"),
		"2020-01-01T00:00:00Z" + sub("Run time", "0.013 s"),
		"<td>falsePositive</td><td>" + badge("not-applicable", "Not Applicable") + sub("Impact", "0.00") +
			sub("CVSS", "v3.1 8.1 high CVSS:3.1/AV:N"),
		"Descriptive string, not an authorization role." + sub("Justification", "protected_at_runtime"),
		`<summary><h4>POA&amp;Ms</h4><span class="count">1</span></summary>`,
		"Tighten strong parameters." + sub("Milestone", "pending · Patch · Remove :role · 2099-12-31T00:00:00Z"),
		`<summary><h4>Baseline details</h4><span class="count">8</span></summary>`,
		"<dt>Title</dt><dd>Static analysis</dd>", "<dt>Version</dt><dd>1.2</dd>", "<dt>Summary</dt><dd>Rails SAST</dd>",
		"<dt>Description</dt><dd>Brakeman rules</dd>", "<dt>Maintainer</dt><dd>AppSec</dd>", "<dt>License</dt><dd>Apache-2.0</dd>",
		"<dt>Copyright</dt><dd>Example</dd>", "<dt>Status message</dt><dd>loaded</dd>",
	} {
		assert.Contains(t, html, want)
	}
	assert.NotContains(t, html, `<span class="k">score</span>`, "a numeric tag is left out")
	assert.NotContains(t, html, `<span class="k">nested</span>`)
	assert.NotContains(t, html, `<span class="k">empty</span>`)
	assert.NotContains(t, html, "<div class=\"req-body\">\n<pre class=\"prose\">\n</pre>", "an empty default description is not shown")
	assert.NotContains(t, html, "<h4>Description</h4>", "an empty default description is not shown")
}

func TestSourceLocation(t *testing.T) {
	line := 12.0
	assert.Empty(t, sourceLocation(nil))
	assert.Empty(t, sourceLocation(&hdf.SourceLocation{}))
	assert.Equal(t, "a.rb", sourceLocation(&hdf.SourceLocation{Ref: hdfutil.Ptr("a.rb")}))
	assert.Equal(t, "line 12", sourceLocation(&hdf.SourceLocation{Line: &line}))
	assert.Equal(t, "a.rb:12", sourceLocation(&hdf.SourceLocation{Ref: hdfutil.Ptr("a.rb"), Line: &line}))
}

func TestFindingTextHelpers(t *testing.T) {
	assert.Empty(t, epssText(nil))
	assert.Equal(t, "score 0.10000, percentile 0.20000", epssText(&hdf.Epss{Score: 0.1, Percentile: 0.2}))
	assert.Empty(t, kevText(nil))
	assert.Equal(t, "Not listed", kevText(&hdf.Kev{}))
	assert.Empty(t, cvssText([]hdf.Cvss{{}}))
	assert.Empty(t, packagesText([]hdf.AffectedPackage{{}}))
	assert.Empty(t, evidenceText([]hdf.Evidence{{}}))
	assert.Empty(t, subLine("X", ""))
	_, ok := tagText(nil)
	assert.False(t, ok)
}

// The legacy converters write the zero time when a source has no start time.
// It is not a time, so it is neither shown nor taken as the assessment time.
func TestConvertHDFToHTML_ZeroTimeIsAbsent(t *testing.T) {
	out, err := ConvertHDFToHTML([]byte(`{"baselines":[{"name":"b","requirements":[{"id":"V-1","impact":0.5,"tags":{},` +
		`"descriptions":[{"label":"default","data":"d"}],"results":[{"status":"failed","codeDesc":"c","startTime":"0001-01-01T00:00:00Z"}]}]}]}`))
	require.NoError(t, err)
	assert.NotContains(t, string(out), "0001-01-01")
	assert.NotContains(t, string(out), "evaluated as of")
}

// v3 results can carry enrichment: inert external references at the document,
// baseline, requirement and override levels, some embedding the referenced
// object (a STIX vulnerability, a triage note). The report shows each one and
// the embedded object whole.
func TestConvertHDFToHTML_Enrichment(t *testing.T) {
	out, err := ConvertHDFToHTML(findingDetail(t))
	require.NoError(t, err)
	html := string(out)
	sub := func(label, value string) string {
		return `<span class="sub"><span class="k">` + label + `</span> ` + value + "</span>"
	}

	for _, want := range []string{
		"<dt>External references</dt><dd>6 (annotation 1, threat-intel 1)</dd>",
		`<summary><h3>Enrichment and External References</h3><span class="count">1</span></summary>`,
		// document level: a STIX bundle by location, with integrity and attribution
		"<tr><td>stix</td><td></td><td></td><td>investigate</td><td class=\"text\">" +
			sub("Location", "https://cti.example.org/bundles/log4shell.json") + sub("Media type", "application/json") +
			sub("Checksum", "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") +
			sub("Added", "analyst@agency.gov · 2026-07-26T00:00:00Z") + "</td></tr>",
		// baseline level: an ATT&CK technique by id and location
		"<tr><td>mitre-att&amp;ck</td><td>T1059</td><td></td><td>canonical</td><td class=\"text\">" +
			sub("Location", "https://attack.mitre.org/techniques/T1059/") + "</td></tr>",
		// requirement level: by identity only
		`<tr><td>cve</td><td>CVE-2021-44228</td><td></td><td>definition</td><td class="text"></td></tr>`,
		// requirement level: an embedded STIX object
		"<td>stix</td><td>vulnerability--f7c1b8e0-1234-4a2b-9c3d-000000000001</td><td>threat-intel</td><td>investigate</td>",
		sub("Embedded", "vulnerability · CVE-2021-44228") + `<details class="doc"><summary>Embedded document</summary><pre class="code">` + "\n{\n" +
			"  &quot;external_references&quot;: [\n    {\n      &quot;external_id&quot;: &quot;CVE-2021-44228&quot;,\n",
		// an embedded object with no type or name, and values that need escaping
		"Reviewed with the application team." + `<details class="doc"><summary>Embedded document</summary>`,
		"&quot;meta&quot;: {},", "&quot;tags&quot;: []",
		`<span class="tag enriched">Enriched (3)</span>`,
		`<summary><h4>References for override 1</h4><span class="count">1</span></summary>`,
	} {
		assert.Contains(t, html, want)
	}
	assert.NotContains(t, html, "<role>", "an embedded document is text, never markup")
	require.NoError(t, htmlStructureValidator{}.Validate(out))

	executive, err := ConvertHDFToHTMLWithOptions(findingDetail(t), Options{ReportType: Executive})
	require.NoError(t, err)
	assert.Contains(t, string(executive), "<dt>External references</dt><dd>6 (annotation 1, threat-intel 1)</dd>")
	assert.Contains(t, string(executive), "<h3>Enrichment and External References</h3>", "document-level enrichment is context for every reader")
}

func TestIndentJSON(t *testing.T) {
	assert.Equal(t, "{}", indentJSON("{}"))
	assert.Equal(t, "[]", indentJSON("[]"))
	assert.Equal(t, "{\n  \"a\": [\n    1,\n    \"x,{}[]:\\\"y\"\n  ],\n  \"b\": {}\n}", indentJSON(`{"a":[1,"x,{}[]:\"y"],"b":{}}`))
	assert.Equal(t, "\"a\\\\\"", indentJSON(`"a\\"`), "an escaped backslash does not escape the closing quote")
}

func TestReferenceCensus(t *testing.T) {
	assert.Empty(t, referenceCensus(&hdf.HDFResults{}))
	assert.Equal(t, "1", referenceCensus(&hdf.HDFResults{ExternalReferences: []hdf.ExternalReference{{SourceName: "cve"}}}))
	assert.Empty(t, embeddedDocument(nil))
}

// foldOpening finds the opening tag of the collapsible block whose heading is
// title, so a test can say whether it starts open.
func foldOpening(t *testing.T, html, heading string) string {
	t.Helper()
	i := strings.Index(html, "<summary>"+heading)
	require.GreaterOrEqual(t, i, 0, "no block headed %s", heading)
	start := strings.LastIndex(html[:i], "<details ")
	require.GreaterOrEqual(t, start, 0)
	return html[start:i]
}

// Anything longer than two lines or rows sits behind its heading, with a count,
// and ends with a way back to its own top; a short block is simply shown.
func TestConvertHDFToHTML_LongBlocksAreCollapsed(t *testing.T) {
	short := testhdf.Req("V-1", testhdf.Impact(0.5), testhdf.Status(hdf.Failed), testhdf.Desc("one line"), testhdf.Code("a\nb"))
	long := testhdf.Req("V-2", testhdf.Impact(0.5), testhdf.Status(hdf.Failed), testhdf.Desc("one\ntwo\nthree"), testhdf.Code("a\nb\nc"))
	long.Results = append(long.Results,
		hdf.RequirementResult{Status: hdf.Failed, CodeDesc: "2", StartTime: testhdf.DefaultStartTime},
		hdf.RequirementResult{Status: hdf.Failed, CodeDesc: "3", StartTime: testhdf.DefaultStartTime})
	html := renderDoc(t, testhdf.Results(short, long, testhdf.Req("V-3", testhdf.Impact(0.5))), Administrator)

	first := html[strings.Index(html, `id="req-1"`):strings.Index(html, `id="req-2"`)]
	second := html[strings.Index(html, `id="req-2"`):strings.Index(html, `id="req-3"`)]

	// one result, one description line, two code lines: shown as they are
	assert.Contains(t, foldOpening(t, first, "<h4>Test Results</h4>"), `open="open"`)
	assert.Contains(t, first, `<summary><h4>Test Results</h4><span class="count">1</span></summary>`)
	assert.Contains(t, foldOpening(t, first, "<h4>Code</h4>"), `open="open"`)
	assert.NotContains(t, first, "<h4>Description</h4>", "a short description needs no block of its own")
	assert.Contains(t, first, "<pre class=\"prose\">\none line</pre>")

	// three of each: behind a heading that says how many
	for heading, count := range map[string]string{"Test Results": "3", "Description": "3", "Code": "3"} {
		opening := foldOpening(t, second, "<h4>"+heading+"</h4>")
		assert.NotContains(t, opening, "open=", heading)
		assert.Contains(t, second, "<summary><h4>"+heading+`</h4><span class="count">`+count+"</span></summary>")
		id := regexp.MustCompile(`id="(block-[0-9]+)"`).FindStringSubmatch(opening)
		require.NotNil(t, id, heading)
		assert.Contains(t, second, `<p class="to-top"><a href="#`+id[1]+`">Back to the top of the `, heading)
	}

	// the detail table always has more than two rows; a three-requirement baseline is long too
	assert.NotContains(t, foldOpening(t, first, "<h4>Result Details</h4>"), "open=")
	baseline := foldOpening(t, html, "<h3>test</h3>")
	assert.Contains(t, baseline, `class="fold group baseline"`)
	assert.NotContains(t, baseline, "open=")
	assert.Contains(t, html, `<summary><h3>test</h3><span class="count">3</span></summary>`)

	// every requirement ends with a way back to its own top
	for _, id := range []string{"req-1", "req-2", "req-3"} {
		assert.Contains(t, html, `<p class="to-top"><a href="#`+id+`">Back to the top of this requirement</a></p>`)
	}
	// and every return link points at an id that exists
	for _, m := range regexp.MustCompile(`href="#([^"]+)"`).FindAllStringSubmatch(html, -1) {
		assert.Contains(t, html, `id="`+m[1]+`"`, "link target %s", m[1])
	}
}

func TestIsLongText(t *testing.T) {
	assert.False(t, isLongText(""))
	assert.False(t, isLongText("one\ntwo"))
	assert.True(t, isLongText("one\ntwo\nthree"))
	assert.False(t, isLongText(strings.Repeat("é", 240)), "length is counted in characters, not bytes")
	assert.True(t, isLongText(strings.Repeat("é", 241)))
}

// The reader can switch between the light and dark palettes from the header in
// every report type, so every report carries the script and the policy pins it.
func TestConvertHDFToHTML_ThemeSwitchInEveryReportType(t *testing.T) {
	for _, reportType := range []ReportType{Executive, Manager, Administrator} {
		html := renderDoc(t, richDoc(t), reportType)
		assert.Contains(t, html, `<button type="button" id="theme-toggle" class="theme-toggle" aria-label="Switch to dark mode">Dark mode</button>`)
		assert.Contains(t, html, "script-src '"+scriptHash+"'")
		assert.Equal(t, 1, strings.Count(html, "<script>"))
		assert.Contains(t, html, "<html lang=\"en\">\n", "the document states no theme; the reader's choice is applied when it is opened")
	}
	for _, want := range []string{"theme-toggle", "data-theme", "localStorage", "prefers-color-scheme", "beforeprint"} {
		assert.Contains(t, script, want)
	}
	assert.Contains(t, stylesheet, `:root[data-theme="dark"] {`)
	assert.Contains(t, stylesheet, `:root:not([data-theme="light"]) {`)
}
