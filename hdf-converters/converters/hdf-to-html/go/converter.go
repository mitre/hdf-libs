// Package hdftohtml renders an HDF results document as one self-contained HTML
// report. The TypeScript peer emits the same bytes for the same input, so every
// choice here that affects output (ordering, escaping, number and time
// formatting) is mirrored there and pinned by the shared goldens.
package hdftohtml

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	shared "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go"
	hdfengine "github.com/mitre/hdf-libs/hdf-engine/go/v3"
	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	hdfutil "github.com/mitre/hdf-libs/hdf-utilities/go/v3"
)

const converterName = "hdf-to-html"

// Status and severity values as HDF spells them. The passed, failed and error
// statuses and every severity are stylesheet classes under the same spelling.
const (
	statusPassed        = "passed"
	statusFailed        = "failed"
	statusNotReviewed   = "notReviewed"
	statusNotApplicable = "notApplicable"
	statusError         = "error"

	classNotReviewed   = "not-reviewed"
	classNotApplicable = "not-applicable"

	labelPassed        = "Passed"
	labelFailed        = "Failed"
	labelNotReviewed   = "Not Reviewed"
	labelNotApplicable = "Not Applicable"
	labelError         = "Error"

	severityCritical = "critical"
	severityHigh     = "high"
	severityMedium   = "medium"
	severityLow      = "low"
	severityNone     = "none"
)

// Markup and wording the report repeats.
const (
	closeDiv     = "</div>"
	closeSpan    = "</span>"
	closeSection = "</section>"
	closeList    = "</ul>"
	rowOpen      = "<tr><td>"
	cell         = "</td><td>"
	textCell     = `</td><td class="text">`
	rowClose     = "</td></tr>"
	separator    = " \u00b7 "

	headingDescription = "Description"
	headingEnrichment  = "Enrichment and External References"
)

// ReportType selects how much of the document the report shows. The three
// levels are the ones `saf convert hdf2html` offers, each a superset of the last.
type ReportType string

const (
	// Executive shows the assessment context, components and status summary.
	Executive ReportType = "executive"
	// Manager adds every requirement with its results and overrides.
	Manager ReportType = "manager"
	// Administrator adds each requirement's test code.
	Administrator ReportType = "administrator"
)

// Options configures a conversion. The zero value is the Administrator report.
type Options struct {
	ReportType ReportType
}

// ParseReportType reads a report type case-insensitively; empty selects the
// default, Administrator.
func ParseReportType(s string) (ReportType, error) {
	switch ReportType(strings.ToLower(strings.TrimSpace(s))) {
	case "", Administrator:
		return Administrator, nil
	case Manager:
		return Manager, nil
	case Executive:
		return Executive, nil
	}
	return "", fmt.Errorf("unknown report type %q: must be one of executive, manager, administrator", s)
}

// ConvertHDFToHTML renders the Administrator report.
func ConvertHDFToHTML(input []byte) ([]byte, error) {
	return ConvertHDFToHTMLWithOptions(input, Options{})
}

// ConvertHDFToHTMLWithOptions renders an HDF results document as HTML. The
// output depends on the input bytes and options alone: nothing is read from the
// clock or the host, so the same document always yields the same report.
func ConvertHDFToHTMLWithOptions(input []byte, opts Options) ([]byte, error) {
	return render([]Document{{Data: input}}, opts, false)
}

// Document is one results document going into an aggregated report. Name is how
// the report refers to it, usually its file name.
type Document struct {
	Name string
	Data []byte
}

// ConvertHDFDocumentsToHTML renders several results documents as one report:
// combined status, severity and compliance, then each document's own context,
// components and results under its name. Documents appear in the order given.
func ConvertHDFDocumentsToHTML(docs []Document, opts Options) ([]byte, error) {
	if len(docs) == 0 {
		return nil, fmt.Errorf("%s: no documents to report on", converterName)
	}
	return render(docs, opts, true)
}

func render(docs []Document, opts Options, aggregated bool) ([]byte, error) {
	reportType, err := ParseReportType(string(opts.ReportType))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", converterName, err)
	}

	r := &renderer{reportType: reportType, aggregated: aggregated, sources: make([]source, len(docs))}
	for i := range docs {
		src := &r.sources[i]
		src.name = docs[i].Name
		if err := shared.RequireHDFResultsTyped(docs[i].Data, converterName, &src.doc); err != nil {
			if aggregated {
				return nil, fmt.Errorf("%s: %w", docs[i].Name, err)
			}
			return nil, err
		}
		src.ref, src.hasRef = assessmentTime(&src.doc)
		src.baselineLabels = baselineLabels(src.doc.Baselines)
		src.attributed = attributesResults(&src.doc)
	}
	r.document()
	return []byte(r.b.String()), nil
}

// source is one input document and the instant its overrides are judged at.
type source struct {
	name string
	doc  hdf.HDFResults
	// baselineLabels names each of doc's baselines as the report shows it.
	baselineLabels []string
	// attributed is whether doc ties any of its requirements to a component.
	attributed bool
	// ref is the instant override expiry is judged against. Epoch when the
	// document carries no usable time, which leaves every override in force.
	ref    time.Time
	hasRef bool
}

// baselineLabels names each baseline as the report shows it: its title, which
// is what carries the scan target in real scanner output, falling back to its
// name. A label two baselines would share takes the 1-based document position
// of the baseline it names (hdf-engine's 0-based baselineIndex plus one).
func baselineLabels(baselines []hdf.EvaluatedBaseline) []string {
	shared := make(map[string]int, len(baselines))
	labels := make([]string, len(baselines))
	for i := range baselines {
		labels[i] = baselineLabel(&baselines[i])
		shared[labels[i]]++
	}
	for i := range labels {
		if shared[labels[i]] > 1 {
			labels[i] += ordinalSuffix(i)
		}
	}
	// A title that already ends in another baseline's suffix would collide with
	// the label built for it, so a label that is still taken takes another.
	taken := make(map[string]bool, len(labels))
	for i := range labels {
		for taken[labels[i]] {
			labels[i] += ordinalSuffix(i)
		}
		taken[labels[i]] = true
	}
	return labels
}

func baselineLabel(b *hdf.EvaluatedBaseline) string {
	if title := hdfutil.Deref(b.Title); title != "" {
		return title
	}
	return b.Name
}

func ordinalSuffix(i int) string {
	return " #" + strconv.Itoa(i+1)
}

// labelComponent is the well-known baseline label naming the component a
// baseline's requirements were assessed against.
const labelComponent = "component"

// attributesResults reports whether the document ties any requirement to a
// component. HDF results carry that link at baseline granularity only — a
// baseline's labels.component names a component, or a component's baselineRefs
// name a baseline — so a per-component number means nothing without one.
func attributesResults(doc *hdf.HDFResults) bool {
	for i := range doc.Baselines {
		if doc.Baselines[i].Labels[labelComponent] != "" {
			return true
		}
	}
	for i := range doc.Components {
		if len(doc.Components[i].BaselineRefs) > 0 {
			return true
		}
	}
	return false
}

type renderer struct {
	b          strings.Builder
	reportType ReportType
	sources    []source
	// aggregated lays the report out by source, even for a single document; the
	// single-document layout has no source level.
	aggregated bool
	// src is the source being rendered, which fixes the reference time.
	src *source
	// folds and requirements number the blocks a reader can jump back to.
	folds        int
	requirements int
}

// fold is an open collapsible block.
type fold struct {
	id, label string
	long      bool
}

// collapsedAbove is the size past which a block starts closed: anything longer
// than two lines or rows is behind its heading, so a long report is a list of
// headings with counts instead of a scroll.
const collapsedAbove = 2

// openFold starts a collapsible block: a heading with a count that opens onto
// the content. title is HTML; label is the plain text the return link names.
// An empty id takes the next number.
func (r *renderer) openFold(class, id, tag, title, label string, count int) fold {
	return r.openFoldCounted(class, id, tag, title, label, count, true)
}

// openFoldCounted is openFold with the choice of whether the heading states its
// count. A block that drops it still collapses at the same size.
func (r *renderer) openFoldCounted(class, id, tag, title, label string, count int, counted bool) fold {
	if id == "" {
		r.folds++
		id = "block-" + strconv.Itoa(r.folds)
	}
	f := fold{id: id, label: label, long: count > collapsedAbove}
	classes := "fold"
	if class != "" {
		classes += " " + class
	}
	open := ` open="open"`
	if f.long {
		open = ""
	}
	badge := ""
	if counted {
		badge = `<span class="count">` + strconv.Itoa(count) + closeSpan
	}
	r.line(`<details class="` + classes + `" id="` + id + `"` + open + ">")
	r.line("<summary><" + tag + ">" + title + "</" + tag + ">" + badge + "</summary>")
	r.line(`<div class="fold-body">`)
	return f
}

// closeFold ends the block, with a way back to its top when it is long enough
// to need one.
func (r *renderer) closeFold(f fold) {
	if f.long {
		r.line(`<p class="to-top"><a href="#` + f.id + `">Back to the top of ` + escape(f.label) + "</a></p>")
	}
	r.line(closeDiv)
	r.line("</details>")
}

// lineCount is how many lines text occupies.
func lineCount(text string) int {
	return strings.Count(text, "\n") + 1
}

// isLongText reports text that would take more than two lines on the page:
// more than two lines of its own, or one long enough to wrap that far.
func isLongText(text string) bool {
	return lineCount(text) > collapsedAbove || utf8.RuneCountInString(text) > 240
}

func countFacts(pairs []pair) int {
	n := 0
	for _, p := range pairs {
		if p.value != "" {
			n++
		}
	}
	return n
}

// baselineHeading and detailHeading keep the heading outline in order: the
// aggregated layout has a source heading above the baselines.
func (r *renderer) baselineHeading() string {
	if r.aggregated {
		return "h4"
	}
	return "h3"
}

func (r *renderer) detailHeading() string {
	if r.aggregated {
		return "h5"
	}
	return "h4"
}

// assessmentTime is when the assessment ran: the document timestamp, else its
// latest result start time. Overrides are judged against it instead of the wall
// clock, which is what keeps the report reproducible.
func assessmentTime(doc *hdf.HDFResults) (time.Time, bool) {
	if doc.Timestamp != nil && !doc.Timestamp.IsZero() {
		return *doc.Timestamp, true
	}
	latest := latestStart(doc)
	if latest.IsZero() {
		return time.Unix(0, 0).UTC(), false
	}
	return latest, true
}

// latestStart is the latest result start time in the document; zero when no
// result carries one.
func latestStart(doc *hdf.HDFResults) time.Time {
	var latest time.Time
	for i := range doc.Baselines {
		for j := range doc.Baselines[i].Requirements {
			for _, res := range doc.Baselines[i].Requirements[j].Results {
				if res.StartTime.After(latest) {
					latest = res.StartTime
				}
			}
		}
	}
	return latest
}

func (r *renderer) line(s string) {
	r.b.WriteString(s)
	r.b.WriteByte('\n')
}

func (r *renderer) document() {
	detailed := r.reportType != Executive
	policy := "default-src 'none'; style-src 'unsafe-inline'; script-src '" + scriptHash + "'"

	r.line("<!DOCTYPE html>")
	r.line(`<html lang="en">`)
	r.line("<head>")
	r.line(`<meta charset="utf-8" />`)
	r.line(`<meta http-equiv="Content-Security-Policy" content="` + policy + `" />`)
	r.line(`<meta name="viewport" content="width=device-width, initial-scale=1" />`)
	// Declared in the head so the browser's own controls and scrollbars follow the
	// reader's scheme before the stylesheet is parsed.
	r.line(`<meta name="color-scheme" content="light dark" />`)
	r.line("<title>HDF Assessment Report</title>")
	r.line("<style>")
	r.b.WriteString(stylesheet)
	r.line("</style>")
	r.line("</head>")
	r.line("<body>")
	r.line(`<a class="skip" href="#main">Skip to content</a>`)
	r.line(`<header class="topbar" id="top">`)
	r.line(`<h1 class="brand">HDF Assessment Report</h1>`)
	r.line(`<span class="report-type">Report type: ` + reportTypeLabel(r.reportType) + closeSpan)
	r.line(`<nav aria-label="Sections">`)
	r.line("<ul>")
	r.line(`<li><a href="#status">Status</a></li>`)
	if r.aggregated {
		r.line(`<li><a href="#sources">Sources</a></li>`)
	} else {
		r.line(`<li><a href="#assessment">Assessment</a></li>`)
	}
	r.line(`<li><a href="#components">Components</a></li>`)
	if detailed {
		r.line(`<li><a href="#results">Results</a></li>`)
	}
	r.line(closeList)
	r.line("</nav>")
	r.line(`<button type="button" id="theme-toggle" class="theme-toggle" aria-label="Switch to dark mode">Dark mode</button>`)
	r.line("</header>")
	r.line(`<main id="main" class="container">`)

	r.status()
	if r.aggregated {
		r.sourceList()
	} else {
		r.assessment(&r.sources[0].doc)
	}
	r.components()
	if detailed {
		r.results()
	}

	r.line("</main>")
	r.line(`<a class="page-top" href="#top">Top</a>`)
	r.line("<script>")
	r.b.WriteString(script)
	r.line("</script>")
	r.line("</body>")
	r.line("</html>")
}

func reportTypeLabel(t ReportType) string {
	switch t {
	case Executive:
		return "Executive"
	case Manager:
		return "Manager"
	case Administrator:
		return "Administrator"
	default:
		return "Administrator"
	}
}

// pair is one definition-list row; an empty value is not rendered.
type pair struct{ term, value string }

// definitionList writes the non-empty pairs and reports whether it wrote any.
func (r *renderer) definitionList(pairs []pair) bool {
	wrote := false
	for _, p := range pairs {
		if p.value == "" {
			continue
		}
		if !wrote {
			r.line("<dl>")
			wrote = true
		}
		r.line("<dt>" + escape(p.term) + "</dt><dd>" + escape(p.value) + "</dd>")
	}
	if wrote {
		r.line("</dl>")
	}
	return wrote
}

func documentFacts(doc *hdf.HDFResults) []pair {
	var tool, toolFormat, generator, assessed, duration string
	if doc.Tool != nil {
		tool = joinNonEmpty(" ", hdfutil.Deref(doc.Tool.Name), hdfutil.Deref(doc.Tool.Version))
		toolFormat = hdfutil.Deref(doc.Tool.Format)
	}
	if doc.Generator != nil {
		generator = joinNonEmpty(" ", doc.Generator.Name, doc.Generator.Version)
	}
	if doc.Timestamp != nil {
		assessed = formatTime(*doc.Timestamp)
	}
	if doc.Statistics != nil && doc.Statistics.Duration != nil {
		duration = hdfutil.FormatFixed(*doc.Statistics.Duration, 2) + " s"
	}
	return []pair{
		{"Tool", tool},
		{"Tool format", toolFormat},
		{"Generator", generator},
		{"Assessed", assessed},
		{"Duration", duration},
		{"System reference", hdfutil.Deref(doc.SystemRef)},
		{"Plan reference", hdfutil.Deref(doc.PlanRef)},
		{"Document ID", hdfutil.Deref(doc.ID)},
		{"External references", referenceCensus(doc)},
	}
}

func runnerFacts(runner *hdf.Runner) []pair {
	return []pair{
		{"Name", runner.Name},
		{"Hostname", hdfutil.Deref(runner.Hostname)},
		{"FQDN", hdfutil.Deref(runner.FQDN)},
		{"Domain", hdfutil.Deref(runner.Domain)},
		{"Architecture", hdfutil.Deref(runner.Architecture)},
		{"Release", hdfutil.Deref(runner.Release)},
		{"Container image", hdfutil.Deref(runner.ContainerImage)},
		{"Container ID", hdfutil.Deref(runner.ContainerID)},
		{"Operator", identity(runner.Operator)},
	}
}

func (r *renderer) assessment(doc *hdf.HDFResults) {
	r.line(`<section id="assessment" class="card" aria-labelledby="assessment-heading">`)
	r.line(`<h2 id="assessment-heading">Assessment</h2>`)

	r.line(`<div class="facts">`)
	facts := documentFacts(doc)
	f := r.openFold("", "", "h3", "Document", "the document facts", countFacts(facts))
	if !r.definitionList(facts) {
		r.line(`<p class="empty">The document carries no assessment metadata.</p>`)
	}
	r.closeFold(f)

	if doc.Runner != nil {
		facts = runnerFacts(doc.Runner)
		f = r.openFold("", "", "h3", "Runner", "the runner facts", countFacts(facts))
		r.definitionList(facts)
		r.closeFold(f)
	}
	r.line(closeDiv)
	r.externalReferences("h3", headingEnrichment, doc.ExternalReferences)
	r.line(closeSection)
}

// sourceList is the aggregated layout's assessment section: one panel per input
// document, each the target of the links in the status tables.
func (r *renderer) sourceList() {
	r.line(`<section id="sources" class="card" aria-labelledby="sources-heading">`)
	r.line(`<h2 id="sources-heading">Sources (` + strconv.Itoa(len(r.sources)) + ")</h2>")
	r.line(`<div class="facts">`)
	for i := range r.sources {
		src := &r.sources[i]
		facts := documentFacts(&src.doc)
		f := r.openFold("", sourceID(i), "h3", escape(src.name), src.name, countFacts(facts))
		if !r.definitionList(facts) {
			r.line(`<p class="empty">The document carries no assessment metadata.</p>`)
		}
		if src.doc.Runner != nil {
			r.line("<h4>Runner</h4>")
			r.definitionList(runnerFacts(src.doc.Runner))
		}
		r.externalReferences("h4", headingEnrichment, src.doc.ExternalReferences)
		r.closeFold(f)
	}
	r.line(closeDiv)
	r.line(closeSection)
}

func sourceID(i int) string {
	return "source-" + strconv.Itoa(i+1)
}

func identity(id *hdf.Identity) string {
	if id == nil {
		return ""
	}
	if id.Type == "" {
		return id.Identifier
	}
	return joinNonEmpty(" ", id.Identifier, "("+string(id.Type)+")")
}

func (r *renderer) components() {
	total := 0
	for i := range r.sources {
		total += len(r.sources[i].doc.Components)
	}
	r.line(`<section id="components" class="card" aria-labelledby="components-heading">`)
	r.line(`<h2 id="components-heading">Components (` + strconv.Itoa(total) + ")</h2>")
	switch {
	case total > 0:
		r.line(`<div class="components">`)
		for i := range r.sources {
			r.src = &r.sources[i]
			for j := range r.src.doc.Components {
				r.component(&r.src.doc.Components[j])
			}
		}
		r.line(closeDiv)
	case r.aggregated:
		r.line(`<p class="empty">The documents name no components.</p>`)
	default:
		r.line(`<p class="empty">The document names no components.</p>`)
	}
	r.line(closeSection)
}

func (r *renderer) component(c *hdf.Component) {
	port := ""
	if c.Port != nil {
		port = strconv.FormatInt(*c.Port, 10)
	}
	provider := ""
	if c.Provider != nil {
		provider = string(*c.Provider)
	}
	origin := ""
	if r.aggregated {
		origin = r.src.name
	}
	facts := []pair{
		{"Source", origin},
		{"Component ID", hdfutil.Deref(c.ComponentID)},
		{headingDescription, hdfutil.Deref(c.Description)},
		{"Hostname", hdfutil.Deref(c.Hostname)},
		{"FQDN", hdfutil.Deref(c.FQDN)},
		{"Domain", hdfutil.Deref(c.Domain)},
		{"IP address", hdfutil.Deref(c.IPAddress)},
		{"MAC address", hdfutil.Deref(c.MACAddress)},
		{"OS name", hdfutil.Deref(c.OSName)},
		{"OS version", hdfutil.Deref(c.OSVersion)},
		{"Image ID", hdfutil.Deref(c.ImageID)},
		{"Registry", hdfutil.Deref(c.Registry)},
		{"Repository", hdfutil.Deref(c.Repository)},
		{"Tag", hdfutil.Deref(c.Tag)},
		{"Container ID", hdfutil.Deref(c.ContainerID)},
		{"Image", hdfutil.Deref(c.Image)},
		{"Runtime", hdfutil.Deref(c.Runtime)},
		{"Cluster name", hdfutil.Deref(c.ClusterName)},
		{"Namespace", hdfutil.Deref(c.Namespace)},
		{"Platform type", hdfutil.Deref(c.PlatformType)},
		{"Version", hdfutil.Deref(c.Version)},
		{"Account ID", hdfutil.Deref(c.AccountID)},
		{"Provider", provider},
		{"Region", hdfutil.Deref(c.Region)},
		{"ARN", hdfutil.Deref(c.Arn)},
		{"Resource ID", hdfutil.Deref(c.ResourceID)},
		{"Resource type", hdfutil.Deref(c.ResourceType)},
		{"Branch", hdfutil.Deref(c.Branch)},
		{"Commit", hdfutil.Deref(c.Commit)},
		{"URL", hdfutil.Deref(c.URL)},
		{"Environment", hdfutil.Deref(c.Environment)},
		{"Package manager", hdfutil.Deref(c.PackageManager)},
		{"Package name", hdfutil.Deref(c.PackageName)},
		{"CIDR", hdfutil.Deref(c.CIDR)},
		{"Gateway", hdfutil.Deref(c.Gateway)},
		{"Engine", hdfutil.Deref(c.Engine)},
		{"Host", hdfutil.Deref(c.Host)},
		{"Port", port},
		{"Model ID", hdfutil.Deref(c.ModelID)},
		{"Dataset ID", hdfutil.Deref(c.DatasetID)},
		{"Owner", identity(c.Owner)},
	}
	f := r.openFoldCounted("component", "", "h3", escape(c.Name)+` <span class="type">`+escape(string(c.Type))+closeSpan, c.Name,
		countFacts(facts)+len(c.Labels)+len(c.ExternalIDS), r.src.attributed)
	r.definitionList(facts)
	r.chips("Labels", c.Labels)
	r.chips("External IDs", c.ExternalIDS)
	r.closeFold(f)
}

// chips writes a map as key/value chips in key order. An empty value is kept:
// the key itself is the information.
func (r *renderer) chips(heading string, m map[string]string) {
	if len(m) == 0 {
		return
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	r.line("<h4>" + heading + "</h4>")
	r.line(`<ul class="chips">`)
	for _, k := range keys {
		r.line(`<li><span class="k">` + escape(k) + `</span><span class="v">` + escape(m[k]) + "</span></li>")
	}
	r.line(closeList)
}

// compliancePercent is the compliance percentage hdf-engine computes, to two
// places, so the report never disagrees with `hdf validate threshold` in the
// last digit. FormatFixed is toFixed's rounding, which is what the TypeScript
// peer uses on the same number.
func compliancePercent(c *hdfengine.StatusCounts) string {
	return hdfutil.FormatFixed(hdfengine.CalculateCompliance(c), 2)
}

func complianceText(c *hdfengine.StatusCounts) string {
	return compliancePercent(c) + "%"
}

// severityClass maps a severity onto the fixed set the stylesheet knows; an
// informational, absent or unrecognized severity is "none".
func severityClass(severity string) string {
	// The engine's bucket rule; its informational catch-all is the stylesheet's "none".
	if b := hdfengine.SeverityBucket(severity); b != "informational" {
		return b
	}
	return severityNone
}

func severityLabel(severity string) string {
	switch severity {
	case severityCritical:
		return "Critical"
	case severityHigh:
		return "High"
	case severityMedium:
		return "Medium"
	case severityLow:
		return "Low"
	case "", severityNone, "informational":
		return "None"
	}
	return severity
}

// checkCounts tallies individual results the way the Heimdall report words
// them: passed checks under passed requirements, and passed and failed checks
// under failed requirements, out of every check in the document. A requirement
// passed by an override keeps its failed checks out of the passed tally.
type checkCounts struct {
	underPassed, passedUnderFailed, failedUnderFailed, total int
}

func (r *renderer) effectiveStatus(req hdf.EvaluatedRequirement) string {
	return hdfutil.ComputeEffectiveStatus(shared.RequirementStatusInput(req), r.src.ref)
}

// add counts one requirement's checks under its effective status.
func (c *checkCounts) add(status string, results []hdf.RequirementResult) {
	c.total += len(results)
	for _, res := range results {
		switch {
		case status == statusPassed && res.Status == hdf.Passed:
			c.underPassed++
		case status == statusFailed && res.Status == hdf.Passed:
			c.passedUnderFailed++
		case status == statusFailed && res.Status == hdf.Failed:
			c.failedUnderFailed++
		}
	}
}

// statusTally is every count the status section reports.
type statusTally struct {
	all         *hdfengine.StatusCounts
	checks      checkCounts
	perSource   []*hdfengine.StatusCounts
	perBaseline [][]*hdfengine.StatusCounts
	anyRef      bool
}

func (r *renderer) tally() *statusTally {
	t := &statusTally{
		perSource:   make([]*hdfengine.StatusCounts, len(r.sources)),
		perBaseline: make([][]*hdfengine.StatusCounts, len(r.sources)),
	}
	for si := range r.sources {
		r.src = &r.sources[si]
		t.anyRef = t.anyRef || r.src.hasRef
		baselines := r.src.doc.Baselines
		t.perBaseline[si] = make([]*hdfengine.StatusCounts, len(baselines))
		for i := range baselines {
			t.perBaseline[si][i] = r.tallyBaseline(t, baselines[i])
		}
		t.perSource[si] = hdfengine.AddCounts(t.perBaseline[si]...)
	}
	t.all = hdfengine.AddCounts(t.perSource...)
	return t
}

// tallyBaseline hands the status and severity tally to hdf-engine, so the
// report's numbers are the ones the threshold gate and the MCP tools report.
// The per-check counts the dashboard words beside them have no engine peer and
// are taken here.
func (r *renderer) tallyBaseline(t *statusTally, baseline hdf.EvaluatedBaseline) *hdfengine.StatusCounts {
	for j := range baseline.Requirements {
		req := &baseline.Requirements[j]
		t.checks.add(r.effectiveStatus(*req), req.Results)
	}
	one := hdf.HDFResults{Baselines: []hdf.EvaluatedBaseline{baseline}}
	return hdfengine.CountControlsByStatusAt(one, r.effectiveStatus, r.src.ref)
}

func (r *renderer) status() {
	t := r.tally()
	r.line(`<section id="status" class="card" aria-labelledby="status-heading">`)
	r.line(`<h2 id="status-heading">Status</h2>`)
	r.asOf(t)
	r.dashboard(t)
	if r.aggregated {
		r.statusBySource(t)
	}
	r.statusByBaseline(t)
	r.line(closeSection)
}

// asOf states the instant effective status was judged at, when there is one.
func (r *renderer) asOf(t *statusTally) {
	switch {
	case hdfengine.SeverityTotals(t.all).Total == 0 || !t.anyRef:
	case r.aggregated:
		r.line(`<p class="as-of">Effective status evaluated for each source as of its own assessment time. ` +
			`Overrides that had expired by then are not applied.</p>`)
	default:
		r.line(`<p class="as-of">Effective status evaluated as of ` + escape(formatTime(r.sources[0].ref)) +
			`, the time of the assessment. Overrides that had expired by then are not applied.</p>`)
	}
}

func (r *renderer) dashboard(t *statusTally) {
	all, severities, checks := t.all, hdfengine.SeverityTotals(t.all), t.checks
	r.line(`<div class="dashboard">`)

	r.line(`<div class="panel">`)
	r.line("<h3>Requirements</h3>")
	r.line(`<ul class="stats">`)
	r.line(stat(statusPassed, all.Passed.Total, labelPassed, plural(checks.underPassed, "individual check")+" passed"))
	r.line(stat(statusFailed, all.Failed.Total, labelFailed, plural(checks.passedUnderFailed, "individual check")+" passed, "+
		strconv.Itoa(checks.failedUnderFailed)+" failed out of "+plural(checks.total, "total check")))
	r.line(stat(classNotApplicable, all.NoImpact.Total, labelNotApplicable, ""))
	r.line(stat(classNotReviewed, all.Skipped.Total, labelNotReviewed, ""))
	r.line(stat(statusError, all.Error.Total, labelError, ""))
	r.line(`<li class="stat stat-total"><span class="num">` + strconv.Itoa(severities.Total) + `</span><span class="lbl">Total</span></li>`)
	r.line(closeList)
	r.line(bar("Requirements by status", []segment{
		{statusPassed, statusPassed, all.Passed.Total}, {statusFailed, statusFailed, all.Failed.Total},
		{classNotApplicable, "not applicable", all.NoImpact.Total},
		{classNotReviewed, "not reviewed", all.Skipped.Total}, {statusError, statusError, all.Error.Total},
	}))
	r.line(closeDiv)

	r.line(`<div class="panel">`)
	r.line("<h3>Severity</h3>")
	r.line(`<ul class="stats">`)
	r.line(stat(severityCritical, severities.Critical, "Critical", ""))
	r.line(stat(severityHigh, severities.High, "High", ""))
	r.line(stat(severityMedium, severities.Medium, "Medium", ""))
	r.line(stat(severityLow, severities.Low, "Low", ""))
	// The engine's informational bucket is this report's "none": every severity
	// outside critical/high/medium/low lands there under both namings.
	r.line(stat(severityNone, severities.Informational, "None", ""))
	r.line(closeList)
	r.line(bar("Requirements by severity", []segment{
		{severityCritical, severityCritical, severities.Critical}, {severityHigh, severityHigh, severities.High},
		{severityMedium, severityMedium, severities.Medium},
		{severityLow, severityLow, severities.Low}, {severityNone, severityNone, severities.Informational},
	}))
	r.line(closeDiv)

	level, levelLabel := complianceLevel(hdfengine.CalculateCompliance(all))
	r.line(`<div class="panel compliance compliance-` + level + `">`)
	r.line(`<h3 id="compliance-heading">Compliance</h3>`)
	// A measurement on a fixed scale, not work in progress, so the ring is a meter
	// to assistive technology. The percentage is printed inside it because the
	// sweep and its band colour say nothing on their own.
	r.line(`<div class="gauge" role="meter" aria-valuemin="0" aria-valuemax="100" aria-valuenow="` + compliancePercent(all) +
		`" aria-labelledby="compliance-heading" style="--pct:` + compliancePercent(all) + `"><span class="pct">` +
		complianceText(all) + "</span>" + closeDiv)
	r.line(`<p class="level">` + levelLabel + "</p>")
	r.line(`<p class="formula">Passed / (Passed + Failed + Not Reviewed + Error) × 100</p>`)
	r.line(closeDiv)

	r.line(closeDiv)
}

// complianceLevel bands the engine's compliance percentage at 90 and 60.
func complianceLevel(pct float64) (class, label string) {
	switch {
	case pct >= 90:
		return severityHigh, "High compliance"
	case pct >= 60:
		return severityMedium, "Medium compliance"
	}
	return severityLow, "Low compliance"
}

func (r *renderer) statusBySource(t *statusTally) {
	f := r.openFold("", "", "h3", "Status by source", "the status by source", len(r.sources))
	r.openTable(`class="summary" aria-label="Status by source"`, summaryHead("Source"))
	for si := range r.sources {
		r.line(summaryRow(`<a href="#`+sourceID(si)+`">`+escape(r.sources[si].name)+"</a>", t.perSource[si]))
	}
	r.closeTable(summaryRow("All sources", t.all))
	r.closeFold(f)
}

func (r *renderer) statusByBaseline(t *statusTally) {
	baselineCount := 0
	for si := range r.sources {
		baselineCount += len(r.sources[si].doc.Baselines)
	}
	f := r.openFold("", "", "h3", "Status by baseline", "the status by baseline", baselineCount)
	r.openTable(`class="summary" aria-label="Status by baseline"`, summaryHead("Baseline"))
	for si := range r.sources {
		for i := range r.sources[si].doc.Baselines {
			label := r.sources[si].baselineLabels[i]
			if r.aggregated {
				label = r.sources[si].name + " \u203a " + label
			}
			r.line(summaryRow(escape(label), t.perBaseline[si][i]))
		}
	}
	r.closeTable(summaryRow("All baselines", t.all))
	r.closeFold(f)
}

// openTable starts a scrollable table: attrs are the table's attributes, head
// its header row, empty for a table without one.
func (r *renderer) openTable(attrs, head string) {
	r.line(`<div class="table-wrap">`)
	r.line("<table " + attrs + ">")
	if head != "" {
		r.line(head)
	}
	r.line("<tbody>")
}

// closeTable ends the table, with a footer row when one is given.
func (r *renderer) closeTable(foot string) {
	r.line("</tbody>")
	if foot != "" {
		r.line("<tfoot>")
		r.line(foot)
		r.line("</tfoot>")
	}
	r.line("</table>")
	r.line(closeDiv)
}

func summaryHead(first string) string {
	return `<thead><tr><th scope="col">` + first + `</th><th scope="col">Passed</th><th scope="col">Failed</th>` +
		`<th scope="col">Not Reviewed</th><th scope="col">Not Applicable</th><th scope="col">Error</th>` +
		`<th scope="col">Total</th><th scope="col">Compliance</th></tr></thead>`
}

func plural(n int, noun string) string {
	if n == 1 {
		return "1 " + noun
	}
	return strconv.Itoa(n) + " " + noun + "s"
}

func stat(class string, n int, label, sub string) string {
	s := `<li class="stat c-` + class + `"><span class="num">` + strconv.Itoa(n) + `</span><span class="lbl">` + label + closeSpan
	if sub != "" {
		s += `<span class="sub">` + sub + closeSpan
	}
	return s + "</li>"
}

type segment struct {
	class, name string
	n           int
}

// bar is a proportional strip; a zero count contributes no segment. It is an
// image to assistive technology, described by the same counts the list above
// it states, so nothing is conveyed by colour alone.
func bar(label string, segments []segment) string {
	described := make([]string, len(segments))
	var spans strings.Builder
	for i, s := range segments {
		described[i] = strconv.Itoa(s.n) + " " + s.name
		if s.n > 0 {
			spans.WriteString(`<span class="seg c-` + s.class + `" style="--n:` + strconv.Itoa(s.n) + `"></span>`)
		}
	}
	return `<div class="bar" role="img" aria-label="` + label + ": " + strings.Join(described, ", ") + `">` + spans.String() + "</div>"
}

// summaryRow takes a name that is already HTML.
func summaryRow(name string, c *hdfengine.StatusCounts) string {
	var b strings.Builder
	b.WriteString(`<tr><th scope="row">` + name + "</th>")
	for _, n := range []int{c.Passed.Total, c.Failed.Total, c.Skipped.Total, c.NoImpact.Total, c.Error.Total, hdfengine.SeverityTotals(c).Total} {
		b.WriteString("<td>" + strconv.Itoa(n) + "</td>")
	}
	b.WriteString("<td>" + complianceText(c) + rowClose)
	return b.String()
}

func (r *renderer) results() {
	r.line(`<section id="results" class="card" aria-labelledby="results-heading">`)
	r.line(`<h2 id="results-heading">Results</h2>`)
	r.line(`<div class="toolbar">`)
	r.line(`<input type="search" id="filter-text" placeholder="Filter by ID, title or control" aria-label="Filter requirements by ID, title or control" />`)
	r.line(`<div class="filters" role="group" aria-label="Filter by status">`)
	r.line(`<button type="button" class="filter" data-status="all" aria-pressed="true">All</button>`)
	for _, f := range [][2]string{
		{statusPassed, labelPassed}, {statusFailed, labelFailed}, {classNotApplicable, labelNotApplicable},
		{classNotReviewed, labelNotReviewed}, {statusError, labelError},
	} {
		r.line(`<button type="button" class="filter" data-status="` + f[0] + `" aria-pressed="false">` + f[1] + "</button>")
	}
	r.line(closeDiv)
	r.line(`<button type="button" id="expand-all">Expand all</button>`)
	r.line(`<button type="button" id="collapse-all">Collapse all</button>`)
	r.line(`<span id="filter-count" class="shown" aria-live="polite"></span>`)
	r.line(closeDiv)

	for si := range r.sources {
		r.src = &r.sources[si]
		var f fold
		if r.aggregated {
			total := 0
			for i := range r.src.doc.Baselines {
				total += len(r.src.doc.Baselines[i].Requirements)
			}
			f = r.openFold("group source", "", "h3", escape(r.src.name), r.src.name, total)
		}
		for i := range r.src.doc.Baselines {
			r.baseline(&r.src.doc.Baselines[i], r.src.baselineLabels[i])
		}
		if r.aggregated {
			r.closeFold(f)
		}
	}
	r.line(closeSection)
}

func (r *renderer) baseline(baseline *hdf.EvaluatedBaseline, label string) {
	f := r.openFold("group baseline", "", r.baselineHeading(), escape(label), label, len(baseline.Requirements))
	facts := []pair{
		// The label may be the title, so the name is stated here: it is the key
		// `hdf query --baseline` and hdf_compliance groups select on.
		{"Name", baseline.Name},
		{"Title", hdfutil.Deref(baseline.Title)},
		{"Version", hdfutil.Deref(baseline.Version)},
		{"Summary", hdfutil.Deref(baseline.Summary)},
		{headingDescription, hdfutil.Deref(baseline.Description)},
		{"Maintainer", hdfutil.Deref(baseline.Maintainer)},
		{"License", hdfutil.Deref(baseline.License)},
		{"Copyright", hdfutil.Deref(baseline.Copyright)},
		{"Status message", hdfutil.Deref(baseline.StatusMessage)},
	}
	if n := countFacts(facts); n > 0 {
		details := r.openFold("", "", r.detailHeading(), "Baseline details", "the baseline details", n)
		r.definitionList(facts)
		r.closeFold(details)
	}
	r.externalReferences(r.detailHeading(), headingEnrichment, baseline.ExternalReferences)
	if len(baseline.Requirements) > 0 {
		r.line(`<div class="req-head" aria-hidden="true"><span>Status</span><span>ID</span><span>Severity</span>` +
			`<span>Title</span><span>800-53 Controls &amp; CCIs</span></div>`)
	}
	for j := range baseline.Requirements {
		r.requirement(&baseline.Requirements[j])
	}
	r.closeFold(f)
}

// descriptionHeading names a description the way the Heimdall report does.
func descriptionHeading(label string) string {
	switch label {
	case "default":
		return headingDescription
	case "check":
		return "Check Text"
	case "fix":
		return "Fix Text"
	case "rationale":
		return "Rationale"
	case "caveat":
		return "Caveat"
	}
	return label
}

func (r *renderer) requirement(req *hdf.EvaluatedRequirement) {
	effective := r.effectiveStatus(*req)
	severity := hdfengine.DeriveSeverity(shared.RequirementEffectiveImpactAt(*req, r.src.ref), req.Severity)
	disposition := shared.RequirementDisposition(*req, r.src.ref)
	nist := hdfutil.TagStrings(req.Tags, "nist")
	cci := hdfutil.TagStrings(req.Tags, "cci")

	class, _ := statusPresentation(effective)
	r.requirements++
	id := "req-" + strconv.Itoa(r.requirements)
	// Each requirement is independently meaningful, so it is an article holding
	// one disclosure rather than a bare disclosure.
	r.line(`<article class="requirement c-` + class + `" data-status="` + class + `" id="` + id + `">`)
	r.line("<details>")
	r.line("<summary>" + statusBadge(effective) + `<span class="req-id">` + escape(req.ID) + closeSpan +
		`<span class="sev c-` + severityClass(severity) + `"><span class="vh">Severity: </span>` + escape(severityLabel(severity)) + closeSpan +
		`<span class="req-title">` + escape(hdfutil.Deref(req.Title)) + `</span><span class="tags">` +
		controlTags(append(append([]string{}, nist...), cci...), len(req.ExternalReferences)) + "</span></summary>")
	r.line(`<div class="req-body">`)

	lead := leadDescription(req.Descriptions)
	location := sourceLocation(req.SourceLocation)
	if location != "" {
		r.line(`<p class="location"><span class="k">Location</span><code>` + escape(location) + "</code></p>")
	}
	if lead >= 0 {
		r.description(req.Descriptions[lead].Data)
	}

	r.resultRows(req.Results)

	rows := requirementRows(req, r.src.ref, effective, severity, disposition, location, nist, cci, lead)
	f := r.openFold("", "", r.detailHeading(), "Result Details", "the result details", len(rows))
	r.openTable(`class="details" aria-label="Result details"`, "")
	for _, row := range rows {
		r.line(row)
	}
	r.closeTable("")
	r.closeFold(f)

	r.tagChips(req.Tags)
	r.externalReferences(r.detailHeading(), headingEnrichment, req.ExternalReferences)
	r.overrideRows(req.StatusOverrides)
	for i := range req.StatusOverrides {
		r.externalReferences(r.detailHeading(), "References for override "+strconv.Itoa(i+1), req.StatusOverrides[i].ExternalReferences)
	}
	r.poamRows(req.Poams)
	r.code(req.Code)

	r.line(`<p class="to-top"><a href="#` + id + `">Back to the top of this requirement</a></p>`)
	r.line(closeDiv)
	r.line("</details>")
	r.line("</article>")
}

// controlTags is the summary line's chips: the controls, then a mark when the
// requirement carries enrichment.
func controlTags(controls []string, enrichments int) string {
	var tags strings.Builder
	for i, t := range controls {
		if i == 0 {
			tags.WriteString(`<span class="vh">Controls: </span>`)
		}
		tags.WriteString(`<span class="tag">` + escape(t) + closeSpan)
	}
	if enrichments > 0 {
		tags.WriteString(`<span class="tag enriched">Enriched (` + strconv.Itoa(enrichments) + ")</span>")
	}
	return tags.String()
}

// leadDescription is the index of the first default description, which leads
// the body; every other one is a detail row. -1 when there is none.
func leadDescription(descriptions []hdf.Description) int {
	for i := range descriptions {
		if descriptions[i].Label == "default" {
			return i
		}
	}
	return -1
}

// description writes the lead description, folded when it is long.
func (r *renderer) description(text string) {
	if text == "" {
		return
	}
	if !isLongText(text) {
		r.line(prose(text))
		return
	}
	f := r.openFold("", "", r.detailHeading(), headingDescription, "the description", lineCount(text))
	r.line(prose(text))
	r.closeFold(f)
}

// requirementRows is the detail table: the two statuses, every field that has a
// value, then the references and the descriptions other than the lead.
func requirementRows(req *hdf.EvaluatedRequirement, ref time.Time, effective, severity, disposition, location string, nist, cci []string, lead int) []string {
	statuses := make([]string, len(req.Results))
	for i := range req.Results {
		statuses[i] = string(req.Results[i].Status)
	}
	// Through the ladder, never the stored cache: the stored effectiveImpact and
	// disposition are output caches a document may carry stale or not at all,
	// and the summary table this page also shows already counts the ladder.
	effectiveImpact := hdfutil.FormatFixed(shared.RequirementEffectiveImpactAt(*req, ref), 2)
	rows := []string{
		detailRow("Effective status", statusBadge(effective)),
		detailRow("Assessed status", statusBadge(hdfutil.WorstStatus(statuses))),
	}
	for _, p := range []pair{
		{"Control", req.ID},
		{"Title", hdfutil.Deref(req.Title)},
		{"Severity", severity},
		{"Impact", hdfutil.FormatFixed(req.Impact, 2)},
		{"Effective impact", effectiveImpact},
		{"Disposition", disposition},
		{"Control type", string(hdfutil.Deref(req.ControlType))},
		{"Verification method", string(hdfutil.Deref(req.VerificationMethod))},
		{"Applicability", string(hdfutil.Deref(req.Applicability))},
		{"Source location", location},
		{"NIST Controls", strings.Join(nist, ", ")},
		{"CCI Controls", strings.Join(cci, ", ")},
		{"CWE", strings.Join(req.Cwe, ", ")},
		{"CVSS", cvssText(req.Cvss)},
		{"EPSS", epssText(req.Epss)},
		{"KEV", kevText(req.Kev)},
		{"Affected packages", packagesText(req.AffectedPackages)},
		{"Evidence", evidenceText(req.Evidence)},
	} {
		if p.value != "" {
			rows = append(rows, detailRow(p.term, escape(p.value)))
		}
	}
	if references := referenceLines(req.Refs); len(references) > 0 {
		rows = append(rows, detailRow("References", prose(strings.Join(references, "\n"))))
	}
	for i, d := range req.Descriptions {
		if i != lead {
			rows = append(rows, detailRow(escape(descriptionHeading(d.Label)), prose(d.Data)))
		}
	}
	return rows
}

// code shows a requirement's test code, which only the Administrator report carries.
func (r *renderer) code(code *string) {
	if r.reportType != Administrator || code == nil || *code == "" {
		return
	}
	f := r.openFold("", "", r.detailHeading(), "Code", "the code", lineCount(*code))
	r.line(`<pre class="code">` + "\n" + escape(*code) + "</pre>")
	r.closeFold(f)
}

// detailRow takes a heading and a value that are already HTML.
func detailRow(heading, value string) string {
	return `<tr><th scope="row">` + heading + "</th><td>" + value + rowClose
}

// prose carries text verbatim. An HTML parser drops one newline directly after
// <pre>, so one is always written for it to drop.
func prose(text string) string {
	return `<pre class="prose">` + "\n" + escape(text) + "</pre>"
}

func (r *renderer) resultRows(results []hdf.RequirementResult) {
	if len(results) == 0 {
		return
	}
	f := r.openFold("", "", r.detailHeading(), "Test Results", "the test results", len(results))
	r.openTable(`aria-label="Test results"`, `<thead><tr><th scope="col">Status</th><th scope="col">Test</th><th scope="col">Result</th>`+
		`<th scope="col">Started</th></tr></thead>`)
	for i := range results {
		res := &results[i]
		runTime := ""
		if res.RunTime != nil {
			runTime = hdfutil.FormatFixed(*res.RunTime, 3) + " s"
		}
		r.line(rowOpen + statusBadge(string(res.Status)) + textCell + escape(res.CodeDesc) +
			subLine("Resource", joinNonEmpty(separator, hdfutil.Deref(res.Resource), hdfutil.Deref(res.ResourceID))) +
			textCell + escape(hdfutil.Deref(res.Message)) +
			subLine("Exception", hdfutil.Deref(res.Exception)) + subLine("Backtrace", strings.Join(res.Backtrace, "\n")) +
			cell + escape(formatTime(res.StartTime)) + subLine("Run time", runTime) + rowClose)
	}
	r.closeTable("")
	r.closeFold(f)
}

func (r *renderer) overrideRows(overrides []hdf.StatusOverride) {
	if len(overrides) == 0 {
		return
	}
	governing := hdfutil.GoverningStatusOverrideIndex(shared.StatusOverrideInputs(overrides), r.src.ref)

	f := r.openFold("", "", r.detailHeading(), "Overrides", "the overrides", len(overrides))
	r.openTable(`aria-label="Overrides"`, `<thead><tr><th scope="col">Type</th><th scope="col">Status</th><th scope="col">Reason</th>`+
		`<th scope="col">Applied by</th><th scope="col">Applied at</th><th scope="col">Expires at</th>`+
		`<th scope="col">State</th></tr></thead>`)
	for i := range overrides {
		o := &overrides[i]
		status := ""
		if o.Status != nil && *o.Status != "" {
			status = statusBadge(string(*o.Status))
		}
		state := ""
		switch {
		case i == governing:
			state = "governing"
		case !o.ExpiresAt.IsZero() && !o.ExpiresAt.After(r.src.ref):
			state = "expired"
		}
		impact := ""
		if o.Impact != nil {
			impact = hdfutil.FormatFixed(o.Impact.Value, 2)
		}
		cvss := ""
		if o.Cvss != nil {
			cvss = cvssText([]hdf.Cvss{*o.Cvss})
		}
		r.line(rowOpen + escape(string(o.Type)) + cell + status + subLine("Impact", impact) + subLine("CVSS", cvss) +
			textCell + escape(o.Reason) + subLine("Justification", string(hdfutil.Deref(o.Justification))) +
			cell + escape(o.AppliedBy.Identifier) + cell + escape(formatTime(o.AppliedAt)) +
			cell + escape(formatTime(o.ExpiresAt)) + cell + state + rowClose)
	}
	r.closeTable("")
	r.closeFold(f)
}

func (r *renderer) poamRows(poams []hdf.PoamElement) {
	if len(poams) == 0 {
		return
	}
	f := r.openFold("", "", r.detailHeading(), "POA&amp;Ms", "the POA&Ms", len(poams))
	r.openTable(`aria-label="Plans of action and milestones"`, `<thead><tr><th scope="col">Type</th><th scope="col">Explanation</th><th scope="col">Applied by</th>`+
		`<th scope="col">Applied at</th><th scope="col">Expires at</th></tr></thead>`)
	for i := range poams {
		p := &poams[i]
		var milestones strings.Builder
		for j := range p.Milestones {
			m := &p.Milestones[j]
			milestones.WriteString(subLine("Milestone", joinNonEmpty(separator, string(m.Status), hdfutil.Deref(m.Title), m.Description,
				formatTime(m.EstimatedCompletion))))
		}
		r.line(rowOpen + escape(string(p.Type)) + textCell + escape(p.Explanation) + milestones.String() +
			cell + escape(p.AppliedBy.Identifier) + cell + escape(formatTime(p.AppliedAt)) +
			cell + escape(formatTime(p.ExpiresAt)) + rowClose)
	}
	r.closeTable("")
	r.closeFold(f)
}

// referenceCensus counts the external references anywhere in the document and
// breaks them down by kind, so even the executive report says whether the
// results carry enrichment.
func referenceCensus(doc *hdf.HDFResults) string {
	total := 0
	kinds := map[string]int{}
	count := func(refs []hdf.ExternalReference) {
		total += len(refs)
		for i := range refs {
			if kind := hdfutil.Deref(refs[i].Kind); kind != "" {
				kinds[kind]++
			}
		}
	}
	count(doc.ExternalReferences)
	for i := range doc.Baselines {
		count(doc.Baselines[i].ExternalReferences)
		for j := range doc.Baselines[i].Requirements {
			req := &doc.Baselines[i].Requirements[j]
			count(req.ExternalReferences)
			for k := range req.StatusOverrides {
				count(req.StatusOverrides[k].ExternalReferences)
			}
		}
	}
	if total == 0 {
		return ""
	}
	if len(kinds) == 0 {
		return strconv.Itoa(total)
	}
	return strconv.Itoa(total) + " (" + kindBreakdown(kinds) + ")"
}

// kindBreakdown lists each kind with its count, in kind order.
func kindBreakdown(kinds map[string]int) string {
	names := make([]string, 0, len(kinds))
	for kind := range kinds {
		names = append(names, kind)
	}
	sort.Strings(names)
	parts := make([]string, len(names))
	for i, kind := range names {
		parts[i] = kind + " " + strconv.Itoa(kinds[kind])
	}
	return strings.Join(parts, ", ")
}

// externalReferences lists references to artifacts outside the document: a CVE,
// an ATT&CK technique, a STIX object. A reference that embeds its payload is an
// enrichment envelope, and the payload is shown whole because HDF carries it
// untouched rather than mapping it into fields.
func (r *renderer) externalReferences(headingTag, heading string, refs []hdf.ExternalReference) {
	if len(refs) == 0 {
		return
	}
	f := r.openFold("", "", headingTag, heading, strings.ToLower(heading[:1])+heading[1:], len(refs))
	r.openTable(`aria-label="`+heading+`"`, `<thead><tr><th scope="col">Source</th><th scope="col">ID</th><th scope="col">Kind</th>`+
		`<th scope="col">Relation</th><th scope="col">Detail</th></tr></thead>`)
	for i := range refs {
		ref := &refs[i]
		checksum := ""
		if ref.Checksum != nil {
			checksum = joinNonEmpty(":", string(ref.Checksum.Algorithm), ref.Checksum.Value)
		}
		added := ""
		if ref.AddedBy != nil {
			added = ref.AddedBy.Identifier
		}
		if ref.AddedAt != nil {
			added = joinNonEmpty(separator, added, formatTime(*ref.AddedAt))
		}
		r.line(rowOpen + escape(ref.SourceName) + cell + escape(hdfutil.Deref(ref.ExternalID)) + cell +
			escape(hdfutil.Deref(ref.Kind)) + cell + escape(hdfutil.Deref(ref.Rel)) + textCell +
			escape(hdfutil.Deref(ref.Description)) + subLine("Location", hdfutil.Deref(ref.Href)) + subLine("Media type", hdfutil.Deref(ref.MediaType)) +
			subLine("Checksum", checksum) + subLine("Added", added) + embeddedDocument(ref.Document) + rowClose)
	}
	r.closeTable("")
	r.closeFold(f)
}

// embeddedDocument shows an enrichment payload: what it says it is, then the
// whole object. Canonical JSON is what makes the text the same in both languages.
func embeddedDocument(document map[string]interface{}) string {
	if document == nil {
		return ""
	}
	canonical, err := hdfutil.CanonicalJSON(document)
	if err != nil {
		return ""
	}
	objectType, _ := document["type"].(string)
	name, _ := document["name"].(string)
	return subLine("Embedded", joinNonEmpty(separator, objectType, name)) +
		`<details class="doc"><summary>Embedded document</summary><pre class="code">` + "\n" +
		escape(indentJSON(string(canonical))) + "</pre></details>"
}

// indentJSON lays compact JSON out over lines, two spaces a level. It only
// inserts whitespace between tokens, so the values stay exactly as serialized.
func indentJSON(compact string) string {
	var b strings.Builder
	depth := 0
	newline := func() {
		b.WriteByte('\n')
		b.WriteString(strings.Repeat("  ", depth))
	}
	for i := 0; i < len(compact); i++ {
		c := compact[i]
		switch c {
		case '"':
			end := stringEnd(compact, i)
			b.WriteString(compact[i:end])
			i = end - 1
		case '{', '[':
			b.WriteByte(c)
			if closesAt(compact, i+1) {
				b.WriteByte(compact[i+1])
				i++
				continue
			}
			depth++
			newline()
		case '}', ']':
			depth--
			newline()
			b.WriteByte(c)
		case ',':
			b.WriteByte(c)
			newline()
		case ':':
			b.WriteString(": ")
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}

// stringEnd is the index just past the JSON string that opens at start; the end
// of the text when it never closes.
func stringEnd(text string, start int) int {
	for i := start + 1; i < len(text); i++ {
		switch text[i] {
		case '\\':
			i++
		case '"':
			return i + 1
		}
	}
	return len(text)
}

func closesAt(text string, i int) bool {
	return i < len(text) && (text[i] == '}' || text[i] == ']')
}

// tagChips shows the tags the detail table does not: every tag but nist and cci
// whose value is text, a list of text, or a boolean. Numbers and nested values
// are left out because the two languages do not print them alike.
func (r *renderer) tagChips(tags map[string]interface{}) {
	keys := make([]string, 0, len(tags))
	values := make(map[string]string, len(tags))
	for k, v := range tags {
		if k == "nist" || k == "cci" {
			continue
		}
		value, ok := tagText(v)
		if !ok {
			continue
		}
		keys = append(keys, k)
		values[k] = value
	}
	if len(keys) == 0 {
		return
	}
	sort.Strings(keys)

	f := r.openFold("", "", r.detailHeading(), "Tags", "the tags", len(keys))
	r.line(`<ul class="chips">`)
	for _, k := range keys {
		r.line(`<li><span class="k">` + escape(k) + `</span><span class="v">` + escape(values[k]) + "</span></li>")
	}
	r.line(closeList)
	r.closeFold(f)
}

func tagText(v interface{}) (string, bool) {
	switch t := v.(type) {
	case string:
		return t, true
	case bool:
		return strconv.FormatBool(t), true
	case []interface{}:
		items := hdfutil.SafeStringSlice(t)
		return strings.Join(items, ", "), len(items) > 0
	}
	return "", false
}

// subLine is a labelled secondary line inside a table cell; empty when there is
// nothing to say.
func subLine(label, value string) string {
	if value == "" {
		return ""
	}
	return `<span class="sub"><span class="k">` + label + `</span> ` + escape(value) + closeSpan
}

// sourceLocation is where the finding sits in the assessed source: file, and
// line when there is one.
func sourceLocation(loc *hdf.SourceLocation) string {
	if loc == nil {
		return ""
	}
	ref := hdfutil.Deref(loc.Ref)
	if loc.Line == nil {
		return ref
	}
	line := strconv.FormatFloat(*loc.Line, 'f', -1, 64)
	if ref == "" {
		return "line " + line
	}
	return ref + ":" + line
}

func cvssText(entries []hdf.Cvss) string {
	parts := make([]string, 0, len(entries))
	for i := range entries {
		c := &entries[i]
		score, severity := c.BaseScore, c.BaseSeverity
		if c.ComputedScore != nil {
			score = c.ComputedScore
		}
		if c.ComputedSeverity != nil {
			severity = c.ComputedSeverity
		}
		scoreText := ""
		if score != nil {
			scoreText = hdfutil.FormatFixed(*score, 1)
		}
		version := string(c.Version)
		if version != "" {
			version = "v" + version
		}
		source := hdfutil.Deref(c.Source)
		if source != "" {
			source = "(" + source + ")"
		}
		if part := joinNonEmpty(" ", version, scoreText, string(hdfutil.Deref(severity)), hdfutil.Deref(c.BaseVector), source); part != "" {
			parts = append(parts, part)
		}
	}
	return strings.Join(parts, "; ")
}

func epssText(e *hdf.Epss) string {
	if e == nil {
		return ""
	}
	text := "score " + hdfutil.FormatFixed(e.Score, 5) + ", percentile " + hdfutil.FormatFixed(e.Percentile, 5)
	if e.Date != "" {
		text += ", as of " + e.Date
	}
	return text
}

func kevText(k *hdf.Kev) string {
	if k == nil {
		return ""
	}
	text := "Not listed"
	if k.InKev {
		text = "Listed"
	}
	if added := hdfutil.Deref(k.DateAdded); added != "" {
		text += ", added " + added
	}
	if due := hdfutil.Deref(k.DueDate); due != "" {
		text += ", due " + due
	}
	if notes := hdfutil.Deref(k.Notes); notes != "" {
		text += ", " + notes
	}
	return text
}

func packagesText(packages []hdf.AffectedPackage) string {
	parts := make([]string, 0, len(packages))
	for i := range packages {
		p := &packages[i]
		part := joinNonEmpty(" ", hdfutil.Deref(p.Name), hdfutil.Deref(p.Version))
		if part == "" {
			part = joinNonEmpty(" ", hdfutil.Deref(p.Purl), hdfutil.Deref(p.Cpe))
		}
		if fixed := hdfutil.Deref(p.FixedInVersion); fixed != "" {
			part = joinNonEmpty(" ", part, "(fixed in "+fixed+")")
		}
		if part != "" {
			parts = append(parts, part)
		}
	}
	return strings.Join(parts, "; ")
}

func evidenceText(evidence []hdf.Evidence) string {
	parts := make([]string, 0, len(evidence))
	for i := range evidence {
		if part := joinNonEmpty(": ", string(evidence[i].Type), hdfutil.Deref(evidence[i].Description)); part != "" {
			parts = append(parts, part)
		}
	}
	return strings.Join(parts, "; ")
}

// referenceLines lists each reference's text. A structured ref is reduced to
// the URLs inside it, sorted, because a map has no order to preserve.
func referenceLines(refs []hdf.Reference) []string {
	var lines []string
	for i := range refs {
		ref := &refs[i]
		if ref.Ref != nil {
			lines = append(lines, structuredRefLines(hdfutil.Deref(ref.Ref.String), ref.Ref.AnythingMapArray)...)
		}
		for _, s := range []string{hdfutil.Deref(ref.URL), hdfutil.Deref(ref.URI)} {
			if s != "" {
				lines = append(lines, s)
			}
		}
	}
	return lines
}

// structuredRefLines is a ref's own text, then the URLs inside its objects.
func structuredRefLines(text string, objects []map[string]interface{}) []string {
	var lines []string
	if text != "" {
		lines = append(lines, text)
	}
	urls := map[string]bool{}
	for _, m := range objects {
		collectURLs(m, urls)
	}
	sorted := make([]string, 0, len(urls))
	for u := range urls {
		sorted = append(sorted, u)
	}
	sort.Strings(sorted)
	return append(lines, sorted...)
}

func collectURLs(v interface{}, into map[string]bool) {
	switch t := v.(type) {
	case map[string]interface{}:
		for k, child := range t {
			if s, ok := child.(string); ok && k == "url" && s != "" {
				into[s] = true
				continue
			}
			collectURLs(child, into)
		}
	case []interface{}:
		for _, child := range t {
			collectURLs(child, into)
		}
	}
}

// statusPresentation gives a status a class from a fixed set, never from the
// document: a status outside the enum is shown as text under one class.
func statusPresentation(status string) (class, label string) {
	switch status {
	case statusPassed:
		return statusPassed, labelPassed
	case statusFailed:
		return statusFailed, labelFailed
	case statusNotReviewed:
		return classNotReviewed, labelNotReviewed
	case statusNotApplicable:
		return classNotApplicable, labelNotApplicable
	case statusError:
		return statusError, labelError
	}
	return "unknown", status
}

// statusIcon is the mark beside the status word. Colour is the least reliable of
// the three channels — it is lost to colour-vision deficiency and to a greyscale
// printer — so every status carries a shape and a word as well.
func statusIcon(class string) string {
	switch class {
	case statusPassed:
		return "✓"
	case statusFailed:
		return "✗"
	case classNotApplicable:
		return "–"
	case classNotReviewed:
		return "?"
	case statusError:
		return "!"
	}
	return "·"
}

func statusBadge(status string) string {
	class, label := statusPresentation(status)
	return `<span class="status c-` + class + `"><span class="ico" aria-hidden="true">` + statusIcon(class) + closeSpan +
		escape(label) + closeSpan
}

func joinNonEmpty(sep string, parts ...string) string {
	kept := make([]string, 0, len(parts))
	for _, p := range parts {
		if p != "" {
			kept = append(kept, p)
		}
	}
	return strings.Join(kept, sep)
}

// formatTime renders HDF's canonical trimmed-UTC RFC3339; a zero time is absent.
func formatTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339Nano)
}

// escape makes text safe as HTML content and inside a double-quoted attribute.
// A carriage return is written as a character reference because a parser would
// otherwise fold it into the following newline. Characters HTML cannot carry at
// all become U+FFFD.
func escape(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, c := range s {
		switch {
		case c == '&':
			b.WriteString("&amp;")
		case c == '<':
			b.WriteString("&lt;")
		case c == '>':
			b.WriteString("&gt;")
		case c == '"':
			b.WriteString("&quot;")
		case c == '\'':
			b.WriteString("&#39;")
		case c == '\r':
			b.WriteString("&#13;")
		case c == '\t' || c == '\n':
			b.WriteRune(c)
		case c < 0x20 || c == 0x7f || c == 0xfffe || c == 0xffff:
			b.WriteRune('�')
		default:
			b.WriteRune(c)
		}
	}
	return b.String()
}
