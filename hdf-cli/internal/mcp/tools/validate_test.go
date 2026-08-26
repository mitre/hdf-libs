package tools

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mitre/hdf-libs/hdf-cli/v3/internal/mcp/handle"
	"github.com/mitre/hdf-libs/hdf-cli/v3/internal/mcp/loader"
	fixtures "github.com/mitre/hdf-libs/hdf-fixtures"
	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

func callValidate(t *testing.T, in validateInput) (*sdkmcp.CallToolResult, validateOutput) {
	t.Helper()
	res, out, err := hdfValidate(loader.New(0, 0, 0))(context.Background(), nil, in)
	if err != nil {
		t.Fatalf("hdfValidate returned a Go error (should use degraded/taxonomy paths): %v", err)
	}
	return res, out
}

func writeInRoot(t *testing.T, name string, content []byte) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(os.Getenv("HDF_MCP_ROOT"), name), content, 0o600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
}

func sha256HexT(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func evidencePkg(planRef string, entries ...map[string]any) []byte {
	pkg := map[string]any{"contents": entries}
	if planRef != "" {
		pkg["planRef"] = planRef
	}
	b, _ := json.Marshal(pkg)
	return b
}

func contentEntry(typ, uri, checksum string) map[string]any {
	e := map[string]any{"type": typ, "uri": uri}
	if checksum != "" {
		e["checksum"] = map[string]any{"algorithm": "sha256", "value": checksum}
	}
	return e
}

// The card's designated first-failing test.
func TestHdfValidate_ChecksumsMode(t *testing.T) {
	results := fixtures.Results.Minimal
	// Package records a WRONG checksum for the referenced results file.
	pkg := evidencePkg("", contentEntry("hdf-results", "r.json", "00"+sha256HexT(results)[2:]))
	writeRoot(t, "ev.json", pkg)
	writeInRoot(t, "r.json", results)

	errRes, out := callValidate(t, validateInput{Source: &handle.Source{Path: "ev.json"}, Mode: "checksums"})
	if errRes != nil {
		t.Fatalf("checksums mode should not be an isError result: %+v", errRes)
	}
	if out.Mode != "checksums" {
		t.Errorf("mode = %q, want checksums", out.Mode)
	}
	if out.Valid {
		t.Fatal("a bad checksum must make the document invalid")
	}
	var found bool
	for _, e := range out.Errors {
		if e.Path == "r.json" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected an error identifying r.json, got %+v", out.Errors)
	}
}

func TestHdfValidate_ChecksumsMode_AllMatch(t *testing.T) {
	results := fixtures.Results.Minimal
	pkg := evidencePkg("", contentEntry("hdf-results", "r.json", sha256HexT(results)))
	writeRoot(t, "ev.json", pkg)
	writeInRoot(t, "r.json", results)

	_, out := callValidate(t, validateInput{Source: &handle.Source{Path: "ev.json"}, Mode: "checksums"})
	if !out.Valid {
		t.Fatalf("all checksums match, expected valid; errors: %+v", out.Errors)
	}
}

func TestHdfValidate_SchemaMode_Valid_Inline(t *testing.T) {
	_, out := callValidate(t, validateInput{Content: string(fixtures.Results.Minimal), Mode: "schema"})
	if !out.Valid {
		t.Fatalf("valid results should validate; errors: %+v", out.Errors)
	}
	if out.DocType != "results" {
		t.Errorf("docType = %q, want results", out.DocType)
	}
}

func TestHdfValidate_SchemaMode_Invalid(t *testing.T) {
	_, out := callValidate(t, validateInput{Content: `{"baselines":"not-an-array"}`, Mode: "schema"})
	if out.Valid {
		t.Fatal("a malformed results doc must be invalid")
	}
	if len(out.Errors) == 0 {
		t.Fatal("expected structured errors")
	}
}

func TestHdfValidate_InlineEqualsSource(t *testing.T) {
	results := fixtures.Results.Minimal
	writeRoot(t, "scan.json", results)
	_, viaPath := callValidate(t, validateInput{Source: &handle.Source{Path: "scan.json"}, Mode: "schema"})
	_, viaInline := callValidate(t, validateInput{Content: string(results), Mode: "schema"})
	if viaPath.Valid != viaInline.Valid || viaPath.DocType != viaInline.DocType {
		t.Fatalf("path vs inline diverge: path=%+v inline=%+v", viaPath, viaInline)
	}
}

func TestHdfValidate_CompletenessMode(t *testing.T) {
	// Plan lists two baselines; the package covers only one.
	plan := []byte(`{"assessments":[{"baselineRef":"RHEL9-STIG"},{"baselineRef":"PostgreSQL-STIG"}]}`)
	rhel := []byte(`{"baselines":[{"name":"RHEL9-STIG"}]}`)
	pkg := evidencePkg("plan.json",
		contentEntry("hdf-results", "rhel.json", sha256HexT(rhel)))
	writeRoot(t, "ev.json", pkg)
	writeInRoot(t, "plan.json", plan)
	writeInRoot(t, "rhel.json", rhel)

	_, out := callValidate(t, validateInput{Source: &handle.Source{Path: "ev.json"}, Mode: "completeness"})
	if out.Mode != "completeness" {
		t.Errorf("mode = %q", out.Mode)
	}
	if out.Valid {
		t.Fatal("missing a planned baseline must be incomplete")
	}
	var namesPostgres bool
	for _, e := range out.Errors {
		if contains(e.Message, "PostgreSQL-STIG") {
			namesPostgres = true
		}
	}
	if !namesPostgres {
		t.Fatalf("completeness error should name the missing baseline: %+v", out.Errors)
	}
}

func TestHdfValidate_CompletenessMode_Complete(t *testing.T) {
	plan := []byte(`{"assessments":[{"baselineRef":"RHEL9-STIG"}]}`)
	rhel := []byte(`{"baselines":[{"name":"RHEL9-STIG"}]}`)
	pkg := evidencePkg("plan.json", contentEntry("hdf-results", "rhel.json", sha256HexT(rhel)))
	writeRoot(t, "ev.json", pkg)
	writeInRoot(t, "plan.json", plan)
	writeInRoot(t, "rhel.json", rhel)

	_, out := callValidate(t, validateInput{Source: &handle.Source{Path: "ev.json"}, Mode: "completeness"})
	if !out.Valid {
		t.Fatalf("all planned baselines covered, expected complete; errors: %+v", out.Errors)
	}
}

func TestHdfValidate_AgentOverrideCount(t *testing.T) {
	results := []byte(`{"baselines":[{"requirements":[{"statusOverrides":[{"appliedBy":{"type":"agent"}},{"appliedBy":{"type":"system"}}]}]}]}`)
	pkg := evidencePkg("", contentEntry("hdf-results", "r.json", sha256HexT(results)))
	writeRoot(t, "ev.json", pkg)
	writeInRoot(t, "r.json", results)

	_, out := callValidate(t, validateInput{Source: &handle.Source{Path: "ev.json"}, Mode: "checksums"})
	if out.AgentOverrideCount != 1 {
		t.Fatalf("agent override count = %d, want 1 (system override excluded)", out.AgentOverrideCount)
	}
}

func TestHdfValidate_ChecksumsRequiresEvidencePackage(t *testing.T) {
	writeRoot(t, "scan.json", fixtures.Results.Minimal)
	_, out := callValidate(t, validateInput{Source: &handle.Source{Path: "scan.json"}, Mode: "checksums"})
	if out.Valid {
		t.Fatal("checksums mode on a results doc must not report valid")
	}
	if len(out.Errors) == 0 || !contains(out.Errors[0].Message, "evidence-package") {
		t.Fatalf("expected an error explaining checksums needs an evidence package: %+v", out.Errors)
	}
}

func TestHdfValidate_SchemaMode_ExplicitDocType(t *testing.T) {
	plan := []byte(`{"assessments":[{"baselineRef":"RHEL9-STIG"}],"name":"p","type":"automated"}`)
	_, out := callValidate(t, validateInput{Content: string(plan), DocType: "hdf-plan", Mode: "schema"})
	if out.DocType != "plan" {
		t.Errorf("explicit docType should drive validation, got docType=%q", out.DocType)
	}
}

func TestHdfValidate_NeitherSourceNorContent(t *testing.T) {
	res, _ := callValidate(t, validateInput{Mode: "schema"})
	if res == nil || !res.IsError {
		t.Fatal("neither source nor content must be an isError result")
	}
}

func TestHdfValidate_UnknownMode(t *testing.T) {
	res, _ := callValidate(t, validateInput{Content: string(fixtures.Results.Minimal), Mode: "bogus"})
	if res == nil || !res.IsError {
		t.Fatal("an unknown mode must be an isError result")
	}
}

func TestHdfValidate_TokenBounded(t *testing.T) {
	out := validateOutput{Valid: false, Mode: "schema"}
	for i := 0; i < 500; i++ {
		out.Errors = append(out.Errors, validateError{
			Path:    "/baselines/very/long/path/segment/number/that/eats/tokens/index",
			Line:    i,
			Message: "a fairly verbose validation error message that consumes a meaningful number of tokens each",
		})
	}
	boundValidateResponse(&out)
	if len(out.Errors) >= 500 {
		t.Fatal("over-budget errors should be dropped")
	}
	if out.Notice == "" {
		t.Fatal("truncation must state its remedy")
	}
}

func TestHdfValidate_SchemaMode_ExplicitDocType_Invalid(t *testing.T) {
	// Invalid against the plan schema → line-numbered errors via the explicit path.
	_, out := callValidate(t, validateInput{Content: `{"assessments":"not-an-array"}`, DocType: "hdf-plan", Mode: "schema"})
	if out.Valid {
		t.Fatal("invalid plan must not validate")
	}
	if len(out.Errors) == 0 {
		t.Fatal("expected structured errors from the explicit-docType path")
	}
}

func TestHdfValidate_SchemaMode_UnknownDocType(t *testing.T) {
	_, out := callValidate(t, validateInput{Content: string(fixtures.Results.Minimal), DocType: "hdf-bogus", Mode: "schema"})
	if out.Valid || len(out.Errors) == 0 || !contains(out.Errors[0].Message, "unknown document type") {
		t.Fatalf("unknown docType should be reported: %+v", out)
	}
}

func TestHdfValidate_Checksums_MissingReferencedFile(t *testing.T) {
	pkg := evidencePkg("", contentEntry("hdf-results", "gone.json", "abc123"))
	writeRoot(t, "ev.json", pkg) // gone.json is never written
	_, out := callValidate(t, validateInput{Source: &handle.Source{Path: "ev.json"}, Mode: "checksums"})
	if out.Valid {
		t.Fatal("a referenced file that cannot be read must invalidate")
	}
	if len(out.Errors) == 0 || !contains(out.Errors[0].Message, "cannot verify checksum") {
		t.Fatalf("expected a checksum-verification error: %+v", out.Errors)
	}
}

func TestHdfValidate_Checksums_UnparseablePackage(t *testing.T) {
	writeRoot(t, "ev.json", []byte(`{"contents":{"not":"an-array"}}`))
	_, out := callValidate(t, validateInput{Source: &handle.Source{Path: "ev.json"}, Mode: "checksums"})
	if out.Valid || len(out.Errors) == 0 || !contains(out.Errors[0].Message, "cannot parse evidence package") {
		t.Fatalf("expected a parse error: %+v", out.Errors)
	}
}

func TestHdfValidate_Checksums_NonEvidenceUnrecognized(t *testing.T) {
	_, out := callValidate(t, validateInput{Content: "not json at all", Mode: "checksums"})
	if out.Valid || len(out.Errors) == 0 || !contains(out.Errors[0].Message, "unrecognized document") {
		t.Fatalf("expected an unrecognized-document message: %+v", out.Errors)
	}
}

func TestHdfValidate_Completeness_NoPlanRef(t *testing.T) {
	rhel := []byte(`{"baselines":[{"name":"RHEL9-STIG"}]}`)
	pkg := evidencePkg("", contentEntry("hdf-results", "rhel.json", sha256HexT(rhel)))
	writeRoot(t, "ev.json", pkg)
	writeInRoot(t, "rhel.json", rhel)
	_, out := callValidate(t, validateInput{Source: &handle.Source{Path: "ev.json"}, Mode: "completeness"})
	if out.Valid || len(out.Errors) == 0 || !contains(out.Errors[0].Message, "no planRef") {
		t.Fatalf("missing planRef should be reported: %+v", out.Errors)
	}
}

func TestHdfValidate_Completeness_PlanUnreadableAndUnparseable(t *testing.T) {
	pkg := evidencePkg("plan.json")
	writeRoot(t, "ev.json", pkg) // plan.json not written → unreadable
	_, out := callValidate(t, validateInput{Source: &handle.Source{Path: "ev.json"}, Mode: "completeness"})
	if out.Valid || !contains(out.Errors[0].Message, "cannot read plan") {
		t.Fatalf("unreadable plan should be reported: %+v", out.Errors)
	}

	writeInRoot(t, "plan.json", []byte("not json"))
	_, out2 := callValidate(t, validateInput{Source: &handle.Source{Path: "ev.json"}, Mode: "completeness"})
	if out2.Valid || !contains(out2.Errors[0].Message, "cannot parse plan") {
		t.Fatalf("unparseable plan should be reported: %+v", out2.Errors)
	}
}

func TestHdfValidate_BothSourceAndContent(t *testing.T) {
	writeRoot(t, "scan.json", fixtures.Results.Minimal)
	res, _ := callValidate(t, validateInput{Source: &handle.Source{Path: "scan.json"}, Content: "x", Mode: "schema"})
	assertArgError(t, res, "either source or content")
}

// A fetch failure must reference only the caller-relative uri, never the
// absolute confined path or raw errno — the error text flows into the
// client-visible ChecksumResult.Error, so a *PathError here would leak the
// deployer's filesystem layout.
func TestConfinedFetchAt_RedactsAbsolutePath(t *testing.T) {
	base := t.TempDir()
	_, err := confinedFetchAt(base)("missing.json")
	if err == nil {
		t.Fatal("fetching a missing referenced file must error")
	}
	if strings.Contains(err.Error(), base) {
		t.Errorf("fetch error leaked the absolute base path %q: %s", base, err.Error())
	}
	if !strings.Contains(err.Error(), "missing.json") {
		t.Errorf("fetch error should name the relative uri, got %s", err.Error())
	}
}

func TestHdfValidate_ConfinedFetchRejectsTraversal(t *testing.T) {
	if _, err := confinedFetchAt(t.TempDir())("../../../etc/passwd"); err == nil {
		t.Fatal("a referenced URI escaping the base directory must be rejected")
	}
}

func TestHdfValidate_Checksums_TraversalReferenceIsError(t *testing.T) {
	// A content URI that tries to escape the package directory must surface as a
	// checksum-verification error (rejected by SafePath), not be read.
	pkg := evidencePkg("", contentEntry("hdf-results", "../outside.json", "abc"))
	writeRoot(t, "ev.json", pkg)
	_, out := callValidate(t, validateInput{Source: &handle.Source{Path: "ev.json"}, Mode: "checksums"})
	if out.Valid {
		t.Fatal("a traversal reference must invalidate")
	}
	if len(out.Errors) == 0 || !contains(out.Errors[0].Message, "cannot verify checksum") {
		t.Fatalf("expected a checksum-verification error for the escaping ref: %+v", out.Errors)
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
