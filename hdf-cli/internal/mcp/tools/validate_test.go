package tools

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mitre/hdf-libs/hdf-cli/v3/internal/mcp/handle"
	"github.com/mitre/hdf-libs/hdf-cli/v3/internal/mcp/loader"
	hdfengine "github.com/mitre/hdf-libs/hdf-engine/go/v3"
	fixtures "github.com/mitre/hdf-libs/hdf-fixtures/v3"
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

// writeInRoot writes content at a root-relative path inside the HDF_MCP_ROOT
// the test established. The path may name subdirectories, which is what lets a
// test place a package somewhere other than the root and so tell the two
// resolution bases apart.
func writeInRoot(t testing.TB, rel string, content []byte) {
	t.Helper()
	// No root means filepath.Join would yield a relative path, so the write — and
	// any parent it needs — would land in the package source directory. There is
	// no fallback location.
	root := os.Getenv("HDF_MCP_ROOT")
	if root == "" {
		t.Fatalf("writeInRoot(%s): HDF_MCP_ROOT is unset — set it first", rel)
	}
	full := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(full), 0o750); err != nil {
		t.Fatalf("mkdir for %s: %v", rel, err)
	}
	if err := os.WriteFile(full, content, 0o600); err != nil {
		t.Fatalf("write %s: %v", rel, err)
	}
}

func sha256HexT(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func evidencePkg(planRef string, entries ...map[string]any) []byte {
	// name is required by the schema, and an empty variadic marshals as null
	// rather than []. Both made fixtures here schema-invalid, which went unnoticed
	// while these modes minted their own verdict instead of carrying the loader's.
	if entries == nil {
		entries = []map[string]any{}
	}
	pkg := map[string]any{"name": "test package", "contents": entries}
	if planRef != "" {
		pkg["planRef"] = planRef
	}
	b, _ := json.Marshal(pkg)
	return b
}

func contentEntry(typ, uri, checksum string) map[string]any {
	return contentEntryAlg(typ, uri, "sha256", checksum)
}

// contentEntryAlg is the shared implementation, with the algorithm as a parameter: every
// MCP-level checksum test hardcoded sha256, so nothing here covered the engine honouring
// the algorithm an entry actually records.
func contentEntryAlg(typ, uri, algorithm, checksum string) map[string]any {
	e := map[string]any{"type": typ, "uri": uri}
	if checksum != "" {
		e["checksum"] = map[string]any{"algorithm": algorithm, "value": checksum}
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
	if errRes != nil && errRes.IsError {
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
	if out.Valid || !anyErrorContains(out.Errors, "no planRef") {
		t.Fatalf("missing planRef should be reported: %+v", out.Errors)
	}
}

// Scanned rather than indexed: this fixture carries no contents entry, which the
// schema refuses (minItems 1), so the loader's error arrives alongside the plan
// one now that completeness mode carries the verdict instead of replacing the
// error list. Which error lands first is not this test's subject.
func TestHdfValidate_Completeness_PlanUnreadableAndUnparseable(t *testing.T) {
	pkg := evidencePkg("plan.json")
	writeRoot(t, "ev.json", pkg) // plan.json not written → unreadable
	_, out := callValidate(t, validateInput{Source: &handle.Source{Path: "ev.json"}, Mode: "completeness"})
	if out.Valid || !anyErrorContains(out.Errors, "cannot read plan") {
		t.Fatalf("unreadable plan should be reported: %+v", out.Errors)
	}

	writeInRoot(t, "plan.json", []byte("not json"))
	_, out2 := callValidate(t, validateInput{Source: &handle.Source{Path: "ev.json"}, Mode: "completeness"})
	if out2.Valid || !anyErrorContains(out2.Errors, "cannot parse plan") {
		t.Fatalf("unparseable plan should be reported: %+v", out2.Errors)
	}
}

// anyErrorContains answers "did the reply say this", which is what these tests
// mean, without pinning WHERE in the list it said it.
func anyErrorContains(errs []validateError, sub string) bool {
	for _, e := range errs {
		if contains(e.Message, sub) {
			return true
		}
	}
	return false
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

// The docType lookup is derived from the engine's enumeration, so hdf_validate
// accepts every type the engine can detect, with or without the hdf- prefix.
func TestSchemaTypeForDoc_CoversEngineKnownTypes(t *testing.T) {
	known := hdfengine.KnownTypes()
	if len(validShortTypes) != len(known) {
		t.Fatalf("validShortTypes has %d entries, engine knows %d", len(validShortTypes), len(known))
	}
	for _, k := range known {
		for _, in := range []string{k, "hdf-" + k} {
			st, ok := schemaTypeForDoc(in)
			if !ok || string(st) != k {
				t.Errorf("schemaTypeForDoc(%q) = %q/%t, want %q/true", in, st, ok, k)
			}
		}
	}
}

// A recorded algorithm this build cannot compute must reach the caller. The switch
// in validate.go handled two statuses — mismatch and error — with no default, so when
// the engine gained a distinct unsupported status the entry fell through: the package
// reported valid with no mention that a checksum had gone unchecked, telling a caller
// "valid" about bytes nobody verified. It is NOT an error (the bytes may be intact), so it
// belongs in the notice, not in a CHECKSUM error. Reached here with an OFF-SCHEMA
// algorithm, which is the only way left now that every algorithm the enum admits is
// computed — and unlike `hdf evidence info --verify`, this path reports such a document
// rather than refusing it.
//
// The verdict is nonetheless false, and the schema error is reported: an off-schema
// algorithm violates the schema, and this mode carries the loader's verdict rather
// than minting one. Maintainer decision 2026-10-13, reversing the earlier notice-only,
// still-valid shape — which was decided when checksum mode set valid itself.
func TestHdfValidate_NoticesAnAlgorithmItCannotCompute(t *testing.T) {
	results := fixtures.Results.Minimal
	pkg := evidencePkg("", map[string]any{
		"type": "hdf-results", "uri": "r.json",
		// md5, which is OFF-SCHEMA: every algorithm Hash_Algorithm admits is computed
		// now, so an uncomputable one can only arrive in a document this tooling did not
		// write. The value is never compared.
		"checksum": map[string]any{
			"algorithm": "md5",
			"value":     "d41d8cd98f00b204e9800998ecf8427e",
		},
	})
	writeRoot(t, "ev.json", pkg)
	writeInRoot(t, "r.json", results)

	errRes, out := callValidate(t, validateInput{Source: &handle.Source{Path: "ev.json"}, Mode: "checksums"})
	if errRes != nil && errRes.IsError {
		t.Fatalf("an unverifiable algorithm is not a tool error: %+v", errRes)
	}
	if out.Valid {
		t.Error("valid = true; an off-schema algorithm violates the schema and the verdict must say so")
	}
	// The error is the SCHEMA's, naming the offending member — not a checksum error
	// claiming the bytes failed verification, which is the distinction this test exists
	// to hold. The bytes may be perfectly intact; nobody checked them.
	for _, e := range out.Errors {
		if strings.Contains(e.Message, "mismatch") || strings.Contains(e.Message, "cannot verify checksum") {
			t.Errorf("an uncomputable algorithm must not be reported as a checksum failure: %q", e.Message)
		}
	}
	var algoNamed bool
	for _, e := range out.Errors {
		if strings.Contains(e.Path, "checksum.algorithm") {
			algoNamed = true
		}
	}
	if !algoNamed {
		t.Errorf("the schema error must name the offending member, got %+v", out.Errors)
	}
	if !strings.Contains(out.Notice, "md5") {
		t.Errorf("notice = %q, want it to name the algorithm that went unverified", out.Notice)
	}
	if !strings.Contains(out.Notice, "r.json") {
		t.Errorf("notice = %q, want it to name the entry", out.Notice)
	}
}

// Every MCP-level checksum test recorded sha256, so nothing here covered the checksums
// mode honouring the algorithm an entry actually records — and the tool's own Description
// told clients it verified "sha256 checksums" while the engine verified whatever was
// recorded. This pins both halves for the algorithm that needs a dependency to compute.
func TestHdfValidate_ChecksumsMode_HonoursBlake3(t *testing.T) {
	results := fixtures.Results.Minimal
	correct, err := hdfengine.ChecksumHex("blake3", results)
	if err != nil {
		t.Fatalf("computing the expected blake3: %v", err)
	}

	t.Run("a correct blake3 verifies", func(t *testing.T) {
		writeRoot(t, "ev.json", evidencePkg("", contentEntryAlg("hdf-results", "r.json", "blake3", correct)))
		writeInRoot(t, "r.json", results)

		_, out := callValidate(t, validateInput{Source: &handle.Source{Path: "ev.json"}, Mode: "checksums"})
		if !out.Valid {
			t.Errorf("valid = false for a CORRECT blake3 checksum; errors = %+v", out.Errors)
		}
		if len(out.Errors) != 0 {
			t.Errorf("errors = %+v, want none", out.Errors)
		}
	})

	t.Run("a wrong blake3 is reported as a mismatch", func(t *testing.T) {
		// A real blake3 digest of DIFFERENT bytes, so the value is well-formed and of the
		// right length — an invented hex string could fail for its shape instead.
		wrong, wrongErr := hdfengine.ChecksumHex("blake3", append(results, '\n'))
		if wrongErr != nil {
			t.Fatalf("computing a differing blake3: %v", wrongErr)
		}
		if wrong == correct {
			t.Fatal("precondition: the two digests must differ")
		}
		writeRoot(t, "ev.json", evidencePkg("", contentEntryAlg("hdf-results", "r.json", "blake3", wrong)))
		writeInRoot(t, "r.json", results)

		_, out := callValidate(t, validateInput{Source: &handle.Source{Path: "ev.json"}, Mode: "checksums"})
		if out.Valid {
			t.Error("valid = true for a WRONG blake3 checksum; the mismatch must make it invalid")
		}
		var found bool
		for _, e := range out.Errors {
			if e.Path == "r.json" && strings.Contains(e.Message, "mismatch") {
				found = true
			}
		}
		if !found {
			t.Errorf("want a mismatch error naming r.json, got %+v", out.Errors)
		}
	})
}

// A content reference means a path relative to the package document's own
// directory. Inline content never existed as a file, so there is no such
// directory and every base is a guess: resolving against HDF_MCP_ROOT reads a
// same-named file the package never referenced. Both halves are asserted here —
// source.path resolves against the package, inline content refuses to resolve —
// because the hazard is not that resolution fails but that it succeeds against
// the wrong file.
func TestHdfValidate_InlineContentResolvesAgainstThePackageNotTheRoot(t *testing.T) {
	// Two DIFFERENT results documents share the name r.json: one at the MCP root,
	// one beside the package in sub/. The package records its NEIGHBOUR's digest,
	// so reading the root's copy instead is observable in the verdict.
	neighbour := []byte(`{"baselines":[{"name":"RHEL9-STIG"}]}`)
	rootDecoy := []byte(`{"baselines":[{"requirements":[{"statusOverrides":[{"appliedBy":{"type":"agent"}}]}]}]}`)
	if sha256HexT(neighbour) == sha256HexT(rootDecoy) {
		t.Fatal("precondition: the two same-named documents must differ")
	}
	pkg := evidencePkg("", contentEntry("hdf-results", "r.json", sha256HexT(neighbour)))
	writeRoot(t, "r.json", rootDecoy)
	writeInRoot(t, "sub/r.json", neighbour)
	writeInRoot(t, "sub/ev.json", pkg)

	// via source.path: the base IS the package file's directory, so the neighbour
	// the package named is the file that gets hashed.
	_, viaPath := callValidate(t, validateInput{Source: &handle.Source{Path: "sub/ev.json"}, Mode: "checksums"})
	if !viaPath.Valid {
		t.Fatalf("via source.path: want valid (the package's own neighbour matches); errors = %+v", viaPath.Errors)
	}
	if viaPath.AgentOverrideCount != 0 {
		t.Errorf("via source.path: agentOverrideCount = %d, want 0 — the neighbour records no override; counting one means the root decoy was read", viaPath.AgentOverrideCount)
	}

	// via content: the same bytes, with no directory of their own.
	_, viaInline := callValidate(t, validateInput{Content: string(pkg), Mode: "checksums"})
	if viaInline.Valid {
		t.Fatal("via content: want invalid — a reference that was never resolved cannot be reported as verified")
	}
	if len(viaInline.Errors) != 1 || viaInline.Errors[0].Path != "r.json" {
		t.Fatalf("via content: want exactly one error naming r.json, got %+v", viaInline.Errors)
	}
	msg := viaInline.Errors[0].Message
	if strings.Contains(msg, "mismatch") {
		t.Errorf("via content: nothing was resolved, so this must not be reported as drift in the operator's evidence: %q", msg)
	}
	// A digest in the message could only have been computed from the root decoy:
	// the entry's own expected digest is only ever printed alongside an actual one.
	if strings.Contains(msg, sha256HexT(rootDecoy)) {
		t.Errorf("via content: message carries the ROOT decoy's digest, so the wrong file was hashed: %q", msg)
	}
	// The remedy the message names is the one this test just exercised above.
	if !strings.Contains(msg, "source.path") {
		t.Errorf("via content: an unresolvable reference must name the remedy, got %q", msg)
	}
	if viaInline.AgentOverrideCount != 0 {
		t.Errorf("via content: agentOverrideCount = %d, want 0 — counting the root decoy's override proves it was read", viaInline.AgentOverrideCount)
	}
}

// completeness shares confinedFetchAt with checksums, and an unreadable content
// reference there makes a planned baseline uncovered — so the same substitution
// silently changes the verdict. This is the dangerous direction: the root's
// documents agree with each other, so resolving against them reports COMPLETE
// for a package whose own plan was never read.
func TestHdfValidate_InlineContentCompletenessDoesNotResolveAgainstTheRoot(t *testing.T) {
	rootPlan := []byte(`{"assessments":[{"baselineRef":"RHEL9-STIG"}]}`)
	subPlan := []byte(`{"assessments":[{"baselineRef":"RHEL9-STIG"},{"baselineRef":"PostgreSQL-STIG"}]}`)
	rhel := []byte(`{"baselines":[{"name":"RHEL9-STIG"}]}`)
	pkg := evidencePkg("plan.json", contentEntry("hdf-results", "rhel.json", sha256HexT(rhel)))
	writeRoot(t, "plan.json", rootPlan)
	writeInRoot(t, "rhel.json", rhel)
	writeInRoot(t, "sub/plan.json", subPlan)
	writeInRoot(t, "sub/rhel.json", rhel)
	writeInRoot(t, "sub/ev.json", pkg)

	_, viaPath := callValidate(t, validateInput{Source: &handle.Source{Path: "sub/ev.json"}, Mode: "completeness"})
	if viaPath.Valid {
		t.Fatal("via source.path: the package's own plan lists a baseline it does not cover, so it is incomplete")
	}
	var namesMissing bool
	for _, e := range viaPath.Errors {
		if strings.Contains(e.Message, "PostgreSQL-STIG") {
			namesMissing = true
		}
	}
	if !namesMissing {
		t.Fatalf("via source.path: want the missing baseline named, got %+v", viaPath.Errors)
	}

	_, viaInline := callValidate(t, validateInput{Content: string(pkg), Mode: "completeness"})
	if viaInline.Valid {
		t.Fatal("via content: want invalid — an unresolvable planRef is not evidence of completeness")
	}
	if len(viaInline.Errors) == 0 || !strings.Contains(viaInline.Errors[0].Message, "cannot read plan") {
		t.Fatalf("via content: want the planRef reported unresolvable, got %+v", viaInline.Errors)
	}
	// No plan was read, so no baseline can be named missing either — that verdict
	// would have come from a plan the package did not reference.
	for _, e := range viaInline.Errors {
		if strings.Contains(e.Message, "missing results for baseline") {
			t.Errorf("via content: no plan was resolved, so nothing can be reported missing: %+v", e)
		}
	}
}

// A handle with an EMPTY path is a document authored or derived in this session and
// never written to disk, so it has no directory of its own — the same condition
// inline content is in. Keying the refusal on the input FIELD rather than on the
// absence of a location left this route resolving against HDF_MCP_ROOT, so
// hdf_author -> hdf_validate still reported a package verified against whatever
// happened to share its reference's name. This is the card's P1 inverse, reachable
// through a different door.
func TestHdfValidate_APathlessHandleResolvesNothingEither(t *testing.T) {
	// The package records the ROOT file's digest. So if the reference resolves
	// against the root the package VERIFIES — a clean verdict over a document the
	// package never named. The assertion is therefore on valid=false.
	rootDecoy := []byte(`{"baselines":[{"name":"RHEL9-STIG"}]}`)
	pkg := evidencePkg("", contentEntry("hdf-results", "r.json", sha256HexT(rootDecoy)))
	writeRoot(t, "r.json", rootDecoy)

	// Seed the loader's content cache, which is what a pathless handle resolves from.
	ldr := loader.New(0, 0, 0)
	if _, err := ldr.Load(pkg); err != nil {
		t.Fatalf("seeding the in-memory cache: %v", err)
	}
	encoded, err := handle.Encode(handle.Compute("", pkg, "evidence-package", hdfengine.Version()))
	if err != nil {
		t.Fatalf("encoding the handle: %v", err)
	}

	_, out, callErr := hdfValidate(ldr)(context.Background(), nil,
		validateInput{Source: &handle.Source{Handle: encoded}, Mode: "checksums"})
	if callErr != nil {
		t.Fatalf("hdfValidate returned a Go error: %v", callErr)
	}

	// completeness shares the fetcher, which is chosen before the mode switch —
	// asserted rather than left to the structure, because that shared fetcher is
	// exactly what a later refactor could split.
	t.Run("completeness refuses the same handle", func(t *testing.T) {
		withPlan := evidencePkg("plan.json", contentEntry("hdf-results", "r.json", sha256HexT(rootDecoy)))
		pldr := loader.New(0, 0, 0)
		if _, err := pldr.Load(withPlan); err != nil {
			t.Fatalf("seeding the in-memory cache: %v", err)
		}
		enc, err := handle.Encode(handle.Compute("", withPlan, "evidence-package", hdfengine.Version()))
		if err != nil {
			t.Fatalf("encoding the handle: %v", err)
		}
		_, cOut, cErr := hdfValidate(pldr)(context.Background(), nil,
			validateInput{Source: &handle.Source{Handle: enc}, Mode: "completeness"})
		if cErr != nil {
			t.Fatalf("hdfValidate returned a Go error: %v", cErr)
		}
		if cOut.Valid {
			t.Error("an unresolvable planRef is not evidence of completeness")
		}
		if len(cOut.Errors) == 0 || !strings.Contains(cOut.Errors[0].Message, "cannot be resolved") {
			t.Errorf("want the plan reported as unresolvable, got %+v", cOut.Errors)
		}
	})

	if out.Valid {
		t.Error("a pathless handle has no package directory, so its references must not " +
			"resolve against HDF_MCP_ROOT — reporting valid here is a verdict over bytes nobody read")
	}
	if len(out.Errors) == 0 {
		t.Fatal("want one error per unresolvable entry")
	}
	msg := out.Errors[0].Message
	if !strings.Contains(msg, "cannot be resolved") {
		t.Errorf("the entry must be reported as unresolvable, got %q", msg)
	}
	if strings.Contains(msg, "mismatch") || strings.Contains(msg, sha256HexT(rootDecoy)) {
		t.Errorf("nothing was resolved, so this must not be reported as drift, and must not "+
			"carry the root file's digest: %q", msg)
	}
}

// fatalTB captures a helper's Fatalf instead of failing the enclosing test, so
// the helper's own precondition can be asserted. Fatalf must not return, so it
// panics with the recorder and run recovers exactly that panic.
type fatalTB struct {
	testing.TB
	fired bool
	msg   string
}

func (f *fatalTB) Helper() {}

func (f *fatalTB) Fatalf(format string, args ...any) {
	f.fired = true
	f.msg = fmt.Sprintf(format, args...)
	panic(f)
}

func (f *fatalTB) run(fn func()) {
	defer func() {
		if r := recover(); r != nil && r != any(f) {
			panic(r)
		}
	}()
	fn()
}

// With no HDF_MCP_ROOT, filepath.Join("", rel) would be a bare relative path
// and go test's working directory is this package's source directory, so an
// unguarded helper would MkdirAll a tree into the repo and still report success.
func TestWriteInRoot_FailsWhenRootUnset(t *testing.T) {
	const probeDir = "writeinroot-guard-probe"
	rel := filepath.Join(probeDir, "nested", "pkg.json")
	t.Setenv("HDF_MCP_ROOT", "")
	t.Cleanup(func() { _ = os.RemoveAll(probeDir) })

	rec := &fatalTB{TB: t}
	rec.run(func() { writeInRoot(rec, rel, []byte("{}")) })

	if _, err := os.Stat(probeDir); !errors.Is(err, fs.ErrNotExist) {
		wd, _ := os.Getwd()
		t.Errorf("writeInRoot created %s/ inside the working directory %s (stat: %v)", probeDir, wd, err)
	}
	if !rec.fired {
		t.Error("writeInRoot with no HDF_MCP_ROOT must fail the test, not pick a location")
	}
	// rec.fired alone cannot tell the guard's Fatalf from the mkdir or write one,
	// so assert the cause. The paren is load-bearing: without it the match is a
	// prefix match, satisfied by any longer identifier starting with this name.
	if !strings.Contains(rec.msg, "HDF_MCP_ROOT") {
		t.Errorf("the failure must name the missing precondition, got %q", rec.msg)
	}
	if !strings.Contains(rec.msg, "writeInRoot(") {
		t.Errorf("the failure must name the helper, got %q", rec.msg)
	}
}

// A malformed percent-escape and a traversal are different failures, and an
// operator acts on them differently: one is a producer writing an invalid
// reference, the other is a reference reaching outside the package. Collapsing
// both into the containment message sends them looking for a traversal that is
// not there.
func TestHdfValidate_Checksums_ReportsAMalformedReferenceAsSuch(t *testing.T) {
	pkg := evidencePkg("", contentEntry("hdf-results", "scans/bad%2.json", "abc"))
	writeRoot(t, "ev.json", pkg)
	_, out := callValidate(t, validateInput{Source: &handle.Source{Path: "ev.json"}, Mode: "checksums"})

	if len(out.Errors) == 0 {
		t.Fatal("a malformed reference must surface as an error")
	}
	// Scanned rather than indexed: the schema's own uri-reference error arrives
	// first now that the loader's verdict is carried through, and which error
	// lands where is not what this test is about.
	var decodeNamed bool
	for _, e := range out.Errors {
		if contains(e.Message, "outside the evidence package root") {
			t.Errorf("a malformed escape is not a containment failure; nothing was resolved: %q", e.Message)
		}
		if contains(e.Message, "scans/bad%2.json") && contains(e.Message, "not a valid uri-reference") {
			decodeNamed = true
		}
	}
	if !decodeNamed {
		t.Errorf("one error must name the stored spelling and say it is not a valid uri-reference, got %+v", out.Errors)
	}
}

// Checksum mode inspects a schema-invalid package deliberately — an operator
// calls validate because something is wrong — but it must not REPORT it as
// valid. Before this was fixed, a package missing required members whose
// checksums happened to match came back valid:true with zero errors, so the
// loader's verdict and its schema errors were both discarded and an agent
// reading the reply would conclude the package was sound.
func TestHdfValidate_Checksums_KeepsTheLoadersVerdictOnAnInvalidPackage(t *testing.T) {
	body := []byte("x")
	// No `name`, which the schema requires — measured against the schema's own
	// required list rather than guessed; preparedAt and generator are optional.
	pkg := []byte(`{"hdfVersion":"3.8.0","type":"evidencePackage",
	  "contents":[{"type":"hdf-results","uri":"r.json","checksum":{"algorithm":"sha256","value":"` + sha256HexT(body) + `"}}]}`)
	writeRootFiles(t, map[string][]byte{"r.json": body, "ev.json": pkg})

	_, out := callValidate(t, validateInput{Source: &handle.Source{Path: "ev.json"}, Mode: "checksums"})

	if out.Valid {
		t.Error("a schema-invalid package must not be reported valid, however its checksums verify")
	}
	if len(out.Errors) == 0 {
		t.Fatal("the loader's schema errors must survive into the reply")
	}
	var named bool
	for _, e := range out.Errors {
		if contains(e.Message, "name") {
			named = true
		}
	}
	if !named {
		t.Errorf("the reply must name the missing member, got %+v", out.Errors)
	}
}

// The two early returns that carryLoaderVerdict does NOT already cover. The
// plan-unreadable test's fixture carries no contents entry, so the schema has
// already set the verdict false there and those two assignments go unmeasured —
// delete either and nothing fails. This package is schema-VALID, so the guard
// is the only thing that can make the verdict false.
func TestHdfValidate_Completeness_AnUnreadablePlanInvalidatesAValidPackage(t *testing.T) {
	rhel := []byte(`{"baselines":[{"name":"RHEL9-STIG"}]}`)
	pkg := evidencePkg("missing-plan.json",
		contentEntry("hdf-results", "rhel.json", sha256HexT(rhel)))
	writeRootFiles(t, map[string][]byte{"ev.json": pkg, "rhel.json": rhel}) // no plan written

	_, out := callValidate(t, validateInput{Source: &handle.Source{Path: "ev.json"}, Mode: "completeness"})

	// The premise: nothing BUT the guard can falsify this one.
	for _, e := range out.Errors {
		if contains(e.Message, "is required") || contains(e.Message, "must have at least") {
			t.Fatalf("fixture is not schema-valid, so this cannot measure the guard: %+v", out.Errors)
		}
	}
	if out.Valid {
		t.Error("completeness could not be checked, so the verdict must not claim it was")
	}
	if !anyErrorContains(out.Errors, "cannot read plan") {
		t.Errorf("the unreadable plan must be named, got %+v", out.Errors)
	}

	// The sibling branch, which has its own Valid=false and needs its own measure.
	writeInRoot(t, "missing-plan.json", []byte("not json"))
	_, out2 := callValidate(t, validateInput{Source: &handle.Source{Path: "ev.json"}, Mode: "completeness"})
	if out2.Valid {
		t.Error("an unparseable plan means completeness was not checked; the verdict must not claim it was")
	}
	if !anyErrorContains(out2.Errors, "cannot parse plan") {
		t.Errorf("the unparseable plan must be named, got %+v", out2.Errors)
	}
}

// The case the && in `out.Valid = out.Valid && comp.Complete` exists for: a
// schema-invalid package whose planned baselines ARE all covered. Completeness
// says complete; the schema says no. Without the &&, completeness would rescue a
// document the loader rejected — and the no-planRef test cannot reach this line,
// because it returns early.
func TestHdfValidate_Completeness_CompleteDoesNotRescueAnInvalidPackage(t *testing.T) {
	plan := []byte(`{"assessments":[{"baselineRef":"RHEL9-STIG"}]}`)
	rhel := []byte(`{"baselines":[{"name":"RHEL9-STIG"}]}`)
	// No `name`, which the schema requires — otherwise a complete, coherent package.
	pkg := []byte(`{"hdfVersion":"3.8.0","type":"evidencePackage","planRef":"plan.json",
	  "contents":[{"type":"hdf-results","uri":"rhel.json","checksum":{"algorithm":"sha256","value":"` + sha256HexT(rhel) + `"}}]}`)
	writeRootFiles(t, map[string][]byte{"ev.json": pkg, "plan.json": plan, "rhel.json": rhel})

	_, out := callValidate(t, validateInput{Source: &handle.Source{Path: "ev.json"}, Mode: "completeness"})

	if !anyErrorContains(out.Errors, "name") {
		t.Fatalf("the loader's schema error must be present, got %+v", out.Errors)
	}
	if out.Valid {
		t.Error("every planned baseline is covered, but the package is schema-invalid: the verdict must stay false")
	}
}

// The same obligation as checksum mode, and completeness mode broke it harder:
// it assigned out.Valid from the completeness result and REPLACED out.Errors in
// its early returns, so a schema-invalid package whose planned baselines were all
// covered came back valid with the loader's errors discarded.
func TestHdfValidate_Completeness_KeepsTheLoadersVerdictOnAnInvalidPackage(t *testing.T) {
	// No `name`, which the schema requires. No planRef either, so completeness
	// takes the early return that used to clobber the error list.
	pkg := []byte(`{"hdfVersion":"3.8.0","type":"evidencePackage",
	  "contents":[{"type":"hdf-results","uri":"r.json"}]}`)
	writeRootFiles(t, map[string][]byte{"r.json": []byte("x"), "ev.json": pkg})

	_, out := callValidate(t, validateInput{Source: &handle.Source{Path: "ev.json"}, Mode: "completeness"})

	if out.Valid {
		t.Error("a schema-invalid package must not be reported valid by completeness mode")
	}
	var schemaNamed bool
	for _, e := range out.Errors {
		if contains(e.Message, "name") {
			schemaNamed = true
		}
	}
	if !schemaNamed {
		t.Errorf("the loader's schema error must survive the early return, got %+v", out.Errors)
	}
}
