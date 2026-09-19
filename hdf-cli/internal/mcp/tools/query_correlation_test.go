package tools

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/mitre/hdf-libs/hdf-cli/v3/internal/mcp/handle"
)

// rowByID returns the projected row with the given id, or nil.
func rowByID(rows []map[string]any, id string) map[string]any {
	for _, r := range rows {
		if r["id"] == id {
			return r
		}
	}
	return nil
}

// TestQuery_ProjectsCorrelationFields is g3zo's designated first-failing test:
// the bounded correlation set is returned only under an explicit fields opt-in,
// and is absent from the default (and full) projection.
func TestQuery_ProjectsCorrelationFields(t *testing.T) {
	path := writeRoot(t, "correlation-results.json", readToolsFixture(t, "correlation-results.json"))

	// Default (no fields) must NOT carry any correlation key.
	_, base := callQuery(t, queryInput{Source: handle.Source{Path: path}})
	row := rowByID(base.Requirements, "VULN-01")
	if row == nil {
		t.Fatal("VULN-01 must be in the default result set")
	}
	for _, k := range []string{"cwe", "cvss", "affectedPackages", "sourceLocation"} {
		if _, ok := row[k]; ok {
			t.Errorf("default projection must NOT include correlation field %q", k)
		}
	}

	// Opt-in: fields=[cwe,cvss,affectedPackages,sourceLocation] adds exactly those.
	_, out := callQuery(t, queryInput{
		Source: handle.Source{Path: path},
		Fields: []string{"cwe", "cvss", "affectedPackages", "sourceLocation"},
	})
	row = rowByID(out.Requirements, "VULN-01")
	if row == nil {
		t.Fatal("VULN-01 must be in the opt-in result set")
	}
	for _, k := range []string{"cwe", "cvss", "affectedPackages", "sourceLocation"} {
		if _, ok := row[k]; !ok {
			t.Errorf("opt-in projection must include correlation field %q; row keys=%v", k, keysOf(row))
		}
	}
	// The concise base fields are still present alongside the correlation keys.
	for _, k := range []string{"id", "title", "status", "severity", "impact"} {
		if _, ok := row[k]; !ok {
			t.Errorf("correlation projection must retain base field %q", k)
		}
	}
}

// A requirement lacking a requested correlation field simply omits that key
// (no null, no empty container) — so a correlation consumer joins on presence.
func TestQuery_CorrelationFieldsOmittedWhenAbsent(t *testing.T) {
	path := writeRoot(t, "correlation-results.json", readToolsFixture(t, "correlation-results.json"))
	_, out := callQuery(t, queryInput{
		Source: handle.Source{Path: path},
		Fields: []string{"cwe", "cvss", "affectedPackages", "sourceLocation"},
	})
	row := rowByID(out.Requirements, "PLAIN-02")
	if row == nil {
		t.Fatal("PLAIN-02 must be present")
	}
	for _, k := range []string{"cwe", "cvss", "affectedPackages", "sourceLocation"} {
		if _, ok := row[k]; ok {
			t.Errorf("PLAIN-02 has no %s; the key must be omitted, not null", k)
		}
	}
}

// An unknown fields value fails loud at the handler boundary (the schema tag is
// description-only, so validation lives here) — the same fail-fast discipline
// the tool-selection surface uses.
func TestQuery_UnknownCorrelationFieldErrors(t *testing.T) {
	path := writeRoot(t, "correlation-results.json", readToolsFixture(t, "correlation-results.json"))
	res, out := callQuery(t, queryInput{
		Source: handle.Source{Path: path},
		Fields: []string{"cwe", "not_a_field"},
	})
	if res == nil || !res.IsError {
		t.Fatal("an unknown correlation field must be refused with an isError result")
	}
	if len(out.Requirements) != 0 {
		t.Fatalf("a refused query must return no rows, got %d", len(out.Requirements))
	}
	if !strings.Contains(payloadText(t, res), "not_a_field") {
		t.Errorf("error must name the bad field, got %q", payloadText(t, res))
	}
}

// Correlation fields are additive to full verbosity too (full still carries its
// baseline/tags/descriptions, plus the requested correlation keys).
func TestQuery_CorrelationAdditiveToFull(t *testing.T) {
	path := writeRoot(t, "correlation-results.json", readToolsFixture(t, "correlation-results.json"))
	_, out := callQuery(t, queryInput{
		Source:    handle.Source{Path: path},
		Verbosity: "full",
		Fields:    []string{"cwe"},
	})
	row := rowByID(out.Requirements, "VULN-01")
	if row == nil {
		t.Fatal("VULN-01 must be present")
	}
	for _, k := range []string{"baseline", "tags", "descriptions", "cwe"} {
		if _, ok := row[k]; !ok {
			t.Errorf("full+correlation must carry %q; keys=%v", k, keysOf(row))
		}
	}
}

// rowsByID returns every projected row with the given id, in response order.
func rowsByID(rows []map[string]any, id string) []map[string]any {
	var out []map[string]any
	for _, r := range rows {
		if r["id"] == id {
			out = append(out, r)
		}
	}
	return out
}

// packageNames marshals a row's affectedPackages projection and returns its
// package names, so the assertion reads the wire shape rather than a Go type.
func packageNames(t *testing.T, v any) []string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal affectedPackages: %v", err)
	}
	var pkgs []struct {
		Name string `json:"name"`
	}
	if err := json.Unmarshal(b, &pkgs); err != nil {
		t.Fatalf("unmarshal affectedPackages: %v", err)
	}
	names := make([]string, len(pkgs))
	for i, p := range pkgs {
		names[i] = p.Name
	}
	return names
}

// TestQuery_CorrelationFields_DistinctOnRepeatedIDs (js1nv.2): grype emits one
// requirement per package instance, so one CVE id appears more than once in a
// baseline. Each projected row must carry ITS OWN affectedPackages — joining on
// (baseline name, id) hands every duplicate the last requirement's fields.
func TestQuery_CorrelationFields_DistinctOnRepeatedIDs(t *testing.T) {
	path := writeRoot(t, "grype.json", readToolsFixture(t, "grype-duplicate-ids.json"))
	_, out := callQuery(t, queryInput{
		Source: handle.Source{Path: path},
		Search: "CVE-2024-7264",
		Fields: []string{"affectedPackages"},
	})
	rows := rowsByID(out.Requirements, "Grype/CVE-2024-7264")
	if len(rows) != 2 {
		t.Fatalf("expected the repeated id twice, got %d row(s): %v", len(rows), out.Requirements)
	}
	// Document order: requirement 6 is curl, requirement 7 is libcurl3-gnutls.
	if got := packageNames(t, rows[0]["affectedPackages"]); len(got) != 1 || got[0] != "curl" {
		t.Errorf("first row affectedPackages = %v, want [curl]", got)
	}
	if got := packageNames(t, rows[1]["affectedPackages"]); len(got) != 1 || got[0] != "libcurl3-gnutls" {
		t.Errorf("second row affectedPackages = %v, want [libcurl3-gnutls]", got)
	}
	// Full verbosity joins tags/descriptions through the same positional lookup.
	// In this fixture the two requirements share one CVE description (grype
	// describes the vulnerability, not the package), so descriptions cannot
	// discriminate; affectedPackages above is the field that proves the join is
	// positional. Here: full rows still come back one per duplicate, joined.
	_, full := callQuery(t, queryInput{Source: handle.Source{Path: path}, Search: "CVE-2024-7264", Verbosity: "full"})
	frows := rowsByID(full.Requirements, "Grype/CVE-2024-7264")
	if len(frows) != 2 {
		t.Fatalf("full: expected 2 rows, got %d", len(frows))
	}
	for i, r := range frows {
		if r["baseline"] == "" || r["descriptions"] == nil {
			t.Errorf("full row %d lost its joined fields: %v", i, keysOf(r))
		}
	}
}
