package tools

import (
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
