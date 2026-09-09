package tools

import (
	"strings"
	"testing"

	"github.com/mitre/hdf-libs/hdf-cli/v3/internal/mcp/handle"
	"github.com/mitre/hdf-libs/hdf-cli/v3/internal/mcp/mcperr"
	convreg "github.com/mitre/hdf-libs/hdf-converters/v3/registry/convert"
)

// fidelityFake converts like the real gosec converter but declares whatever
// requirement count the test says, so the MCP's refusal can be exercised
// without depending on any converter's own relation.
type fidelityFake struct {
	inner  convreg.Converter
	expect int
}

func (f *fidelityFake) Name() string                      { return "Fidelity fake" }
func (f *fidelityFake) Convert(in []byte) ([]byte, error) { return f.inner.Convert(in) }
func (f *fidelityFake) ExpectedRequirementCount([]byte) (int, string, error) {
	return f.expect, "fake findings", nil
}

func registerFidelityFake(t *testing.T, name string, expect int) {
	t.Helper()
	inner, err := convreg.GetConverter("gosec", "hdf")
	if err != nil {
		t.Fatal(err)
	}
	convreg.RegisterConverter(name, "hdf", &fidelityFake{inner: inner, expect: expect})
	t.Cleanup(func() { convreg.UnregisterConverter(name, "hdf") })
}

// The gosec fixture converts to 3 requirements; a converter declaring 99 has
// lost findings and the tool must refuse rather than hand back a smaller
// document as a success.
func TestHdfConvert_RefusesLostFindings(t *testing.T) {
	registerFidelityFake(t, "fidelity-fake-mismatch", 99)
	res, out := callConvert(t, convertInput{Content: string(gosecFixture(t)), From: "fidelity-fake-mismatch"})
	if res == nil || !res.IsError {
		t.Fatalf("a conversion whose requirement count disagrees with the declaration must be refused, got %+v", out)
	}
	tr := toolResultPayload(t, res)
	if tr.Code != mcperr.SchemaInvalid {
		t.Errorf("code = %q, want %q", tr.Code, mcperr.SchemaInvalid)
	}
	for _, want := range []string{"conversion lost findings", "expected 99 requirements", "fake findings", "produced 3"} {
		if !strings.Contains(tr.Message, want) {
			t.Errorf("message %q lacks %q", tr.Message, want)
		}
	}
	if out.Handle != "" || out.Valid {
		t.Errorf("a refused conversion must not mint a handle: %+v", out)
	}
}

func TestHdfConvert_MatchingCountConverts(t *testing.T) {
	registerFidelityFake(t, "fidelity-fake-match", 3)
	res, out := callConvert(t, convertInput{Content: string(gosecFixture(t)), From: "fidelity-fake-match"})
	if res != nil && res.IsError {
		t.Fatalf("a matching count must convert: %s", payloadText(t, res))
	}
	if !out.Valid || out.RequirementCount != 3 {
		t.Fatalf("unexpected summary: %+v", out)
	}
}

// The batch path shares the single-file pipeline, so the same refusal lands
// on the per-file entry.
func TestHdfConvert_BatchRefusesLostFindings(t *testing.T) {
	registerFidelityFake(t, "fidelity-fake-batch", 99)
	writeRoot(t, "scan.json", gosecFixture(t))
	_, out := callConvert(t, convertInput{Sources: []handle.Source{{Path: "scan.json"}}, From: "fidelity-fake-batch"})
	if len(out.Batch) != 1 {
		t.Fatalf("want one batch entry, got %+v", out.Batch)
	}
	entry := out.Batch[0]
	if entry["code"] != string(mcperr.SchemaInvalid) || entry["valid"] != false {
		t.Errorf("batch entry must carry the refusal: %+v", entry)
	}
	if msg, _ := entry["error"].(string); !strings.Contains(msg, "conversion lost findings") {
		t.Errorf("batch entry error = %q", msg)
	}
}
