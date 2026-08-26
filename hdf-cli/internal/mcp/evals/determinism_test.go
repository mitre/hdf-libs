package evals

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestDeterminism_ByteIdenticalOutput — identical inputs run twice produce
// byte-identical output and the same content hash (§10: no wall-clock in
// payloads, canonical trimmed-UTC timestamps, stable key ordering). Exercised on
// hdf_diff (which stamps effective checksums anchored to the doc timestamp, not
// the wall clock).
//
// The two runs are deliberately separated past a one-second boundary: any
// wall-clock value leaking into the payload (the engine's generation Timestamp
// is trimmed to whole seconds) would otherwise only diverge when the two runs
// happened to straddle a tick — a flake that passes locally and fails on a
// loaded CI runner. Forcing the gap turns that latent flake into a deterministic
// regression guard.
func TestDeterminism_ByteIdenticalOutput(t *testing.T) {
	t.Setenv("HDF_MCP_ENABLE_WRITES", "1")
	root := stageRoot(t, [2]string{fxDiffFrom, "from.json"}, [2]string{fxDiffTo, "to.json"})

	run := func(out string) (string, string) {
		sc := structured(t, driveCalls(t, []call{{"hdf_diff", map[string]any{
			"from": map[string]any{"path": "from.json"}, "to": map[string]any{"path": "to.json"}, "output": out,
		}}})[0])
		sha, _ := sc["sha256"].(string)
		b, err := os.ReadFile(filepath.Join(root, out))
		if err != nil {
			t.Fatalf("read %s: %v", out, err)
		}
		return sha, string(b)
	}

	sha1, body1 := run("a.json")
	time.Sleep(1100 * time.Millisecond)
	sha2, body2 := run("b.json")
	if sha1 == "" || sha1 != sha2 {
		t.Fatalf("content hash not deterministic: %q vs %q", sha1, sha2)
	}
	if body1 != body2 {
		t.Fatal("hdf_diff output is not byte-identical across identical runs")
	}
}

// TestDeterminism_AuthorHandleStable — authoring the same NON-judgment document
// twice yields the same content hash and handle. This holds for the paths that
// carry no wall-clock: system (here), plan, evidence, and VEX-derived (system)
// amendments — the byte-reproducible set (§12). The judgment path is the one
// deliberate exception, covered separately below.
func TestDeterminism_AuthorHandleStable(t *testing.T) {
	stageRoot(t)
	call1 := call{"hdf_author", map[string]any{
		"docType": "system", "name": "S",
		"content": []any{map[string]any{"type": "host", "name": "h1"}},
	}}
	a := structured(t, driveCalls(t, []call{call1})[0])
	b := structured(t, driveCalls(t, []call{call1})[0])
	if a["sha256"] != b["sha256"] || a["sha256"] == "" {
		t.Fatalf("sha256 not stable: %v vs %v", a["sha256"], b["sha256"])
	}
	if a["handle"] != b["handle"] || a["handle"] == "" {
		t.Fatalf("handle not stable: %v vs %v", a["handle"], b["handle"])
	}
}

// TestDeterminism_JudgmentPathStampsActionTimestamp documents the ONE deliberate
// exception to output determinism: the judgment path (content[] of overrides)
// stamps a real appliedAt — the "when the agent applied this" accountability
// timestamp of §2 — which folds into the document's sha256/handle. So an
// authored amendments document is NOT byte-reproducible across calls, by design
// (ADR-0007 §12). This is why the response-golden strips handle/sha256 for
// author/apply — the exception is documented, not a hidden determinism gap. The
// test exercises the judgment path (which the stable-handle test above does not)
// and confirms it produces a content-derived handle/sha256; it deliberately does
// NOT assert stability, since a real appliedAt makes that timing-dependent.
func TestDeterminism_JudgmentPathStampsActionTimestamp(t *testing.T) {
	stageRoot(t)
	c := call{"hdf_author", map[string]any{
		"docType": "amendments", "name": "A",
		"content": []any{map[string]any{
			"type": "attestation", "requirementId": "V-1", "status": "passed",
			"reason": "manually verified", "expiresAt": "2099-12-31T00:00:00Z",
		}},
	}}
	got := structured(t, driveCalls(t, []call{c})[0])
	if got["sha256"] == "" || got["handle"] == "" {
		t.Fatalf("judgment-path author must return a content-derived handle+sha256: %v", got)
	}
}
