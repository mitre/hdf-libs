package evals

import (
	"os"
	"path/filepath"
	"testing"
)

// TestDeterminism_ByteIdenticalOutput — identical inputs run twice produce
// byte-identical output and the same content hash (§10: no wall-clock in
// payloads, canonical trimmed-UTC timestamps, stable key ordering). Exercised on
// hdf_diff (which stamps effective checksums anchored to the doc timestamp, not
// the wall clock).
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
	sha2, body2 := run("b.json")
	if sha1 == "" || sha1 != sha2 {
		t.Fatalf("content hash not deterministic: %q vs %q", sha1, sha2)
	}
	if body1 != body2 {
		t.Fatal("hdf_diff output is not byte-identical across identical runs")
	}
}

// TestDeterminism_AuthorHandleStable — authoring the same document twice yields
// the same content hash and the same handle (the handle is content-derived).
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
