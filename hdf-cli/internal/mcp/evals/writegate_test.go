package evals

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fileExists reports whether name exists under root.
func fileExists(root, name string) bool {
	_, err := os.Stat(filepath.Join(root, name))
	return err == nil
}

// TestWriteGate_DisabledPreviewsTouchNoFile — with HDF_MCP_ENABLE_WRITES unset,
// every write tool returns a WRITES_DISABLED preview (not an error) and writes
// no file (§12/§Verification).
func TestWriteGate_DisabledPreviewsTouchNoFile(t *testing.T) {
	os.Unsetenv("HDF_MCP_ENABLE_WRITES")
	root := stageRoot(t,
		[2]string{fxSystem, "system.json"},
		[2]string{fxDiffFrom, "from.json"}, [2]string{fxDiffTo, "to.json"},
		[2]string{fxVexResults, "results.json"},
		[2]string{fxOpenvexAmendments, "amendments.json"},
		[2]string{fxGosecRaw, "gosec.json"},
	)
	// Every write tool: author, diff, convert, apply_amendment.
	cases := []struct {
		name string
		c    call
		out  string
	}{
		{"hdf_author", call{"hdf_author", map[string]any{
			"docType": "system", "name": "S",
			"content": []any{map[string]any{"type": "host", "name": "h1"}}, "output": "sys-out.json"}}, "sys-out.json"},
		{"hdf_diff", call{"hdf_diff", map[string]any{
			"from": map[string]any{"path": "from.json"}, "to": map[string]any{"path": "to.json"}, "output": "diff-out.json"}}, "diff-out.json"},
		{"hdf_convert", call{"hdf_convert", map[string]any{
			"source": map[string]any{"path": "gosec.json"}, "from": "gosec", "output": "conv-out.json"}}, "conv-out.json"},
		{"hdf_apply_amendment", call{"hdf_apply_amendment", map[string]any{
			"results": map[string]any{"path": "results.json"}, "amendments": map[string]any{"path": "amendments.json"},
			"output": "apply-out.json"}}, "apply-out.json"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sc := structured(t, driveCalls(t, []call{tc.c})[0])
			notice, _ := sc["notice"].(string)
			if !strings.Contains(notice, "WRITES_DISABLED") {
				t.Fatalf("%s: expected a WRITES_DISABLED notice, got %q", tc.name, notice)
			}
			if op, _ := sc["outputPath"].(string); op != "" {
				t.Fatalf("%s: writes-disabled must report no outputPath, got %q", tc.name, op)
			}
			if fileExists(root, tc.out) {
				t.Fatalf("%s: writes-disabled must touch no file, but %s exists", tc.name, tc.out)
			}
		})
	}
}

// TestWriteGate_DryRunTouchesNoFile — with writes enabled, dry_run previews and
// writes no file.
func TestWriteGate_DryRunTouchesNoFile(t *testing.T) {
	t.Setenv("HDF_MCP_ENABLE_WRITES", "1")
	root := stageRoot(t, [2]string{fxSystem, "system.json"})
	sc := structured(t, driveCalls(t, []call{{"hdf_author", map[string]any{
		"docType": "system", "name": "S",
		"content": []any{map[string]any{"type": "host", "name": "h1"}},
		"output":  "out.json", "dryRun": true,
	}}})[0])
	if op, _ := sc["outputPath"].(string); op != "" {
		t.Fatalf("dry_run must report no outputPath, got %q", op)
	}
	if fileExists(root, "out.json") {
		t.Fatal("dry_run must write no file")
	}
}

// TestWriteGate_ApplyNeverOverwritesResultsInput — hdf_apply_amendment leaves its
// results input byte-unchanged even on an enabled write.
func TestWriteGate_ApplyNeverOverwritesResultsInput(t *testing.T) {
	t.Setenv("HDF_MCP_ENABLE_WRITES", "1")
	root := stageRoot(t, [2]string{fxVEX, "vex.json"}, [2]string{fxVexResults, "results.json"})
	before, _ := os.ReadFile(filepath.Join(root, "results.json"))
	// author amendments from the VEX, then apply to the results.
	driveCalls(t, []call{{"hdf_author", map[string]any{
		"docType": "amendments", "name": "V", "source": map[string]any{"path": "vex.json"},
		"expiresAt": "2099-12-31T00:00:00Z", "output": "amendments.json"}}})
	driveCalls(t, []call{{"hdf_apply_amendment", map[string]any{
		"results": map[string]any{"path": "results.json"}, "amendments": map[string]any{"path": "amendments.json"},
		"output": "applied.json"}}})
	after, _ := os.ReadFile(filepath.Join(root, "results.json"))
	if string(before) != string(after) {
		t.Fatal("apply must never overwrite/modify its results input")
	}
	if !fileExists(root, "applied.json") {
		t.Fatal("apply should have written the distinct applied.json")
	}
}
