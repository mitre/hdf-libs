package convert

import (
	"os/exec"
	"strings"
	"testing"
)

// wantRegisteredPairs is the number of format pairs registered when every
// converter's init() has run (measured against the pre-move registry in
// package cmd). It guards the mass relocation: a dropped or double-registered
// converter changes this count. Bump it deliberately when adding/removing a
// converter — never to make a failing test pass. (80 includes spdx-vex→hdf and
// trivy→hdf, both added on main and integrated into this registry on a feat/mcp
// merge — trivy's registration was relocated here from package cmd.)
const wantRegisteredPairs = 80

// TestRegistry_ListsAllConverters asserts count parity: importing this package
// self-registers every converter, so ListConverters must report the full set.
func TestRegistry_ListsAllConverters(t *testing.T) {
	got := len(ListConverters())
	if got != wantRegisteredPairs {
		t.Fatalf("registered converter pairs = %d, want %d (a converter was dropped or double-registered during the lift)", got, wantRegisteredPairs)
	}
}

// TestRegistry_NoCobraInImportGraph proves this package is safe to import from
// the stdio MCP process (ADR-0007 §14): its transitive import graph must not
// pull in cobra or any console framework. Verified against the real dependency
// graph via `go list -deps`, not a structural guess.
func TestRegistry_NoCobraInImportGraph(t *testing.T) {
	out, err := exec.Command("go", "list", "-deps", ".").CombinedOutput()
	if err != nil {
		t.Skipf("go list unavailable: %v (%s)", err, out)
	}
	for _, dep := range strings.Fields(string(out)) {
		if strings.Contains(dep, "spf13/cobra") || strings.Contains(dep, "spf13/pflag") {
			t.Fatalf("registry import graph must be cobra-free for the stdio MCP, but pulls in %q", dep)
		}
	}
}
