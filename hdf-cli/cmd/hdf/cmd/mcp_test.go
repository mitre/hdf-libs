package cmd

import (
	"strings"
	"testing"
)

func TestMCPToolSpec_Precedence(t *testing.T) {
	t.Run("neither flag nor env selects the default (empty)", func(t *testing.T) {
		t.Setenv("HDF_MCP_TOOLS", "")
		cmd := NewMCPCmd()
		spec, err := mcpToolSpec(cmd)
		if err != nil {
			t.Fatal(err)
		}
		if spec != "" {
			t.Errorf("expected empty default spec, got %q", spec)
		}
	})

	t.Run("env is used when the flag is unset", func(t *testing.T) {
		t.Setenv("HDF_MCP_TOOLS", "read")
		cmd := NewMCPCmd()
		spec, err := mcpToolSpec(cmd)
		if err != nil {
			t.Fatal(err)
		}
		if spec != "read" {
			t.Errorf("expected env value 'read', got %q", spec)
		}
	})

	t.Run("flag overrides env", func(t *testing.T) {
		t.Setenv("HDF_MCP_TOOLS", "read")
		cmd := NewMCPCmd()
		if err := cmd.Flags().Set("tools", "hdf_open"); err != nil {
			t.Fatal(err)
		}
		spec, err := mcpToolSpec(cmd)
		if err != nil {
			t.Fatal(err)
		}
		if spec != "hdf_open" {
			t.Errorf("flag must win over env; got %q", spec)
		}
	})
}

// TestMCPCmd_InvalidToolsErrorsBeforeServing proves an unknown --tools value is
// rejected at startup (ResolveToolSelection fails before mcp.Run is reached), so
// the command returns an error rather than serving with a wrong surface.
func TestMCPCmd_InvalidToolsErrorsBeforeServing(t *testing.T) {
	cmd := NewMCPCmd()
	cmd.SetArgs([]string{"--tools", "bogus_tool"})
	err := cmd.Execute()
	if err == nil {
		t.Fatal("an invalid --tools value must return an error")
	}
	if !strings.Contains(err.Error(), "bogus_tool") {
		t.Errorf("error should name the bad token, got: %v", err)
	}
}
