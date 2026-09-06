package tools

import (
	"fmt"
	"sort"
	"strings"

	"github.com/mitre/hdf-libs/hdf-cli/v3/internal/mcp/loader"
	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

// canonicalToolOrder is every registerable tool in a stable order. It is the
// order ResolveToolSelection returns names in, so a selection is deterministic
// regardless of how the operator listed it. (tools/list itself sorts by name,
// so this order does not affect the advertised surface — it only makes the
// resolver's output predictable.) Read tools come first, then the write/author
// tools, matching the read-profile split below.
var canonicalToolOrder = []string{
	"hdf_open",
	"hdf_inspect",
	"hdf_query",
	"hdf_compliance",
	"hdf_aggregate",
	"hdf_diff",
	"hdf_validate",
	"hdf_convert",
	"hdf_author",
	"hdf_apply_amendment",
}

// registrarByName binds each advertised tool name to its register function, so a
// selection installs exactly the named tools sharing one loader.
var registrarByName = map[string]func(*sdkmcp.Server, *loader.Loader){
	"hdf_open":            RegisterOpen,
	"hdf_inspect":         RegisterInspect,
	"hdf_query":           RegisterQuery,
	"hdf_compliance":      RegisterCompliance,
	"hdf_aggregate":       RegisterAggregate,
	"hdf_diff":            RegisterDiff,
	"hdf_validate":        RegisterValidate,
	"hdf_convert":         RegisterConvert,
	"hdf_author":          RegisterAuthor,
	"hdf_apply_amendment": RegisterApplyAmendment,
}

// toolProfiles are named tool sets an operator can request instead of listing
// every name. "read" is the read/analysis surface — the tools an agent that only
// reads HDF documents needs — deliberately excluding the convert/author/apply
// write tools. "all" is every tool (the default). Advertising only the profile a
// client needs is the largest lever on the per-turn schema cost: an unadvertised
// tool sends none of its schema.
var toolProfiles = map[string][]string{
	"read": {"hdf_open", "hdf_inspect", "hdf_query", "hdf_compliance", "hdf_aggregate", "hdf_diff", "hdf_validate"},
	"all":  canonicalToolOrder,
}

// ResolveToolSelection parses a tool-selection spec (the HDF_MCP_TOOLS env var or
// the --tools flag) into the ordered, deduplicated list of tool names to
// advertise. The spec is a comma-separated list whose tokens are exact tool
// names (hdf_query) or a profile word (read|all); empty comma fields are ignored.
// An empty spec selects every tool — the backward-compatible default. An unknown
// token is an error naming the offending token and the valid set, so a launch
// config can be corrected without reading source.
func ResolveToolSelection(spec string) ([]string, error) {
	if strings.TrimSpace(spec) == "" {
		return append([]string(nil), canonicalToolOrder...), nil
	}
	selected := map[string]bool{}
	for _, raw := range strings.Split(spec, ",") {
		tok := strings.TrimSpace(raw)
		if tok == "" {
			continue
		}
		if names, ok := toolProfiles[tok]; ok {
			for _, n := range names {
				selected[n] = true
			}
			continue
		}
		if _, ok := registrarByName[tok]; ok {
			selected[tok] = true
			continue
		}
		return nil, fmt.Errorf("unknown tool %q in tool selection; valid tools are %s, or a profile (%s)",
			tok, strings.Join(canonicalToolOrder, ", "), strings.Join(profileNames(), ", "))
	}
	out := make([]string, 0, len(selected))
	for _, n := range canonicalToolOrder {
		if selected[n] {
			out = append(out, n)
		}
	}
	return out, nil
}

// profileNames returns the profile words in stable order for error messages.
func profileNames() []string {
	names := make([]string, 0, len(toolProfiles))
	for n := range toolProfiles {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}
