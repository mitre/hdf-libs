// Command equivalence-dump emits a canonical JSON description of an
// extension graph for cross-language equivalence checking against the
// TypeScript implementation. See ../../test/equivalence-dump.ts for
// the matching producer. Both must agree on the same shape, with array
// orderings as documented in equivalence-dump.ts.
//
// Usage: equivalence-dump <hdf-results.json>
//
// Normalizes timezone-less timestamps via hdfparsers.NormalizeTimestamps
// so it can read the hdf-extension-graph test fixtures (real-world InSpec
// output shape).
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sort"

	hdfextension "github.com/mitre/hdf-libs/hdf-extension-graph/go/v3"
	hdfparsers "github.com/mitre/hdf-libs/hdf-parsers/go/v3"
	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
)

type baselineDump struct {
	Name             string   `json:"name"`
	ParentBaseline   *string  `json:"parentBaseline"`
	ExtendsFromNames []string `json:"extendsFromNames"`
	ExtendedByNames  []string `json:"extendedByNames"`
	RequirementCount int      `json:"requirementCount"`
}

type modDump struct {
	Field         string `json:"field"`
	OriginalValue any    `json:"originalValue"`
	NewValue      any    `json:"newValue"`
	InBaseline    string `json:"inBaseline"`
}

type reqDump struct {
	BaselineName        string    `json:"baselineName"`
	ID                  string    `json:"id"`
	IsRoot              bool      `json:"isRoot"`
	RootBaselineName    string    `json:"rootBaselineName"`
	RootID              string    `json:"rootId"`
	IsRedundant         bool      `json:"isRedundant"`
	FullCodeSHA256      string    `json:"fullCodeSHA256"`
	ExtensionChainNames []string  `json:"extensionChainNames"`
	Modifications       []modDump `json:"modifications"`
}

type output struct {
	BaselineCount    int            `json:"baselineCount"`
	RequirementCount int            `json:"requirementCount"`
	Baselines        []baselineDump `json:"baselines"`
	Requirements     []reqDump      `json:"requirements"`
}

func sha256Hex(s string) string {
	if s == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: equivalence-dump <hdf-results.json>")
		os.Exit(2)
	}
	raw, err := os.ReadFile(os.Args[1]) //nolint:gosec // path supplied by developer, not user input
	if err != nil {
		fmt.Fprintln(os.Stderr, "read:", err)
		os.Exit(1)
	}
	raw = hdfparsers.NormalizeTimestamps(raw)

	var results hdf.HDFResults
	if err := json.Unmarshal(raw, &results); err != nil {
		fmt.Fprintln(os.Stderr, "parse:", err)
		os.Exit(1)
	}

	g := hdfextension.BuildExtensionGraph(&results)

	out := output{
		BaselineCount:    len(g.Baselines),
		RequirementCount: len(g.Requirements),
		Baselines:        make([]baselineDump, 0, len(g.Baselines)),
		Requirements:     make([]reqDump, 0, len(g.Requirements)),
	}

	for _, b := range g.Baselines {
		ef := make([]string, 0, len(b.ExtendsFrom))
		for _, p := range b.ExtendsFrom {
			ef = append(ef, p.Data.Name)
		}
		sort.Strings(ef)
		eb := make([]string, 0, len(b.ExtendedBy))
		for _, c := range b.ExtendedBy {
			eb = append(eb, c.Data.Name)
		}
		sort.Strings(eb)
		out.Baselines = append(out.Baselines, baselineDump{
			Name:             b.Data.Name,
			ParentBaseline:   b.Data.ParentBaseline,
			ExtendsFromNames: ef,
			ExtendedByNames:  eb,
			RequirementCount: len(b.Requirements),
		})
	}
	sort.Slice(out.Baselines, func(i, j int) bool {
		return out.Baselines[i].Name < out.Baselines[j].Name
	})

	for _, r := range g.Requirements {
		root := r.Root()
		chain := r.ExtensionChain()
		chainNames := make([]string, 0, len(chain))
		for _, c := range chain {
			chainNames = append(chainNames, c.Data.Name)
		}
		mods := r.Modifications()
		modDumps := make([]modDump, 0, len(mods))
		for _, m := range mods {
			modDumps = append(modDumps, modDump{
				Field:         m.Field,
				OriginalValue: m.OriginalValue,
				NewValue:      m.NewValue,
				InBaseline:    m.InBaseline,
			})
		}
		sort.Slice(modDumps, func(i, j int) bool {
			return modDumps[i].Field < modDumps[j].Field
		})
		out.Requirements = append(out.Requirements, reqDump{
			BaselineName:        r.SourcedFrom.Data.Name,
			ID:                  r.Data.ID,
			IsRoot:              len(r.ExtendsFrom) == 0,
			RootBaselineName:    root.SourcedFrom.Data.Name,
			RootID:              root.Data.ID,
			IsRedundant:         r.IsRedundant(),
			FullCodeSHA256:      sha256Hex(r.FullCode()),
			ExtensionChainNames: chainNames,
			Modifications:       modDumps,
		})
	}
	sort.Slice(out.Requirements, func(i, j int) bool {
		if out.Requirements[i].BaselineName != out.Requirements[j].BaselineName {
			return out.Requirements[i].BaselineName < out.Requirements[j].BaselineName
		}
		return out.Requirements[i].ID < out.Requirements[j].ID
	})

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(&out); err != nil {
		fmt.Fprintln(os.Stderr, "encode:", err)
		os.Exit(1)
	}
}
