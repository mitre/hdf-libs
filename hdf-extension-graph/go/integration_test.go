package hdfextension

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	hdfparsers "github.com/mitre/hdf-libs/hdf-parsers/go/v3"
	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	"github.com/stretchr/testify/assert"
)

// reqWith builds an EvaluatedRequirement with the fields integration tests
// commonly need to set. Empty string for code/title means "leave nil".
func reqWith(id string, code string, impact float64, title string) hdf.EvaluatedRequirement {
	r := hdf.EvaluatedRequirement{ID: id, Impact: impact}
	if code != "" {
		r.Code = ptr(code)
	}
	if title != "" {
		r.Title = ptr(title)
	}
	return r
}

func TestIntegration_SingleBaseline(t *testing.T) {
	results := makeResults(makeBaselineData("rhel9-stig-baseline", "", []hdf.EvaluatedRequirement{
		reqWith("SV-001", "describe sshd_config do\n  its(\"PermitRootLogin\") { should eq \"no\" }\nend", 0.7, "Disable root login"),
		reqWith("SV-002", "describe package(\"aide\") do\n  it { should be_installed }\nend", 0.5, "Install AIDE"),
		reqWith("SV-003", "", 0.0, "N/A control"),
	}))

	t.Run("builds graph with one baseline and all requirements", func(t *testing.T) {
		g := BuildExtensionGraph(results)
		assert.Len(t, g.Baselines, 1)
		assert.Len(t, g.Requirements, 3)
		assert.Len(t, g.RootBaselines(), 1)
	})

	t.Run("all requirements are their own root and have empty derived state", func(t *testing.T) {
		g := BuildExtensionGraph(results)
		for _, r := range g.Requirements {
			assert.Same(t, r, r.Root())
			assert.False(t, r.IsRedundant())
			assert.Empty(t, r.ExtendsFrom)
			assert.Empty(t, r.ExtendedBy)
			assert.Empty(t, r.Modifications())
			assert.Len(t, r.ExtensionChain(), 1)
		}
	})

	t.Run("FullCode contains baseline header for requirements with code", func(t *testing.T) {
		g := BuildExtensionGraph(results)
		sv001 := g.FindRequirements("SV-001")[0]
		assert.Contains(t, sv001.FullCode(), "# rhel9-stig-baseline")
		assert.Contains(t, sv001.FullCode(), "PermitRootLogin")
	})

	t.Run("FullCode is empty for requirements without code", func(t *testing.T) {
		g := BuildExtensionGraph(results)
		sv003 := g.FindRequirements("SV-003")[0]
		assert.Equal(t, "", sv003.FullCode())
	})
}

func TestIntegration_TwoLayerOverlay(t *testing.T) {
	results := makeResults(
		makeBaselineData("rhel9-stig-baseline", "", []hdf.EvaluatedRequirement{
			reqWith("SV-001", "describe sshd_config do\n  its(\"PermitRootLogin\") { should eq \"no\" }\nend", 0.7, "Disable root login"),
			reqWith("SV-002", "describe package(\"aide\") do\n  it { should be_installed }\nend", 0.5, "Install AIDE"),
			reqWith("SV-003", "describe file(\"/etc/shadow\") do\n  it { should exist }\nend", 0.3, "Shadow file exists"),
		}),
		makeBaselineData("cms-rhel9-overlay", "rhel9-stig-baseline", []hdf.EvaluatedRequirement{
			reqWith("SV-001", "", 0.7, "Disable root login"),
			reqWith("SV-002", "describe package(\"aide\") do\n  it { should be_installed }\n  its(\"version\") { should cmp >= \"0.16\" }\nend", 0.5, "Install AIDE (CMS)"),
			reqWith("SV-003", "", 0.0, "Shadow file exists"),
		}),
	)

	t.Run("links baselines correctly", func(t *testing.T) {
		g := BuildExtensionGraph(results)
		base := g.FindBaseline("rhel9-stig-baseline")
		overlay := g.FindBaseline("cms-rhel9-overlay")

		assert.Contains(t, base.ExtendedBy, overlay)
		assert.Contains(t, overlay.ExtendsFrom, base)
		assert.Len(t, g.RootBaselines(), 1)
		assert.Same(t, base, g.RootBaselines()[0])
	})

	t.Run("SV-001 overlay is redundant (empty code) and has no modifications", func(t *testing.T) {
		g := BuildExtensionGraph(results)
		overlaySV001 := g.Baselines[1].Requirements[0]

		assert.True(t, overlaySV001.IsRedundant())
		assert.Same(t, g.Baselines[0].Requirements[0], overlaySV001.Root())
		assert.Empty(t, overlaySV001.Modifications())
	})

	t.Run("SV-002 overlay has modified code and title", func(t *testing.T) {
		g := BuildExtensionGraph(results)
		overlaySV002 := g.Baselines[1].Requirements[1]

		assert.False(t, overlaySV002.IsRedundant())
		assert.Contains(t, overlaySV002.FullCode(), "cms-rhel9-overlay")
		assert.Contains(t, overlaySV002.FullCode(), "version")
		assert.Contains(t, overlaySV002.FullCode(), "rhel9-stig-baseline")

		hasTitleMod := false
		for _, m := range overlaySV002.Modifications() {
			if m.Field == "title" {
				hasTitleMod = true
				break
			}
		}
		assert.True(t, hasTitleMod)
	})

	t.Run("SV-003 overlay disables the control (impact 0.3 → 0.0)", func(t *testing.T) {
		g := BuildExtensionGraph(results)
		overlaySV003 := g.Baselines[1].Requirements[2]

		assert.True(t, overlaySV003.IsRedundant(), "empty code → redundant")

		mods := overlaySV003.Modifications()
		var impactMod *Modification
		for i := range mods {
			if mods[i].Field == "impact" {
				impactMod = &mods[i]
				break
			}
		}
		assert.NotNil(t, impactMod)
		assert.Equal(t, 0.3, impactMod.OriginalValue)
		assert.Equal(t, 0.0, impactMod.NewValue)
	})

	t.Run("extension chain is correct for overlay requirements", func(t *testing.T) {
		g := BuildExtensionGraph(results)
		overlaySV002 := g.Baselines[1].Requirements[1]
		chain := overlaySV002.ExtensionChain()

		assert.Len(t, chain, 2)
		assert.Equal(t, "rhel9-stig-baseline", chain[0].Data.Name)
		assert.Equal(t, "cms-rhel9-overlay", chain[1].Data.Name)
	})
}

func TestIntegration_ThreeLayerChain(t *testing.T) {
	results := makeResults(
		makeBaselineData("disa-rhel7-stig", "", []hdf.EvaluatedRequirement{
			reqWith("V-71849", "describe sshd_config do\n  its(\"ClientAliveInterval\") { should cmp <= 600 }\nend", 0.5, "SSH timeout"),
			reqWith("V-71855", "describe shadow.where { user == \"root\" } do\n  its(\"max_days\") { should cmp <= 60 }\nend", 0.7, "Password max age"),
		}),
		makeBaselineData("cms-rhel7-overlay", "disa-rhel7-stig", []hdf.EvaluatedRequirement{
			reqWith("V-71849", "describe sshd_config do\n  its(\"ClientAliveInterval\") { should cmp <= 300 }\nend", 0.5, "SSH timeout (CMS)"),
			reqWith("V-71855", "", 0.7, "Password max age"),
		}),
		makeBaselineData("project-specific-overlay", "cms-rhel7-overlay", []hdf.EvaluatedRequirement{
			reqWith("V-71849", "describe sshd_config do\n  its(\"ClientAliveInterval\") { should cmp <= 120 }\nend", 0.9, "SSH timeout (project)"),
			reqWith("V-71855", "", 0.0, "Password max age (waived)"),
		}),
	)

	t.Run("builds a three-node baseline chain", func(t *testing.T) {
		g := BuildExtensionGraph(results)
		assert.Len(t, g.Baselines, 3)
		assert.Len(t, g.RootBaselines(), 1)
		assert.Equal(t, "disa-rhel7-stig", g.RootBaselines()[0].Data.Name)

		disa := g.FindBaseline("disa-rhel7-stig")
		cms := g.FindBaseline("cms-rhel7-overlay")
		proj := g.FindBaseline("project-specific-overlay")

		assert.Contains(t, disa.ExtendedBy, cms)
		assert.Contains(t, cms.ExtendedBy, proj)
		assert.Contains(t, proj.ExtendsFrom, cms)
	})

	t.Run("V-71849 FullCode stacks all three layers top-to-bottom", func(t *testing.T) {
		g := BuildExtensionGraph(results)
		projReq := g.Baselines[2].Requirements[0]
		full := projReq.FullCode()

		assert.Contains(t, full, "project-specific-overlay")
		assert.Contains(t, full, "120")
		assert.Contains(t, full, "cms-rhel7-overlay")
		assert.Contains(t, full, "300")
		assert.Contains(t, full, "disa-rhel7-stig")
		assert.Contains(t, full, "600")

		projIdx := strings.Index(full, "120")
		cmsIdx := strings.Index(full, "300")
		disaIdx := strings.Index(full, "600")
		assert.True(t, projIdx < cmsIdx, "project layer should appear before CMS")
		assert.True(t, cmsIdx < disaIdx, "CMS layer should appear before DISA")
	})

	t.Run("V-71849 root resolves to the DISA baseline requirement", func(t *testing.T) {
		g := BuildExtensionGraph(results)
		projReq := g.Baselines[2].Requirements[0]
		disaReq := g.Baselines[0].Requirements[0]

		assert.Same(t, disaReq, projReq.Root())
	})

	t.Run("V-71849 extension chain has three entries in root→leaf order", func(t *testing.T) {
		g := BuildExtensionGraph(results)
		projReq := g.Baselines[2].Requirements[0]

		var names []string
		for _, b := range projReq.ExtensionChain() {
			names = append(names, b.Data.Name)
		}
		assert.Equal(t, []string{"disa-rhel7-stig", "cms-rhel7-overlay", "project-specific-overlay"}, names)
	})

	t.Run("V-71849 detects impact + title changes against the CMS parent", func(t *testing.T) {
		g := BuildExtensionGraph(results)
		projReq := g.Baselines[2].Requirements[0]
		mods := projReq.Modifications()

		var impactFound, titleFound bool
		for _, m := range mods {
			if m.Field == "impact" && m.OriginalValue == 0.5 && m.NewValue == 0.9 {
				impactFound = true
			}
			if m.Field == "title" {
				titleFound = true
			}
		}
		assert.True(t, impactFound)
		assert.True(t, titleFound)
	})

	t.Run("V-71855 redundant overlays skip to base code", func(t *testing.T) {
		g := BuildExtensionGraph(results)
		projReq := g.Baselines[2].Requirements[1]

		assert.True(t, projReq.IsRedundant())
		full := projReq.FullCode()
		assert.Contains(t, full, "disa-rhel7-stig")
		assert.Contains(t, full, "max_days")
		assert.NotContains(t, full, "cms-rhel7-overlay")
		assert.NotContains(t, full, "project-specific-overlay")
	})
}

func TestIntegration_WrapperPattern(t *testing.T) {
	// Three independent baselines (no parentBaseline anywhere). The wrapper-
	// profile pattern in InSpec uses `depends:` rather than parentBaseline,
	// and depends is not honored by extension-graph linking — so all three
	// baselines stay roots.
	results := makeResults(
		makeBaselineData("k8s-stig-baseline", "", []hdf.EvaluatedRequirement{
			reqWith("K8S-001", "describe kubelet do\n  it { should be_running }\nend", 0.5, ""),
		}),
		makeBaselineData("rhel9-stig-baseline", "", []hdf.EvaluatedRequirement{
			reqWith("SV-001", "describe sshd_config do\n  its(\"PermitRootLogin\") { should eq \"no\" }\nend", 0.7, ""),
		}),
		makeBaselineData("wrapper-profile", "", nil),
	)

	t.Run("wrapper has no parent and no requirements", func(t *testing.T) {
		g := BuildExtensionGraph(results)
		wrapper := g.FindBaseline("wrapper-profile")
		assert.Empty(t, wrapper.ExtendsFrom)
		assert.Empty(t, wrapper.ExtendedBy)
		assert.Empty(t, wrapper.Requirements)
	})

	t.Run("independent baselines stay unlinked", func(t *testing.T) {
		g := BuildExtensionGraph(results)
		k8s := g.FindBaseline("k8s-stig-baseline")
		rhel := g.FindBaseline("rhel9-stig-baseline")

		assert.Empty(t, k8s.ExtendsFrom)
		assert.Empty(t, k8s.ExtendedBy)
		assert.Empty(t, rhel.ExtendsFrom)
		assert.Empty(t, rhel.ExtendedBy)
	})

	t.Run("all three baselines are roots", func(t *testing.T) {
		g := BuildExtensionGraph(results)
		assert.Len(t, g.RootBaselines(), 3)
	})
}

func TestIntegration_EdgeCases(t *testing.T) {
	t.Run("handles dangling parentBaseline gracefully", func(t *testing.T) {
		results := makeResults(makeBaselineData("orphan-overlay", "deleted-baseline", []hdf.EvaluatedRequirement{
			reqWith("R1", "some code", 0.5, ""),
		}))

		g := BuildExtensionGraph(results)
		orphan := g.FindBaseline("orphan-overlay")

		assert.Empty(t, orphan.ExtendsFrom)
		req := orphan.Requirements[0]
		assert.Same(t, req, req.Root())
		assert.False(t, req.IsRedundant())
		assert.Len(t, req.ExtensionChain(), 1)
	})

	t.Run("handles duplicate requirement ids within the same baseline", func(t *testing.T) {
		results := makeResults(makeBaselineData("base", "", []hdf.EvaluatedRequirement{
			reqWith("R1", "first", 0.5, ""),
			reqWith("R1", "second", 0.5, ""),
		}))

		g := BuildExtensionGraph(results)
		assert.Len(t, g.FindRequirements("R1"), 2)
	})

	t.Run("handles a baseline with empty requirements array", func(t *testing.T) {
		results := makeResults(makeBaselineData("empty", "", nil))

		g := BuildExtensionGraph(results)
		assert.Len(t, g.Baselines, 1)
		assert.Empty(t, g.Requirements)
	})
}

// ── Real InSpec multi-layered profile fixture ──────────────────────────
//
// Profile chain:
//
//	metawrapper (root)
//	├── wrapper (parent=metawrapper)
//	│   ├── k8s-node-stig-baseline (parent=wrapper)
//	│   └── redhat-enterprise-linux-9-stig-baseline (parent=wrapper)
//	└── dep (parent=metawrapper)
//
// The fixture is the TypeScript package's test/fixtures/multilayered-inspec.json
// — same data exercises both implementations so behavior stays aligned.
func TestIntegration_RealMultilayeredFixture(t *testing.T) {
	// #nosec G304 -- fixture path is repo-relative and not user-controlled.
	data, err := os.ReadFile("../test/fixtures/multilayered-inspec.json")
	if err != nil {
		t.Skipf("fixture not available: %v", err)
	}
	data = hdfparsers.NormalizeTimestamps(data)

	var results hdf.HDFResults
	err = json.Unmarshal(data, &results)
	if err != nil {
		t.Fatalf("fixture must unmarshal as HDFResults: %v", err)
	}

	graph := BuildExtensionGraph(&results)

	t.Run("detects all 5 baselines", func(t *testing.T) {
		assert.Len(t, graph.Baselines, 5)
	})

	t.Run("identifies metawrapper as the only root baseline", func(t *testing.T) {
		roots := graph.RootBaselines()
		assert.Len(t, roots, 1)
		assert.Equal(t, "metawrapper", roots[0].Data.Name)
	})

	t.Run("links wrapper to metawrapper via parentBaseline", func(t *testing.T) {
		wrapper := graph.FindBaseline("wrapper")
		assert.NotNil(t, wrapper)
		assert.Len(t, wrapper.ExtendsFrom, 1)
		assert.Equal(t, "metawrapper", wrapper.ExtendsFrom[0].Data.Name)
	})

	t.Run("links both STIG baselines to wrapper", func(t *testing.T) {
		rhel9 := graph.FindBaseline("redhat-enterprise-linux-9-stig-baseline")
		k8s := graph.FindBaseline("k8s-node-stig-baseline")
		assert.NotNil(t, rhel9)
		assert.NotNil(t, k8s)
		assert.Len(t, rhel9.ExtendsFrom, 1)
		assert.Equal(t, "wrapper", rhel9.ExtendsFrom[0].Data.Name)
		assert.Len(t, k8s.ExtendsFrom, 1)
		assert.Equal(t, "wrapper", k8s.ExtendsFrom[0].Data.Name)
	})

	t.Run("links dep to metawrapper", func(t *testing.T) {
		dep := graph.FindBaseline("dep")
		assert.NotNil(t, dep)
		assert.Len(t, dep.ExtendsFrom, 1)
		assert.Equal(t, "metawrapper", dep.ExtendsFrom[0].Data.Name)
	})

	t.Run("has requirements from all baselines", func(t *testing.T) {
		assert.Greater(t, len(graph.Requirements), 500)
	})

	t.Run("identifies overlaid requirements via extension chain", func(t *testing.T) {
		// Requirements in wrapper that share IDs with rhel9/k8s baselines
		// should have chains showing the overlay relationship. The TS test
		// looks at wrapper's reqs that extend down; here we mirror that:
		// reqs sourced from wrapper whose ExtensionChain length > 1 are the
		// overlay cases.
		var withChain int
		for _, r := range graph.Requirements {
			if r.SourcedFrom.Data.Name == "wrapper" && len(r.ExtensionChain()) > 1 {
				withChain++
			}
		}
		assert.Greater(t, withChain, 0)
	})
}
