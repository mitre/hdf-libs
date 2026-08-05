package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	xccdf "github.com/mitre/hdf-libs/hdf-converters/v3/converters/xccdf-results-to-hdf/go"
	"github.com/mitre/hdf-libs/hdf-diff/go/v3/matching"
	generators "github.com/mitre/hdf-libs/hdf-generators/go/v3"
	schema "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	hdfutil "github.com/mitre/hdf-libs/hdf-utilities/go/v3"
	validators "github.com/mitre/hdf-libs/hdf-validators/go/v3"
	"github.com/spf13/cobra"
)

// defaultUpgradeStrategies is the upgrade strategy chain:
// SRG tiers → existing general strategies as fallback.
var defaultUpgradeStrategies = []string{
	"srgDeterministic",
	"srgCciTiebreak",
	"vendorFuzzyTitle",
	"exactId",
	"cciMatch",
	"fuzzyTitle",
}

func newGenerateUpgradeCmd() *cobra.Command { //nolint:funlen,gocyclo // CLI command — one big shape so all flag wiring lives in one place
	var (
		outputDir     string
		reportDir     string
		idType        string
		prefer        string
		strategy      string
		noCode        bool
		keepUnmatched bool
	)

	cmd := &cobra.Command{
		Use:     "upgrade <current> <upstream>",
		Aliases: []string{"delta"},
		Short:   "Upgrade an existing baseline or InSpec profile to match a newer XCCDF/baseline",
		Long: `Upgrade <current> to reflect the guidance in <upstream>, matching
requirements between them and smart-merging fields so your customizations
survive the version bump.

Conceptual model
================

  current:   your existing baseline or profile — the version with your code,
             custom tags, and any local descriptions.
  upstream:  the new guidance — typically a freshly released XCCDF benchmark,
             or another HDF Baseline you want to adopt.
  upgrade:   for each upstream requirement, find the matching one in current
             (via SRG/CCI semantics, not exact-ID), then smart-merge:
               - upstream wins on metadata (title, impact, descriptions, tags)
               - current wins on code (your authored InSpec tests stay)
               - collections (tags, descriptions, refs) are unioned

Input modes
===========

The behavior of upgrade depends on what <current> is:

  - InSpec profile DIRECTORY (has inspec.yml + controls/):
        The default action is an IN-PLACE update of the profile —
        controls/*.rb are overwritten with merged versions, stale .rb
        files are pruned, and inspec.yml is preserved verbatim.
        baseline.json + delta reports land in a new .upgrade/
        subdirectory inside the profile.

        Pass -o <dir> to write a fresh copy of the profile to <dir>
        instead of touching the original. Useful for reviewing the
        upgrade before committing it back.

        Reading the profile directory requires cinc-auditor or inspec
        on PATH (the upgrade tool shells out to one of them to extract
        control metadata).

  - File input (HDF Results JSON / HDF Baseline JSON / InSpec JSON /
    XCCDF XML):
        The upgraded baseline.json is emitted. With no -o it streams
        to stdout (pipe-friendly); with -o <dir> it's written to
        <dir>/baseline.json. No InSpec profile is emitted in this mode
        — if you want one, chain a second command:

            hdf generate inspec-profile baseline.json /path/to/profile/

        Delta reports (delta.json, delta.md) are NOT written in
        file-input mode unless --report-dir is given. Each artifact
        has exactly one flag controlling it: -o for the baseline,
        --report-dir for the reports.

Matching strategy
=================

The matching engine tries strategies in order until one yields a match:

  1. srgDeterministic  — exact tags.gtitle equality (the cleanest 1:1)
  2. srgCciTiebreak    — within a shared SRG block, score by CCI Jaccard
                         and title similarity. Catches renames that
                         exact-ID matching misses.
  3. vendorFuzzyTitle  — cross-vendor Levenshtein on titles (Windows ↔
                         Linux STIGs occasionally share controls).
  4. exactId           — same SV-/V- identifier.
  5. cciMatch          — shared CCI identifiers.
  6. fuzzyTitle        — token Jaccard on titles.

Use --strategy to override the chain (advanced; expert use).`,
		Example: `  # In-place update of an existing InSpec profile to a new STIG XCCDF.
  # Reads profile via cinc-auditor json, prunes deprecated controls,
  # writes baseline.json + delta reports to <profile>/.upgrade/.
  hdf generate upgrade /path/to/profile/ new-stig-xccdf.xml

  # Fresh copy of the profile, leaving the original untouched.
  # The copy is upgraded in place.
  hdf generate upgrade /path/to/profile/ new-stig-xccdf.xml -o /tmp/upgraded/

  # Baseline-to-baseline upgrade — baseline.json streams to stdout.
  hdf generate upgrade old.json upstream.xml | jq '.requirements | length'

  # Same, written to a file instead of stdout.
  hdf generate upgrade old.json upstream.xml -o /tmp/out/

  # Baseline to stdout, but also keep the delta reports.
  hdf generate upgrade old.json upstream.xml --report-dir /tmp/reports/

  # Keep unmatched current controls (default drops them, matching SAF delta).
  hdf generate upgrade /path/to/profile/ new.xml --keep-unmatched

  # When current and upstream conflict on scalars, prefer current's values.
  hdf generate upgrade /path/to/profile/ new.xml --prefer current

  # 'delta' is an alias for backward compatibility with SAF CLI muscle memory.
  hdf generate delta /path/to/profile/ new.xml`,
		Args: cobra.ExactArgs(2),
		RunE: func(_ *cobra.Command, args []string) error {
			currentPath := args[0]
			upstreamPath := args[1]

			// Validate --prefer flag
			if prefer != "" && prefer != "current" && prefer != "upstream" {
				return fmt.Errorf("--prefer must be 'current' or 'upstream', got %q", prefer)
			}

			// Validate --id-type flag
			switch idType {
			case "rule", "group", "cis", "version":
			default:
				return fmt.Errorf("--id-type must be 'rule', 'group', 'cis', or 'version', got %q", idType)
			}

			// Detect: is <current> an InSpec profile directory?
			profileDirMode := isInSpecProfileDir(currentPath)

			// Resolve effective output dir.
			// Profile dir input:  default to in-place (currentPath); -o overrides.
			// File input:         -o is required.
			effectiveOutput := outputDir
			inPlace := false
			if profileDirMode {
				if effectiveOutput == "" {
					// In-place: write back into the profile directory.
					effectiveOutput = currentPath
					inPlace = true
				} else {
					// Fresh copy: clone the profile dir to -o, then upgrade in place there.
					if err := os.MkdirAll(effectiveOutput, 0o750); err != nil { //nolint:gosec // profile dirs need group read
						return fmt.Errorf("creating output dir: %w", err)
					}
					if err := copyDir(currentPath, effectiveOutput); err != nil {
						return fmt.Errorf("copying profile to output dir: %w", err)
					}
					// The upgrade now runs against the COPY's controls; the original
					// is untouched. Treat the copy as the in-place target.
					inPlace = true
				}
			}
			// File input with no -o is valid: baseline.json streams to stdout.

			// Read current baseline data. For profile dirs, shell out to
			// cinc-auditor/inspec to get the InSpec JSON form. For files,
			// just read the bytes.
			var currentData []byte
			if profileDirMode {
				stop := startSpinner("Reading InSpec profile via cinc-auditor...")
				cinged, err := generateProfileJSON(currentPath)
				stop()
				if err != nil {
					return fmt.Errorf("reading InSpec profile %q: %w", currentPath, err)
				}
				currentData = cinged
			} else {
				data, err := readInputFile(currentPath)
				if err != nil {
					return fmt.Errorf("reading current baseline: %w", err)
				}
				currentData = data
			}

			// Read upstream baseline data (always a file).
			upstreamData, err := readInputFile(upstreamPath)
			if err != nil {
				return fmt.Errorf("reading upstream baseline: %w", err)
			}

			// Parse current baseline
			currentBaseline, err := parseInputBaseline(currentData)
			if err != nil {
				return fmt.Errorf("parsing current baseline: %w", err)
			}
			if idType != "rule" {
				remapBaselineIDs(currentBaseline, idType)
			}

			// Parse upstream baseline
			upstreamBaseline, err := parseInputBaseline(upstreamData)
			if err != nil {
				return fmt.Errorf("parsing upstream baseline: %w", err)
			}
			if idType != "rule" {
				remapBaselineIDs(upstreamBaseline, idType)
			}

			// Convert to EvaluatedRequirements for matching
			currentEvalReqs := baselineToEvalReqs(currentBaseline.Requirements)
			upstreamEvalReqs := baselineToEvalReqs(upstreamBaseline.Requirements)

			// Run matching
			strategyChain := defaultUpgradeStrategies
			if strategy != "" {
				strategyChain = []string{strategy}
			}
			matchOpts := matching.Options{
				Strategy:           strategyChain[0],
				FallbackStrategies: strategyChain[1:],
			}
			matchResult, matchErr := matching.MatchRequirementsWithError(currentEvalReqs, upstreamEvalReqs, matchOpts)
			if matchErr != nil {
				return fmt.Errorf("matching failed: %w", matchErr)
			}

			linkRecords := buildUpgradeLinkRecords(matchResult)

			// Build upgrade options. In profile-dir mode we always want
			// InSpec output ("both") so the .rb files get regenerated; in
			// file-input mode we only emit baseline.json.
			upgradeOpts := &generators.UpgradeOptions{
				Prefer:        prefer,
				NoCode:        noCode,
				KeepUnmatched: keepUnmatched,
			}
			if profileDirMode {
				upgradeOpts.OutputFormat = "both"
			} else {
				upgradeOpts.OutputFormat = "baseline"
			}

			result := generators.GenerateUpgrade(*currentBaseline, *upstreamBaseline, linkRecords, upgradeOpts)

			// Resolve the delta-report destination. Reports are written
			// ONLY when this resolves to a non-empty path:
			//   - explicit --report-dir always wins
			//   - directory-input mode defaults it to <profile>/.upgrade/
			//   - file-input mode has no default — no --report-dir, no reports
			reportTarget := reportDir
			if reportTarget == "" && inPlace {
				reportTarget = filepath.Join(effectiveOutput, ".upgrade")
			}

			// Write the upgraded baseline.
			switch {
			case inPlace:
				if result.Profile != nil {
					if err := writeInPlaceProfile(*result.Profile, effectiveOutput); err != nil {
						return err
					}
				}
				// baseline.json is grouped with the delta reports.
				if err := writeBaselineJSON(result, reportTarget); err != nil {
					return err
				}
			case effectiveOutput == "":
				// File input, no -o: stream baseline.json to stdout.
				if err := writeBaselineStdout(result); err != nil {
					return err
				}
			default:
				if err := writeBaselineJSON(result, effectiveOutput); err != nil {
					return err
				}
			}

			// Write delta reports only when a destination resolved.
			if reportTarget != "" {
				if err := writeUpgradeReports(result, reportTarget); err != nil {
					return err
				}
			}

			// Summary to stderr. In stdout-streaming mode (file input, no -o)
			// upgrade acts as a filter — stay quiet, like jq or cat. The only
			// stderr output in that mode is a note if reports hit disk.
			stats := result.Statistics
			printStats := func() {
				fmt.Fprintf(os.Stderr, "Upgrade: %d match, %d possible mismatch, %d related, %d no match (of %d upstream from %d current)\n",
					stats.Match, stats.PosMisMatch, stats.DupMatch, stats.NoMatch, stats.NewControlsLength, stats.OldControlsLength)
			}
			switch {
			case inPlace:
				printStats()
				fmt.Fprintf(os.Stderr, "Updated profile in-place at %s; reports in %s\n", effectiveOutput, reportTarget)
			case effectiveOutput == "":
				// stdout-streaming mode: stay quiet. Note only disk side-effects.
				if reportTarget != "" {
					fmt.Fprintf(os.Stderr, "Wrote delta reports to %s\n", reportTarget)
				}
			default:
				printStats()
				fmt.Fprintf(os.Stderr, "Wrote baseline.json to %s\n", effectiveOutput)
				if reportTarget != "" {
					fmt.Fprintf(os.Stderr, "Wrote delta reports to %s\n", reportTarget)
				}
			}

			return nil
		},
	}

	// Output destination for the upgraded baseline.
	cmd.Flags().StringVarP(&outputDir, "output-dir", "o", "",
		"Destination for the upgraded baseline.\n"+
			"  file input:       with no -o, baseline.json streams to stdout\n"+
			"                    (pipe-friendly); with -o <dir> it's written to\n"+
			"                    <dir>/baseline.json.\n"+
			"  profile directory: with no -o, the profile is updated in place;\n"+
			"                    with -o <dir> a fresh upgraded copy is written\n"+
			"                    there and the original is left untouched.")
	cmd.Flags().StringVar(&reportDir, "report-dir", "",
		"Destination for the delta reports (delta.json, delta.md).\n"+
			"  profile directory: defaults to <profile>/.upgrade/ — reports are\n"+
			"                    always written there alongside baseline.json.\n"+
			"  file input:        no default — delta reports are written ONLY\n"+
			"                    when this flag is given. Without it, you get the\n"+
			"                    baseline and nothing else.")

	// Matching / merge behavior
	cmd.Flags().StringVar(&prefer, "prefer", "",
		"Conflict resolution mode for fields present on both current and upstream:\n"+
			"  (unset)   smart merge — upstream wins on scalars (title, impact),\n"+
			"            current wins on code, collections are unioned.\n"+
			"  current   current's values win on every conflict (your customizations\n"+
			"            are sticky, even when upstream updates the field).\n"+
			"  upstream  upstream replaces current entirely (forget customizations,\n"+
			"            take the new guidance verbatim).")
	cmd.Flags().BoolVar(&keepUnmatched, "keep-unmatched", false,
		"Preserve current requirements that have no upstream match.\n"+
			"By default, unmatched-current controls are DROPPED — matching SAF CLI\n"+
			"delta: a control DISA removed in the new XCCDF should be removed from\n"+
			"your profile too. Set this flag when you have custom controls outside\n"+
			"the DISA STIG, or want to inspect what would be dropped before\n"+
			"committing to the upgrade.")
	cmd.Flags().BoolVar(&noCode, "no-code", false,
		"Don't preserve current's test code on matched requirements. By default,\n"+
			"smart merge keeps the InSpec test bodies you've already written (the\n"+
			"whole point of a delta-style upgrade — your tests survive metadata\n"+
			"updates). With --no-code, upstream's empty code is taken instead,\n"+
			"effectively regenerating stubs. Useful when starting fresh from a\n"+
			"new XCCDF release without carrying old tests forward.")
	cmd.Flags().StringVarP(&idType, "id-type", "T", "rule",
		"Which XCCDF ID field becomes the requirement ID:\n"+
			"  rule     SV-NNNN (Rule ID, default — current DISA convention)\n"+
			"  group    V-NNNN  (Group/Vuln ID — older STIG convention)\n"+
			"  cis      CIS catalog identifier (e.g. 1.1.1)\n"+
			"  version  STIG version string (e.g. RHEL-08-010000)\n"+
			"Only relevant when an input is XCCDF; ignored for JSON inputs.")
	cmd.Flags().StringVar(&strategy, "strategy", "",
		"Override the matching strategy chain (advanced). By default, upgrade\n"+
			"tries srgDeterministic → srgCciTiebreak → vendorFuzzyTitle → exactId\n"+
			"→ cciMatch → fuzzyTitle, in order, falling through on no-match.\n"+
			"Pass a single strategy name to use only that one.")

	return cmd
}

// parseInputBaseline parses input data as an HDF Baseline. Supports HDF Results JSON,
// HDF Baseline JSON, and XCCDF XML with auto-detection.
func parseInputBaseline(data []byte) (*schema.HDFBaseline, error) {
	trimmed := bytes.TrimLeft(data, " \t\r\n")
	if len(trimmed) == 0 {
		return nil, fmt.Errorf("empty input")
	}

	if trimmed[0] == '<' {
		baseline, err := xccdf.ConvertXccdfBenchmarkToHDF(data, version)
		if err != nil {
			return nil, fmt.Errorf("XCCDF conversion failed: %w", err)
		}
		return baseline, nil
	}

	// Try as HDF Results first (has baselines[].requirements with code)
	var results schema.HDFResults
	if err := json.Unmarshal(data, &results); err == nil && len(results.Baselines) > 0 {
		var reqs []schema.BaselineRequirement
		for _, b := range results.Baselines {
			for _, r := range b.Requirements {
				reqs = append(reqs, evalReqToBaselineReq(r))
			}
		}
		if len(reqs) > 0 {
			return &schema.HDFBaseline{
				Name:         results.Baselines[0].Name,
				Requirements: reqs,
			}, nil
		}
	}

	// Try as InSpec JSON (profiles[].controls[] format from `inspec json`)
	baseline, err := tryParseInSpecJSON(data)
	if err == nil && baseline != nil {
		return baseline, nil
	}

	// Try as HDF Baseline
	validationResult := validators.ValidateBaseline(data)
	if validationResult.Valid {
		var bl schema.HDFBaseline
		if err := json.Unmarshal(data, &bl); err != nil {
			return nil, fmt.Errorf("failed to parse baseline JSON: %w", err)
		}
		return &bl, nil
	}

	return nil, fmt.Errorf("could not parse input as HDF Results, HDF Baseline, InSpec JSON, or XCCDF")
}

// evalReqToBaselineReq converts an EvaluatedRequirement to a BaselineRequirement.
func evalReqToBaselineReq(r schema.EvaluatedRequirement) schema.BaselineRequirement {
	return schema.BaselineRequirement{
		ID:           r.ID,
		Title:        r.Title,
		Impact:       r.Impact,
		Tags:         r.Tags,
		Descriptions: r.Descriptions,
		Code:         r.Code,
		Refs:         r.Refs,
		Severity:     r.Severity,
	}
}

// buildUpgradeLinkRecords converts MatchPairs into LinkRecords for the upgrade engine.
func buildUpgradeLinkRecords(matchResult matching.MatchResult) []generators.LinkRecord {
	linkRecords := make([]generators.LinkRecord, 0, len(matchResult.Matched)+len(matchResult.UnmatchedNew))
	seenNewIDs := make(map[string]bool)

	for _, pair := range matchResult.Matched {
		relationship := pair.Relationship
		if relationship == "" {
			relationship = "primary"
		}

		var srg string
		if pair.NewReq.Tags != nil {
			if g, ok := pair.NewReq.Tags["gtitle"]; ok {
				if s, ok := g.(string); ok {
					srg = s
				}
			}
		}

		linkRecords = append(linkRecords, generators.LinkRecord{
			OldID:             pair.OldReq.ID,
			NewID:             pair.NewReq.ID,
			MatchMethod:       pair.Strategy,
			Confidence:        pair.Confidence,
			Relationship:      relationship,
			SRG:               srg,
			PotentialMismatch: computePotentialMismatch(pair.Strategy, relationship, pair.Confidence),
		})
		seenNewIDs[pair.NewReq.ID] = true
	}

	for _, req := range matchResult.UnmatchedNew {
		if seenNewIDs[req.ID] {
			continue
		}
		var srg string
		if req.Tags != nil {
			if g, ok := req.Tags["gtitle"]; ok {
				if s, ok := g.(string); ok {
					srg = s
				}
			}
		}
		linkRecords = append(linkRecords, generators.LinkRecord{
			NewID:        req.ID,
			MatchMethod:  "none",
			Relationship: "no-match",
			SRG:          srg,
		})
	}

	return linkRecords
}

// writeBaselineStdout marshals the upgraded baseline and streams it to
// stdout. Used for file inputs when no -o is given — pipe-friendly.
func writeBaselineStdout(result generators.UpgradeResult) error {
	baselineJSON, err := json.MarshalIndent(result.Baseline, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal baseline: %w", err)
	}
	if _, err := os.Stdout.Write(append(baselineJSON, '\n')); err != nil {
		return fmt.Errorf("failed to write baseline to stdout: %w", err)
	}
	return nil
}

// writeBaselineJSON marshals the upgraded baseline and writes it to dir/baseline.json.
func writeBaselineJSON(result generators.UpgradeResult, dir string) error {
	if err := os.MkdirAll(dir, 0o750); err != nil { //nolint:gosec // dir needs group read
		return fmt.Errorf("failed to create directory: %w", err)
	}
	baselineJSON, err := json.MarshalIndent(result.Baseline, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal baseline: %w", err)
	}
	baselinePath := filepath.Join(dir, "baseline.json")
	if err := os.WriteFile(baselinePath, baselineJSON, 0o600); err != nil {
		return fmt.Errorf("failed to write %s: %w", baselinePath, err)
	}
	printDebug("Wrote %s", baselinePath)
	return nil
}

// writeInPlaceProfile writes the upgraded controls into an existing
// InSpec profile directory. The existing inspec.yml is preserved
// verbatim; control .rb files for IDs no longer in the upgraded baseline
// are pruned. Used when <current> is a profile directory.
func writeInPlaceProfile(profile generators.InSpecProfile, profileDir string) error {
	controlsDir := filepath.Join(profileDir, "controls")
	if err := os.MkdirAll(controlsDir, 0o750); err != nil { //nolint:gosec // profile dirs need group read
		return fmt.Errorf("failed to create controls directory: %w", err)
	}

	// Write updated control files. Collect the set of IDs we wrote so
	// we can prune stale files afterwards.
	keepIDs := make(map[string]bool, len(profile.Controls))
	for name, content := range profile.Controls {
		controlPath, pathErr := hdfutil.SafePath(profileDir, name)
		if pathErr != nil {
			return fmt.Errorf("unsafe control path %q: %w", name, pathErr)
		}
		dir := filepath.Dir(controlPath)
		if err := os.MkdirAll(dir, 0o750); err != nil { //nolint:gosec // profile dirs need group read
			return fmt.Errorf("failed to create directory %s: %w", dir, err)
		}
		if err := os.WriteFile(controlPath, []byte(content), 0o600); err != nil {
			return fmt.Errorf("failed to write %s: %w", controlPath, err)
		}
		printDebug("Wrote %s", controlPath)
		// Extract the control ID from the filename ("controls/SV-X.rb" → "SV-X").
		base := filepath.Base(name)
		keepIDs[strings.TrimSuffix(base, ".rb")] = true
	}

	// Prune stale .rb files (IDs no longer in the upgraded baseline).
	pruned, err := pruneStaleControlFiles(controlsDir, keepIDs)
	if err != nil {
		return fmt.Errorf("pruning stale control files: %w", err)
	}

	fmt.Fprintf(os.Stderr, "Updated %d controls in %s (%d stale .rb files pruned)\n",
		len(profile.Controls), controlsDir, pruned)
	return nil
}

// writeUpgradeReports writes delta.json and delta.md to the report directory.
func writeUpgradeReports(result generators.UpgradeResult, reportDir string) error {
	if err := os.MkdirAll(reportDir, 0o750); err != nil { //nolint:gosec // report dir needs group read
		return fmt.Errorf("failed to create report directory: %w", err)
	}

	jsonData, err := generators.GenerateDeltaJSON(result)
	if err != nil {
		return fmt.Errorf("failed to generate report JSON: %w", err)
	}
	jsonPath := filepath.Join(reportDir, "delta.json")
	if err := os.WriteFile(jsonPath, jsonData, 0o600); err != nil {
		return fmt.Errorf("failed to write %s: %w", jsonPath, err)
	}
	printDebug("Wrote %s", jsonPath)

	md := generators.GenerateDeltaMarkdown(result)
	mdPath := filepath.Join(reportDir, "delta.md")
	if err := os.WriteFile(mdPath, []byte(md), 0o600); err != nil {
		return fmt.Errorf("failed to write %s: %w", mdPath, err)
	}
	printDebug("Wrote %s", mdPath)

	return nil
}

// inspecJSONProfile is a minimal struct for detecting InSpec JSON format.
type inspecJSONProfile struct {
	Name     string              `json:"name"`
	Title    *string             `json:"title,omitempty"`
	Version  *string             `json:"version,omitempty"`
	Controls []inspecJSONControl `json:"controls"`
}

type inspecJSONControl struct {
	ID           string                 `json:"id"`
	Title        *string                `json:"title,omitempty"`
	Desc         *string                `json:"desc,omitempty"`
	Descriptions json.RawMessage        `json:"descriptions,omitempty"`
	Impact       float64                `json:"impact"`
	Tags         map[string]interface{} `json:"tags,omitempty"`
	Code         *string                `json:"code,omitempty"`
}

type inspecJSONDoc struct {
	Profiles []inspecJSONProfile `json:"profiles"`
}

// tryParseInSpecJSON attempts to parse data as InSpec JSON.
// Supports two formats:
//   - Multi-profile wrapper: { profiles: [{ controls: [...] }] } (from `inspec exec --reporter json`)
//   - Single-profile: { name: "...", controls: [...] } (from `inspec json <profile>`)
//
// Returns nil, nil if the data doesn't match either format.
func tryParseInSpecJSON(data []byte) (*schema.HDFBaseline, error) {
	// Try multi-profile wrapper first
	var doc inspecJSONDoc
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, nil //nolint:nilerr // not InSpec JSON format
	}

	var profile inspecJSONProfile
	switch {
	case len(doc.Profiles) > 0 && len(doc.Profiles[0].Controls) > 0:
		profile = doc.Profiles[0]
	default:
		// Try single-profile format (top-level controls[])
		var single inspecJSONProfile
		if err := json.Unmarshal(data, &single); err != nil || len(single.Controls) == 0 {
			return nil, nil //nolint:nilerr // not InSpec JSON format
		}
		profile = single
	}

	reqs := make([]schema.BaselineRequirement, 0, len(profile.Controls))
	for _, c := range profile.Controls {
		descs := parseInSpecDescriptions(c.Desc, c.Descriptions)

		tags := c.Tags
		if tags == nil {
			tags = map[string]interface{}{}
		}

		req := schema.BaselineRequirement{
			ID:           c.ID,
			Title:        c.Title,
			Impact:       c.Impact,
			Tags:         tags,
			Descriptions: descs,
			Code:         c.Code,
		}
		reqs = append(reqs, req)
	}

	return &schema.HDFBaseline{
		Name:         profile.Name,
		Title:        profile.Title,
		Version:      profile.Version,
		Requirements: reqs,
	}, nil
}

// parseInSpecDescriptions handles both InSpec description formats:
//   - Map format: { "default": "...", "check": "..." } (from `inspec json`)
//   - Array format: [{ "label": "default", "data": "..." }] (HDF style)
//
// Falls back to the `desc` field if descriptions is missing or empty.
func parseInSpecDescriptions(desc *string, raw json.RawMessage) []schema.Description {
	var descs []schema.Description

	if len(raw) > 0 {
		// Try as map first (InSpec JSON native format)
		var descMap map[string]string
		if json.Unmarshal(raw, &descMap) == nil && len(descMap) > 0 {
			for label, data := range descMap {
				descs = append(descs, schema.Description{Label: label, Data: data})
			}
			return descs
		}

		// Try as array (HDF style)
		var descArr []struct {
			Label string `json:"label"`
			Data  string `json:"data"`
		}
		if json.Unmarshal(raw, &descArr) == nil && len(descArr) > 0 {
			for _, d := range descArr {
				descs = append(descs, schema.Description{Label: d.Label, Data: d.Data})
			}
			return descs
		}
	}

	// Fallback to desc field
	if desc != nil && *desc != "" {
		return []schema.Description{{Label: "default", Data: *desc}}
	}

	return []schema.Description{{Label: "default", Data: ""}}
}

// controlIDRegex matches `control 'ID' do` or `control "ID" do` in Ruby files.
var controlIDRegex = regexp.MustCompile(`(?m)^\s*control\s+['"]([^'"]+)['"]\s+do`)

// remapBaselineIDs changes requirement IDs based on the --id-type flag.
// XCCDF-sourced baselines have tags: rid (rule ID), gid (group/V-ID),
// stig_id (version/STIG ID). This remaps the primary ID field.
func remapBaselineIDs(baseline *schema.HDFBaseline, idType string) {
	for i := range baseline.Requirements {
		req := &baseline.Requirements[i]
		tags := req.Tags
		if tags == nil {
			continue
		}

		var newID string
		switch idType {
		case "group":
			if gid, ok := tags["gid"].(string); ok && gid != "" {
				newID = gid
			}
		case "version":
			if stigID, ok := tags["stig_id"].(string); ok && stigID != "" {
				newID = stigID
			}
		case "cis":
			// CIS benchmarks use the rule ID as-is (from rid tag)
			if rid, ok := tags["rid"].(string); ok && rid != "" {
				newID = rid
			}
		}

		if newID != "" {
			req.ID = newID
		}
	}
}

// startSpinner animates a status message on stderr while a slow,
// blocking operation runs (e.g. the cinc-auditor shell-out). Call the
// returned stop function when the operation completes — it clears the
// spinner line and blocks until the animation goroutine has exited.
//
// When stderr is not a terminal (piped, redirected, CI), it prints the
// message once as a static line and returns a no-op stop function, so
// log files don't fill with carriage-return frames.
func startSpinner(message string) func() {
	info, err := os.Stderr.Stat()
	isTTY := err == nil && info.Mode()&os.ModeCharDevice != 0
	if !isTTY {
		fmt.Fprintln(os.Stderr, message)
		return func() {}
	}

	done := make(chan struct{})
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		frames := []rune("⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏")
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()
		for i := 0; ; i++ {
			select {
			case <-done:
				fmt.Fprint(os.Stderr, "\r\033[K") // clear the spinner line
				return
			case <-ticker.C:
				fmt.Fprintf(os.Stderr, "\r%c %s", frames[i%len(frames)], message)
			}
		}
	}()
	return func() {
		close(done)
		<-finished
	}
}

// isInSpecProfileDir reports whether path is a directory containing an
// inspec.yml file — i.e., a runnable InSpec/CINC profile root. Used to
// auto-detect when upgrade should operate in in-place mode.
func isInSpecProfileDir(path string) bool {
	info, err := os.Stat(path)
	if err != nil || !info.IsDir() {
		return false
	}
	if _, err := os.Stat(filepath.Join(path, "inspec.yml")); err == nil {
		return true
	}
	return false
}

// generateProfileJSON shells out to cinc-auditor (preferred) or inspec
// to produce the profile.json equivalent of an InSpec profile directory.
// Returns the JSON bytes so they can be parsed via the existing
// tryParseInSpecJSON path.
func generateProfileJSON(profileDir string) ([]byte, error) {
	for _, bin := range []string{"cinc-auditor", "inspec"} {
		if _, err := exec.LookPath(bin); err != nil {
			continue
		}
		// #nosec G204 -- bin is from a fixed allowlist; profileDir is user-supplied
		// path validated by isInSpecProfileDir before reaching here.
		cmd := exec.CommandContext(context.Background(), bin, "json", profileDir)
		out, err := cmd.Output()
		if err != nil {
			return nil, fmt.Errorf("running %s json: %w", bin, err)
		}
		return out, nil
	}
	return nil, fmt.Errorf("neither cinc-auditor nor inspec found on PATH " +
		"(needed to read InSpec profile directories). Install one, or " +
		"pre-generate profile.json with 'cinc-auditor json <dir>' and " +
		"pass that file path instead")
}

// pruneStaleControlFiles removes .rb files from a controls directory
// whose control IDs are not in the keepIDs set. Used after writing an
// in-place upgrade to clean out controls that were dropped or renamed.
func pruneStaleControlFiles(controlsDir string, keepIDs map[string]bool) (int, error) {
	entries, err := os.ReadDir(controlsDir)
	if err != nil {
		return 0, fmt.Errorf("reading controls directory: %w", err)
	}
	pruned := 0
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".rb") {
			continue
		}
		path := filepath.Join(controlsDir, entry.Name())
		content, err := os.ReadFile(path) //nolint:gosec // path is a .rb file in user-supplied profile dir
		if err != nil {
			return pruned, fmt.Errorf("reading %s: %w", path, err)
		}
		match := controlIDRegex.FindStringSubmatch(string(content))
		if match == nil {
			// File doesn't look like a control file — leave it alone
			// (could be a helper or shared library file).
			continue
		}
		controlID := match[1]
		if !keepIDs[controlID] {
			if err := os.Remove(path); err != nil {
				return pruned, fmt.Errorf("removing stale %s: %w", path, err)
			}
			pruned++
			printDebug("Pruned stale %s", path)
		}
	}
	return pruned, nil
}

// copyDir recursively copies the contents of src into dst. Used when
// upgrade is invoked with a directory input AND an -o output dir —
// the original profile is copied to -o, then upgrade runs in-place
// within the copy. Preserves file modes and skips dotfiles at the root
// (to avoid copying .git directories from cloned baselines).
func copyDir(src, dst string) error {
	return filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		// Skip top-level dotfiles (.git, etc) to avoid copying VCS metadata.
		if rel != "." && strings.HasPrefix(rel, ".") && !strings.ContainsRune(rel, filepath.Separator) {
			if info.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		target := filepath.Join(dst, rel)
		if info.IsDir() {
			return os.MkdirAll(target, info.Mode())
		}
		// #nosec G122 -- copyDir walks a profile directory the user supplied
		// and owns; there is no TOCTOU threat model for this local CLI copy.
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		// #nosec G703 -- target is filepath.Join(dst, rel) where rel comes from
		// filepath.Rel(src, path) and path is always a descendant of src
		// (filepath.Walk invariant), so rel never contains "..".
		return os.WriteFile(target, data, info.Mode())
	})
}
