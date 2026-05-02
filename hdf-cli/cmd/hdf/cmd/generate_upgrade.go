package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	xccdf "github.com/mitre/hdf-libs/hdf-converters/v3/converters/xccdf-results-to-hdf/go"
	"github.com/mitre/hdf-libs/hdf-diff/go/v3/matching"
	generators "github.com/mitre/hdf-libs/hdf-generators/go/v3"
	schema "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
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

func newGenerateUpgradeCmd() *cobra.Command { //nolint:funlen,gocyclo // CLI command with many flags
	var (
		controlsDir   string
		idType        string
		prefer        string
		outputFormat  string
		singleFile    bool
		noCode        bool
		maintainer    string
		copyright     string
		license       string
		profileVer    string
		inspecVersion string
		reportFormat  string
		reportDir     string
		strategy      string
	)

	cmd := &cobra.Command{
		Use:     "upgrade <current-baseline> <upstream-baseline> <output-dir>",
		Aliases: []string{"delta"},
		Short:   "Upgrade baseline with new upstream metadata, preserving customizations",
		Long: `Upgrade an HDF Baseline by matching requirements between the current (customized)
baseline and a new upstream baseline, then smart-merging fields.

The current baseline provides your existing customizations (code, tags, descriptions).
The upstream baseline provides updated guidance (titles, descriptions, impacts).

Smart merge behavior (default):
  - ID: always from upstream (target version)
  - Scalars (title, impact, severity): upstream wins
  - Tags: union of keys; upstream wins key conflicts
  - Descriptions: union by label; upstream wins on same label
  - Code: preserved from current (your tests)
  - Refs: union (deduplicated)

Use --prefer to override: "current" keeps your values on conflict,
"upstream" does a full replacement.

The matching engine uses a multi-tier strategy chain:
  1. SRG deterministic — exact tags.gtitle match
  2. SRG CCI tiebreak — CCI+title scoring for ambiguous SRG blocks
  3. Vendor fuzzy title — cross-vendor Levenshtein matching
  4. Exact ID — same requirement ID
  5. CCI match — shared CCI identifiers
  6. Fuzzy title — token Jaccard similarity

Input formats are auto-detected: XML = XCCDF, JSON = HDF Results/Baseline.`,
		Example: `  # Upgrade with new STIG release
  hdf generate upgrade current-profile.json new-stig-xccdf.xml upgraded/

  # Prefer current values on conflict
  hdf generate upgrade current.json upstream.json out/ --prefer current

  # Output only baseline JSON (no InSpec profile)
  hdf generate upgrade current.json upstream.json out/ -f baseline

  # Output both baseline JSON and InSpec profile
  hdf generate upgrade current.json upstream.json out/ -f both

  # Using the delta alias
  hdf generate delta current.json new.xml out/

  # Enrich current baseline with code from InSpec controls directory
  hdf generate upgrade current.json new.xml out/ -c controls/

  # Override profile metadata for InSpec output
  hdf generate upgrade old.json new.json out/ -f inspec --maintainer "MITRE SAF"`,
		Args: cobra.ExactArgs(3),
		RunE: func(_ *cobra.Command, args []string) error {
			currentPath := args[0]
			upstreamPath := args[1]
			outputDir := args[2]

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

			// When -c is provided, force inspec output
			if controlsDir != "" && outputFormat == "baseline" {
				outputFormat = "both"
			}

			// Validate --output-format flag
			if outputFormat == "" {
				outputFormat = "baseline"
			}
			switch outputFormat {
			case "baseline", "inspec", "both":
			default:
				return fmt.Errorf("--output-format must be 'baseline', 'inspec', or 'both', got %q", outputFormat)
			}

			// Read inputs
			currentData, err := readInputFile(currentPath)
			if err != nil {
				return fmt.Errorf("reading current baseline: %w", err)
			}
			upstreamData, err := readInputFile(upstreamPath)
			if err != nil {
				return fmt.Errorf("reading upstream baseline: %w", err)
			}

			// Parse current baseline
			currentBaseline, err := parseInputBaseline(currentData)
			if err != nil {
				return fmt.Errorf("parsing current baseline: %w", err)
			}

			// Apply --id-type remapping if not default
			if idType != "rule" {
				remapBaselineIDs(currentBaseline, idType)
			}

			// Enrich current baseline with code from controls directory
			if controlsDir != "" {
				if err := enrichBaselineFromControlsDir(currentBaseline, controlsDir); err != nil {
					return fmt.Errorf("reading controls directory: %w", err)
				}
			}

			// Parse upstream baseline
			upstreamBaseline, err := parseInputBaseline(upstreamData)
			if err != nil {
				return fmt.Errorf("parsing upstream baseline: %w", err)
			}

			// Apply --id-type remapping to upstream too
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

			// Convert MatchPairs → LinkRecords
			linkRecords := buildUpgradeLinkRecords(matchResult)

			// Build upgrade options
			upgradeOpts := &generators.UpgradeOptions{
				Prefer:       prefer,
				NoCode:       noCode,
				OutputFormat: outputFormat,
				SingleFile:   singleFile,
			}
			if inspecVersion != "" {
				upgradeOpts.InSpecVersion = inspecVersion
			}
			if maintainer != "" || copyright != "" || license != "" || profileVer != "" {
				upgradeOpts.Metadata = &generators.ProfileMetadata{
					Maintainer: maintainer,
					Copyright:  copyright,
					License:    license,
					Version:    profileVer,
				}
			}

			// Generate upgrade
			result := generators.GenerateUpgrade(*currentBaseline, *upstreamBaseline, linkRecords, upgradeOpts)

			// Write outputs
			if err := writeUpgradeOutputs(result, outputDir, outputFormat); err != nil {
				return err
			}

			// Write reports
			rDir := reportDir
			if rDir == "" {
				rDir = outputDir
			}
			if err := writeUpgradeReports(result, rDir, reportFormat); err != nil {
				return err
			}

			// Print statistics to stderr
			stats := result.Statistics
			fmt.Fprintf(os.Stderr, "Upgrade: %d match, %d possible mismatch, %d related, %d no match (of %d upstream from %d current)\n",
				stats.Match, stats.PosMisMatch, stats.DupMatch, stats.NoMatch, stats.NewControlsLength, stats.OldControlsLength)

			return nil
		},
	}

	// Input enrichment
	cmd.Flags().StringVarP(&controlsDir, "controls-dir", "c", "", "InSpec controls directory (enriches current baseline with code)")
	cmd.Flags().StringVarP(&idType, "id-type", "T", "rule", "XCCDF control ID type: rule, group, cis, or version")

	// Merge behavior
	cmd.Flags().StringVar(&prefer, "prefer", "", "Conflict resolution: current or upstream (default: smart merge)")
	cmd.Flags().BoolVar(&noCode, "no-code", false, "Don't preserve current test code")

	// Output control
	cmd.Flags().StringVarP(&outputFormat, "output-format", "f", "baseline", "Output format: baseline, inspec, or both")
	cmd.Flags().BoolVar(&singleFile, "single-file", false, "All controls in one .rb file (inspec output only)")

	// Profile metadata overrides (inspec output)
	cmd.Flags().StringVar(&maintainer, "maintainer", "", "Override maintainer in inspec.yml")
	cmd.Flags().StringVar(&copyright, "copyright", "", "Override copyright in inspec.yml")
	cmd.Flags().StringVar(&license, "license", "", "Override license in inspec.yml")
	cmd.Flags().StringVar(&profileVer, "version", "", "Override version in inspec.yml")
	cmd.Flags().StringVar(&inspecVersion, "inspec-version", "", "InSpec version constraint (default: >=6.0)")

	// Reporting
	cmd.Flags().StringVar(&reportFormat, "report-format", "both", "Report format: json, markdown, or both")
	cmd.Flags().StringVar(&reportDir, "report-dir", "", "Report output directory (default: output-dir)")

	// Matching
	cmd.Flags().StringVar(&strategy, "strategy", "", "Override matching strategy chain")

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

// writeUpgradeOutputs writes the upgrade result to disk based on output format.
func writeUpgradeOutputs(result generators.UpgradeResult, outputDir, outputFormat string) error {
	if err := os.MkdirAll(outputDir, 0o750); err != nil { //nolint:gosec // output dir needs group read
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	// Always write baseline.json for "baseline" or "both"
	if outputFormat == "baseline" || outputFormat == "both" {
		baselineJSON, err := json.MarshalIndent(result.Baseline, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal baseline: %w", err)
		}
		baselinePath := filepath.Join(outputDir, "baseline.json")
		if err := os.WriteFile(baselinePath, baselineJSON, 0o600); err != nil {
			return fmt.Errorf("failed to write %s: %w", baselinePath, err)
		}
		printDebug("Wrote %s", baselinePath)
	}

	// Write InSpec profile for "inspec" or "both"
	if (outputFormat == "inspec" || outputFormat == "both") && result.Profile != nil {
		if err := writeInSpecProfile(*result.Profile, outputDir); err != nil {
			return err
		}
	}

	return nil
}

// writeUpgradeReports writes delta.json and/or delta.md to the report directory.
func writeUpgradeReports(result generators.UpgradeResult, reportDir, format string) error {
	if err := os.MkdirAll(reportDir, 0o750); err != nil { //nolint:gosec // report dir needs group read
		return fmt.Errorf("failed to create report directory: %w", err)
	}

	writeJSON := format == "json" || format == "both"
	writeMD := format == "markdown" || format == "both"

	if writeJSON {
		jsonData, err := generators.GenerateDeltaJSON(result)
		if err != nil {
			return fmt.Errorf("failed to generate report JSON: %w", err)
		}
		jsonPath := filepath.Join(reportDir, "delta.json")
		if err := os.WriteFile(jsonPath, jsonData, 0o600); err != nil {
			return fmt.Errorf("failed to write %s: %w", jsonPath, err)
		}
		printDebug("Wrote %s", jsonPath)
	}

	if writeMD {
		md := generators.GenerateDeltaMarkdown(result)
		mdPath := filepath.Join(reportDir, "delta.md")
		if err := os.WriteFile(mdPath, []byte(md), 0o600); err != nil {
			return fmt.Errorf("failed to write %s: %w", mdPath, err)
		}
		printDebug("Wrote %s", mdPath)
	}

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

// enrichBaselineFromControlsDir reads .rb files from a controls directory and
// enriches the current baseline requirements with code from those files.
// Each .rb file's content becomes the code body for the matching requirement.
func enrichBaselineFromControlsDir(baseline *schema.HDFBaseline, controlsDir string) error {
	entries, err := os.ReadDir(controlsDir)
	if err != nil {
		return fmt.Errorf("reading directory %s: %w", controlsDir, err)
	}

	// Build code map: control ID → full file content
	codeMap := make(map[string]string)
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".rb") {
			continue
		}

		filePath := filepath.Join(controlsDir, entry.Name())
		content, err := os.ReadFile(filePath) //nolint:gosec // path comes from user flag, not untrusted input
		if err != nil {
			return fmt.Errorf("reading %s: %w", filePath, err)
		}

		// Extract control ID from the file content
		matches := controlIDRegex.FindAllStringSubmatch(string(content), -1)
		for _, m := range matches {
			if len(m) >= 2 {
				codeMap[m[1]] = string(content)
			}
		}
	}

	// Enrich baseline requirements with code
	for i := range baseline.Requirements {
		if code, ok := codeMap[baseline.Requirements[i].ID]; ok {
			baseline.Requirements[i].Code = &code
		}
	}

	return nil
}

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
