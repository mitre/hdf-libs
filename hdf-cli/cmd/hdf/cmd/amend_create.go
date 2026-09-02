package cmd

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/huh"
	hdfutil "github.com/mitre/hdf-libs/hdf-utilities/go/v3"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

func newAmendCreateCmd() *cobra.Command {
	var (
		outputPath string
		fromPath   string
		fromVex    string
		expires    string
	)

	cmd := &cobra.Command{
		Use:   "create [results-file]",
		Short: "Create waivers, attestations, and other amendments",
		Long: `Create an hdf-amendments document, interactively or from a spec.

Headless (non-interactive) mode — pass --from <spec.json|-> (or pipe a spec on
stdin). The spec is a lean JSON array of override specs (or an envelope object
with an overrides[] array). Each spec declares its "type" and that type's
fields; create fills appliedAt, resolves expiresAt, chains previousChecksum,
validates against the hdf-amendments schema, and writes a ready-to-apply file.
Works for all override types (waiver, attestation, poam, inherited,
falsePositive, riskAdjustment, operationalRequirement).

Interactive mode — with a terminal and no --from, requirements from an optional
results file are listed for selection (or IDs are entered one at a time in
standalone mode), and each amendment's details are collected via prompts.
Press Escape or Ctrl+C to cancel at any time.

Expiration accepts relative durations (30d, 3m, 6m, 1y), a bare date
(YYYY-MM-DD), or a full RFC3339 timestamp; relative/bare forms resolve to an
absolute time at create.

Examples:
  hdf amend create --from spec.json -o waivers.json   # headless from a spec file
  cat spec.json | hdf amend create -o waivers.json    # headless from stdin
  hdf amend create results.json -o waivers.json        # interactive, seeded by results
  hdf amend create -o waivers.json                     # interactive, standalone`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			resultsPath := ""
			if len(args) > 0 {
				resultsPath = args[0]
			}
			// Deterministic VEX import: no interactive/spec path, just the mapping.
			if fromVex != "" {
				return runAmendFromVex(fromVex, expires, outputPath)
			}
			// Headless when --from is given, or when stdin is not a terminal.
			if fromPath != "" {
				return runAmendCreateHeadless(fromPath, outputPath)
			}
			if !term.IsTerminal(int(os.Stdin.Fd())) { // #nosec G115 -- fd conversion is safe for stdin
				return runAmendCreateHeadless("-", outputPath)
			}
			return runAmendCreate(resultsPath, outputPath)
		},
	}

	cmd.Flags().StringVarP(&outputPath, "output", "o", "", "Output file (default: stdout)")
	cmd.Flags().StringVar(&fromPath, "from", "", "Create headlessly from a spec file (\"-\" for stdin)")
	cmd.Flags().StringVar(&fromVex, "from-vex", "", "Create deterministically from an OpenVEX file (status→override mapping, stamped appliedBy.type=system)")
	cmd.Flags().StringVar(&expires, "expires", "", "Expiry for every emitted override (required with --from-vex): RFC3339, YYYY-MM-DD, or a duration like 30d/6m/1y")

	return cmd
}

// amendKeyMap returns a huh KeyMap with Escape mapped as an additional quit key.
func amendKeyMap() *huh.KeyMap {
	km := huh.NewDefaultKeyMap()
	km.Quit = key.NewBinding(key.WithKeys("esc", "ctrl+c"))
	return km
}

// requirementInfo represents a requirement available for amendment.
type requirementInfo struct {
	ID       string
	Title    string
	Status   string
	Impact   float64
	Baseline string
	// HasCvss + Cvss* are prefilled from the source requirement's cvss[][0]
	// and consumed by draftStub to scaffold a cvss block on CVE-ecosystem
	// riskAdjustments only.
	HasCvss     bool
	CvssVersion string
	CvssSource  string
}

func (r requirementInfo) String() string {
	statusSymbol := statusToSymbol(r.Status)
	return fmt.Sprintf("%s %-10s %-45s [%s]",
		statusSymbol, r.ID, truncateString(r.Title, 45), r.Baseline)
}

// Status and identity type constants.
const (
	statusNotApplicable = "notApplicable"
	identityEmail       = "email"
	identitySimple      = "simple"
)

// amendOverride holds the details for a single amendment override.
type amendOverride struct {
	RequirementID string
	AmendType     string
	Reason        string
	ExpiresAt     string // absolute YYYY-MM-DD
	Approver      string
	Impact        *float64 // for riskAdjustment or combined overrides
}

func runAmendCreate(resultsPath, outputPath string) error {
	// Check for interactive terminal
	if !term.IsTerminal(int(os.Stdin.Fd())) { // #nosec G115 -- fd conversion is safe for stdin
		return fmt.Errorf("hdf amend create requires an interactive terminal\n" +
			"Use 'hdf amend apply' for non-interactive amendment workflows")
	}

	var overrides []amendOverride

	if resultsPath != "" {
		ov, err := amendFromResults(resultsPath)
		if err != nil {
			return err
		}
		overrides = ov
	} else {
		ov, err := amendStandalone()
		if err != nil {
			return err
		}
		overrides = ov
	}

	if len(overrides) == 0 {
		fmt.Println("No amendments created.")
		return nil
	}

	amendments := buildAmendmentsFromOverrides(overrides)
	return writeAmendmentsOutput(amendments, outputPath, len(overrides), overrides[0].AmendType)
}

// amendFromResults reads a results file, lets the user select requirements,
// then collects amendment details for each selected requirement.
func amendFromResults(resultsPath string) ([]amendOverride, error) {
	data, err := os.ReadFile(resultsPath) // #nosec G304 -- CLI reads user-provided path
	if err != nil {
		return nil, fmt.Errorf("failed to read results file: %w", err)
	}

	doc, err := loadAndValidateHDFDoc(data, "results")
	if err != nil {
		return nil, fmt.Errorf("results file %s: %w", resultsPath, err)
	}

	allReqs := extractAllRequirements(doc)
	if len(allReqs) == 0 {
		fmt.Println("No requirements found in results file.")
		return nil, nil
	}

	fmt.Printf("Found %d requirements across all baselines.\n", len(allReqs))
	fmt.Println("  + passed  - failed  ! error  o N/A  ? not reviewed")
	fmt.Println()
	fmt.Println("Use SPACE to select/deselect requirements, then ENTER to confirm.")

	// Multi-select from all requirements
	options := make([]huh.Option[string], len(allReqs))
	for i, r := range allReqs {
		options[i] = huh.NewOption(r.String(), r.ID)
	}

	var selectedIDs []string
	form := huh.NewForm(
		huh.NewGroup(
			huh.NewMultiSelect[string]().
				Title("Requirements").
				Options(options...).
				Value(&selectedIDs),
		),
	).WithKeyMap(amendKeyMap())

	if err := form.Run(); err != nil {
		if errors.Is(err, huh.ErrUserAborted) {
			fmt.Fprintln(os.Stderr, "Cancelled.")
			return nil, nil
		}
		return nil, fmt.Errorf("form cancelled: %w", err)
	}

	if len(selectedIDs) == 0 {
		return nil, nil
	}

	// Collect details for each selected requirement
	return collectPerRequirementDetails(selectedIDs)
}

// amendStandalone loops, collecting one requirement + details at a time.
func amendStandalone() ([]amendOverride, error) {
	fmt.Println("Standalone mode — enter amendments one at a time.")

	var overrides []amendOverride
	for {
		ov, err := collectSingleAmendment()
		if err != nil {
			return nil, err
		}
		if ov == nil {
			// User cancelled
			break
		}
		overrides = append(overrides, *ov)

		addAnother, err := askAddAnother()
		if err != nil {
			return nil, err
		}
		if !addAnother {
			break
		}
	}
	return overrides, nil
}

// collectSingleAmendment prompts for one requirement ID + amendment details.
func collectSingleAmendment() (*amendOverride, error) {
	var reqID string
	form := huh.NewForm(
		huh.NewGroup(
			huh.NewInput().
				Title("Requirement ID").
				Placeholder("e.g. SV-230001 or AC-1").
				Value(&reqID).
				Validate(func(s string) error {
					if strings.TrimSpace(s) == "" {
						return fmt.Errorf("requirement ID is required")
					}
					return nil
				}),
		),
	).WithKeyMap(amendKeyMap())

	if err := form.Run(); err != nil {
		if errors.Is(err, huh.ErrUserAborted) {
			fmt.Fprintln(os.Stderr, "Cancelled.")
			return nil, nil
		}
		return nil, fmt.Errorf("form cancelled: %w", err)
	}

	reqID = strings.TrimSpace(reqID)
	details, err := collectAmendmentDetails(reqID)
	if err != nil {
		return nil, err
	}
	if details == nil {
		return nil, nil
	}
	return details, nil
}

// collectPerRequirementDetails collects amendment details for each requirement ID.
func collectPerRequirementDetails(reqIDs []string) ([]amendOverride, error) {
	var overrides []amendOverride
	for i, id := range reqIDs {
		fmt.Printf("\n--- Amendment %d/%d: %s ---\n", i+1, len(reqIDs), id)
		ov, err := collectAmendmentDetails(id)
		if err != nil {
			return nil, err
		}
		if ov == nil {
			// User cancelled mid-flow
			fmt.Fprintln(os.Stderr, "Cancelled.")
			return nil, nil
		}
		overrides = append(overrides, *ov)
	}
	return overrides, nil
}

// collectAmendmentDetails prompts for amendment type, reason, expiration, and approver
// for a single requirement.
func collectAmendmentDetails(reqID string) (*amendOverride, error) {
	var (
		amendType     string
		reason        string
		expiresInput  string
		approverEmail string
	)

	form := huh.NewForm(
		huh.NewGroup(
			huh.NewSelect[string]().
				Title(fmt.Sprintf("Amendment type for %s", reqID)).
				Options(
					huh.NewOption("Waiver — risk accepted by AO", "waiver"),
					huh.NewOption("Attestation — manually verified by assessor", "attestation"),
					huh.NewOption("False Positive — scanner incorrectly identified finding", "falsePositive"),
					huh.NewOption("Risk Adjustment — impact score adjusted (prompts for value)", "riskAdjustment"),
					huh.NewOption("Operational Requirement — cannot remediate due to mission need", "operationalRequirement"),
					huh.NewOption("POA&M — remediation planned (no status change)", "poam"),
					huh.NewOption("Inherited — control provided by another component/system", "inherited"),
				).
				Value(&amendType),
			huh.NewText().
				Title("Reason").
				Placeholder("Explain why this amendment is appropriate...").
				Value(&reason).
				Validate(func(s string) error {
					if len(s) < 5 { //nolint:mnd // minimum reason length
						return fmt.Errorf("reason must be at least 5 characters")
					}
					return nil
				}),
			huh.NewInput().
				Title("Expiration (30d, 3m, 6m, 1y, or YYYY-MM-DD)").
				Placeholder("6m").
				Value(&expiresInput).
				Validate(validateExpiryInput),
			huh.NewInput().
				Title("Approver email or identifier").
				Placeholder("issm@acme.com").
				Value(&approverEmail).
				Validate(func(s string) error {
					if len(s) < 3 { //nolint:mnd // minimum approver length
						return fmt.Errorf("approver must be at least 3 characters")
					}
					return nil
				}),
		),
	).WithKeyMap(amendKeyMap())

	if err := form.Run(); err != nil {
		if errors.Is(err, huh.ErrUserAborted) {
			return nil, nil
		}
		return nil, fmt.Errorf("form cancelled: %w", err)
	}

	expiresDate, _ := parseExpiryInput(expiresInput, time.Now()) // already validated

	ov := &amendOverride{
		RequirementID: reqID,
		AmendType:     amendType,
		Reason:        reason,
		ExpiresAt:     expiresDate,
		Approver:      approverEmail,
	}

	// Prompt for impact value when riskAdjustment is selected
	if amendType == "riskAdjustment" {
		impactVal, err := collectImpactValue(reqID)
		if err != nil {
			return nil, err
		}
		if impactVal == nil {
			return nil, nil // user cancelled
		}
		ov.Impact = impactVal
	}

	return ov, nil
}

// collectImpactValue prompts for an impact override value (0.0–1.0).
func collectImpactValue(reqID string) (*float64, error) {
	var impactInput string
	form := huh.NewForm(
		huh.NewGroup(
			huh.NewInput().
				Title(fmt.Sprintf("Adjusted impact score for %s (0.0–1.0)", reqID)).
				Placeholder("0.3").
				Value(&impactInput).
				Validate(func(s string) error {
					v, err := strconv.ParseFloat(strings.TrimSpace(s), 64)
					if err != nil {
						return fmt.Errorf("must be a number between 0.0 and 1.0")
					}
					if v < 0 || v > 1 {
						return fmt.Errorf("must be between 0.0 and 1.0")
					}
					return nil
				}),
		),
	).WithKeyMap(amendKeyMap())

	if err := form.Run(); err != nil {
		if errors.Is(err, huh.ErrUserAborted) {
			return nil, nil
		}
		return nil, fmt.Errorf("form cancelled: %w", err)
	}

	val, _ := strconv.ParseFloat(strings.TrimSpace(impactInput), 64) // already validated
	return &val, nil
}

// askAddAnother prompts whether to add another amendment.
func askAddAnother() (bool, error) {
	var another bool
	form := huh.NewForm(
		huh.NewGroup(
			huh.NewConfirm().
				Title("Add another amendment?").
				Affirmative("Yes").
				Negative("No, finish").
				Value(&another),
		),
	).WithKeyMap(amendKeyMap())

	if err := form.Run(); err != nil {
		if errors.Is(err, huh.ErrUserAborted) {
			return false, nil
		}
		return false, fmt.Errorf("form cancelled: %w", err)
	}
	return another, nil
}

// --- Expiry date parsing ---

// validateExpiryInput validates that the input is a valid relative duration or future date.
func validateExpiryInput(s string) error {
	now := time.Now()
	date, err := parseExpiryInput(s, now)
	if err != nil {
		return err
	}
	parsed, _ := time.Parse("2006-01-02", date)
	if !parsed.After(now) {
		return fmt.Errorf("expiration date must be in the future")
	}
	return nil
}

// parseExpiryInput converts a relative duration (30d, 3m, 6m, 1y) or absolute date
// (YYYY-MM-DD) to an absolute YYYY-MM-DD string. The now argument is the anchor
// for relative durations — pass time.Now() at runtime; tests pass a fixed clock.
func parseExpiryInput(input string, now time.Time) (string, error) {
	input = strings.TrimSpace(input)
	if input == "" {
		return "", fmt.Errorf("expiration is required")
	}

	// Try absolute date first
	if _, err := time.Parse("2006-01-02", input); err == nil {
		return input, nil
	}

	// Try relative duration: Nd, Nm, Ny
	if len(input) < 2 {
		return "", fmt.Errorf("invalid format: use 30d, 3m, 1y, or YYYY-MM-DD")
	}

	unit := input[len(input)-1]
	numStr := input[:len(input)-1]
	num, err := strconv.Atoi(numStr)
	if err != nil || num <= 0 {
		return "", fmt.Errorf("invalid format: use 30d, 3m, 1y, or YYYY-MM-DD")
	}

	var target time.Time
	switch unit {
	case 'd':
		target = now.AddDate(0, 0, num)
	case 'm':
		target = now.AddDate(0, num, 0)
	case 'y':
		target = now.AddDate(num, 0, 0)
	default:
		return "", fmt.Errorf("invalid unit %q: use d (days), m (months), or y (years)", string(unit))
	}

	return target.Format("2006-01-02"), nil
}

// --- Requirement extraction ---

// extractAllRequirements returns all requirements across all baselines with their status.
func extractAllRequirements(doc map[string]interface{}) []requirementInfo {
	var results []requirementInfo
	baselines, _ := doc["baselines"].([]interface{})

	for _, bRaw := range baselines {
		b, ok := bRaw.(map[string]interface{})
		if !ok {
			continue
		}
		baselineName, _ := b["name"].(string)
		reqs, _ := b["requirements"].([]interface{})

		for _, rRaw := range reqs {
			r, ok := rRaw.(map[string]interface{})
			if !ok {
				continue
			}

			id, _ := r["id"].(string)
			title := id
			if t, ok := r["title"].(string); ok && t != "" {
				title = t
			}
			impact := 0.5
			if imp, ok := r["impact"].(float64); ok {
				impact = imp
			}

			status := determineRequirementStatus(r)

			info := requirementInfo{
				ID:       id,
				Title:    title,
				Status:   status,
				Impact:   impact,
				Baseline: baselineName,
			}
			if cvssArr, ok := r["cvss"].([]interface{}); ok && len(cvssArr) > 0 {
				info.HasCvss = true
				if first, ok := cvssArr[0].(map[string]interface{}); ok {
					info.CvssVersion, _ = first["version"].(string)
					info.CvssSource, _ = first["source"].(string)
				}
			}
			results = append(results, info)
		}
	}
	return results
}

// determineRequirementStatus rolls a requirement's result statuses up
// worst-wins via the canonical shared ordering in hdf-utilities.
func determineRequirementStatus(req map[string]interface{}) string {
	reqResults, _ := req["results"].([]interface{})
	statuses := make([]string, 0, len(reqResults))
	for _, resRaw := range reqResults {
		if res, ok := resRaw.(map[string]interface{}); ok {
			if status, ok := res["status"].(string); ok {
				statuses = append(statuses, status)
			}
		}
	}
	return hdfutil.WorstStatus(statuses)
}

// --- Document building ---

// buildAmendmentsFromOverrides creates an amendments document from per-requirement overrides.
func buildAmendmentsFromOverrides(overrides []amendOverride) map[string]interface{} {
	now := time.Now().UTC().Format(time.RFC3339)

	docs := make([]map[string]interface{}, len(overrides))
	for i, ov := range overrides {
		doc := map[string]interface{}{
			"type":          ov.AmendType,
			"requirementId": ov.RequirementID,
			"reason":        ov.Reason,
			"appliedBy": map[string]interface{}{
				"type":       identityType(ov.Approver),
				"identifier": ov.Approver,
			},
			"appliedAt": now,
			"expiresAt": ov.ExpiresAt + "T23:59:59Z",
		}
		// Only set status if the amendment type changes status
		if status := amendTypeToStatus(ov.AmendType); status != "" {
			doc["status"] = status
		}
		// Set impact override if provided
		if ov.Impact != nil {
			doc["impact"] = map[string]interface{}{"value": *ov.Impact}
		}
		docs[i] = doc
	}

	// Derive name from most common amendment type
	typeCounts := make(map[string]int)
	for _, ov := range overrides {
		typeCounts[ov.AmendType]++
	}
	dominantType := overrides[0].AmendType
	for t, c := range typeCounts {
		if c > typeCounts[dominantType] {
			dominantType = t
		}
	}

	return map[string]interface{}{
		"name":      fmt.Sprintf("%ss-%s", dominantType, time.Now().Format("2006-01-02")),
		"overrides": docs,
	}
}

// identityType returns "email" if the string contains @, otherwise "simple".
func identityType(s string) string {
	if strings.Contains(s, "@") {
		return identityEmail
	}
	return identitySimple
}

// amendTypeToStatus returns the default status for an amendment type, or "" if
// no status should be emitted. The schema rule on Standalone_Override is
// type-conditional: when type is "operationalRequirement", neither status nor
// impact may be set (documentation-only); for all other types, at least one of
// status or impact must be set.
func amendTypeToStatus(amendType string) string {
	switch amendType {
	case "waiver", "attestation":
		return "passed"
	case "falsePositive", "inherited":
		return statusNotApplicable
	case "poam":
		return "failed" // Remediation tracked; finding remains open
	case "riskAdjustment", "operationalRequirement":
		return "" // riskAdjustment: impact-only. operationalRequirement: documentation-only.
	default:
		return ""
	}
}

// --- Output ---

// writeAmendmentsOutput serializes and writes the amendments document.
func writeAmendmentsOutput(amendments map[string]interface{}, outputPath string, count int, amendType string) error {
	output, err := json.MarshalIndent(amendments, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to serialize amendments: %w", err)
	}

	if outputPath == "" {
		fmt.Println(string(output))
		return nil
	}

	if err := os.WriteFile(outputPath, output, 0o600); err != nil { // #nosec G703 -- CLI writes user path
		return fmt.Errorf("failed to write amendments: %w", err)
	}
	fmt.Fprintf(os.Stderr, "Created %s with %d amendments (%s)\n", outputPath, count, amendType)
	return nil
}

func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}
