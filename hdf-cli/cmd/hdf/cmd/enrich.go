package cmd

import (
	"fmt"
	"os"

	shared "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go"
	"github.com/spf13/cobra"
)

// NewEnrichCmd creates the `enrich` command: overlay an enrichment source (a
// STIX 2.1 bundle today) onto an HDF results document. Positional parity with
// `convert` — <results> <source> — with `--from` as the optional format
// assertion. A thin wrapper over the shared enrich pass; no logic lives here.
func NewEnrichCmd() *cobra.Command {
	var (
		fromFormat    string
		outputPath    string
		recomputeCVSS bool
	)

	cmd := &cobra.Command{
		Use:   "enrich <results> <source> [flags]",
		Short: "Enrich HDF results with external context (e.g. a STIX bundle)",
		Long: `Overlay an enrichment source onto an HDF results document, attaching inert
externalReferences[] to findings (matched by CVE) or to the results root.

Enrichment is INFORMATIONAL by default: it adds context and never changes a
finding's status or impact. --recompute-cvss additionally authors an auditable
CVSS riskAdjustment on a finding whose STIX object shows active exploitation and
that carries a CVSS 3.1 base vector (Exploit Maturity E:H recompute). The source
format is auto-detected; assert it with --from. Supported sources: stix.

Examples:
  hdf enrich results.json log4shell-bundle.json -o enriched.json
  hdf enrich results.json feed.json --from stix -o enriched.json
  hdf enrich results.json bundle.json --recompute-cvss -o enriched.json  # + CVSS E:H recompute
  hdf enrich results.json bundle.json                       # write to stdout`,
		Args: cobra.ExactArgs(2),
		RunE: func(_ *cobra.Command, args []string) error {
			return runEnrich(args[0], args[1], fromFormat, outputPath, recomputeCVSS)
		},
	}

	cmd.Flags().StringVar(&fromFormat, "from", "", "Enrichment source format (auto-detected if omitted; e.g. stix)")
	cmd.Flags().StringVarP(&outputPath, "output", "o", "", "Output file (default: stdout)")
	cmd.Flags().BoolVar(&recomputeCVSS, "recompute-cvss", false, "Also author an E:H CVSS riskAdjustment on exploited, 3.1-base-vector findings")
	return cmd
}

func runEnrich(resultsPath, sourcePath, fromFormat, outputPath string, recomputeCVSS bool) error {
	resultsData, err := os.ReadFile(resultsPath) // #nosec G304 -- CLI reads user-provided file path
	if err != nil {
		return fmt.Errorf("failed to read results file: %w", err)
	}
	sourceData, err := os.ReadFile(sourcePath) // #nosec G304 -- CLI reads user-provided file path
	if err != nil {
		return fmt.Errorf("failed to read source file: %w", err)
	}

	if _, typeErr := requireDocumentType(resultsData, []string{"results"}, "hdf enrich"); typeErr != nil {
		return typeErr
	}

	source, err := resolveEnrichmentSource(fromFormat, sourceData)
	if err != nil {
		return err
	}
	printDebug("Enrichment source: %s", source)

	enriched, err := shared.EnrichStix(resultsData, sourceData, shared.EnrichOptions{RecomputeCVSS: recomputeCVSS})
	if err != nil {
		return fmt.Errorf("enrich failed: %w", err)
	}

	if outputPath != "" {
		if len(enriched) > 0 && enriched[len(enriched)-1] != '\n' {
			enriched = append(enriched, '\n')
		}
		if writeErr := os.WriteFile(outputPath, enriched, 0o600); writeErr != nil { // #nosec G306 G703 -- CLI intentionally writes to user-provided path
			return fmt.Errorf("failed to write output file: %w", writeErr)
		}
		fmt.Fprintf(os.Stderr, "Enriched output written to %s\n", outputPath)
		return nil
	}

	fmt.Println(string(enriched))
	return nil
}

// resolveEnrichmentSource applies the --from format assertion or auto-detects
// the enrichment source. --from is a detect-then-match assertion (never a
// force-parse): even when asserted, the source must actually look like that
// format. Returns the resolved source format.
func resolveEnrichmentSource(fromFormat string, data []byte) (string, error) {
	switch fromFormat {
	case "":
		if shared.DetectStixBundle(data) {
			return "stix", nil
		}
		return "", fmt.Errorf("could not auto-detect the enrichment source format (supported: stix); pass --from to assert it")
	case "stix":
		if !shared.DetectStixBundle(data) {
			return "", fmt.Errorf("--from stix asserted, but the source is not a STIX 2.1 bundle ({type:\"bundle\", objects:[…]})")
		}
		return "stix", nil
	default:
		return "", fmt.Errorf("unsupported enrichment source format %q (supported: stix)", fromFormat)
	}
}
