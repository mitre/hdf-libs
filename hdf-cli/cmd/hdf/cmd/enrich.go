package cmd

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/mitre/hdf-libs/hdf-cli/v3/internal/atomicfile"
	shared "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go"
	"github.com/spf13/cobra"
)

// NewEnrichCmd creates the `enrich` command: the type gate and the attachment
// report live here, the enrichment itself in the shared pass. Everything
// user-facing is described in Long, not restated here.
func NewEnrichCmd() *cobra.Command {
	var (
		fromFormat    string
		outputPath    string
		recomputeCVSS bool
	)

	cmd := &cobra.Command{
		Use:   "enrich <document> <source> [flags]",
		Short: "Enrich an HDF document with external context (e.g. a STIX bundle)",
		Long: `Overlay an enrichment source onto an HDF document, attaching inert
externalReferences[] to it.

Accepts the document types that declare externalReferences and can carry
enrichment: results, system, plan and comparison. A results document is matched
by CVE, so a reference lands on the findings that cite it and anything unmatched
lands at the document root. The other three have no findings to match on, so
every reference lands at the document root — nothing is invented to hang one
from. An
evidence-package also declares the field, but 'hdf evidence add-reference' owns
that array on that type, so enrich refuses one and says so. A baseline and an
amendments document declare no externalReferences at all and are refused.

Enrichment is INFORMATIONAL by default: it adds context and never changes a
finding's status or impact. --recompute-cvss additionally authors an auditable
CVSS riskAdjustment on a finding whose STIX object shows active exploitation and
that carries a CVSS 3.1 base vector (Exploit Maturity E:H recompute). It is
results-only: a posture change needs requirements to apply to, and the other
types have none. The source format is auto-detected; assert it with --from.
Supported sources: stix.

Examples:
  hdf enrich results.json log4shell-bundle.json -o enriched.json
  hdf enrich system.json cti-bundle.json -o enriched.json     # attaches at the root
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

func runEnrich(docPath, sourcePath, fromFormat, outputPath string, recomputeCVSS bool) error {
	// readInputFile is the security-gated pipeline: --max-size pre-read
	// enforcement, symlink policy, regular-file check, BOM stripping.
	docData, err := readInputFile(docPath)
	if err != nil {
		return fmt.Errorf("failed to read the document to enrich: %w", err)
	}
	sourceData, err := readInputFile(sourcePath)
	if err != nil {
		return fmt.Errorf("failed to read source file: %w", err)
	}

	docType, err := enrichableDocumentType(docData)
	if err != nil {
		return err
	}
	// The detected type drives validation, so each document is checked against its
	// OWN schema rather than always against hdf-results.
	if _, validateErr := loadAndValidateHDFDoc(docData, docType); validateErr != nil {
		return fmt.Errorf("not a valid hdf-%s document: %w", docType, validateErr)
	}
	// A posture change needs requirements to apply to, and only results has them.
	if recomputeCVSS && docType != "results" {
		return fmt.Errorf("--recompute-cvss is results-only: it authors a riskAdjustment on a finding, "+
			"and an hdf-%s document has no findings to apply one to; enrich it without the flag to attach "+
			"context at its root", docType)
	}

	source, err := resolveEnrichmentSource(fromFormat, sourceData)
	if err != nil {
		return err
	}
	printDebug("Enrichment source: %s", source)

	before := externalReferenceCounts(docData)

	enriched, err := shared.EnrichStix(docData, sourceData, shared.EnrichOptions{
		RecomputeCVSS: recomputeCVSS,
		MaxSize:       int(getMaxFileSize()),
	})
	if err != nil {
		return fmt.Errorf("enrich failed: %w", err)
	}
	reportEnrichment(docType, before, externalReferenceCounts(enriched))

	if outputPath != "" {
		if len(enriched) > 0 && enriched[len(enriched)-1] != '\n' {
			enriched = append(enriched, '\n')
		}
		if writeErr := atomicfile.WriteFile(outputPath, enriched, 0o600); writeErr != nil {
			return fmt.Errorf("failed to write output file: %w", writeErr)
		}
		fmt.Fprintf(os.Stderr, "Enriched output written to %s\n", outputPath)
		return nil
	}

	fmt.Println(string(enriched))
	return nil
}

// enrichableDocumentType names the document types enrich accepts, and refuses the
// rest with a reason rather than a bare no. The four accepted types are exactly
// those that declare externalReferences AND are enrichment targets:
// hdf-evidence-package declares the field too, but `hdf evidence add-reference`
// owns that array on that type, and two commands writing one field on one document
// is an ambiguity worth refusing rather than resolving at runtime.
func enrichableDocumentType(data []byte) (string, error) {
	switch docType := detectHDFDocumentType(data); docType {
	case "results", "system", "plan", "comparison":
		return docType, nil
	case "evidence-package":
		return "", fmt.Errorf("hdf enrich does not write an evidence package's externalReferences[]; " +
			"use `hdf evidence add-reference`, which owns that array and records a checksum for a local href")
	case "baseline", "amendments":
		return "", fmt.Errorf("an hdf-%s document declares no externalReferences[], so there is nowhere to "+
			"attach enrichment; enrich the results document the %s applies to instead", docType, docType)
	case "":
		return "", fmt.Errorf("input is not a recognized HDF document (no top-level discriminator key matched)")
	default:
		return "", fmt.Errorf("hdf enrich cannot enrich an hdf-%s document; it accepts results, system, "+
			"plan and comparison", docType)
	}
}

// externalReferenceCounts totals the externalReferences[] on the document root and
// across every requirement, so the command can report what the pass actually
// attached rather than asserting that it attached something.
func externalReferenceCounts(data []byte) [2]int {
	var root, findings int
	var doc map[string]interface{}
	if json.Unmarshal(data, &doc) != nil {
		return [2]int{}
	}
	if refs, ok := doc["externalReferences"].([]interface{}); ok {
		root = len(refs)
	}
	baselines, _ := doc["baselines"].([]interface{})
	for _, b := range baselines {
		bm, ok := b.(map[string]interface{})
		if !ok {
			continue
		}
		reqs, _ := bm["requirements"].([]interface{})
		for _, r := range reqs {
			rm, ok := r.(map[string]interface{})
			if !ok {
				continue
			}
			if refs, ok := rm["externalReferences"].([]interface{}); ok {
				findings += len(refs)
			}
		}
	}
	return [2]int{root, findings}
}

// reportEnrichment says how many references were attached and where. A document
// with no findings to match on gets everything at its root, and saying so is what
// distinguishes "nothing matched" from "nothing was attached".
func reportEnrichment(docType string, before, after [2]int) {
	rootAdded, findingsAdded := after[0]-before[0], after[1]-before[1]
	switch {
	case rootAdded == 0 && findingsAdded == 0:
		fmt.Fprintf(os.Stderr, "No references attached: the source carried nothing to attach to an hdf-%s document.\n", docType)
	case findingsAdded == 0:
		fmt.Fprintf(os.Stderr, "Attached %d reference(s) at the document root.\n", rootAdded)
	case rootAdded == 0:
		fmt.Fprintf(os.Stderr, "Attached %d reference(s) to findings matched by CVE.\n", findingsAdded)
	default:
		fmt.Fprintf(os.Stderr, "Attached %d reference(s) to findings matched by CVE and %d at the document root.\n",
			findingsAdded, rootAdded)
	}
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
