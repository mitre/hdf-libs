package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

// NewEvidenceCmd creates the evidence command group with info subcommand.
func NewEvidenceCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "evidence",
		Short: "Work with HDF evidence package documents",
		Long: `Commands for viewing and managing HDF evidence package documents.

An HDF evidence package bundles references to all HDF documents for audit,
authorization, and compliance review.

Examples:
  hdf evidence info q1-2026.hdf-evidence-package.json
  hdf evidence info q1-2026.hdf-evidence-package.json --json`,
	}

	cmd.AddCommand(newEvidenceInfoCmd())
	cmd.AddCommand(newEvidenceBuildCmd())
	cmd.AddCommand(newEvidenceVerifyCmd())
	cmd.AddCommand(newEvidenceExportCmd())
	cmd.AddCommand(newEvidenceSetCmd())
	cmd.AddCommand(newEvidenceAddEvidenceCmd())

	return cmd
}

func newEvidenceInfoCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "info <file>",
		Short: "Display summary information about an HDF evidence package",
		Long: `Display summary information about an HDF evidence package including:
- Package name, preparer, timestamp, and system reference
- Contents with document types and checksum status
- Completeness check summary

Examples:
  hdf evidence info q1-2026.hdf-evidence-package.json
  hdf evidence info q1-2026.hdf-evidence-package.json --json`,
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			return runDocInfo(args[0], "hdf evidence info", []string{"evidence-package"}, outputEvidenceInfoHuman)
		},
	}
}

func outputEvidenceInfoHuman(doc map[string]interface{}) error {
	// Package name
	if name, ok := doc["name"].(string); ok {
		fmt.Printf("Evidence Package: %s\n", sanitizeOutput(name))
	}

	// Prepared by
	if preparedBy, ok := doc["preparedBy"].(map[string]interface{}); ok {
		if id, ok := preparedBy["identifier"].(string); ok {
			fmt.Printf("Prepared by: %s\n", sanitizeOutput(id))
		}
	}

	// Prepared at
	if preparedAt, ok := doc["preparedAt"].(string); ok {
		fmt.Printf("Prepared at: %s\n", sanitizeOutput(preparedAt))
	}

	// System reference
	if sysRef, ok := doc["systemRef"].(string); ok {
		fmt.Printf("System: %s\n", sanitizeOutput(sysRef))
	}

	// Contents
	if contents, ok := doc["contents"].([]interface{}); ok && len(contents) > 0 {
		fmt.Printf("\nContents (%d):\n", len(contents))
		for _, cRaw := range contents {
			entry, ok := cRaw.(map[string]interface{})
			if !ok {
				continue
			}
			docType, _ := entry["type"].(string)
			uri, _ := entry["uri"].(string)

			checksumStr := ""
			if _, hasChecksum := entry["checksum"]; hasChecksum {
				checksumStr = "  \u2713 checksum"
			}

			fmt.Printf("  %-16s %s%s\n", sanitizeOutput(docType), sanitizeOutput(uri), checksumStr)
		}
	}

	// External evidence (native log/telemetry corpora carried by reference)
	if ext, ok := doc["externalEvidence"].([]interface{}); ok && len(ext) > 0 {
		fmt.Printf("\nExternal Evidence (%d):\n", len(ext))
		for _, eRaw := range ext {
			entry, ok := eRaw.(map[string]interface{})
			if !ok {
				continue
			}
			format, _ := entry["format"].(string)
			uri, _ := entry["uri"].(string)

			checksumStr := ""
			if _, hasChecksum := entry["checksum"]; hasChecksum {
				checksumStr = "  ✓ checksum"
			}

			fmt.Printf("  %-16s %s%s\n", sanitizeOutput(format), sanitizeOutput(uri), checksumStr)
		}
	}

	// Completeness check
	if cc, ok := doc["completenessCheck"].(map[string]interface{}); ok {
		fmt.Printf("\nCompleteness:\n")

		if v, ok := cc["allBaselinesAssessed"].(bool); ok {
			fmt.Printf("  All baselines assessed: %s\n", boolYesNo(v))
		}
		if v, ok := cc["allComponentsCovered"].(bool); ok {
			fmt.Printf("  All components covered: %s\n", boolYesNo(v))
		}
		if v, ok := cc["expiredWaivers"].(float64); ok {
			fmt.Printf("  Expired waivers: %d\n", int64(v))
		}
		if v, ok := cc["unresolvedPoams"].(float64); ok {
			fmt.Printf("  Unresolved POA&Ms: %d\n", int64(v))
		}
		if v, ok := cc["compliancePercent"].(float64); ok {
			fmt.Printf("  Compliance: %.0f%%\n", v)
		}
	}

	return nil
}

// boolYesNo returns "yes" or "no" for a boolean value.
func boolYesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}
