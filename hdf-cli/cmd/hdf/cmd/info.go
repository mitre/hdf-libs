package cmd

import (
	"encoding/json"
	"fmt"
	"strings"

	hdf "github.com/mitre/hdf-cli/pkg/hdf"
	"github.com/spf13/cobra"
)

// NewInfoCmd creates a new info command with fresh state.
func NewInfoCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "info <file>",
		Short: "Display summary information about an HDF file",
		Long: `Display summary information about an HDF results file including:
- Generator tool and version
- Platform information
- Profile/baseline names and versions
- Target information
- Assessment timestamp

Examples:
  hdf info results.json
  hdf info results.json --json`,
		Args: cobra.MaximumNArgs(1),
		RunE: runInfo,
	}
}

func runInfo(_ *cobra.Command, args []string) error {
	var filename string
	if len(args) == 0 || args[0] == "-" {
		filename = "<stdin>"
	} else {
		filename = args[0]
	}

	data, err := readInputFile(filename)
	if err != nil {
		printError(err.Error())
		return err
	}

	results, err := parseHDFResults(data)
	if err != nil {
		printError(fmt.Sprintf("Failed to parse HDF file: %v", err))
		return err
	}

	if jsonOutput {
		return outputInfoJSON(results, filename)
	}

	return outputInfoHuman(results, filename)
}

func outputInfoJSON(results hdf.HdfResults, filename string) error {
	info := map[string]interface{}{
		"file":    filename,
		"version": results.Version,
		"platform": map[string]string{
			"name":    results.Platform.Name,
			"release": results.Platform.Release,
		},
	}

	if results.Generator != nil {
		info["generator"] = map[string]string{
			"name":    results.Generator.Name,
			"version": results.Generator.Version,
		}
	}

	if results.Timestamp != nil {
		info["timestamp"] = results.Timestamp.Format("2006-01-02T15:04:05Z07:00")
	}

	if results.ID != nil {
		info["id"] = *results.ID
	}

	// Profiles
	profiles := make([]map[string]interface{}, 0, len(results.Profiles))
	for _, p := range results.Profiles {
		profile := map[string]interface{}{
			"name":          p.Name,
			"control_count": len(p.Controls),
		}
		if p.Title != nil {
			profile["title"] = *p.Title
		}
		if p.Version != nil {
			profile["version"] = *p.Version
		}
		profiles = append(profiles, profile)
	}
	info["profiles"] = profiles

	// Targets
	if len(results.Targets) > 0 {
		targets := make([]map[string]interface{}, 0, len(results.Targets))
		for _, t := range results.Targets {
			target := map[string]interface{}{
				"name": t.Name,
				"type": string(t.Type),
			}
			targets = append(targets, target)
		}
		info["targets"] = targets
	}

	output, err := json.MarshalIndent(info, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(output))
	return nil
}

func outputInfoHuman(results hdf.HdfResults, filename string) error {
	fmt.Printf("File: %s\n", sanitizeOutput(filename))
	fmt.Printf("Version: %s\n", sanitizeOutput(results.Version))
	fmt.Println()

	// Generator
	if results.Generator != nil {
		fmt.Printf("Generator: %s %s\n", sanitizeOutput(results.Generator.Name), sanitizeOutput(results.Generator.Version))
	}

	// Timestamp
	if results.Timestamp != nil {
		fmt.Printf("Timestamp: %s\n", results.Timestamp.Format("2006-01-02 15:04:05 MST"))
	}
	fmt.Println()

	// Platform
	fmt.Println("Platform:")
	fmt.Printf("  Name:    %s\n", sanitizeOutput(results.Platform.Name))
	fmt.Printf("  Release: %s\n", sanitizeOutput(results.Platform.Release))
	fmt.Println()

	// Profiles
	fmt.Printf("Profiles: %d\n", len(results.Profiles))
	for _, p := range results.Profiles {
		name := p.Name
		if p.Title != nil && *p.Title != "" {
			name = *p.Title
		}
		version := ""
		if p.Version != nil {
			version = fmt.Sprintf(" (v%s)", sanitizeOutput(*p.Version))
		}
		fmt.Printf("  - %s%s: %d controls\n", sanitizeOutput(name), version, len(p.Controls))
	}

	// Targets
	if len(results.Targets) > 0 {
		fmt.Println()
		fmt.Printf("Targets: %d\n", len(results.Targets))
		for _, t := range results.Targets {
			details := []string{}
			if t.FQDN != nil {
				details = append(details, sanitizeOutput(*t.FQDN))
			} else if t.IPAddress != nil {
				details = append(details, sanitizeOutput(*t.IPAddress))
			}
			detailStr := ""
			if len(details) > 0 {
				detailStr = fmt.Sprintf(" (%s)", strings.Join(details, ", "))
			}
			fmt.Printf("  - [%s] %s%s\n", t.Type, sanitizeOutput(t.Name), detailStr)
		}
	}

	return nil
}
