package cmd

import (
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"
)

// NewPassthroughCmd creates `hdf passthrough`: read/write the v3-native
// extensions.passthrough provenance element, so a pipeline standardized on hdf
// can stamp its own attribution without falling back to saf-cli. Writes MERGE by
// default (a sibling top-level key another tool wrote survives); --replace
// overwrites the whole element.
func NewPassthroughCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "passthrough",
		Short: "Read or write the extensions.passthrough provenance element",
		Long: "Read or write the v3-native extensions.passthrough element that carries " +
			"document provenance, without installing saf-cli. Writes merge by default — a " +
			"sibling key written by another tool survives — so an audit trail is never " +
			"silently clobbered; use --replace to overwrite the whole element.",
	}
	cmd.AddCommand(newPassthroughGetCmd(), newPassthroughSetCmd())
	return cmd
}

func newPassthroughGetCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "get <file>",
		Short: "Print the extensions.passthrough element as JSON",
		Args:  cobra.ExactArgs(1),
		RunE:  runPassthroughGet,
	}
}

func newPassthroughSetCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "set <file>",
		Short: "Merge (or --replace) a JSON object into extensions.passthrough",
		Args:  cobra.ExactArgs(1),
		RunE:  runPassthroughSet,
	}
	cmd.Flags().String("data", "", "Inline JSON object to write (mutually exclusive with --file)")
	cmd.Flags().String("file", "", "Path to a JSON object file to write (mutually exclusive with --data)")
	cmd.Flags().Bool("replace", false, "Replace the whole passthrough element instead of merging its top-level keys")
	cmd.Flags().StringP("output", "o", "", "Output file (default: overwrite the input file in place)")
	return cmd
}

func runPassthroughGet(_ *cobra.Command, args []string) error {
	data, err := readInputFile(args[0])
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}
	pt, err := extractSubMap(data, "extensions", "passthrough")
	if err != nil {
		return err
	}
	if pt == nil {
		return nil // absent → nothing to print
	}
	out, err := json.MarshalIndent(pt, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(out))
	return nil
}

func runPassthroughSet(cmd *cobra.Command, args []string) error {
	filePath := args[0]
	dataFlag, _ := cmd.Flags().GetString("data")
	fileFlag, _ := cmd.Flags().GetString("file")
	replace, _ := cmd.Flags().GetBool("replace")
	outputPath, _ := cmd.Flags().GetString("output")

	obj, err := attributionInputObject(dataFlag, fileFlag)
	if err != nil {
		return err
	}

	data, err := readInputFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		return fmt.Errorf("input is not a JSON object: %w", err)
	}

	ext, _ := doc["extensions"].(map[string]any)
	if ext == nil {
		ext = map[string]any{}
	}
	if replace {
		ext["passthrough"] = obj
	} else {
		existing, _ := ext["passthrough"].(map[string]any)
		if existing == nil {
			existing = map[string]any{}
		}
		for k, v := range obj { // shallow top-level merge: sibling keys survive
			existing[k] = v
		}
		ext["passthrough"] = existing
	}
	doc["extensions"] = ext

	updated, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}

	target := filePath
	if outputPath != "" {
		target = outputPath
	}
	return writeValidatedHDFOutput(cmd, updated, target)
}
