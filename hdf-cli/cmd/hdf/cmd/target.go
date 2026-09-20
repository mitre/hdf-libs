package cmd

import (
	"encoding/json"
	"fmt"

	hdfparsers "github.com/mitre/hdf-libs/hdf-parsers/go/v3"
	"github.com/spf13/cobra"
)

// NewTargetCmd creates `hdf target`: read/write the assessed-target identity
// without saf-cli. v3 has no top-level `target` element (that legacy shape is
// deprecated); the identity lives in components[]. So `set` records a
// {id,type,boundary} descriptor as the matching component by reusing the shipped
// SAF-supplement normalizer (one mapping, shared with convert/parse), and `get`
// prints the target-identity (cloudAccount) components.
func NewTargetCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "target",
		Short: "Read or write the assessed-target identity (as a v3 component)",
		Long: "Read or write the assessed target's identity without saf-cli. The legacy " +
			"top-level `target` element is deprecated in v3, where the identity is carried " +
			"in components[]; `set` records the {id,type,boundary} descriptor as the " +
			"matching component (via the same normalizer convert/parse use), and `get` " +
			"prints the cloudAccount target components.",
	}
	cmd.AddCommand(newTargetGetCmd(), newTargetSetCmd())
	return cmd
}

func newTargetGetCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "get <file>",
		Short: "Print the target-identity (cloudAccount) components as JSON",
		Args:  cobra.ExactArgs(1),
		RunE:  runTargetGet,
	}
}

func newTargetSetCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "set <file>",
		Short: "Record a target descriptor {id,type,boundary} as a v3 component",
		Args:  cobra.ExactArgs(1),
		RunE:  runTargetSet,
	}
	cmd.Flags().String("data", "", `Inline target JSON, e.g. {"id":"prod-account","type":"cloudAccount","boundary":"sparc"} (mutually exclusive with --file)`)
	cmd.Flags().String("file", "", "Path to a target JSON file (mutually exclusive with --data)")
	cmd.Flags().StringP("output", "o", "", "Output file (default: overwrite the input file in place)")
	return cmd
}

func runTargetGet(_ *cobra.Command, args []string) error {
	data, err := readInputFile(args[0])
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}
	var doc struct {
		Components []map[string]any `json:"components"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return fmt.Errorf("input is not a JSON object: %w", err)
	}
	targets := make([]map[string]any, 0)
	for _, c := range doc.Components {
		if c["type"] == "cloudAccount" {
			targets = append(targets, c)
		}
	}
	if len(targets) == 0 {
		return nil // no target-identity component to print
	}
	out, err := json.MarshalIndent(targets, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(out))
	return nil
}

func runTargetSet(cmd *cobra.Command, args []string) error {
	filePath := args[0]
	dataFlag, _ := cmd.Flags().GetString("data")
	fileFlag, _ := cmd.Flags().GetString("file")
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

	// Stamp the descriptor as the legacy target shape, then let the shipped
	// normalizer absorb it into a v3-native component (merge-not-duplicate). Its
	// deprecation warnings describe the legacy→v3 rewrite, which is exactly the
	// intended action here, so they are not surfaced.
	doc["target"] = obj
	spliced, err := json.Marshal(doc)
	if err != nil {
		return err
	}
	absorbed, _ := hdfparsers.NormalizeSAFSupplement(spliced)

	var result map[string]any
	if err := json.Unmarshal(absorbed, &result); err != nil {
		return fmt.Errorf("failed to re-read normalized output: %w", err)
	}
	// The normalizer removes the top-level target once it absorbs it into a
	// component. If it is still there, the descriptor was not recordable (e.g. an
	// unsupported type) — fail loudly rather than write a stray top-level target
	// that the Go validator's unevaluatedProperties gap would let through.
	if _, residual := result["target"]; residual {
		return fmt.Errorf(`could not record target: descriptor is not a valid v3 component — check "type" (must be a supported component type, e.g. cloudAccount, host, containerImage)`)
	}
	out, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return err
	}

	target := filePath
	if outputPath != "" {
		target = outputPath
	}
	return writeValidatedHDFOutput(cmd, out, target)
}
