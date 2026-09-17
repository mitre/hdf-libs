package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	hdfengine "github.com/mitre/hdf-libs/hdf-engine/go/v3"
	hdfutil "github.com/mitre/hdf-libs/hdf-utilities/go/v3"
	validators "github.com/mitre/hdf-libs/hdf-validators/go/v3"
	"github.com/spf13/cobra"
)

// NewMergeCmd creates the merge command: several results documents in, one
// multi-baseline results document out (ADR-0016). The command is I/O only —
// reading, type-checking, writing — and the merge itself is the shared
// hdf-engine Merge that the MCP's hdf_merge and hdf_aggregate also use.
func NewMergeCmd() *cobra.Command {
	var outputPath string

	cmd := &cobra.Command{
		Use:   "merge <results-file> [results-file...] [flags]",
		Short: "Merge several results documents into one multi-baseline document",
		Long: `Combine results documents from several scanners into ONE HDF results
document, one baseline per input baseline, so a single hdf query, hdf_compliance
or hdf_query call can answer a question across every scanner at once.

Each baseline is renamed <tool>/<original name> (tool = the input's root
tool.name, else generator.name, else doc<N>), and carries the labels
  tool, toolVersion (when the input has one), sourceDocument
so hdf_compliance groupBy=baseline (or groupBy=tool) and hdf query
--baseline '<tool>/*' select one scanner's findings. Requirements are never
deduplicated or re-keyed. The merged root records generator hdf-merge, no
single tool, the latest input timestamp, the union of components, and each
input's own root provenance verbatim under extensions["hdf-merge"].sources[].

Warnings (a baseline name that still collides after prefixing, a provenance
label that replaced one already present) are printed to stderr; the merge
still succeeds. Output is byte-reproducible for the same inputs in the same
order. Only results documents are accepted.

Do not export a merged document to formats that assume one tool per document
(XCCDF, ECS/Splunk): they would attribute every finding to the first baseline's
tool. See dev-docs/adr-0016-multi-scanner-results-merge.md.

Examples:
  hdf merge gosec.hdf.json zap.hdf.json grype.hdf.json -o system.hdf.json
  hdf merge scans/*.hdf.json -o system.hdf.json --json   # summary on stdout
  hdf merge a.hdf.json b.hdf.json                        # document on stdout`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			files, err := expandGlobs(args)
			if err != nil {
				return err
			}
			force, _ := cmd.Flags().GetBool("force")
			return runMerge(files, outputPath, force)
		},
	}

	cmd.Flags().StringVarP(&outputPath, "output", "o", "", "Output file (default: stdout)")
	cmd.Flags().BoolP("force", "f", false, "Allow overwriting an input file with output")
	return cmd
}

// mergeSummary is the --json report: counts and integrity of the written
// document, and the engine's warnings — never the document body.
type mergeSummary struct {
	Output       string                   `json:"output"`
	Baselines    int                      `json:"baselines"`
	Requirements int                      `json:"requirements"`
	Components   int                      `json:"components"`
	Sha256       string                   `json:"sha256"`
	Warnings     []hdfengine.MergeWarning `json:"warnings"`
}

// runMerge loads every input, refuses anything that is not a results document
// (the engine API is typed on results; the type check lives here, ADR-0016
// Revision), merges, validates the result, and writes it — to stdout, or
// atomically to the output path.
func runMerge(files []string, outputPath string, force bool) error {
	writingToFile := outputPath != "" && outputPath != "-"

	// hdf convert's convention: an existing output is overwritten; writing
	// over one of the INPUTS needs --force.
	if writingToFile && !force {
		for _, in := range files {
			if in == "-" {
				continue
			}
			if err := checkOutputOverwritesInput(in, outputPath); err != nil {
				return err
			}
		}
	}

	sources := make([]hdfengine.MergeSource, 0, len(files))
	for _, path := range files {
		data, err := readInputFile(path)
		if err != nil {
			return err
		}
		if _, err := requireDocumentType(data, []string{"results"}, "hdf merge"); err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		doc, err := parseHDFResults(data)
		if err != nil {
			return fmt.Errorf("%s: failed to parse HDF file: %w", path, err)
		}
		sources = append(sources, hdfengine.MergeSource{Name: filepath.Base(path), Doc: doc})
	}

	merged, warnings, err := hdfengine.Merge(sources)
	if err != nil {
		return err
	}
	for _, w := range warnings {
		fmt.Fprintln(os.Stderr, formatMergeWarning(w))
	}

	out, err := json.MarshalIndent(merged, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to serialize merged document: %w", err)
	}
	out = append(out, '\n')
	if vr := validators.ValidateResults(out); !vr.Valid {
		return fmt.Errorf("merged document does not validate as hdf-results (engine defect, nothing written): %s", vr.Error())
	}

	if !writingToFile {
		_, err := os.Stdout.Write(out)
		return err
	}
	if err := writeFileAtomic(outputPath, out); err != nil {
		return err
	}
	if jsonOutput {
		reqs := 0
		for i := range merged.Baselines {
			reqs += len(merged.Baselines[i].Requirements)
		}
		if warnings == nil {
			warnings = []hdfengine.MergeWarning{}
		}
		summary, err := json.Marshal(mergeSummary{
			Output: outputPath, Baselines: len(merged.Baselines), Requirements: reqs,
			Components: len(merged.Components), Sha256: hdfutil.SHA256Hex(out), Warnings: warnings,
		})
		if err != nil {
			return err
		}
		fmt.Println(string(summary))
	}
	return nil
}

// formatMergeWarning renders one engine warning for stderr.
func formatMergeWarning(w hdfengine.MergeWarning) string {
	positions := make([]string, len(w.Indices))
	for i, idx := range w.Indices {
		positions[i] = fmt.Sprint(idx)
	}
	switch w.Kind {
	case hdfengine.WarnDuplicateBaselineName:
		return fmt.Sprintf("warning: %s: %q at baselines %s — both kept; name-keyed consumers (hdf diff, baselineRef) cannot tell them apart",
			w.Kind, w.Name, strings.Join(positions, ","))
	case hdfengine.WarnLabelOverwritten:
		return fmt.Sprintf("warning: %s: label %q on baseline %s (%q) replaced by the merge's provenance",
			w.Kind, w.Label, strings.Join(positions, ","), w.Name)
	default:
		return fmt.Sprintf("warning: %s: %q at baselines %s", w.Kind, w.Name, strings.Join(positions, ","))
	}
}

// writeFileAtomic writes data to path through a temporary file in the same
// directory and a rename, so a failure part-way never leaves a truncated
// document behind and an existing file is replaced in one step.
func writeFileAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".*.tmp")
	if err != nil {
		return fmt.Errorf("failed to create temporary file in %s: %w", dir, err)
	}
	tmpPath := tmp.Name()
	cleanup := func() { _ = os.Remove(tmpPath) }
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		cleanup()
		return fmt.Errorf("failed to write %s: %w", path, err)
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return fmt.Errorf("failed to write %s: %w", path, err)
	}
	if err := os.Chmod(tmpPath, 0o600); err != nil {
		cleanup()
		return fmt.Errorf("failed to set permissions on %s: %w", path, err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		cleanup()
		return fmt.Errorf("failed to write %s: %w", path, err)
	}
	return nil
}
