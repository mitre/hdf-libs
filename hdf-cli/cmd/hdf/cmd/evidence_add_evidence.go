package cmd

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
)

type addEvidenceOpts struct {
	uri           string
	format        string
	checksum      string
	mediaType     string
	formatVersion string
	description   string
	collector     string
	recordCount   int64
	timeStart     string
	timeEnd       string
	outputPath    string
}

func newEvidenceAddEvidenceCmd() *cobra.Command {
	opts := addEvidenceOpts{recordCount: -1}

	cmd := &cobra.Command{
		Use:   "add-evidence <file> --uri <uri> --format <format> [flags]",
		Short: "Reference external native-format evidence (logs/telemetry) in an evidence package",
		Long: `Append an external evidence reference to an HDF evidence package. The referenced
artifact (an ECS/OCSF log corpus, or other native-format evidence) is carried by
reference — its URI, an integrity checksum, and a format discriminator — without
recreating the data inside HDF.

If --uri is a local file, its SHA-256 checksum is computed automatically. If --uri
is a URL (the artifact is referenced, not fetched), pass --checksum to record a
precomputed hash, or omit it. Format is an open set: reserved ecs | ocsf |
cyclonedx | spdx | raw-log, plus x- custom values (e.g. x-splunk-export for a
Splunk/Sentinel export — query-time models like CIM/ASIM have no artifact to
reference, so reference their export instead).

Examples:
  hdf evidence add-evidence pkg.json --uri logs/q1.ndjson --format ecs --collector elastic-agent
  hdf evidence add-evidence pkg.json --uri https://lake/ocsf/q1/ --format ocsf --checksum <sha256>`,
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			return runEvidenceAddEvidence(args[0], opts)
		},
	}

	cmd.Flags().StringVar(&opts.uri, "uri", "", "URI of the external evidence artifact (required)")
	cmd.Flags().StringVar(&opts.format, "format", "", "Format: ecs | ocsf | cyclonedx | spdx | raw-log | x-<custom> (required)")
	cmd.Flags().StringVar(&opts.checksum, "checksum", "", "Precomputed SHA-256 hex (for a URL/remote artifact; local files are hashed automatically)")
	cmd.Flags().StringVar(&opts.mediaType, "media-type", "", "IANA media type of the serialization (e.g. application/x-ndjson)")
	cmd.Flags().StringVar(&opts.formatVersion, "format-version", "", "Producer-declared format version (e.g. ECS 9.4.0)")
	cmd.Flags().StringVar(&opts.description, "description", "", "Human-readable description of this evidence")
	cmd.Flags().StringVar(&opts.collector, "collector", "", "Tool/pipeline that produced the corpus (e.g. aws-security-lake)")
	cmd.Flags().Int64Var(&opts.recordCount, "record-count", -1, "Approximate number of records/events in the corpus")
	cmd.Flags().StringVar(&opts.timeStart, "time-start", "", "Start of the time window the corpus covers (ISO 8601)")
	cmd.Flags().StringVar(&opts.timeEnd, "time-end", "", "End of the time window the corpus covers (ISO 8601)")
	cmd.Flags().StringVarP(&opts.outputPath, "output", "o", "", "Output file (default: overwrite input)")

	return cmd
}

func runEvidenceAddEvidence(file string, opts addEvidenceOpts) error {
	if opts.uri == "" {
		return fmt.Errorf("--uri is required")
	}
	if opts.format == "" {
		return fmt.Errorf("--format is required")
	}

	data, err := os.ReadFile(file) // #nosec G304 -- CLI reads user-provided file path
	if err != nil {
		return fmt.Errorf("failed to read evidence package: %w", err)
	}
	doc, err := loadAndValidateHDFDoc(data, "evidencePackage")
	if err != nil {
		return fmt.Errorf("evidence package %s: %w", file, err)
	}

	ref := map[string]interface{}{
		"uri":    filepath.ToSlash(opts.uri),
		"format": opts.format,
	}

	checksum, err := resolveEvidenceChecksum(opts)
	if err != nil {
		return err
	}
	if checksum != "" {
		ref["checksum"] = map[string]interface{}{"algorithm": "sha256", "value": checksum}
	}

	if opts.mediaType != "" {
		ref["mediaType"] = opts.mediaType
	}
	if opts.formatVersion != "" {
		ref["formatVersion"] = opts.formatVersion
	}
	if opts.description != "" {
		ref["description"] = opts.description
	}
	if meta := buildEvidenceMetadata(opts); meta != nil {
		ref["metadata"] = meta
	}

	existing, _ := doc["externalEvidence"].([]interface{})
	doc["externalEvidence"] = append(existing, ref)

	output, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to serialize evidence package: %w", err)
	}
	if err := validateHDFOutput(output); err != nil {
		return fmt.Errorf("evidence package failed validation before write: %w", err)
	}

	target := file
	if opts.outputPath != "" {
		target = opts.outputPath
	}
	if err := os.WriteFile(target, output, 0o600); err != nil {
		return fmt.Errorf("failed to write evidence package: %w", err)
	}
	fmt.Fprintf(os.Stderr, "Added external evidence (%s) to %s\n", opts.format, target)
	return nil
}

// resolveEvidenceChecksum returns the sha256 hex for the reference: a supplied
// value wins; otherwise a local-file URI is hashed; a URL is left unhashed.
func resolveEvidenceChecksum(opts addEvidenceOpts) (string, error) {
	if opts.checksum != "" {
		return opts.checksum, nil
	}
	// A local-path URI is hashed only when the file is actually present at attach
	// time; a URL, a directory, or a path with no local copy is left unhashed
	// (a reference-only entry, not an error).
	if fi, err := os.Stat(opts.uri); err == nil && !fi.IsDir() {
		sum, err := fileChecksumHex(opts.uri)
		if err != nil {
			return "", fmt.Errorf("failed to read local artifact %q to checksum it: %w", opts.uri, err)
		}
		return sum, nil
	}
	fmt.Fprintf(os.Stderr, "Note: no local file to hash at %q; checksum omitted (pass --checksum to record one).\n", opts.uri)
	return "", nil
}

// fileChecksumHex streams the file through SHA-256 so a large corpus is not
// loaded into memory.
func fileChecksumHex(path string) (string, error) {
	f, err := os.Open(path) // #nosec G304 -- CLI reads user-provided file path
	if err != nil {
		return "", err
	}
	defer f.Close() //nolint:errcheck // read-only handle
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// buildEvidenceMetadata assembles the optional metadata object, or nil if empty.
func buildEvidenceMetadata(opts addEvidenceOpts) map[string]interface{} {
	meta := map[string]interface{}{}
	if opts.recordCount >= 0 {
		meta["recordCount"] = opts.recordCount
	}
	if opts.collector != "" {
		meta["collector"] = opts.collector
	}
	timeRange := map[string]interface{}{}
	if opts.timeStart != "" {
		timeRange["start"] = opts.timeStart
	}
	if opts.timeEnd != "" {
		timeRange["end"] = opts.timeEnd
	}
	if len(timeRange) > 0 {
		meta["timeRange"] = timeRange
	}
	if len(meta) == 0 {
		return nil
	}
	return meta
}
