package cmd

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	validators "github.com/mitre/hdf-libs/hdf-validators/go/v3"
	"github.com/spf13/cobra"
)

// externalEvidenceFormatConstraints derives the allowed --format vocabulary from
// the single source of truth — hdf-evidence-package.schema.json
// #/$defs/External_Evidence_Format (an `anyOf` of a reserved enum plus an
// x-<custom> pattern) — so the command-boundary check can never drift from the
// schema. Reads the embedded schema (or the --schema-dir override).
func externalEvidenceFormatConstraints() ([]string, *regexp.Regexp, error) {
	raw, err := validators.SchemaBytes(validators.TypeEvidencePackage)
	if err != nil {
		return nil, nil, fmt.Errorf("load evidence-package schema: %w", err)
	}
	var schema struct {
		Defs struct {
			Format struct {
				AnyOf []struct {
					Enum    []string `json:"enum"`
					Pattern string   `json:"pattern"`
				} `json:"anyOf"`
			} `json:"External_Evidence_Format"`
		} `json:"$defs"`
	}
	if err := json.Unmarshal(raw, &schema); err != nil {
		return nil, nil, fmt.Errorf("parse evidence-package schema: %w", err)
	}
	var reserved []string
	var pattern *regexp.Regexp
	for _, alt := range schema.Defs.Format.AnyOf {
		if len(alt.Enum) > 0 {
			reserved = alt.Enum
		}
		if alt.Pattern != "" {
			re, cerr := regexp.Compile(alt.Pattern)
			if cerr != nil {
				return nil, nil, fmt.Errorf("compile External_Evidence_Format pattern %q: %w", alt.Pattern, cerr)
			}
			pattern = re
		}
	}
	if len(reserved) == 0 && pattern == nil {
		return nil, nil, fmt.Errorf("evidence-package schema: External_Evidence_Format has no enum or pattern")
	}
	return reserved, pattern, nil
}

// validateEvidenceFormat rejects a --format value at the command boundary (with a
// clear message) unless it matches the schema's reserved enum or x-<custom>
// pattern, rather than deferring to post-serialize schema validation.
func validateEvidenceFormat(format string) error {
	reserved, pattern, err := externalEvidenceFormatConstraints()
	if err != nil {
		return err
	}
	for _, r := range reserved {
		if format == r {
			return nil
		}
	}
	if pattern != nil && pattern.MatchString(format) {
		return nil
	}
	patternText := "x-<custom>"
	if pattern != nil {
		patternText = pattern.String()
	}
	return fmt.Errorf("--format %q is not valid: use a reserved value (%s), or a custom value matching %s "+
		"(lower-case only, e.g. x-splunk-export)", format, strings.Join(reserved, ", "), patternText)
}

type addEvidenceOpts struct {
	uris          []string
	formats       []string
	infer         bool
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
		Use:   "add-evidence <package> --uri <uri>... [--format <format>...] [flags]",
		Short: "Reference external native-format evidence (logs/telemetry) in an evidence package",
		Long: `Append an external evidence reference to an HDF evidence package. The referenced
artifact (an ECS/OCSF log corpus, or other native-format evidence) is carried by
reference — its URI, an integrity checksum, and a format discriminator — without
recreating the data inside HDF.

This writes externalEvidence[] — native-format material that IS evidence, such as
a log or telemetry corpus. It is NOT the place for inert context: CTI/STIX,
advisories and the like belong in externalReferences[], which overrides nothing.
'hdf enrich <results> <bundle>' attaches that context to a RESULTS document's
findings. The evidence package's own externalReferences[] has no command yet.

--uri is repeatable. --format takes one value for every artifact, or one per
--uri matched in the order they were given; any other count is refused rather
than guessed. Omit --format and pass --infer to accept a format read from the
artifact's own content discriminator (CycloneDX bomFormat, SPDX 2.x spdxVersion) —
never from its filename. Without --infer a missing format is an error that names
what it would have inferred, because a mislabelled artifact is worse than an
unlabelled one.

The same URI twice is refused, not ignored: a repeat add usually means the
artifact CHANGED, and its differing checksum must be recorded deliberately
rather than absorbed in silence. Remove the existing entry first.

If --uri is a local file, its SHA-256 checksum is computed automatically. If --uri
is a URL (the artifact is referenced, not fetched), pass --checksum to record a
precomputed hash, or omit it; --checksum names one artifact and is refused with
several --uri values. Format is an open set: reserved ecs | ocsf | cyclonedx |
spdx | raw-log, plus x- custom values (e.g. x-splunk-export for a Splunk/Sentinel
export — query-time models like CIM/ASIM have no artifact to reference, so
reference their export instead).

Examples:
  hdf evidence add-evidence pkg.json --uri logs/q1.ndjson --format ecs --collector elastic-agent
  hdf evidence add-evidence pkg.json --uri https://lake/ocsf/q1/ --format ocsf --checksum <sha256>
  hdf evidence add-evidence pkg.json --uri logs/q1.ndjson --uri sbom.cdx.json --format ecs --format cyclonedx
  hdf evidence add-evidence pkg.json --uri sbom.cdx.json --infer`,
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			return runEvidenceAddEvidence(args[0], opts)
		},
	}

	cmd.Flags().StringArrayVar(&opts.uris, "uri", nil, "URI of an external evidence artifact (repeatable, required)")
	cmd.Flags().StringArrayVar(&opts.formats, "format", nil,
		"Format: ecs | ocsf | cyclonedx | spdx | raw-log | x-<custom>. Give one for all artifacts, or one per --uri in order")
	cmd.Flags().BoolVar(&opts.infer, "infer", false,
		"Accept a format inferred from an artifact's own content discriminator when --format is absent")
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

// resolveEvidenceFormats pairs each --uri with a format. One --format covers every
// artifact; len(--uri) formats are matched in order. Any other count is ambiguous
// and refused rather than guessed. An absent format is inferred from the
// artifact's own content — but only with --infer, because a wrongly-labelled
// artifact is worse than an unlabelled one: a consumer trusts the discriminator.
func resolveEvidenceFormats(opts addEvidenceOpts) ([]string, error) {
	switch {
	case len(opts.formats) == len(opts.uris):
		// pairwise
	case len(opts.formats) == 1:
		single := opts.formats[0]
		out := make([]string, len(opts.uris))
		for i := range out {
			out[i] = single
		}
		opts.formats = out
	case len(opts.formats) == 0:
		inferred := make([]string, len(opts.uris))
		var receipts []string
		for i, uri := range opts.uris {
			guess := inferEvidenceFormat(uri)
			if guess == "" {
				// Say which it was: "I read it and found nothing" and "there was
				// nothing to read" call for different fixes.
				if _, statErr := os.Stat(uri); statErr != nil {
					return nil, fmt.Errorf("--format is required for %s; it is not a local file, so its "+
						"format cannot be read from its content", uri)
				}
				return nil, fmt.Errorf("--format is required for %s; its content carries no format "+
					"discriminator this tool recognizes", uri)
			}
			if !opts.infer {
				return nil, fmt.Errorf("--format is required for %s; its content looks like %q — "+
					"pass --infer to accept that, or --format to state it", uri, guess)
			}
			receipts = append(receipts, fmt.Sprintf("Inferred format %q for %s from its content", guess, uri))
			inferred[i] = guess
		}
		// Only now that every artifact resolved: a receipt for a run that aborts
		// claims something that did not happen.
		for _, r := range receipts {
			fmt.Fprintln(os.Stderr, r)
		}
		opts.formats = inferred
	default:
		return nil, fmt.Errorf("%d --format values for %d --uri values; give one --format for all "+
			"artifacts, or one per --uri in order", len(opts.formats), len(opts.uris))
	}
	for _, f := range opts.formats {
		if err := validateEvidenceFormat(f); err != nil {
			return nil, err
		}
	}
	return opts.formats, nil
}

// inferEvidenceFormat reads an artifact's own discriminator — never its filename,
// which lies (a *.cdx.json holding SPDX is SPDX). Returns "" when nothing
// recognizable is found, so the caller can refuse rather than invent.
func inferEvidenceFormat(uri string) string {
	if fi, err := os.Stat(uri); err != nil || fi.IsDir() {
		return "" // a URL or a directory has no content to read here
	}
	data, err := readInputFile(uri)
	if err != nil {
		return ""
	}
	var head struct {
		BomFormat   string `json:"bomFormat"`
		SpdxVersion string `json:"spdxVersion"`
	}
	if json.Unmarshal(data, &head) != nil {
		return ""
	}
	switch {
	case strings.EqualFold(head.BomFormat, "CycloneDX"):
		return "cyclonedx"
	case head.SpdxVersion != "":
		return "spdx"
	}
	return ""
}

func runEvidenceAddEvidence(file string, opts addEvidenceOpts) error {
	if len(opts.uris) == 0 {
		return fmt.Errorf("--uri is required")
	}
	// A checksum names one artifact's digest, so it cannot be shared.
	if opts.checksum != "" && len(opts.uris) > 1 {
		return fmt.Errorf("--checksum names a single artifact's digest and cannot apply to %d --uri "+
			"values; add those artifacts in separate invocations", len(opts.uris))
	}
	formats, err := resolveEvidenceFormats(opts)
	if err != nil {
		return err
	}

	data, err := readInputFile(file) // size-gated read boundary (honors --max-size)
	if err != nil {
		return fmt.Errorf("failed to read evidence package: %w", err)
	}
	doc, err := loadAndValidateHDFDoc(data, "evidence-package")
	if err != nil {
		return fmt.Errorf("evidence package %s: %w", file, err)
	}

	existing, _ := doc["externalEvidence"].([]interface{})
	recorded := recordedEvidenceURIs(existing)

	added := make([]interface{}, 0, len(opts.uris))
	for i, uri := range opts.uris {
		normalized := filepath.ToSlash(uri)
		// Refused, not ignored: a second add at the same URI usually means the
		// artifact CHANGED, and an evidence package must not absorb that silently.
		if _, dup := recorded[normalized]; dup {
			return fmt.Errorf("%s is already referenced in %s; remove that entry first if the "+
				"artifact changed, so the new checksum is recorded deliberately", normalized, file)
		}
		recorded[normalized] = struct{}{}

		ref := map[string]interface{}{
			"uri":    normalized,
			"format": formats[i],
		}
		checksum, csErr := resolveEvidenceChecksum(uri, opts.checksum)
		if csErr != nil {
			return csErr
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
		added = append(added, ref)
	}
	doc["externalEvidence"] = append(existing, added...)

	output, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to serialize evidence package: %w", err)
	}
	if err := validateHDFDocument(output); err != nil {
		return fmt.Errorf("evidence package failed validation before write: %w", err)
	}

	target := file
	if opts.outputPath != "" {
		target = opts.outputPath
	}
	if err := os.WriteFile(target, output, 0o600); err != nil {
		return fmt.Errorf("failed to write evidence package: %w", err)
	}
	fmt.Fprintf(os.Stderr, "Added %d external evidence reference(s) to %s\n", len(added), target)
	for _, a := range added {
		entry := a.(map[string]interface{})
		fmt.Fprintf(os.Stderr, "  %s -> %s\n", entry["uri"], entry["format"])
	}
	return nil
}

// recordedEvidenceURIs indexes the URIs a package already references.
func recordedEvidenceURIs(existing []interface{}) map[string]struct{} {
	seen := make(map[string]struct{}, len(existing))
	for _, e := range existing {
		if entry, ok := e.(map[string]interface{}); ok {
			if uri, ok := entry["uri"].(string); ok {
				seen[uri] = struct{}{}
			}
		}
	}
	return seen
}

// resolveEvidenceChecksum returns the sha256 hex for the reference: a supplied
// value wins; otherwise a local-file URI is hashed; a URL is left unhashed.
func resolveEvidenceChecksum(uri, supplied string) (string, error) {
	if supplied != "" {
		return normalizeSHA256Hex(supplied)
	}
	// A local-path URI is hashed only when the file is actually present at attach
	// time; a URL, a directory, or a path with no local copy is left unhashed
	// (a reference-only entry, not an error).
	if fi, err := os.Stat(uri); err == nil && !fi.IsDir() {
		sum, err := fileChecksumHex(uri)
		if err != nil {
			return "", fmt.Errorf("failed to read local artifact %q to checksum it: %w", uri, err)
		}
		return sum, nil
	}
	fmt.Fprintf(os.Stderr, "Note: no local file to hash at %q; checksum omitted (pass --checksum to record one).\n", uri)
	return "", nil
}

// normalizeSHA256Hex validates that a user-supplied checksum is a 32-byte
// SHA-256 digest and returns it lowercased, so we never stamp algorithm:sha256
// on a value that isn't actually one.
func normalizeSHA256Hex(s string) (string, error) {
	b, err := hex.DecodeString(s)
	if err != nil {
		return "", fmt.Errorf("--checksum must be a hex-encoded SHA-256 digest: %w", err)
	}
	if len(b) != sha256.Size {
		return "", fmt.Errorf("--checksum must be a 32-byte (64 hex-character) SHA-256 digest, got %d bytes", len(b))
	}
	return hex.EncodeToString(b), nil
}

// fileChecksumHex streams the file through SHA-256 so a large corpus is not
// loaded into memory. It is deliberately NOT subject to the --max-size input
// cap: the cap guards against loading untrusted input into memory, and this
// read is constant-memory by construction, so capping it would only reject
// large evidence artifacts (logs, packet captures, images) for no safety gain.
func fileChecksumHex(path string) (string, error) {
	f, err := os.Open(path) // #nosec G304 -- CLI reads user-provided file path; streamed, not slurped
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
