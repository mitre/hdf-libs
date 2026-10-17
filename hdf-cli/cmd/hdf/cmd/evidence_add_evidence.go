package cmd

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/mitre/hdf-libs/hdf-cli/v3/internal/atomicfile"
	"github.com/mitre/hdf-libs/hdf-cli/v3/internal/evidenceref"
	shared "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go"
	hdfengine "github.com/mitre/hdf-libs/hdf-engine/go/v3"
	validators "github.com/mitre/hdf-libs/hdf-validators/go/v3"
	"github.com/spf13/cobra"
	"lukechampine.com/blake3"
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
advisories and the like belong in externalReferences[], written by its sibling
'hdf evidence add-reference' (alias add-ref), which overrides nothing. The test: if
the artifact would support or contradict a finding it is evidence; if it only
explains one it is a reference. To attach context to a RESULTS document's findings
rather than to the package, use 'hdf enrich <document> <bundle>'.

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

A --uri naming an artifact INSIDE the package's directory is recorded relative to the
package, because such an artifact travels in a bundled archive under that relative name
and a machine-local absolute path would leave the extracted copy unable to resolve it.
An ABSOLUTE --uri is treated as a path on this machine, so a name needing escapes is
escaped for you; a RELATIVE one is treated as a reference already and recorded as you
wrote it — the same split 'hdf evidence set' documents, because both commands record
through one function.
An artifact outside the package, or a remote URL, is recorded exactly as given: it is
external by design and rewriting it would claim the artifact is somewhere it is not.
Because the URI is normalized before the duplicate check, two spellings of the same
artifact are recognized as the same artifact and the second is refused.

If --uri is a regular local file, its checksum is computed automatically; a path
that is present but is not a regular file is refused rather than opened, naming what
it found, because opening a fifo can block with no timeout. If --uri
is a URL (the artifact is referenced, not fetched), pass --checksum to record a
precomputed hash, or omit it; --checksum names one artifact and is refused with
several --uri values. Format is an open set: reserved ecs | ocsf | cyclonedx |
spdx | raw-log, plus x- custom values (e.g. x-splunk-export for a Splunk/Sentinel
export — query-time models like CIM/ASIM have no artifact to reference, so
reference their export instead).

Examples:
  hdf evidence add-evidence pkg.json --uri logs/q1.ndjson --format ecs --collector elastic-agent
  hdf evidence add-evidence pkg.json --uri https://lake/ocsf/q1/ --format ocsf --checksum sha256:<hex>
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
	cmd.Flags().StringVar(&opts.checksum, "checksum", "",
		"Precomputed digest as <algorithm>:<hex> — sha256, sha384, sha512 or blake3 "+
			"(for a URL/remote artifact; local files are hashed automatically). The "+
			"algorithm must be stated: a digest's length cannot identify it, since "+
			"sha256 and blake3 are both 64 hex characters")
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
func resolveEvidenceFormats(pkgDir string, opts addEvidenceOpts) ([]string, error) {
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
			data, readErr := artifactContent(pkgDir, uri)
			if readErr != nil {
				// The reason travels WITH the error. Dropped, every cause of a read
				// failure surfaced as the no-discriminator message below — a claim
				// about content that nothing had managed to look at.
				return nil, fmt.Errorf("--format is required for %s; %w", uri, readErr)
			}
			guess := formatFromContent(data)
			if guess == "" {
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

// nonRegularKind names what a non-regular mode is, or "" for a regular file. A refusal
// that says only "unusable" leaves the operator guessing; naming the kind points at the
// one thing they can act on.
func nonRegularKind(mode os.FileMode) string {
	switch {
	case mode&os.ModeNamedPipe != 0:
		return "a named pipe"
	case mode&os.ModeSocket != 0:
		return "a socket"
	case mode&os.ModeCharDevice != 0:
		return "a character device"
	case mode&os.ModeDevice != 0:
		return "a block device"
	case mode&os.ModeDir != 0:
		return "a directory"
	case !mode.IsRegular():
		return "an irregular file"
	}
	return ""
}

// artifactContent returns the bytes --infer inspects, or an error whose text completes
// the sentence "--format is required for <uri>; ". Only an actual attempt tells the
// reasons apart, so the resolution, the stat and the read all live here — kept apart,
// they described the same artifact differently.
//
// The stat GATES the read rather than describing it afterwards: a read of a fifo blocks
// until a writer appears, with no timeout, so the kind has to be settled before anything
// opens the path.
func artifactContent(pkgDir, uri string) ([]byte, error) {
	path, resolved := localArtifactPath(pkgDir, uri)
	if !resolved {
		return nil, fmt.Errorf("it does not resolve inside the package's directory, so its " +
			"format cannot be read from its content")
	}
	fi, err := os.Stat(path)
	if err != nil {
		// A URL or an absent path: nothing local to read. A directory IS local, so it
		// falls through and is named by nonRegularKind below.
		return nil, fmt.Errorf("it is not a local file, so its format cannot be read from its content")
	}
	if kind := nonRegularKind(fi.Mode()); kind != "" {
		return nil, fmt.Errorf("it is %s, not a regular file, so its content cannot be read", kind)
	}
	if fi.Size() == 0 {
		// Read fine; there is simply nothing in it to discriminate on, so it belongs
		// with the no-discriminator case rather than the unreadable one.
		return nil, nil
	}
	data, err := readInputFile(path)
	if err != nil {
		return nil, fmt.Errorf("it could not be read: %w", err)
	}
	return data, nil
}

// formatFromContent reads an artifact's own discriminator — never its filename, which
// lies (a *.cdx.json holding SPDX is SPDX). Returns "" when nothing recognizable is
// found, so the caller can refuse rather than invent.
func formatFromContent(data []byte) string {
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
	// Refused HERE, ahead of any format resolution: the format error for a blank name
	// reads as a lost argument rather than as a rejected one. Whitespace-only counts as
	// blank, because it names no artifact either.
	for i, uri := range opts.uris {
		if strings.TrimSpace(uri) == "" {
			return fmt.Errorf("--uri value %d is blank; name the artifact being referenced, "+
				"because an entry with no uri is evidence of nothing", i+1)
		}
	}
	// A checksum names one artifact's digest, so it cannot be shared.
	if opts.checksum != "" && len(opts.uris) > 1 {
		return fmt.Errorf("--checksum names a single artifact's digest and cannot apply to %d --uri "+
			"values; add those artifacts in separate invocations", len(opts.uris))
	}
	formats, err := resolveEvidenceFormats(filepath.Dir(file), opts)
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
	recorded, err := recordedEvidenceURIs(data)
	if err != nil {
		return fmt.Errorf("evidence package %s: %w", file, err)
	}

	// An in-package artifact IS carried into a bundled archive, under an entry name
	// relative to the package, so recording a machine-local absolute path leaves the
	// extracted copy unable to resolve it. Normalized through the same predicate `build`
	// and `evidence set` use; an artifact outside the package is external by design and
	// is recorded exactly as given. Done BEFORE the duplicate guard below, so two
	// spellings of one artifact collide rather than landing as two entries.
	pkgDir := filepath.Dir(file)
	added := make([]interface{}, 0, len(opts.uris))
	for i, uri := range opts.uris {
		normalized := filepath.ToSlash(packageRelativeIfInside(pkgDir, uri))
		// Asked in the same terms the map is keyed in. packageRelativeIfInside returns a
		// uri-reference, so the lookup decodes it back to the artifact it names.
		lookup := normalized
		if decoded, err := evidenceref.Decode(normalized); err == nil {
			lookup = string(decoded)
		}
		// Refused, not ignored: a second add at the same URI usually means the
		// artifact CHANGED, and an evidence package must not absorb that silently.
		if stored, dup := recorded[lookup]; dup {
			// Names the STORED spelling, which is the entry the operator has to find and
			// remove. Naming the incoming one sent them looking for a string their
			// package does not contain, because a duplicate can be reached by a different
			// spelling of the same artifact — the same correction 52n0c.29 made to
			// update's type-conflict refusal.
			return fmt.Errorf("%s is already referenced in %s; remove that entry first if the "+
				"artifact changed, so the new checksum is recorded deliberately", stored, file)
		}
		recorded[lookup] = normalized

		ref := map[string]interface{}{
			"uri":    normalized,
			"format": formats[i],
		}
		checksum, algorithm, csErr := resolveEvidenceChecksum(pkgDir, uri, opts.checksum)
		if csErr != nil {
			return csErr
		}
		if checksum != "" {
			ref["checksum"] = map[string]interface{}{"algorithm": algorithm, "value": checksum}
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
	if err := atomicfile.WriteFile(target, output, 0o600); err != nil {
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
// KEYED ON THE DECODED FORM, because that is what identifies the artifact. Keyed on the
// raw recorded string, this guard failed for any entry not already canonically
// percent-encoded — every package written before 52n0c.31, and any written by a producer
// that does not escape — since the incoming reference is canonicalised before the lookup.
// A second, inconsistent entry was then added for one file, one of them without a
// checksum, splitting its attestation across two records. The command's help has always
// promised the opposite.
func recordedEvidenceURIs(pkgData []byte) (map[string]string, error) {
	refs, err := evidenceref.Collect(pkgData)
	if err != nil {
		return nil, err
	}
	seen := make(map[string]string, len(refs))
	for _, r := range refs {
		if r.Field != "externalEvidence" || r.Stored == "" {
			continue
		}
		// An undecodable reference is keyed as recorded: it identifies nothing, but a
		// package carrying one must not silently lose it from the guard either.
		if r.Err != nil {
			seen[r.Stored] = r.Stored
			continue
		}
		seen[string(r.Decoded)] = r.Stored
	}
	return seen, nil
}

// evidenceComputedAlgorithm is the algorithm every authoring command uses when IT
// computes a digest. One constant because the three — add-evidence, add-reference and
// build — must agree: one of them recording an algorithm another cannot is the
// inconsistency 52n0c.30 exists to remove.
//
// sha512 by maintainer decision, a deliberate behaviour change from sha256 flagged in
// the CHANGELOG. A new path computing a security-relevant hash emits sha512, and no
// command is hardlocked to one algorithm for a digest the OPERATOR supplies — that
// comes through ParseDigest, which records whatever the schema admits.
const evidenceComputedAlgorithm = "sha512"

// computeEvidenceDigest hashes bytes and returns the value WITH the algorithm that
// produced it. One function because the two must never be chosen separately: while
// fixing 52n0c.30 I relabelled an embedded artifact's digest as sha512 while the code
// beside it still computed sha256 — the very mislabelling the card exists to remove,
// reintroduced inside the fix, because the value came from one place and the name from
// another. A caller that gets both from here cannot make that mistake.
func computeEvidenceDigest(data []byte) (value, algorithm string, err error) {
	v, err := hdfengine.ChecksumHex(evidenceComputedAlgorithm, data)
	if err != nil {
		return "", "", err
	}
	return v, evidenceComputedAlgorithm, nil
}

// resolveEvidenceChecksum returns the digest AND the algorithm it is under: a supplied
// "<algo>:<hex>" wins and is recorded as stated; otherwise a local-file URI is hashed
// with the algorithm this command computes; a URL is left unhashed.
//
// The algorithm is returned rather than assumed by the caller. It used to be hardcoded
// at the record site, so a stated blake3 digest — the same 64 hex characters as a
// sha256 one — was written down as sha256, and `bundle` then hashed the file as sha256
// and accused the operator's own evidence of having changed.
func resolveEvidenceChecksum(pkgDir, uri, supplied string) (value, algorithm string, err error) {
	if supplied != "" {
		parsed, perr := shared.ParseDigest(supplied)
		if perr != nil {
			return "", "", fmt.Errorf("--checksum %w", perr)
		}
		return parsed.Value, string(parsed.Algorithm), nil
	}
	// Resolved against the PACKAGE's directory, which is what the reference means:
	// bundle and verify both read it that way. Reading it against the process CWD
	// instead did more than miss the file — where one happened to exist at the same
	// relative spelling under the CWD, it recorded that file's digest against a
	// reference naming a different file, and `bundle` then reported a mismatch and
	// refused the package. The uri itself is still recorded exactly as typed.
	path, readable := localArtifactPath(pkgDir, uri)
	if !readable {
		// Said distinctly from "not present": the artifact may well exist, but reading it
		// would leave the package, and a digest of bytes the reference does not name is
		// worse than no digest at all.
		fmt.Fprintf(os.Stderr, "Note: %q does not resolve inside the package's directory, "+
			"so it was not hashed; checksum omitted (pass --checksum to record one).\n", uri)
		return "", "", nil
	}
	// Hashed only when something is actually present at this path; what is present
	// but cannot be a document is refused just below, and what is absent is left
	// unhashed by the branch above.
	if fi, err := os.Stat(path); err == nil {
		// Refused BEFORE the open, not reported after it: opening a fifo blocks until a
		// writer appears, so the command waited with no timeout and then hashed whatever
		// that writer sent — a digest of bytes nobody chose to attest, at exit 0.
		if kind := nonRegularKind(fi.Mode()); kind != "" {
			return "", "", fmt.Errorf("%q is %s, not a regular file, so it cannot be hashed; "+
				"reference a regular file, or pass --checksum to record a digest you computed", uri, kind)
		}
		sum, algorithm, err := fileChecksumHex(path)
		if err != nil {
			return "", "", fmt.Errorf("failed to read local artifact %q to checksum it: %w", path, err)
		}
		return sum, algorithm, nil
	}
	// The path actually tried, not the uri as typed, so an operator can see where it looked.
	fmt.Fprintf(os.Stderr, "Note: no local file to hash at %q; checksum omitted (pass --checksum to record one).\n", path)
	return "", "", nil
}

// localArtifactPath is where a --uri is read from to hash it, and ("", false) when it
// must not be read at all. A remote uri and an absolute path are taken as given; a
// relative one is resolved inside the package through evidenceref.PathFromRecorded, the
// same boundary the read side uses — which DECODES before it confines, because a reference
// is a uri-reference and a decoded "%2e%2e/" must meet containment rather than pass it as
// a literal name.
//
// This comment named hdfutil.SafePath for four rounds after the call beneath it changed,
// and a prose review driven by behavioural vocabulary did not catch it: the claim asserts
// a fact by naming a FUNCTION, not by describing behaviour. When a change swaps which
// function performs a resolution, grep for the old identifier too.
//
// The base is made absolute FIRST. SafePath resolves symlinks on both sides and then
// relates them, so a relative base against an absolute symlink target makes filepath.Rel
// fail and SafePath refuse — which meant correctness depended on whether the operator
// typed the package path relatively or absolutely, and left legitimate in-package
// symlinks unhashed in the relative case.
//
// A uri SafePath refuses yields false, NOT the raw uri. Returning the raw uri handed it
// back to CWD resolution for exactly the inputs the boundary had just rejected, so
// `--uri ../outside.ndjson` hashed a file outside the package and recorded its digest
// against a reference naming something else. Refusing to read is the whole point of the
// boundary; there is no safe fallback.
func localArtifactPath(pkgDir, uri string) (string, bool) {
	if uri == "" {
		return uri, false
	}
	if isRemoteURI(uri) || filepath.IsAbs(uri) {
		return uri, true
	}
	base, err := filepath.Abs(pkgDir)
	if err != nil {
		return "", false
	}
	// --uri is raw operator input, so it decodes here: an operator who writes the legal
	// encoding of a filename must find that file.
	resolved, err := evidenceref.PathFromRecorded(base, uri)
	if err != nil {
		return "", false
	}
	return resolved, true
}

// fileChecksumHex streams the file through evidenceComputedAlgorithm so a large corpus is not
// loaded into memory. It is deliberately NOT subject to the --max-size input
// cap: the cap guards against loading untrusted input into memory, and this
// read is constant-memory by construction, so capping it would only reject
// large evidence artifacts (logs, packet captures, images) for no safety gain.
// streamingHasher returns a streaming hash for one of the algorithms Hash_Algorithm
// admits. Separate from hdfengine.ChecksumHex, which takes the whole []byte: an evidence
// corpus can be large, and the point of hashing it here is to never hold it in memory.
// The algorithms are the same set, so a value recorded by one verifies under the other.
func streamingHasher(algorithm string) (hash.Hash, error) {
	switch algorithm {
	case "", "sha256":
		return sha256.New(), nil
	case "sha384":
		return sha512.New384(), nil
	case "sha512":
		return sha512.New(), nil
	case "blake3":
		// 32 bytes, no key: the default-length digest ChecksumHex computes and the one the
		// BLAKE3 reference vectors compare against. A different length here would hash the
		// same bytes to a value verification could never reproduce.
		return blake3.New(32, nil), nil
	default:
		return nil, fmt.Errorf("cannot compute %q: this build computes sha256, sha384, sha512 and blake3", algorithm)
	}
}

func fileChecksumHex(path string) (value, algorithm string, err error) {
	f, err := os.Open(path) // #nosec G304 -- CLI reads user-provided file path; streamed, not slurped
	if err != nil {
		return "", "", err
	}
	defer f.Close() //nolint:errcheck // read-only handle
	h, hErr := streamingHasher(evidenceComputedAlgorithm)
	if hErr != nil {
		return "", "", hErr
	}
	if _, err := io.Copy(h, f); err != nil {
		return "", "", err
	}
	// Both facts from one return, like computeEvidenceDigest: a caller that took the
	// value here and the name from elsewhere is how a sha256 digest got labelled sha512
	// while 52n0c.30 was being fixed.
	return hex.EncodeToString(h.Sum(nil)), evidenceComputedAlgorithm, nil
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
