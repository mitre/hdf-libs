package cmd

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/mitre/hdf-libs/hdf-cli/v3/internal/evidenceref"
	shared "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go"
	validators "github.com/mitre/hdf-libs/hdf-validators/go/v3"
	"github.com/spf13/cobra"
)

type addReferenceOpts struct {
	sourceName   string
	href         string
	externalID   string
	kind         string
	rel          string
	description  string
	mediaType    string
	checksum     string
	contentFile  string
	documentFile string
	encoding     string
	outputPath   string
}

// externalReferenceIdentityFlags names the flag that authors each of External_Reference's
// anyOf identity branches. Every branch the schema admits must appear here:
// externalReferenceIdentityFields() derives the branches FROM the schema, this map says
// how an operator supplies each one, and a branch missing from it is a branch the CLI
// cannot author. Deriving a flag name from a field name by string surgery would advertise
// a flag that does not exist the moment the schema gains a branch, so the mapping is
// explicit and a test asserts the two sets are equal.
//
// content and document are FILE flags: both carry an artifact, and an artifact's bytes
// belong in a file rather than on argv — a Fortify FPR or a 10 MB catalog is not typeable.
var externalReferenceIdentityFlags = map[string]string{
	"externalId":  "--external-id",
	"href":        "--href",
	"description": "--description",
	"content":     "--content-file",
	"document":    "--document-file",
}

// externalReferenceDefinition resolves External_Reference out of the bundled
// evidence-package schema, so every rule this command enforces at its boundary is read
// from the single source of truth rather than restated here.
//
// The $ref is FOLLOWED rather than guessed. The bundler nests each primitive under its
// versioned $id inside the package schema's $defs, so External_Reference lives at
// $defs["…/primitives/common/vX.Y.Z"].$defs.External_Reference — a path that moves every
// minor release. Resolving the ref the schema itself declares survives that.
func externalReferenceDefinition() (json.RawMessage, error) {
	raw, err := validators.SchemaBytes(validators.TypeEvidencePackage)
	if err != nil {
		return nil, fmt.Errorf("load evidence-package schema: %w", err)
	}
	var schema struct {
		Properties struct {
			ExternalReferences struct {
				Items struct {
					Ref string `json:"$ref"`
				} `json:"items"`
			} `json:"externalReferences"`
		} `json:"properties"`
		Defs map[string]json.RawMessage `json:"$defs"`
	}
	if err := json.Unmarshal(raw, &schema); err != nil {
		return nil, fmt.Errorf("parse evidence-package schema: %w", err)
	}
	ref := schema.Properties.ExternalReferences.Items.Ref
	base, name, found := strings.Cut(ref, "#/$defs/")
	if !found {
		return nil, fmt.Errorf("evidence-package schema: externalReferences items $ref %q is not a $defs reference", ref)
	}

	// An in-document ref ("#/$defs/X") has an empty base and resolves against this
	// schema's own $defs; otherwise the base names a nested primitive document.
	defs := schema.Defs
	if base != "" {
		nested, ok := schema.Defs[base]
		if !ok {
			return nil, fmt.Errorf("evidence-package schema: no bundled primitive %q to resolve %q", base, ref)
		}
		var doc struct {
			Defs map[string]json.RawMessage `json:"$defs"`
		}
		if err := json.Unmarshal(nested, &doc); err != nil {
			return nil, fmt.Errorf("parse bundled primitive %q: %w", base, err)
		}
		defs = doc.Defs
	}
	target, ok := defs[name]
	if !ok {
		return nil, fmt.Errorf("evidence-package schema: %q resolves to no definition named %q", ref, name)
	}
	return target, nil
}

// externalReferenceIdentityFields derives the at-least-one rule from the schema:
// External_Reference's anyOf requires one of externalId | href | description | content |
// document alongside sourceName (the STIX 2.1 external_references rule, widened by
// ADR-0017 so an entry that only embeds needs no synthetic href). Read from the schema,
// as add-evidence reads its format vocabulary, so the boundary check cannot drift.
func externalReferenceIdentityFields() ([]string, error) {
	target, err := externalReferenceDefinition()
	if err != nil {
		return nil, err
	}
	var def struct {
		AnyOf []struct {
			Required []string `json:"required"`
		} `json:"anyOf"`
	}
	if err := json.Unmarshal(target, &def); err != nil {
		return nil, fmt.Errorf("parse External_Reference: %w", err)
	}
	fields := make([]string, 0, len(def.AnyOf))
	for _, alt := range def.AnyOf {
		fields = append(fields, alt.Required...)
	}
	if len(fields) == 0 {
		return nil, fmt.Errorf("evidence-package schema: External_Reference declares no anyOf identity fields")
	}
	sort.Strings(fields)
	return fields, nil
}

// externalReferenceEncodings derives the accepted --encoding values from the schema's own
// enum, so an override is checked at the boundary against what the schema will accept
// rather than against a list copied into this file.
func externalReferenceEncodings() ([]string, error) {
	target, err := externalReferenceDefinition()
	if err != nil {
		return nil, err
	}
	var def struct {
		Properties struct {
			Encoding struct {
				Enum []string `json:"enum"`
			} `json:"encoding"`
		} `json:"properties"`
	}
	if err := json.Unmarshal(target, &def); err != nil {
		return nil, fmt.Errorf("parse External_Reference: %w", err)
	}
	if len(def.Properties.Encoding.Enum) == 0 {
		return nil, fmt.Errorf("evidence-package schema: External_Reference.encoding declares no enum")
	}
	return def.Properties.Encoding.Enum, nil
}

func newEvidenceAddReferenceCmd() *cobra.Command {
	var opts addReferenceOpts

	cmd := &cobra.Command{
		Use: "add-reference <package> --source-name <name> " +
			"(--external-id <id> | --href <uri> | --description <text> | --content-file <path> | --document-file <path>) [flags]",
		Aliases: []string{"add-ref"},
		Short:   "Reference inert external context (CTI/STIX, advisories, BOMs) in an evidence package",
		Long: `Append an external reference to an HDF evidence package's externalReferences[].

This writes externalReferences[] — inert context that overrides NOTHING. The schema
names CTI/STIX, BOMs and advisories. It is the sibling of 'hdf evidence
add-evidence', which writes externalEvidence[]: native-format material that IS
evidence, such as a log or telemetry corpus indexed by URI and hash. If the artifact
would support or contradict a finding, it is evidence; if it only explains one, it is
a reference.

Nothing here is fetched over the network. A reference records where the context
lives and, when it is a local file, what it hashed to at attach time.

To attach context to a RESULTS document's findings rather than to the package, use
'hdf enrich <document> <bundle>', which matches STIX objects to findings by CVE
for a results document and attaches at the root for a system, plan or comparison.

--source-name is required, and so is at least one of --external-id, --href,
--description, --content-file or --document-file: External_Reference's own anyOf.
sourceName names the SYSTEM being cited; one of those five identifies, locates or
carries what is referenced within it, so a bare source name cites nothing and is
refused.

EMBEDDING, and what it does with --checksum:

--document-file reads a JSON OBJECT and stores it verbatim in document. It is not
hashed: document holds a parsed object, which cannot preserve the source file's
whitespace, key order or trailing bytes, so a digest of those bytes would not
verify against what is stored. Pass --checksum to record the source artifact's
digest as a claim about it.

--content-file reads a non-empty file's bytes and stores them in content, which
is the branch for artifacts document cannot hold (XML, CSV, NDJSON, text, or
bytes that are not text at all). encoding is DERIVED from the bytes — utf-8
when they are valid UTF-8, base64 otherwise — because an embedded copy whose
encoding a consumer has to guess is not lossless. Carriage is byte-exact, so
the bytes ARE hashed: content gets a sha512 of the file as read, which a
consumer can verify against the stored copy.

The two kinds of path differ, and it is worth knowing which is which: --href names
an artifact relative to the PACKAGE's own directory, because it is recorded in the
document and read by whoever opens it; --content-file and --document-file name a
file relative to the DIRECTORY THIS COMMAND RUNS IN, like --results or --system,
because they are inputs consumed here and nothing about them is recorded.

--encoding overrides the derivation; base64 is the only valid override for bytes
that are not valid UTF-8. An explicit --checksum always wins over either
derivation, and when bytes are embedded alongside --href it is the embedded bytes
that are hashed, since those are the copy a consumer can verify.

--kind and --rel are deliberately open strings, not enums: the schema documents
starter vocabularies (kind: threat-intel, annotation; rel: reference, definition,
evidence) and accepts any value, including x- customs, so this command does not
invent validation the schema does not have.

Examples:
  hdf evidence add-reference pkg.json --source-name stix --kind threat-intel --href cti/bundle.json
  hdf evidence add-ref pkg.json --source-name cve --external-id CVE-2021-44228 --rel reference
  hdf evidence add-ref pkg.json --source-name nvd --href https://nvd.nist.gov/vuln/detail/CVE-2021-44228
  hdf evidence add-ref pkg.json --source-name stix --kind threat-intel --document-file cti/vuln.json
  hdf evidence add-ref pkg.json --source-name openscap --rel raw-source --media-type application/xml --content-file scan.xml`,
		Args: evidencePackageArg,
		RunE: func(_ *cobra.Command, args []string) error {
			return runEvidenceAddReference(args[0], opts)
		},
	}

	cmd.Flags().StringVar(&opts.sourceName, "source-name", "",
		"External system or source being referenced, e.g. stix | taxii | cve | mitre-att&ck | x-<vendor>. Required; surrounding whitespace is trimmed")
	cmd.Flags().StringVar(&opts.href, "href", "", "Location of the artifact — a local path or a URL; never fetched")
	cmd.Flags().StringVar(&opts.externalID, "external-id", "", "Identifier within the source, e.g. CVE-2021-44228")
	cmd.Flags().StringVar(&opts.kind, "kind", "",
		"What the referenced payload is, e.g. threat-intel | annotation | x-<custom>. Open vocabulary")
	cmd.Flags().StringVar(&opts.rel, "rel", "",
		"How the reference relates to the package, e.g. reference | definition | evidence | x-<custom>. Open vocabulary")
	cmd.Flags().StringVar(&opts.description, "description", "", "Human-readable description of what is referenced")
	cmd.Flags().StringVar(&opts.mediaType, "media-type", "",
		"IANA media type of the referenced artifact; meaningful only with --href, --content-file or --document-file")
	cmd.Flags().StringVar(&opts.checksum, "checksum", "",
		"Precomputed digest as <algorithm>:<hex> — sha256, sha384, sha512 or blake3 — "+
			"for a remote --href or an embedded artifact; a local --href and "+
			"--content-file bytes are hashed automatically. The algorithm must be "+
			"stated, because a digest's length cannot identify it")
	cmd.Flags().StringVar(&opts.contentFile, "content-file", "",
		// DERIVED from the constant that decides it, not a literal. This string said
		// "a sha256 checksum" for one review round after the command had moved to
		// sha512 — and the phrase-matching guard beside it could not see a wording it
		// had not been told about. A claim built from the thing it describes cannot
		// drift from it.
		fmt.Sprintf("Embed this file's bytes verbatim in content, for artifacts document "+
			"cannot hold (XML, CSV, text, binary); sets encoding and a %s checksum",
			evidenceComputedAlgorithm))
	cmd.Flags().StringVar(&opts.documentFile, "document-file", "",
		"Embed this file's JSON object verbatim in document, e.g. a STIX object; not hashed, since a parsed object cannot reproduce the source bytes")
	cmd.Flags().StringVar(&opts.encoding, "encoding", "",
		"Override the encoding derived from --content-file's bytes: utf-8 | base64. Meaningless without --content-file")
	cmd.Flags().StringVarP(&opts.outputPath, "output", "o", "", "Output file (default: overwrite input)")

	return cmd
}

// embedReferenceContent reads an artifact's bytes for the content branch and returns the
// string to store, the encoding that describes it, and a digest of the bytes as read
// under evidenceComputedAlgorithm.
//
// readFromFile rather than readInputFile: the latter strips a UTF-8 BOM, and content is
// carried verbatim, so a BOM must survive — stripping it would both alter the artifact and
// leave the recorded digest unverifiable against the stored copy.
func embedReferenceContent(path, override string) (content, encoding, checksum, algorithm string, err error) {
	raw, err := readFromFile(path, false) // size-gated, symlink-aware, empty refused
	if err != nil {
		return "", "", "", "", fmt.Errorf("--content-file: %w", err)
	}
	// Derived from the bytes, because a guess is exactly what encoding exists to prevent.
	encoding = override
	if encoding == "" {
		if utf8.Valid(raw) {
			encoding = "utf-8"
		} else {
			encoding = "base64"
		}
	}
	switch encoding {
	case "utf-8":
		// Refused rather than written: JSON encoding replaces invalid UTF-8 with U+FFFD,
		// which would silently corrupt the artifact and void the digest beside it.
		if !utf8.Valid(raw) {
			return "", "", "", "", fmt.Errorf("--encoding utf-8 but %s is not valid UTF-8; "+
				"use base64, or omit --encoding to have it derived from the bytes", path)
		}
		content = string(raw)
	case "base64":
		content = base64.StdEncoding.EncodeToString(raw)
	default:
		// Unreachable: the boundary check rejects anything outside the schema's enum.
		return "", "", "", "", fmt.Errorf("--encoding %q is not supported", encoding)
	}
	// Value and algorithm from one call, so the recorded name always describes the
	// computation that produced the value beside it.
	value, algo, hErr := computeEvidenceDigest(raw)
	if hErr != nil {
		return "", "", "", "", hErr
	}
	return content, encoding, value, algo, nil
}

// embedReferenceDocument reads a JSON object for the document branch. Objects only: the
// schema restricts document to an object, and anything else — an array, a scalar, or
// non-JSON bytes — belongs in content, which is told to the operator rather than left to
// surface as a validation failure after the work is done.
func embedReferenceDocument(path string) (map[string]interface{}, error) {
	raw, err := readInputFile(path) // size-gated read boundary (honors --max-size)
	if err != nil {
		return nil, fmt.Errorf("--document-file: %w", err)
	}
	var embedded map[string]interface{}
	if err := json.Unmarshal(raw, &embedded); err != nil {
		return nil, fmt.Errorf("--document-file %s must contain a single JSON object "+
			"(document is object-only; embed anything else with --content-file): %w", path, err)
	}
	// A literal null unmarshals into a nil map WITHOUT error, so it is caught here rather
	// than written as a null document the validator would reject after the work is done.
	if embedded == nil {
		return nil, fmt.Errorf("--document-file %s contains JSON null, not an object", path)
	}
	return embedded, nil
}

func runEvidenceAddReference(file string, opts addReferenceOpts) error {
	// sourceName is the schema's only required field on External_Reference, and it
	// carries minLength 1 — so a whitespace-only value is refused here rather than
	// left for the validator to reject after the work is done.
	if strings.TrimSpace(opts.sourceName) == "" {
		return fmt.Errorf("--source-name is required: name the system being referenced " +
			"(e.g. stix, taxii, cve, or an x-<vendor> label)")
	}
	// kind also carries minLength 1. rel carries no constraint at all, so an empty
	// --rel is simply omitted rather than refused.
	if opts.kind != "" && strings.TrimSpace(opts.kind) == "" {
		return fmt.Errorf("--kind cannot be blank; omit it, or give a value such as threat-intel")
	}
	// Both describe "the artifact", and the schema says that is either the one at href
	// or the one embedded here — so an embed makes them meaningful without an href.
	embedding := opts.contentFile != "" || opts.documentFile != ""
	if opts.checksum != "" && opts.href == "" && !embedding {
		return fmt.Errorf("--checksum records the digest of the artifact at --href, or of one embedded " +
			"by --content-file or --document-file; it means nothing without one of those")
	}
	if opts.mediaType != "" && opts.href == "" && !embedding {
		return fmt.Errorf("--media-type describes the artifact at --href, or one embedded by " +
			"--content-file or --document-file; it means nothing without one of those")
	}
	// The schema makes encoding and content inseparable: its allOf requires encoding
	// whenever content is present AND content whenever encoding is, so an --encoding with
	// nothing to decode is refused rather than written into an invalid document.
	if opts.encoding != "" && opts.contentFile == "" {
		return fmt.Errorf("--encoding states how to read the bytes embedded by --content-file; " +
			"the schema makes it meaningless without content")
	}
	if opts.encoding != "" {
		encodings, encErr := externalReferenceEncodings()
		if encErr != nil {
			return encErr
		}
		if !slices.Contains(encodings, opts.encoding) {
			return fmt.Errorf("--encoding must be one of %s (External_Reference.encoding's enum), not %q",
				strings.Join(encodings, ", "), opts.encoding)
		}
	}
	// sourceName names the SYSTEM; the schema additionally requires the reference to
	// identify, locate or carry something within it — an id, a location, a description,
	// or the artifact itself. A bare source name cites nothing.
	identity, identityErr := externalReferenceIdentityFields()
	if identityErr != nil {
		return identityErr
	}
	// Keyed by schema field, valued by what the operator supplied for it. The two embed
	// branches are satisfied by a PATH: the flag names a file whose contents become the
	// field, so a non-empty path is that branch being used.
	supplied := map[string]string{
		"externalId":  opts.externalID,
		"href":        opts.href,
		"description": opts.description,
		"content":     opts.contentFile,
		"document":    opts.documentFile,
	}
	named := false
	for _, f := range identity {
		if strings.TrimSpace(supplied[f]) != "" {
			named = true
			break
		}
	}
	if !named {
		// A branch with no flag is still reported as the gap it is. Every branch the
		// schema admits today HAS a flag, but that is a fact about the current schema,
		// not a guarantee — the next branch it gains arrives here unmapped.
		flagFor := externalReferenceIdentityFlags
		flags := make([]string, 0, len(identity))
		var noFlag []string
		for _, f := range identity {
			if flag, known := flagFor[f]; known {
				flags = append(flags, flag)
				continue
			}
			// The schema gaining an identity branch must not cost the OPERATOR their
			// guidance: they are told what they can pass, and the gap is reported after
			// it rather than instead of it. Returning early here meant one new branch in
			// the schema replaced the whole flag list with a message addressed to us.
			noFlag = append(noFlag, f)
		}
		gap := ""
		if len(noFlag) > 0 {
			gap = fmt.Sprintf(" (the schema also accepts %s to identify a reference, which this command "+
				"has no flag for yet)", strings.Join(noFlag, ", "))
		}
		if len(flags) == 0 {
			return fmt.Errorf("--source-name names the system but nothing identifies what is referenced "+
				"within it, and this command has no flag for any way the schema allows: %s",
				strings.Join(noFlag, ", "))
		}
		return fmt.Errorf("--source-name names the system but nothing identifies what is referenced within it; "+
			"give at least one of %s%s", strings.Join(flags, ", "), gap)
	}

	data, err := readInputFile(file) // size-gated read boundary (honors --max-size)
	if err != nil {
		return fmt.Errorf("failed to read evidence package: %w", err)
	}
	doc, err := loadAndValidateHDFDoc(data, "evidence-package")
	if err != nil {
		return fmt.Errorf("evidence package %s: %w", file, err)
	}

	// Trimmed deliberately: a source name is an identifier, and " stix " and "stix"
	// naming two different sources would be a trap. Documented in the flag help.
	ref := map[string]interface{}{"sourceName": strings.TrimSpace(opts.sourceName)}

	// Embedded first, because the digest of bytes carried IN the package is the one a
	// consumer can verify, and it therefore wins over hashing whatever --href points at.
	var embeddedChecksum, embeddedAlgorithm string
	if opts.contentFile != "" {
		content, encoding, sum, algo, cErr := embedReferenceContent(opts.contentFile, opts.encoding)
		if cErr != nil {
			return cErr
		}
		ref["content"] = content
		ref["encoding"] = encoding
		embeddedChecksum, embeddedAlgorithm = sum, algo
	}
	if opts.documentFile != "" {
		embedded, dErr := embedReferenceDocument(opts.documentFile)
		if dErr != nil {
			return dErr
		}
		ref["document"] = embedded
	}

	if opts.href != "" {
		// ENCODED, like every other command that records a reference.
		// externalReferences[].href is the same uri-reference primitive as
		// contents[].uri, so an unescaped name here is the same contract violation —
		// and this was the one write path that still wrote the raw value while build,
		// set, add-evidence and update all encoded.
		ref["href"] = evidenceref.Encode(filepath.ToSlash(opts.href))
	}

	// checksum describes ONE artifact, so the precedence is stated here rather than left
	// to fall out of the order the flags happen to be handled in:
	//  1. an explicit --checksum — the operator's claim about the source artifact, and the
	//     only way to record one for --document-file, whose parsed object cannot reproduce
	//     the source bytes for a digest to be verified against;
	//  2. embedded content's own bytes — verifiable against the copy stored in the package;
	//  3. a local --href, hashed from beside the package.
	checksumHex, checksumAlgorithm := "", ""
	switch {
	case opts.checksum != "":
		parsed, nErr := shared.ParseDigest(opts.checksum)
		if nErr != nil {
			return fmt.Errorf("--checksum %w", nErr)
		}
		checksumHex, checksumAlgorithm = parsed.Value, string(parsed.Algorithm)
	case embeddedChecksum != "":
		checksumHex, checksumAlgorithm = embeddedChecksum, embeddedAlgorithm
	case opts.href != "":
		// Reuses add-evidence's resolver so a local file is hashed and a URL is left
		// unhashed by exactly the same rule, rather than a second implementation of it —
		// which means it also shares the package-relative resolution: an href is read from
		// beside the PACKAGE, not from the process CWD.
		resolved, algorithm, csErr := resolveEvidenceChecksum(filepath.Dir(file), opts.href, "")
		if csErr != nil {
			return csErr
		}
		checksumHex, checksumAlgorithm = resolved, algorithm
	}
	if checksumHex != "" {
		ref["checksum"] = map[string]interface{}{"algorithm": checksumAlgorithm, "value": checksumHex}
	}
	for key, value := range map[string]string{
		"externalId":  opts.externalID,
		"kind":        opts.kind,
		"rel":         opts.rel,
		"description": opts.description,
		"mediaType":   opts.mediaType,
	} {
		if value != "" {
			ref[key] = value
		}
	}

	existing, _ := doc["externalReferences"].([]interface{})
	doc["externalReferences"] = append(existing, ref)

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

	fmt.Fprintf(os.Stderr, "Added 1 external reference to %s\n", target)
	fmt.Fprintf(os.Stderr, "  %s", ref["sourceName"])
	if id, ok := ref["externalId"]; ok {
		fmt.Fprintf(os.Stderr, " %s", id)
	}
	if href, ok := ref["href"]; ok {
		fmt.Fprintf(os.Stderr, " -> %s", href)
	}
	// Named explicitly, because reaching for the wrong array is the mistake this
	// command exists to prevent.
	fmt.Fprintf(os.Stderr, " (externalReferences — inert context)\n")
	return nil
}
