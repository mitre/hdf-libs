package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	validators "github.com/mitre/hdf-libs/hdf-validators/go/v3"
	"github.com/spf13/cobra"
)

type addReferenceOpts struct {
	sourceName  string
	href        string
	externalID  string
	kind        string
	rel         string
	description string
	mediaType   string
	checksum    string
	outputPath  string
}

// externalReferenceIdentityFields derives the at-least-one rule from the single source
// of truth: External_Reference's anyOf requires one of externalId | href | description
// alongside sourceName (the STIX 2.1 external_references rule). Read from the schema, as
// add-evidence reads its format vocabulary, so the command-boundary check cannot drift.
//
// The $ref is FOLLOWED rather than guessed. The bundler nests each primitive under its
// versioned $id inside the package schema's $defs, so External_Reference lives at
// $defs["…/primitives/common/vX.Y.Z"].$defs.External_Reference — a path that moves every
// minor release. Resolving the ref the schema itself declares survives that.
func externalReferenceIdentityFields() ([]string, error) {
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

	var def struct {
		AnyOf []struct {
			Required []string `json:"required"`
		} `json:"anyOf"`
	}
	if err := json.Unmarshal(target, &def); err != nil {
		return nil, fmt.Errorf("parse %s: %w", name, err)
	}
	fields := make([]string, 0, len(def.AnyOf))
	for _, alt := range def.AnyOf {
		fields = append(fields, alt.Required...)
	}
	if len(fields) == 0 {
		return nil, fmt.Errorf("evidence-package schema: %s declares no anyOf identity fields", name)
	}
	sort.Strings(fields)
	return fields, nil
}

func newEvidenceAddReferenceCmd() *cobra.Command {
	var opts addReferenceOpts

	cmd := &cobra.Command{
		Use:     "add-reference <package> --source-name <name> (--external-id <id> | --href <uri> | --description <text>) [flags]",
		Aliases: []string{"add-ref"},
		Short:   "Reference inert external context (CTI/STIX, advisories, BOMs) in an evidence package",
		Long: `Append an external reference to an HDF evidence package's externalReferences[].

This writes externalReferences[] — inert context that overrides NOTHING. The schema
names CTI/STIX, BOMs and advisories. It is the sibling of 'hdf evidence
add-evidence', which writes externalEvidence[]: native-format material that IS
evidence, such as a log or telemetry corpus indexed by URI and hash. If the artifact
would support or contradict a finding, it is evidence; if it only explains one, it is
a reference.

Nothing here is fetched, resolved or transcoded. A reference records where the
context lives and, when it is a local file, what it hashed to at attach time.

To attach context to a RESULTS document's findings rather than to the package, use
'hdf enrich <results> <bundle>', which matches STIX objects to findings by CVE.

--source-name is required, and so is at least one of --external-id, --href or
--description: External_Reference's own anyOf, the STIX 2.1 rule. sourceName names
the SYSTEM being cited; one of those three identifies or locates what is referenced
within it, so a bare source name cites nothing and is refused.

--kind and --rel are deliberately open strings, not enums: the schema documents
starter vocabularies (kind: threat-intel, annotation; rel: reference, definition,
evidence) and accepts any value, including x- customs, so this command does not
invent validation the schema does not have.

Examples:
  hdf evidence add-reference pkg.json --source-name stix --kind threat-intel --href cti/bundle.json
  hdf evidence add-ref pkg.json --source-name cve --external-id CVE-2021-44228 --rel reference
  hdf evidence add-ref pkg.json --source-name nvd --href https://nvd.nist.gov/vuln/detail/CVE-2021-44228`,
		Args: cobra.ExactArgs(1),
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
		"IANA media type of the referenced artifact; meaningful only with --href")
	cmd.Flags().StringVar(&opts.checksum, "checksum", "",
		"Precomputed SHA-256 hex for a remote --href; a local file is hashed automatically")
	cmd.Flags().StringVarP(&opts.outputPath, "output", "o", "", "Output file (default: overwrite input)")

	return cmd
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
	if opts.checksum != "" && opts.href == "" {
		return fmt.Errorf("--checksum records the digest of the artifact at --href; " +
			"it means nothing without one")
	}
	if opts.mediaType != "" && opts.href == "" {
		return fmt.Errorf("--media-type describes the artifact at --href; it means nothing without one")
	}
	// sourceName names the SYSTEM; the schema additionally requires the reference to
	// identify or locate something within it — an id, a location, or failing both a
	// description. A bare source name cites nothing.
	identity, identityErr := externalReferenceIdentityFields()
	if identityErr != nil {
		return identityErr
	}
	supplied := map[string]string{"externalId": opts.externalID, "href": opts.href, "description": opts.description}
	named := false
	for _, f := range identity {
		if strings.TrimSpace(supplied[f]) != "" {
			named = true
			break
		}
	}
	if !named {
		// Mapped explicitly, and a branch with no flag is reported as the gap it is.
		// Deriving a flag name from a field name by string surgery would advertise a
		// flag that does not exist the moment the schema gains a branch.
		flagFor := map[string]string{"externalId": "--external-id", "href": "--href", "description": "--description"}
		flags := make([]string, 0, len(identity))
		for _, f := range identity {
			flag, known := flagFor[f]
			if !known {
				return fmt.Errorf("the schema's External_Reference now accepts %q to identify a reference, "+
					"but this command has no flag for it; add one", f)
			}
			flags = append(flags, flag)
		}
		return fmt.Errorf("--source-name names the system but nothing identifies what is referenced within it; "+
			"give at least one of %s", strings.Join(flags, ", "))
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
	if opts.href != "" {
		ref["href"] = filepath.ToSlash(opts.href)
		// Reuses add-evidence's resolver so a local file is hashed and a URL is left
		// unhashed by exactly the same rule, rather than a second implementation of it.
		checksum, csErr := resolveEvidenceChecksum(opts.href, opts.checksum)
		if csErr != nil {
			return csErr
		}
		if checksum != "" {
			ref["checksum"] = map[string]interface{}{"algorithm": "sha256", "value": checksum}
		}
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
