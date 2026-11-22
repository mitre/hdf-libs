//nolint:dupl
package cmd

import (
	"fmt"
	"path/filepath"

	"github.com/mitre/hdf-libs/hdf-cli/v3/internal/evidenceref"
	"github.com/spf13/cobra"
)

func newEvidenceSetCmd() *cobra.Command {
	var (
		name        string
		description string
		packageID   string
		systemRef   string
		planRef     string
		docVersion  string
		outputPath  string
		unsetFields []string
	)

	cmd := &cobra.Command{
		Use:   "set <file>",
		Short: "Set, update, or unset top-level fields on an HDF evidence package",
		Long: `Set, update, or remove top-level metadata fields on an existing HDF evidence package.
Reads the file, applies the specified changes, and writes it back (or to -o).

Use --unset to remove optional fields. Required fields (name, contents) cannot be unset.

--system-ref and --plan-ref are recorded as references read by whoever opens the package, not as
paths on this machine: an absolute path resolving INSIDE the package's directory is recorded
relative to the package, exactly as 'hdf evidence build' records one. A reference to something
the package does not contain — an absolute path elsewhere, a parent traversal, or a remote URI —
keeps the location given, because relocating it would claim the artifact is somewhere it is not.
An absolute path is still escaped into a legal uri-reference; only its target is left alone.

An ABSOLUTE value is treated as a path on this machine and recorded as a uri-reference, so a
name needing escapes is escaped for you. A RELATIVE value is treated as a reference already
and recorded as you wrote it, so write it the way the format admits ('my%20scans/sys.json',
not 'my scans/sys.json'): an unescaped spelling is refused rather than recorded, because it
is not a legal uri-reference and the package would fail its own schema.

Examples:
  hdf evidence set evidence.json --name "Q2 2026 Evidence"
  hdf evidence set evidence.json --package-id "550e8400-..."
  hdf evidence set evidence.json --system-ref portal-prod.hdf-system.json
  hdf evidence set evidence.json --plan-ref quarterly-plan.hdf-plan.json
  hdf evidence set evidence.json --unset description -o updated.json`,
		Args: evidencePackageArg,
		RunE: func(_ *cobra.Command, args []string) error {
			if name == "" && description == "" && packageID == "" && systemRef == "" && planRef == "" && docVersion == "" && len(unsetFields) == 0 {
				return fmt.Errorf("at least one field flag is required (--name, --description, --package-id, --system-ref, --plan-ref, --version, --unset)")
			}
			if err := requireOutputForStdinPackage(args[0], outputPath); err != nil {
				return err
			}
			// Normalized against the INPUT package's directory, which is where the documents
			// sit (for a stdin package, the -o file's). Whether -o moving the package should
			// re-base its references is a separate question, not settled here.
			pkgDir := evidencePackageDir(args[0], outputPath)
			sysRef, err := packageRelativeIfInside(pkgDir, systemRef)
			if err != nil {
				return fmt.Errorf("--system-ref %w", err)
			}
			plRef, err := packageRelativeIfInside(pkgDir, planRef)
			if err != nil {
				return fmt.Errorf("--plan-ref %w", err)
			}
			return runGenericDocSet(args[0], outputPath, "evidence-package", unsetFields, requiredEvidenceFields, map[string]string{
				"name":        name,
				"description": description,
				"packageId":   packageID,
				"systemRef":   sysRef,
				"planRef":     plRef,
				"version":     docVersion,
			})
		},
	}

	cmd.Flags().StringVar(&name, "name", "", "Package name")
	cmd.Flags().StringVar(&description, "description", "", "Package description")
	cmd.Flags().StringVar(&packageID, "package-id", "", "Package UUID")
	cmd.Flags().StringVar(&systemRef, "system-ref", "", "URI to the target HDF system document")
	cmd.Flags().StringVar(&planRef, "plan-ref", "", "URI to the assessment plan document")
	cmd.Flags().StringVar(&docVersion, "version", "", "Package version")
	cmd.Flags().StringArrayVar(&unsetFields, "unset", nil, "Remove a field (repeatable)")
	cmd.Flags().StringVarP(&outputPath, "output", "o", "", "Output file (default: overwrite input)")

	return cmd
}

var requiredEvidenceFields = map[string]bool{
	"name":     true,
	"contents": true,
}

// packageRelativeIfInside rewrites an ABSOLUTE reference resolving inside the package's
// directory to the package-relative form `build` already records, and returns anything
// else untouched. A reference is data read by whoever opens the package, not a path on the
// machine that wrote it, so a machine-local absolute path does not survive being handed on
// — it bundles into an archive carrying the file under a relative name while the package
// still names the original path. A reference pointing OUTSIDE the package is a legitimate
// external reference by standing decision and keeps the location given: relocating it
// would claim the artifact is somewhere it is not. Its spelling is still escaped, because
// an absolute value is a path. Resolution goes through
// packageSubtreeRef, the one predicate bundle and verify already use.
// THE SPLIT IS THE CONTRACT, decided deliberately (maintainer, 2026-10-13): an ABSOLUTE
// value is a path on this machine, so it is resolved, relativized and ENCODED into a
// uri-reference; a RELATIVE value is already a reference and is recorded as given.
//
// Why not encode a relative value too, which would make every recorded reference
// schema-perfect: an operator who correctly passes "my%20scans/sys.json" would get
// "my%2520scans/sys.json", a double-encode and a worse defect than the one it fixes.
// Telling a raw path from an encoded reference requires inferring from whether the value
// contains a %, which this package's anti-patterns forbid outright — it would make what
// is recorded depend on the filename.
//
// So a relative value is CHECKED and refused when uri-reference does not admit it
// (maintainer, 2026-11-21, superseding the 2026-10-13 decision to record it anyway).
// That decision declined refusing because the unescaped spelling worked; it worked only
// in Go, because the shipped TypeScript validator always refused it, so such a package
// was already invalid to half this toolchain. Both validators now implement RFC 3986, so
// writing one fails validation either way — refusing, and naming the encoding, is the
// actionable form of the same outcome.
//
// A value that is not valid UTF-8 is refused in every shape: no reference can carry it,
// and encoding/json would rewrite its bytes to U+FFFD, recording a different name.
func packageRelativeIfInside(pkgDir, ref string) (string, error) {
	if err := evidenceref.Recordable(ref); err != nil {
		return "", fmt.Errorf("%q cannot be recorded as a reference: %w", ref, err)
	}
	if ref == "" || isRemoteURI(ref) || !filepath.IsAbs(ref) {
		if err := evidenceref.RecordableAsGiven(ref); err != nil {
			return "", fmt.Errorf("%q cannot be recorded as a reference: %w", ref, err)
		}
		return ref, nil
	}
	// Decoded before resolving and re-encoded by nothing: what this returns is a
	// reference to RECORD, and recording the decoded form would write a value the schema
	// calls malformed if the name contains a character uri-reference does not admit.
	// So a reference that resolves inside the package is rewritten to its relative form
	// only when that form needs no escaping — otherwise the absolute spelling stands,
	// which the caller already reports.
	decoded, decErr := evidenceref.Decode(ref)
	if decErr == nil {
		if resolved, ok := packageSubtreeRef(pkgDir, decoded); ok {
			// RE-ENCODED, because what this returns is a reference to RECORD and the field
			// is a uri-reference: writing the decoded form would store a value the schema
			// calls malformed the moment the name contains a space. Per SEGMENT, since
			// PathEscape escapes a separator too — escaping the whole path turned every
			// "scans/x.json" into "scans%2Fx.json", which silently stopped normalizing.
			return encodeRef(ref, string(resolved))
		}
		// Outside the package the LOCATION stands, but the spelling is still a path's, so
		// it is encoded too: an absolute name carrying a space was otherwise recorded in a
		// form uri-reference does not admit, and the write then failed with a bare schema
		// error instead of the escaping the operator needed.
		return encodeRef(ref, filepath.ToSlash(string(decoded)))
	}
	// Its % introduces no escape, so it is a literal percent in a filename — encoded as it
	// stands, which is the only spelling in which such a name is expressible at all.
	return encodeRef(ref, filepath.ToSlash(ref))
}
