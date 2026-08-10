package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	openvex "github.com/mitre/hdf-libs/hdf-converters/v3/converters/openvex-to-hdf/go"
	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	validators "github.com/mitre/hdf-libs/hdf-validators/go/v3"
)

// amendmentsFromVex builds an additive hdf-amendments document from an OpenVEX
// document via the shared, deterministic VEX→Override_Type mapping (reusing the
// openvex-to-hdf converter), then applies the two amend-command policies the
// converter does not: every emitted override is stamped appliedBy.type = system
// (a deterministic mapping is not agent judgment — ADR §2/§4), and its expiresAt
// is the caller-supplied value (never a fabricated default — v3.5.0/#195).
func amendmentsFromVex(data []byte, expiresAt time.Time, converterVersion string) (*hdf.HDFAmendments, error) {
	doc, err := openvex.ConvertOpenVEXToHDF(data, converterVersion)
	if err != nil {
		// Covers both a malformed document and one with no actionable statements
		// (all affected/under_investigation) — the converter reports each, and
		// never returns a success with an empty override set.
		return nil, fmt.Errorf("cannot build amendments from VEX: %w", err)
	}
	for i := range doc.Overrides {
		doc.Overrides[i].ExpiresAt = expiresAt
		doc.Overrides[i].AppliedBy.Type = hdf.IdentityTypeSystem
	}
	return doc, nil
}

// runAmendFromVex is the `hdf amend create --from-vex` path: resolve the required
// expiry, convert the VEX document, validate, and write.
func runAmendFromVex(vexPath, expires, outputPath string) error {
	resolved, err := resolveDraftExpiry(expires, time.Now().UTC())
	if err != nil {
		return err
	}
	if resolved == "" {
		return fmt.Errorf("--from-vex requires --expires (RFC3339, YYYY-MM-DD, or a duration like 30d/6m/1y); the mapping never fabricates a default expiry")
	}
	expiresAt, err := time.Parse(time.RFC3339, resolved)
	if err != nil {
		return fmt.Errorf("invalid --expires value: %w", err)
	}

	data, err := readInputFile(vexPath)
	if err != nil {
		return fmt.Errorf("failed to read VEX file: %w", err)
	}

	doc, err := amendmentsFromVex(data, expiresAt.UTC(), version)
	if err != nil {
		return err
	}

	output, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to serialize amendments: %w", err)
	}
	if res := validators.ValidateAmendments(output); !res.Valid {
		return fmt.Errorf("generated amendments failed schema validation: %s", res.Error())
	}

	if outputPath == "" {
		fmt.Println(string(output))
		return nil
	}
	if err := os.WriteFile(outputPath, append(output, '\n'), 0o600); err != nil { //nolint:gosec // CLI writes a user-provided path
		return fmt.Errorf("failed to write amendments: %w", err)
	}
	fmt.Fprintf(os.Stderr, "Created %s with %d amendments from VEX\n", outputPath, len(doc.Overrides))
	return nil
}
