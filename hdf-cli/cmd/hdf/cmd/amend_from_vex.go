package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/mitre/hdf-libs/hdf-cli/v3/internal/hdfdoc"
	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	hdfutil "github.com/mitre/hdf-libs/hdf-utilities/go/v3"
	validators "github.com/mitre/hdf-libs/hdf-validators/go/v3"
)

// amendmentsFromVex delegates to the shared hdfdoc.AmendmentsFromVex helper so
// the CLI and the MCP from_vex path use one deterministic VEX→Override_Type
// mapping.
func amendmentsFromVex(data []byte, expiresAt time.Time, converterVersion string) (*hdf.HDFAmendments, error) {
	return hdfdoc.AmendmentsFromVex(data, expiresAt, converterVersion)
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
	expiresAt := hdfutil.ParseTimestamp(resolved)
	if expiresAt.IsZero() {
		return fmt.Errorf("invalid --expires value: %q", resolved)
	}

	data, err := readInputFile(vexPath)
	if err != nil {
		return fmt.Errorf("failed to read VEX file: %w", err)
	}

	doc, err := amendmentsFromVex(data, expiresAt, version)
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
