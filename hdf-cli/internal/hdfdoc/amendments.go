package hdfdoc

import (
	"fmt"
	"time"

	openvex "github.com/mitre/hdf-libs/hdf-converters/v3/converters/openvex-to-hdf/go"
	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
)

// AmendmentsFromVex builds an additive hdf-amendments document from an OpenVEX
// document via the shared, deterministic VEX→Override_Type mapping (reusing the
// openvex-to-hdf converter), then applies the two policies the converter does
// not: every emitted override is stamped appliedBy.type = system (a
// deterministic mapping is not agent judgment — ADR-0007 §2/§4), and its
// expiresAt is the caller-supplied value (never a fabricated default). Shared by
// the CLI `hdf amend create --from-vex` and the MCP hdf_author from_vex path so
// the mapping lives in one place.
func AmendmentsFromVex(data []byte, expiresAt time.Time, converterVersion string) (*hdf.HDFAmendments, error) {
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
