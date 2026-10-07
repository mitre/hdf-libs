package tools

import (
	hdfengine "github.com/mitre/hdf-libs/hdf-engine/go/v3"

	"github.com/mitre/hdf-libs/hdf-cli/v3/internal/mcp/contract"
)

// The response shapes this package returns, registered for the ADR-0008 API generator.
//
// Registered here rather than exported: the generator reads the reflected schema from the
// tracked contract golden, so widening this package's API would add surface no consumer
// needs. The diff keys are built from the DiffMode vocabulary so a shape name cannot drift
// from the mode the tool advertises.
func init() {
	contract.RegisterShape("query.concise", conciseRow{})
	// query.full's tags is map[string]any, so its additionalProperties reflects to `true`.
	// Also deliberate: the HDF schema declares tags additionalProperties:true as
	// tool-specific metadata, so the contract would be lying to constrain it. NOTE for
	// ADR-0008 Phase 2, whose generator hard-fails on a non-document schema without
	// additionalProperties:false — this shape will trip that rule and needs an allowlist
	// entry there, or the operation must reference the document schema instead.
	contract.RegisterShape("query.full", fullRow{})

	// The two .full shapes carry fieldChanges[], whose oldValue/newValue reflect to a bare
	// `true` — any JSON value. That is deliberate and not a widening: a field change can be
	// on ANY requirement or component field, so the value is whatever that field holds, and
	// typing it would mean a union of every type in the HDF schema. Recorded here because
	// the card's decision point asks for a decision, not an unexplained blob; the leaves are
	// listed in TestContractGolden_NoUnrecordedUntypedLeaf so a SIXTH one fails.
	contract.RegisterShape("diff."+string(DiffModeTemporal)+".concise", temporalConcise{})
	contract.RegisterShape("diff."+string(DiffModeTemporal)+".full", temporalFull{})
	contract.RegisterShape("diff."+string(DiffModeSystemDrift)+".concise", componentConcise{})
	contract.RegisterShape("diff."+string(DiffModeSystemDrift)+".full", componentFull{})

	contract.RegisterShape("convert.batch.entry", fileConvertSummary{})

	// Per-docType open summaries. The four document types with no summary are recorded in
	// summarylessDocTypes with the reason, and TestOpenSummaries_EveryDocTypeAccountedFor
	// fails if one is neither here nor there.
	contract.RegisterShape("open.summary.results", resultsOpenSummary{})
	contract.RegisterShape("open.summary.baseline", baselineOpenSummary{})
	contract.RegisterShape("open.summary.system", systemOpenSummary{})
	contract.RegisterShape("open.summary.plan", planOpenSummary{})

	// Owned by hdf-engine, registered here because a library must not import this
	// server's internals. Both cross a tool boundary: a compliance roll-up returns the
	// counts, and a threshold verdict is evaluated against the config.
	contract.RegisterShape("engine.statusCounts", hdfengine.StatusCounts{})
	contract.RegisterShape("engine.thresholdConfig", hdfengine.ThresholdConfig{})
}
