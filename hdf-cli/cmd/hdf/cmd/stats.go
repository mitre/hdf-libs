package cmd

import (
	"time"

	shared "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go"
	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	hdfutil "github.com/mitre/hdf-libs/hdf-utilities/go/v3"
)

// determineControlStatus derives a display status string from a requirement
// via the canonical effective-status computation in hdf-utilities (impact==0,
// governing override, stored effectiveStatus, worst-wins rollup — see
// status-determination.md). Used by list, diff, and query commands.
func determineControlStatus(control hdf.EvaluatedRequirement) string {
	status := hdfutil.ComputeEffectiveStatus(shared.RequirementStatusInput(control), time.Time{})
	return SchemaStatusToDisplay(hdf.ResultStatus(status))
}
