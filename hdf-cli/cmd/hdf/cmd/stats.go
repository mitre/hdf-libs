package cmd

import (
	shared "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go"
	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
)

// determineControlStatus derives a display status string from a requirement via
// the canonical effective-status computation in hdf-utilities (a governing
// override, else the worst-wins roll-up — see status-determination.md). Used by
// list, diff, and query commands.
func determineControlStatus(control hdf.EvaluatedRequirement) string {
	return SchemaStatusToDisplay(hdf.ResultStatus(shared.RequirementEffectiveStatus(control)))
}
