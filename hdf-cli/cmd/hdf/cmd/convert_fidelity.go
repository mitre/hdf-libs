package cmd

import (
	"fmt"
	"os"

	convreg "github.com/mitre/hdf-libs/hdf-converters/v3/registry/convert"
)

// checkConversionFidelity runs the shared count-fidelity checks — requirements,
// and results for a converter that declares a result relation — and reports the
// outcome the CLI way: the relations on stderr (and on the bulk per-file line),
// a refusal as the command's error. Both sides run because a rolled-up
// converter's requirement count no longer tracks its findings, leaving the
// result count as the only under-extraction guard.
func checkConversionFidelity(converter Converter, input, output []byte, inputPath string) error {
	reqNote, err := convreg.CheckRequirementFidelity(converter, input, output)
	if err != nil {
		return fmt.Errorf("%s: %w", inputPath, err)
	}
	resultNote, err := convreg.CheckResultFidelity(converter, input, output)
	if err != nil {
		return fmt.Errorf("%s: %w", inputPath, err)
	}

	note := joinFidelityNotes(reqNote, resultNote)
	if note == "" {
		if declaresACount(converter) {
			printDebug("%s: converter states no count relation for this input; fidelity not checked", inputPath)
		}
		return nil
	}
	fmt.Fprintf(os.Stderr, "%s: %s\n", inputPath, note)
	// Bulk mode captures this stderr; the note is handed to the bulk runner so
	// the per-file "ok" line still shows the relation.
	fidelityNote = " (" + note + ")"
	return nil
}

// joinFidelityNotes combines the relations the two checks reported, either of
// which may be absent when the converter declared only one of them.
func joinFidelityNotes(requirements, results string) string {
	switch {
	case requirements != "" && results != "":
		return requirements + "; " + results
	case requirements != "":
		return requirements
	default:
		return results
	}
}

// declaresACount reports whether the converter declares either count, so a
// converter that declined to state a relation for this particular input is
// distinguished in the debug log from one that declares none at all.
func declaresACount(converter Converter) bool {
	if _, declares := converter.(RequirementCountExpecter); declares {
		return true
	}
	_, declares := converter.(ResultCountExpecter)
	return declares
}

// fidelityNote is the relation the last successful fidelity check produced,
// for the bulk runner to append to its per-file line. The runner takes it
// after each file; conversions are sequential, so one slot suffices.
var fidelityNote string

// noteLegacySeverityKey marks the per-file bulk line when a spec names a severity
// bucket by a non-category name. The full note goes to stderr, which a bulk run
// captures and discards — so it rides out on the same channel the fidelity
// relation uses, and a directory run still says which files to look at.
func noteLegacySeverityKey(n int) {
	fidelityNote = fmt.Sprintf(" (%d non-category severity %s)", n, plural("key", n))
}

func takeFidelityNote() string {
	n := fidelityNote
	fidelityNote = ""
	return n
}
