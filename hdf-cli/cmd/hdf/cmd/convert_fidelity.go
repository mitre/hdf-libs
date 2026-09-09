package cmd

import (
	"fmt"
	"os"

	convreg "github.com/mitre/hdf-libs/hdf-converters/v3/registry/convert"
)

// checkRequirementFidelity runs the shared count-fidelity check and reports
// its outcome the CLI way: the relation on stderr (and on the bulk per-file
// line), a refusal as the command's error.
func checkRequirementFidelity(converter Converter, input, output []byte, inputPath string) error {
	note, err := convreg.CheckRequirementFidelity(converter, input, output)
	if err != nil {
		return fmt.Errorf("%s: %w", inputPath, err)
	}
	if note == "" {
		if _, declares := converter.(RequirementCountExpecter); declares {
			printDebug("%s: converter states no requirement-count relation for this input; fidelity not checked", inputPath)
		}
		return nil
	}
	fmt.Fprintf(os.Stderr, "%s: %s\n", inputPath, note)
	// Bulk mode captures this stderr; the note is handed to the bulk runner so
	// the per-file "ok" line still shows the relation.
	fidelityNote = " (" + note + ")"
	return nil
}

// fidelityNote is the relation the last successful fidelity check produced,
// for the bulk runner to append to its per-file line. The runner takes it
// after each file; conversions are sequential, so one slot suffices.
var fidelityNote string

func takeFidelityNote() string {
	n := fidelityNote
	fidelityNote = ""
	return n
}
