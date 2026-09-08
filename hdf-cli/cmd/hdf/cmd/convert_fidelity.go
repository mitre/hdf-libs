package cmd

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"

	convreg "github.com/mitre/hdf-libs/hdf-converters/v3/registry/convert"
)

// checkRequirementFidelity refuses a conversion whose output carries a
// different number of requirements than the converter declared its input must
// yield. It runs on every conversion whose converter declares a relation, with
// no flag in either direction: a document that lost findings is not a smaller
// success, it is a failed conversion. Count fidelity only — a document with
// the right count and the wrong severities still passes.
func checkRequirementFidelity(ex RequirementCountExpecter, input, output []byte, inputPath string) error {
	expected, unit, err := ex.ExpectedRequirementCount(input)
	if errors.Is(err, convreg.ErrNoExpectation) {
		printDebug("%s: converter states no requirement-count relation for this input; fidelity not checked", inputPath)
		return nil
	}
	if err != nil {
		return fmt.Errorf("%s: cannot state the expected requirement count: %w", inputPath, err)
	}
	produced, err := countRequirements(output)
	if err != nil {
		return fmt.Errorf("%s: cannot count the converted requirements: %w", inputPath, err)
	}
	if produced != expected {
		return fmt.Errorf("%s: conversion lost findings: expected %d %s from the input's %s, produced %d; no output written",
			inputPath, expected, requirementsWord(expected), unit, produced)
	}
	relation := fmt.Sprintf("%d %s, matching the input's %s", produced, requirementsWord(produced), unit)
	fmt.Fprintf(os.Stderr, "%s: %s\n", inputPath, relation)
	// Bulk mode captures this stderr; the note is handed to the bulk runner so
	// the per-file "ok" line still shows the relation.
	fidelityNote = " (" + relation + ")"
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

// countRequirements totals a document's primary items without decoding
// anything else: requirements across the baselines of a results document,
// the top-level requirements of a baseline, the assessments of a plan, or
// the overrides of an amendments document. A document with none of those
// shapes cannot be checked and is an error rather than a zero.
func countRequirements(output []byte) (int, error) {
	var doc struct {
		Baselines []struct {
			Requirements []json.RawMessage `json:"requirements"`
		} `json:"baselines"`
		Requirements []json.RawMessage `json:"requirements"`
		Assessments  []json.RawMessage `json:"assessments"`
		Overrides    []json.RawMessage `json:"overrides"`
	}
	if err := json.Unmarshal(output, &doc); err != nil {
		return 0, err
	}
	switch {
	case doc.Baselines != nil:
		n := 0
		for _, b := range doc.Baselines {
			n += len(b.Requirements)
		}
		return n, nil
	case doc.Requirements != nil:
		return len(doc.Requirements), nil
	case doc.Assessments != nil:
		return len(doc.Assessments), nil
	case doc.Overrides != nil:
		return len(doc.Overrides), nil
	}
	return 0, fmt.Errorf("document carries no baselines, requirements, assessments or overrides to count")
}

func requirementsWord(n int) string {
	if n == 1 {
		return "requirement"
	}
	return "requirements"
}
