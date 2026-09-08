package cmd

import (
	"encoding/json"
	"fmt"
	"os"
)

// checkRequirementFidelity refuses a conversion whose output carries a
// different number of requirements than the converter declared its input must
// yield. It runs on every conversion whose converter declares a relation, with
// no flag in either direction: a document that lost findings is not a smaller
// success, it is a failed conversion. Count fidelity only — a document with
// the right count and the wrong severities still passes.
func checkRequirementFidelity(ex RequirementCountExpecter, input, output []byte, inputPath string) error {
	expected, unit, err := ex.ExpectedRequirementCount(input)
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
	fmt.Fprintf(os.Stderr, "%s: %d %s, matching the input's %s\n", inputPath, produced, requirementsWord(produced), unit)
	return nil
}

// countRequirements totals the requirements across every baseline of an HDF
// results document without decoding anything else.
func countRequirements(output []byte) (int, error) {
	var doc struct {
		Baselines []struct {
			Requirements []json.RawMessage `json:"requirements"`
		} `json:"baselines"`
	}
	if err := json.Unmarshal(output, &doc); err != nil {
		return 0, err
	}
	n := 0
	for _, b := range doc.Baselines {
		n += len(b.Requirements)
	}
	return n, nil
}

func requirementsWord(n int) string {
	if n == 1 {
		return "requirement"
	}
	return "requirements"
}
