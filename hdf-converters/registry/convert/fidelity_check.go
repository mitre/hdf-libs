package convert

import (
	"encoding/json"
	"errors"
	"fmt"
)

// CheckRequirementFidelity holds a conversion to the requirement count its
// converter declared for the input. It returns the relation as a note when the
// counts agree, an empty note when the converter declares no relation (or
// states none for this input), and an error when the counts differ: a document
// that lost findings is not a smaller success, it is a failed conversion. Count
// fidelity only — the right count with the wrong severities still passes. Both
// adapters (the CLI and the MCP) run it so a conversion is refused the same way
// on every surface.
func CheckRequirementFidelity(conv Converter, input, output []byte) (string, error) {
	ex, ok := conv.(RequirementCountExpecter)
	if !ok {
		return "", nil
	}
	expected, unit, err := ex.ExpectedRequirementCount(input)
	if errors.Is(err, ErrNoExpectation) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("cannot state the expected requirement count: %w", err)
	}
	produced, err := CountRequirements(output)
	if err != nil {
		return "", fmt.Errorf("cannot count the converted requirements: %w", err)
	}
	if produced != expected {
		return "", fmt.Errorf("conversion lost findings: expected %d %s from the input's %s, produced %d; no output written",
			expected, requirementsWord(expected), unit, produced)
	}
	return fmt.Sprintf("%d %s, matching the input's %s", produced, requirementsWord(produced), unit), nil
}

// CountRequirements totals a document's primary items without decoding
// anything else: requirements across the baselines of a results document,
// the top-level requirements of a baseline, the assessments of a plan, or
// the overrides of an amendments document. A document with none of those
// shapes cannot be checked and is an error rather than a zero.
func CountRequirements(output []byte) (int, error) {
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
	return 0, errors.New("document carries no baselines, requirements, assessments or overrides to count")
}

func requirementsWord(n int) string {
	if n == 1 {
		return "requirement"
	}
	return "requirements"
}
