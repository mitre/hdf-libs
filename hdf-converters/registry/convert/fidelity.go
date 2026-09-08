package convert

import "errors"

// ErrNoExpectation is returned by a converter's ExpectedRequirementCount for an
// input it converts but cannot state a relation for — a dispatching converter
// whose delegate emits a document with no primary items (an hdf-system from an
// OSCAL SSP). The convert command then skips the check for that file, and says
// so in debug output; it is the converter's statement, never a user flag.
var ErrNoExpectation = errors.New("no requirement-count relation for this input")

// RequirementCountExpecter is an optional interface a converter implements when
// its input alone determines how many requirements the output must carry. The
// convert command compares the declaration with the produced document and
// refuses a document that lost findings: a conversion that quietly shrinks is
// otherwise indistinguishable from a clean scan. The count is the converter's
// own statement of its grouping (one per finding, one per rule, plus any
// synthesized requirements), computed from the input without converting it.
type RequirementCountExpecter interface {
	// ExpectedRequirementCount returns how many requirements the input must
	// yield and the unit the count is stated in, e.g. "distinct SARIF rules".
	ExpectedRequirementCount(input []byte) (count int, unit string, err error)
}

// ExpectedCountFn is the converter-side function behind RequirementCountExpecter.
type ExpectedCountFn func(input []byte) (count int, unit string, err error)

// WithExpectedRequirementCount declares the converter's input-to-requirement
// relation. Converters registered without it are not checked.
func WithExpectedRequirementCount(fn ExpectedCountFn) ConverterOption {
	return func(o *converterOptions) { o.expect = fn }
}

// expectingConverter adds the declaration to a standard results converter.
// Embedding keeps every other optional behaviour (AcceptsEmptyInput) intact,
// and only converters that declared a relation ever satisfy the interface.
type expectingConverter struct {
	*hdfResultsConverter
	expect ExpectedCountFn
}

func (c *expectingConverter) ExpectedRequirementCount(input []byte) (int, string, error) {
	return c.expect(input)
}

// withExpectation wraps c when a relation was declared, else returns c as is.
func withExpectation(c *hdfResultsConverter, o converterOptions) Converter {
	if o.expect == nil {
		return c
	}
	return &expectingConverter{hdfResultsConverter: c, expect: o.expect}
}

// expectingTypedConverter adds the declaration to a baseline, plan or
// amendments converter. Those wrappers carry no other optional behaviour, so
// one wrapper over the Converter interface serves all three; the results
// wrapper stays separate to keep AcceptsEmptyInput reachable.
type expectingTypedConverter struct {
	Converter
	expect ExpectedCountFn
}

func (c *expectingTypedConverter) ExpectedRequirementCount(input []byte) (int, string, error) {
	return c.expect(input)
}

// withTypedExpectation wraps c when a relation was declared, else returns c as is.
func withTypedExpectation(c Converter, o converterOptions) Converter {
	if o.expect == nil {
		return c
	}
	return &expectingTypedConverter{Converter: c, expect: o.expect}
}
