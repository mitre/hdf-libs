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

// ResultCountExpecter is the result-side analogue of RequirementCountExpecter,
// and ADR-0017 §6 makes it mandatory for a converter that rolls its requirements
// up: roll-up moves the raw-finding count from the requirements to the results,
// so the requirement count stops tracking the findings and only a result count
// still catches a silent under-extraction. Like the requirement count, it is the
// converter's own statement about its input, never a user flag.
type ResultCountExpecter interface {
	// ExpectedResultCount returns how many results the input must yield and the
	// unit the count is stated in, e.g. "raw findings".
	ExpectedResultCount(input []byte) (count int, unit string, err error)
}

// ExpectedCountFn is the converter-side function behind RequirementCountExpecter
// and ResultCountExpecter.
type ExpectedCountFn func(input []byte) (count int, unit string, err error)

// WithExpectedRequirementCount declares the converter's input-to-requirement
// relation. Converters registered without it are not checked.
func WithExpectedRequirementCount(fn ExpectedCountFn) ConverterOption {
	return func(o *converterOptions) { o.expect = fn }
}

// WithExpectedResultCount declares the converter's input-to-result relation.
// Converters registered without it are not checked — except that
// WithRequirementRollUp refuses to register without it.
func WithExpectedResultCount(fn ExpectedCountFn) ConverterOption {
	return func(o *converterOptions) { o.expectResults = fn }
}

// behaviorAwareConverter is what the expecting wrappers embed: the Converter
// interface plus every optional behaviour declared at registration, so adding a
// fidelity declaration never hides one behind the wrapper.
type behaviorAwareConverter interface {
	Converter
	EmptyInputAccepting
	RequirementRollingUp
}

// resultExpectingConverter adds the result-count declaration to a registered
// converter. Embedding keeps every other optional behaviour intact, and only
// converters that declared a relation ever satisfy ResultCountExpecter.
type resultExpectingConverter struct {
	behaviorAwareConverter
	expectResults ExpectedCountFn
}

func (c *resultExpectingConverter) ExpectedResultCount(input []byte) (int, string, error) {
	return c.expectResults(input)
}

// expectingConverter adds the requirement-count declaration to a registered
// converter.
type expectingConverter struct {
	behaviorAwareConverter
	expect ExpectedCountFn
}

func (c *expectingConverter) ExpectedRequirementCount(input []byte) (int, string, error) {
	return c.expect(input)
}

// bothExpectingConverter carries both declarations. It embeds the result-side
// wrapper by its concrete type rather than by interface, so ExpectedResultCount
// is promoted through it — an interface field would drop the method a converter
// just declared.
type bothExpectingConverter struct {
	*resultExpectingConverter
	expect ExpectedCountFn
}

func (c *bothExpectingConverter) ExpectedRequirementCount(input []byte) (int, string, error) {
	return c.expect(input)
}

// withExpectation wraps c in the wrappers its declarations call for, and returns
// it untouched when it declared neither count. A converter satisfies an expecter
// interface only when it declared that count.
func withExpectation(c behaviorAwareConverter, o converterOptions) Converter {
	switch {
	case o.expect != nil && o.expectResults != nil:
		return &bothExpectingConverter{
			resultExpectingConverter: &resultExpectingConverter{behaviorAwareConverter: c, expectResults: o.expectResults},
			expect:                   o.expect,
		}
	case o.expect != nil:
		return &expectingConverter{behaviorAwareConverter: c, expect: o.expect}
	case o.expectResults != nil:
		return &resultExpectingConverter{behaviorAwareConverter: c, expectResults: o.expectResults}
	}
	return c
}
