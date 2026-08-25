package shared

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"testing"

	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	testhdf "github.com/mitre/hdf-libs/hdf-schema/testhdf/go"
	"github.com/stretchr/testify/require"
)

// CorpusContract is the obligation an exporter owes for one corpus input.
//
// A single "HDF-invalid input must be rejected" rule conflated two different
// obligations. A document whose TOP-LEVEL shape is wrong is not the document
// type it claims to be, and refusing it is the only honest outcome. A document
// that is merely wrong in NESTED content is something no converter validates —
// the shared structural guard is deliberately top-level only, and full
// per-conversion schema validation was never the design — so demanding rejection
// there asserted something no converter satisfies, which forced per-converter
// exemptions. Exemptions that accumulate quietly are how a corpus stops meaning
// anything, so the distinction belongs to the case, not to each converter.
type CorpusContract int

const (
	// MustConvert marks sparse but schema-valid HDF: the exporter must convert
	// it, and the output must satisfy the target schema. Refusing legal input is
	// as much a defect as emitting an invalid document for it.
	MustConvert CorpusContract = iota

	// MustReject marks input whose top-level shape the HDF schema rejects — a
	// missing, null, or wrong-typed required collection, or a document that is
	// not an object at all. The exporter must return an error.
	MustReject

	// MustNotCorrupt marks input the HDF schema rejects only in nested content.
	// Either outcome is acceptable — converting it is tolerant, refusing it is
	// strict — but if the exporter does convert, the output must still satisfy
	// the target schema. This is the weaker contract that nested cases can
	// actually be held to, and it still catches the two real defects this class
	// has found: a converter that panics, and one that emits an invalid document.
	MustNotCorrupt
)

// String renders the contract for failure output.
func (c CorpusContract) String() string {
	switch c {
	case MustConvert:
		return "MustConvert"
	case MustReject:
		return "MustReject"
	case MustNotCorrupt:
		return "MustNotCorrupt"
	}
	return "unknown"
}

// CorpusCase is one adversarial exporter input. Every shipped defect this corpus
// exists to catch sat in one of the three contracts above, and a test suite that
// only feeds fully-populated fixtures exercises none of them.
type CorpusCase struct {
	Name string
	// Input is the raw exporter input.
	Input []byte
	// Contract is the obligation the exporter owes for this input. Derived
	// observably rather than asserted: TestCorpusContracts_AreDerivableFromTheSchemaAndGuard
	// checks each case against the real HDF schema AND the shared top-level
	// guard, so a case cannot be quietly reclassified to make a converter pass.
	Contract CorpusContract
	// Why records what the case is probing, surfaced in failure output.
	Why string
}

// mustJSON marshals a builder-produced document. A build-time marshal failure is
// a corpus bug, not a converter bug, so it panics rather than taking a *testing.T
// through every corpus constructor.
func mustJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic("schemacorpus: marshal corpus case: " + err.Error())
	}
	return b
}

// withTimestamp stamps the deterministic builder time onto a document so that
// cases probing some other absent field are not silently also probing a missing
// timestamp. Fixed, never wall-clock, per the repo timestamp convention.
func withTimestamp(d hdf.HDFResults) hdf.HDFResults {
	ts := testhdf.DefaultStartTime
	d.Timestamp = &ts
	return d
}

// ResultsCorpus returns the adversarial HDF Results inputs every exporter that
// consumes HDF Results should survive.
//
// MustConvert cases are built with the testhdf builder wherever it can express
// the case. The
// one exception is zero-baselines: Go's variadic testhdf.Doc() leaves Baselines
// nil, and HDFResults.Baselines carries no omitempty, so it marshals to null
// rather than []. It is therefore stated as a typed struct literal — never hand
// written JSON. (The TS peer has no such problem: a JS rest parameter yields [],
// so schema-corpus.ts uses testhdf.doc() directly. The asymmetry is real, not an
// oversight on either side.)
//
// Each MustConvert case isolates exactly one absent field, so a failure names the
// cause. Two cases differing only in a field neither exercises would double the
// runtime and halve the signal.
func ResultsCorpus() []CorpusCase {
	gen := &hdf.Generator{Name: "testhdf", Version: "0.0.0"}

	return []CorpusCase{
		// --- MustConvert: sparse but schema-valid HDF.
		{
			Name:     "zero-baselines",
			Input:    mustJSON(hdf.HDFResults{Baselines: []hdf.EvaluatedBaseline{}, Generator: gen}),
			Contract: MustConvert,
			Why:      "baselines has no minItems, so an assessment that evaluated nothing is legal HDF",
		},
		{
			Name: "no-timestamp",
			// Everything else populated, so a failure here is unambiguously the timestamp.
			Input: mustJSON(testhdf.Results(testhdf.Req("V-1",
				testhdf.Title("t"), testhdf.Severity("medium"), testhdf.Code("c")))),
			Contract: MustConvert,
			Why:      "timestamp is optional in HDF but feeds target fields that are required (XCCDF end-time)",
		},
		{
			Name: "requirement-without-title",
			Input: mustJSON(withTimestamp(testhdf.Results(testhdf.Req("V-1",
				testhdf.Severity("medium"), testhdf.Code("c"))))),
			Contract: MustConvert,
			Why:      "title is optional in HDF but backs target title fields that are often minLength-constrained",
		},
		{
			Name: "requirement-without-code",
			Input: mustJSON(withTimestamp(testhdf.Results(testhdf.Req("V-1",
				testhdf.Title("t"), testhdf.Severity("medium"))))),
			Contract: MustConvert,
			Why:      "absent code must omit the check element entirely, not emit an empty one",
		},
		{
			Name: "requirement-with-non-token-id",
			// Every other MustConvert case uses an id that happens to satisfy
			// OSCAL's token pattern, which is why an exporter copying ids into a
			// token-typed field passed the corpus while failing on 46% of the
			// converters' fixture ids. A package-style id is the commonest
			// non-token shape in real data.
			Input: mustJSON(withTimestamp(testhdf.Results(testhdf.Req("CVE-2018-25032/ruby:nokogiri/1.10.9",
				testhdf.Title("t"), testhdf.Severity("medium"), testhdf.Code("c"))))),
			Contract: MustConvert,
			Why:      "requirement ids are whatever the source tool numbers rules with; target formats often constrain them lexically",
		},
		{
			Name: "requirement-without-severity",
			Input: mustJSON(withTimestamp(testhdf.Results(testhdf.Req("V-1",
				testhdf.Title("t"), testhdf.Code("c"))))),
			Contract: MustConvert,
			Why:      "severity is optional in HDF but target formats constrain it to a fixed vocabulary",
		},

		// --- MustReject: the top-level shape is wrong, so this is not a results
		// document at all. MustNotCorrupt: the top level is fine and only nested
		// content is invalid, which no converter validates.
		{
			Name:     "baselines-missing",
			Input:    []byte(`{"generator":{"name":"t","version":"0.0.0"}}`),
			Contract: MustReject,
			Why:      "baselines is the one required top-level field",
		},
		{
			Name:     "baselines-null",
			Input:    []byte(`{"baselines":null}`),
			Contract: MustReject,
			Why:      "a nil slice marshals to null, so an upstream producer with this bug must be rejected",
		},
		{
			Name:     "baselines-wrong-type",
			Input:    []byte(`{"baselines":"not-an-array"}`),
			Contract: MustReject,
			Why:      "a typed decode can coerce or zero-fill where a structural guard must reject",
		},
		{
			Name:     "baseline-empty-requirements",
			Input:    []byte(`{"baselines":[{"name":"b","requirements":[]}]}`),
			Contract: MustNotCorrupt,
			Why:      "requirements has minItems 1; exporters that map it unguarded emit empty container elements",
		},
		{
			Name:     "requirement-empty-results",
			Input:    []byte(`{"baselines":[{"name":"b","requirements":[{"id":"V-1","impact":0,"tags":{},"descriptions":[{"label":"default","data":"d"}],"results":[]}]}]}`),
			Contract: MustNotCorrupt,
			Why:      "results has minItems 1; exporters that index results[0] unguarded panic",
		},
		{
			Name:     "requirement-missing-id",
			Input:    []byte(`{"baselines":[{"name":"b","requirements":[{"impact":0,"tags":{},"descriptions":[{"label":"default","data":"d"}],"results":[{"status":"passed","codeDesc":"c","startTime":"2020-01-01T00:00:00Z"}]}]}]}`),
			Contract: MustNotCorrupt,
			Why:      "id is required; absent it, exporters emit empty-string identifiers into required target fields",
		},
		{
			Name:     "top-level-array",
			Input:    []byte(`[]`),
			Contract: MustReject,
			Why:      "the one degenerate shape most exporters already reject — pins that they keep doing so",
		},
	}
}

// AmendmentsCorpus returns the adversarial HDF Amendments inputs every exporter
// that consumes HDF Amendments should survive.
func AmendmentsCorpus() []CorpusCase {
	const cve = "CVE-2021-44228"

	return []CorpusCase{
		// --- MustConvert: sparse but schema-valid HDF Amendments.
		{
			Name: "override-empty-reason",
			Input: mustJSON(testhdf.Amendments("a",
				testhdf.Override(hdf.OverrideTypeWaiver, cve,
					testhdf.OverrideStatus(hdf.Failed), testhdf.OverrideReason("")))),
			Contract: MustConvert,
			Why:      "reason carries no minLength, but backs target fields that require non-empty text",
		},
		{
			Name: "override-no-milestones",
			Input: mustJSON(testhdf.Amendments("a",
				testhdf.Override(hdf.OverrideTypeWaiver, cve,
					testhdf.OverrideStatus(hdf.Failed), testhdf.OverrideReason("accepted")))),
			Contract: MustConvert,
			Why:      "milestones are optional; without them remediation text must still be derivable",
		},
		{
			Name:     "evidence-without-description",
			Input:    amendmentsWithBareEvidence(cve),
			Contract: MustConvert,
			Why:      "evidence description is optional but backs CSAF references[].summary, which is minLength 1",
		},

		// --- MustReject: the top-level shape is wrong.
		{
			Name:     "overrides-missing",
			Input:    []byte(`{"name":"a"}`),
			Contract: MustReject,
			Why:      "overrides is required alongside name",
		},
		{
			Name:     "overrides-empty",
			Input:    []byte(`{"name":"a","overrides":[]}`),
			Contract: MustReject,
			Why:      "overrides has minItems 1, so an amendments document that amends nothing is not convertible",
		},
		{
			Name:     "top-level-array",
			Input:    []byte(`[]`),
			Contract: MustReject,
			Why:      "pins that the structural guard rejects a non-object document",
		},
	}
}

// amendmentsWithBareEvidence builds an override carrying url evidence with no
// description. testhdf.Override exposes no evidence option, so the override is
// finished by hand here rather than hand-writing the whole document as JSON —
// keeping the builder's schema-valid scaffolding (appliedAt, expiresAt, identity)
// which is exactly the part that is tedious and easy to get wrong.
func amendmentsWithBareEvidence(reqID string) []byte {
	doc := testhdf.Amendments("a",
		testhdf.Override(hdf.OverrideTypeWaiver, reqID,
			testhdf.OverrideStatus(hdf.Failed), testhdf.OverrideReason("accepted")))
	doc.Overrides[0].Evidence = []hdf.Evidence{{
		Type: hdf.URL,
		Data: "https://example.com/advisory",
	}}
	return mustJSON(doc)
}

// CorpusConvertFn is an exporter entry point taking raw HDF bytes and returning
// its rendered output.
type CorpusConvertFn func(input []byte) ([]byte, error)

// DocumentValidator is the contract the corpus needs from a target-format
// validator: report a document's violations without failing a test. Both the
// JSON Schema validator and the XSD one satisfy it, so a converter whose target
// is an XSD (XCCDF) reuses the same corpus as the JSON-schema converters.
type DocumentValidator interface {
	Validate(doc []byte) error
}

// CheckCase applies the corpus contract to a single case and returns the reason
// it failed, or "" when it passes.
//
// The contract lives here, as a pure function, rather than inline in the
// t.Run loop: assertions buried in a subtest closure cannot be exercised without
// a real *testing.T, so the runner's own logic would go untested — and it was
// exactly an untested branch (a panic satisfying a rejection contract) that
// shipped broken.
//
// A panic fails EVERY contract and is checked before the contract switch. A
// panic is a crash, not a rejection, so letting it satisfy MustReject or
// MustNotCorrupt would green-light the precise defect those contracts exist to
// catch (an unguarded results[0] index is the live example).
func CheckCase(v DocumentValidator, c CorpusCase, convert CorpusConvertFn) string {
	out, err := convertNoPanic(convert, c.Input)

	var panicked *PanicError
	if errors.As(err, &panicked) {
		return fmt.Sprintf("%s: %v (%s)", c.Name, panicked, c.Why)
	}

	switch c.Contract {
	case MustConvert:
		if err != nil {
			return fmt.Sprintf("%s: schema-valid HDF must convert (%s): %v", c.Name, c.Why, err)
		}
		if verr := v.Validate(out); verr != nil {
			return fmt.Sprintf("%s: output does not satisfy the target schema (%s):\n%v", c.Name, c.Why, verr)
		}
		return ""

	case MustReject:
		if err == nil {
			return fmt.Sprintf("%s: input whose top-level shape HDF rejects must not be converted (%s)", c.Name, c.Why)
		}
		return ""

	case MustNotCorrupt:
		// Rejecting is fine: no converter validates nested content, so tolerance
		// and strictness are both defensible. What is never acceptable is
		// converting it into a document the target schema rejects.
		if err != nil {
			return ""
		}
		if verr := v.Validate(out); verr != nil {
			return fmt.Sprintf("%s: converted nested-invalid HDF into output the target schema rejects (%s):\n%v", c.Name, c.Why, verr)
		}
		return ""
	}
	return fmt.Sprintf("%s: unknown contract %v", c.Name, c.Contract)
}

// ValidateCorpus reports why a corpus cannot be meaningfully run, or nil when it
// can. Pure, like CheckCase, so the guard itself is testable — an assertion that
// only exists inside a t.Run closure cannot be exercised without failing the test
// that exercises it.
func ValidateCorpus(cases []CorpusCase) error {
	if len(cases) == 0 {
		return errors.New("corpus is empty — the run would pass vacuously")
	}
	return nil
}

// RunSchemaCorpus asserts every corpus contract against one exporter: see
// CorpusContract for what each obliges. Converters opt in with a single call, so
// the corpus has one definition rather than a copy per converter.
func RunSchemaCorpus(t *testing.T, v DocumentValidator, cases []CorpusCase, convert CorpusConvertFn) {
	t.Helper()
	require.NoError(t, ValidateCorpus(cases))

	for _, c := range cases {
		t.Run(c.Name, func(t *testing.T) {
			if msg := CheckCase(v, c, convert); msg != "" {
				t.Fatal(msg)
			}
		})
	}
}

// convertNoPanic turns a converter panic into an error so a crash is reported as
// a failing case rather than aborting the suite.
func convertNoPanic(convert CorpusConvertFn, input []byte) (out []byte, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = &PanicError{Value: r}
			out = nil
		}
	}()
	return convert(input)
}

// PanicError reports that a converter panicked. It is a distinct type, not a
// plain error, so CheckCase can tell a crash apart from a deliberate rejection:
// a rejection contract is satisfied by an error, and without this distinction a
// panicking converter would pass the very contract meant to catch it.
type PanicError struct{ Value any }

func (e *PanicError) Error() string {
	return "converter panicked (a panic is never an acceptable rejection): " +
		toString(e.Value)
}

func toString(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	if e, ok := v.(error); ok {
		return e.Error()
	}
	b, err := json.Marshal(v)
	if err != nil {
		return "unprintable panic value"
	}
	return string(b)
}

// --- Cross-language parity ---------------------------------------------------

// CanonicalJSON re-serializes a document with map keys sorted, HTML escaping
// disabled, and negative zero normalized, so the same values produce the same
// bytes in Go and TypeScript for every value the corpus can express.
//
// Raw serialization cannot be compared across the two: Go marshals struct fields
// in declaration order while TS uses insertion order, Go escapes <, > and & by
// default while JSON.stringify does not, and Go preserves -0 on a float64 where
// JSON.stringify renders it 0. All three are language artifacts, not meaningful
// differences — normalizing them lets the corpora be asserted byte-equal rather
// than merely assumed equivalent.
//
// Known limit: a lone UTF-16 surrogate still differs (Go substitutes U+FFFD, JS
// preserves the escape). No corpus case can produce one, and one appearing would
// fail the golden loudly rather than pass silently, so it is left unhandled
// rather than carrying speculative code.
func CanonicalJSON(raw []byte) ([]byte, error) {
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil, fmt.Errorf("canonical json: %w", err)
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(normalizeNegativeZero(v)); err != nil {
		return nil, fmt.Errorf("canonical json: %w", err)
	}
	// Encode appends a newline; drop it so the value is the whole payload.
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

// normalizeNegativeZero rewrites -0 to 0. encoding/json emits "-0" for a
// negative-zero float64 while JSON.stringify emits "0"; since the two are equal
// numerically, preserving the sign would fail the parity golden over a
// difference no consumer can observe.
func normalizeNegativeZero(v any) any {
	switch t := v.(type) {
	case float64:
		if t == 0 {
			return 0.0
		}
		return t
	case []any:
		for i, e := range t {
			t[i] = normalizeNegativeZero(e)
		}
		return t
	case map[string]any:
		for k, e := range t {
			t[k] = normalizeNegativeZero(e)
		}
		return t
	}
	return v
}

// CorpusGoldenEntry is one case as recorded in the cross-language golden.
type CorpusGoldenEntry struct {
	Name string `json:"name"`
	// Contract is recorded so a reclassification on one side alone is caught,
	// not just a renamed or reordered case. Stored as its name rather than its
	// ordinal so the golden stays readable and reordering the constants cannot
	// silently change what it asserts.
	Contract string `json:"contract"`
	// Input is the canonicalized case input.
	Input string `json:"input"`
}

// CorpusGolden is the checked-in cross-language contract: both the Go and the
// TypeScript corpus must reproduce it exactly. Go owns regeneration (go test
// -update); TypeScript only verifies, so neither side can quietly redefine the
// shared corpus to match itself.
type CorpusGolden struct {
	Results    []CorpusGoldenEntry `json:"results"`
	Amendments []CorpusGoldenEntry `json:"amendments"`
}

// CorpusGoldenPath is the golden's location, resolved from this file so it works
// regardless of the package under test.
func CorpusGoldenPath() string {
	return filepath.Join(getSharedDir(), "..", "corpus-golden.json")
}

// BuildCorpusGolden renders the current corpus in golden form.
func BuildCorpusGolden(t *testing.T) CorpusGolden {
	t.Helper()
	return CorpusGolden{
		Results:    goldenEntries(t, ResultsCorpus()),
		Amendments: goldenEntries(t, AmendmentsCorpus()),
	}
}

func goldenEntries(t *testing.T, cases []CorpusCase) []CorpusGoldenEntry {
	t.Helper()
	out := make([]CorpusGoldenEntry, 0, len(cases))
	for _, c := range cases {
		canon, err := CanonicalJSON(c.Input)
		require.NoError(t, err, "canonicalize corpus case %s", c.Name)
		out = append(out, CorpusGoldenEntry{Name: c.Name, Contract: c.Contract.String(), Input: string(canon)})
	}
	return out
}
