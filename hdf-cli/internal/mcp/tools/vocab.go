package tools

import (
	"encoding/json"
	"fmt"

	"github.com/google/jsonschema-go/jsonschema"

	"github.com/mitre/hdf-libs/hdf-cli/v3/internal/mcp/resources"
)

// Every closed vocabulary a tool advertises, declared once.
//
// Two kinds live here. The schema-derived ones are read from the bundled schemas through
// resources.SchemaEnumValues, the same index that serves hdf://enum/{name}, so a schema
// enum gaining a member moves the tool with it. The MCP-local ones are this server's own
// switch values; they had no definition at all before, only a literal repeated at each
// dispatch site, in the error message and in the struct tag.
//
// Where a vocabulary has behaviour behind it, the dispatch is keyed by these constants
// (validateChecks, groupPartitioners, authorBuilders) so a member cannot be advertised
// without an implementation. verbosity needs no table: every value is accepted and
// anything that is not full renders concise.
//
// The `jsonschema` struct tag cannot carry a vocabulary: the inference pass assigns it to
// Description and rejects any `WORD=` prefix, so an advertised enum has to come from an
// explicit input schema. mustEnumSchema builds one.

// Verbosity selects how much detail a response carries.
type Verbosity string

const (
	VerbosityConcise Verbosity = "concise"
	VerbosityFull    Verbosity = "full"
)

var verbosityVocabulary = []Verbosity{VerbosityConcise, VerbosityFull}

// IsFull reports whether a raw verbosity argument selects the full projection. The default
// is concise, so anything unrecognised reads as concise rather than erroring — verbosity
// widens a response, it does not change what the tool means.
func IsFull(raw string) bool { return Verbosity(raw) == VerbosityFull }

// verbosityVocab is the shared fragment three tools advertise, so the default lives in
// exactly one place.
func verbosityVocab() closedVocabulary {
	return closedVocabulary{values: vocabValues(verbosityVocabulary), defaultValue: string(VerbosityConcise)}
}

// DiffMode selects which pair of document types hdf_diff compares.
type DiffMode string

const (
	DiffModeTemporal    DiffMode = "temporal"
	DiffModeSystemDrift DiffMode = "system-drift"
)

var diffModeVocabulary = []DiffMode{DiffModeTemporal, DiffModeSystemDrift}

// ValidateMode selects which check hdf_validate runs.
type ValidateMode string

const (
	ValidateModeSchema       ValidateMode = "schema"
	ValidateModeChecksums    ValidateMode = "checksums"
	ValidateModeCompleteness ValidateMode = "completeness"
)

var validateModeVocabulary = []ValidateMode{ValidateModeSchema, ValidateModeChecksums, ValidateModeCompleteness}

// ComplianceGroupBy selects the bucketing dimension for a compliance roll-up.
type ComplianceGroupBy string

const (
	GroupByBaseline   ComplianceGroupBy = "baseline"
	GroupBySeverity   ComplianceGroupBy = "severity"
	GroupByNistFamily ComplianceGroupBy = "nistFamily"
	GroupByTool       ComplianceGroupBy = "tool"
	GroupByCwe        ComplianceGroupBy = "cwe"
)

var complianceGroupByVocabulary = []ComplianceGroupBy{
	GroupByBaseline, GroupBySeverity, GroupByNistFamily, GroupByTool, GroupByCwe,
}

// values renders a typed vocabulary as the strings an input schema advertises, in
// declaration order — the order a reader of the enum sees.
func vocabValues[T ~string](vocabulary []T) []string {
	out := make([]string, 0, len(vocabulary))
	for _, v := range vocabulary {
		out = append(out, string(v))
	}
	return out
}

// contains reports whether raw is a member of the vocabulary.
func isMember[T ~string](vocabulary []T, raw string) bool {
	for _, v := range vocabulary {
		if string(v) == raw {
			return true
		}
	}
	return false
}

// list renders a vocabulary for an error message, so the message cannot disagree with the
// advertised enum.
func vocabList[T ~string](vocabulary []T) string {
	out := ""
	for i, v := range vocabulary {
		switch {
		case i == 0:
			out = string(v)
		case i == len(vocabulary)-1:
			out += " or " + string(v)
		default:
			out += ", " + string(v)
		}
	}
	return out
}

// schemaEnum returns a schema-derived vocabulary by its `$defs` name, panicking if the
// schemas do not define it. A missing enum means the schema and this server disagree about
// what a field accepts, which is not a condition to serve a contract under.
func schemaEnum(def string) []string {
	v, ok, err := resources.SchemaEnumValues(def)
	if err != nil {
		panic(fmt.Sprintf("tools: reading the %s enum from the bundled schemas: %v", def, err))
	}
	if !ok {
		panic("tools: the bundled schemas define no enum named " + def)
	}
	return v
}

// closedVocabulary is what one property advertises: its members, and which member applies
// when the argument is omitted.
//
// defaultValue is carried as JSON Schema's `default` rather than stated in prose. A
// description saying "concise by default" would be a second copy of a vocabulary member,
// free to disagree with the enum and invisible to a generator.
type closedVocabulary struct {
	values       []string
	defaultValue string
}

// mustEnumSchema reflects T's input schema and attaches each named property's vocabulary.
//
// Panics when a property does not exist, which is the point: a renamed or dropped field
// would otherwise silently stop advertising its vocabulary, and the tool would keep
// accepting values no generator knows about. Registration is deterministic, so this fails
// at server start rather than on a request.
func mustEnumSchema[T any](enums map[string]closedVocabulary) *jsonschema.Schema {
	s, err := jsonschema.For[T](nil)
	if err != nil {
		panic(fmt.Sprintf("tools: reflecting an input schema: %v", err))
	}
	for property, vocabulary := range enums {
		p, ok := s.Properties[property]
		if !ok {
			panic(fmt.Sprintf("tools: input schema has no %q property to attach an enum to", property))
		}
		if vocabulary.defaultValue != "" {
			if !isMember(vocabulary.values, vocabulary.defaultValue) {
				panic(fmt.Sprintf("tools: %q defaults to %q, which is not in its own vocabulary",
					property, vocabulary.defaultValue))
			}
			raw, err := json.Marshal(vocabulary.defaultValue)
			if err != nil {
				panic(fmt.Sprintf("tools: encoding the %q default: %v", property, err))
			}
			p.Default = raw
		}
		// For a repeated field the vocabulary constrains each ITEM. An enum on the array
		// itself says the whole array must equal one of the values, which rejects every
		// valid call.
		//
		// Keyed off Items, not off the type: a Go slice reflects to the UNION
		// `"type":["null","array"]`, so Type is empty and a `Type == "array"` check is
		// dead code that silently puts the enum on the array.
		target := p
		if p.Items != nil {
			target = p.Items
		}
		target.Enum = make([]any, 0, len(vocabulary.values))
		for _, v := range vocabulary.values {
			target.Enum = append(target.Enum, v)
		}
	}
	return s
}
