package hdfengine

import (
	"encoding/json"
	"fmt"

	"gopkg.in/yaml.v3"
)

// Values is one predicate field's value set. It exists so every multi-value
// field accepts the same three spellings through one decoder rather than each
// field growing its own: a bare scalar for the common single-value case, a list,
// and a {not: [...]} object for exclusion.
//
// Negation is PURE: Not means "does not match any of these", and a requirement
// whose field is ABSENT satisfies it. The alternative — requiring the field to be
// present — silently weakens gates, because the requirement a gate most needs to
// catch is usually the one nobody has touched. "{status: [failed], disposition:
// {not: [waiver]}}, max: 0" must catch a failure nobody adjudicated; under a
// presence-requiring reading that requirement is excluded and the bound passes.
//
// The cost is that a narrow-looking predicate can select broadly: {poamType:
// {not: [remediation]}} matches everything with no governing plan, because
// having no plan is indeed not being governed by a remediation. An author who
// means "governed by a plan, but not that kind" writes the conjunction with
// disposition, which is available because the two are separate keys.
type Values struct {
	In  []string
	Not []string
}

// In builds an inclusive value set, for callers assembling Options in code
// rather than decoding a policy file.
func In(values ...string) Values { return Values{In: values} }

// Active reports whether the field constrains anything at all.
func (v Values) Active() bool { return len(v.In) > 0 || len(v.Not) > 0 }

// All returns every value the field names, in either mode, for callers that
// validate the vocabulary — a value inside not must be refused exactly as one
// outside it is, or a typo there matches everything instead of nothing.
func (v Values) All() []string {
	all := make([]string, 0, len(v.In)+len(v.Not))
	all = append(all, v.In...)
	return append(all, v.Not...)
}

// Match applies the field's own per-value test. test reports whether the
// requirement matches ONE named value; Match combines those the way this
// vocabulary has always combined them — values within a field OR — and then
// applies the exclusion.
func (v Values) Match(test func(string) bool) bool {
	if len(v.In) > 0 && !anyValue(v.In, test) {
		return false
	}
	if len(v.Not) > 0 && anyValue(v.Not, test) {
		return false
	}
	return true
}

func anyValue(values []string, test func(string) bool) bool {
	for _, value := range values {
		if test(value) {
			return true
		}
	}
	return false
}

// notForm is the object spelling. A separate type so the decoder can reject an
// object carrying anything else — an unknown key there would otherwise be
// silently dropped and the predicate would assert nothing.
type notForm struct {
	Not Values `yaml:"not" json:"not"`
}

// UnmarshalYAML accepts the scalar, the sequence and the {not: ...} object. A
// custom unmarshaller does NOT inherit KnownFields from the parent decoder, so
// the object form checks its own keys rather than trusting strict decoding.
func (v *Values) UnmarshalYAML(node *yaml.Node) error {
	switch node.Kind {
	case yaml.ScalarNode:
		var one string
		if err := node.Decode(&one); err != nil {
			return err
		}
		v.In = []string{one}
		return nil
	case yaml.SequenceNode:
		var many []string
		if err := node.Decode(&many); err != nil {
			return err
		}
		v.In = many
		return nil
	case yaml.MappingNode:
		for i := 0; i < len(node.Content); i += 2 {
			if key := node.Content[i].Value; key != "not" {
				return fmt.Errorf("field %q is not a known form; a predicate value is a value, a list, or {not: ...}", key)
			}
		}
		var form notForm
		if err := node.Decode(&form); err != nil {
			return err
		}
		if len(form.Not.Not) > 0 {
			return fmt.Errorf("not cannot be nested inside not")
		}
		if len(form.Not.In) == 0 {
			return fmt.Errorf("not excludes nothing; a predicate that asserts nothing is refused")
		}
		v.Not = form.Not.In
		return nil
	default:
		return fmt.Errorf("a predicate value is a value, a list, or {not: ...}")
	}
}

// UnmarshalJSON mirrors the YAML forms, because an inline spec and the MCP both
// arrive as JSON and must mean the same thing as a file.
func (v *Values) UnmarshalJSON(data []byte) error {
	var one string
	if err := json.Unmarshal(data, &one); err == nil {
		v.In = []string{one}
		return nil
	}
	var many []string
	if err := json.Unmarshal(data, &many); err == nil {
		v.In = many
		return nil
	}
	var form map[string]json.RawMessage
	if err := json.Unmarshal(data, &form); err != nil {
		return fmt.Errorf("a predicate value is a value, a list, or {not: ...}")
	}
	raw, ok := form["not"]
	if !ok || len(form) != 1 {
		return fmt.Errorf("a predicate value is a value, a list, or {not: ...}")
	}
	var inner Values
	if err := inner.UnmarshalJSON(raw); err != nil {
		return err
	}
	if len(inner.Not) > 0 {
		return fmt.Errorf("not cannot be nested inside not")
	}
	if len(inner.In) == 0 {
		return fmt.Errorf("not excludes nothing; a predicate that asserts nothing is refused")
	}
	v.Not = inner.In
	return nil
}

// MarshalJSON round-trips the decoded form, so a spec echoed back to a caller
// reads as something they could have written.
func (v Values) MarshalJSON() ([]byte, error) {
	if len(v.Not) > 0 {
		return json.Marshal(map[string][]string{"not": v.Not})
	}
	return json.Marshal(v.In)
}
