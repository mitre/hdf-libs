package oscal

import (
	"encoding/json"
	"log"
)

// OscalPropsTag is the reserved HDF requirement tag that carries the OSCAL SAR
// props HDF does not consume (ADR-0014 §3.2). No other converter uses this key.
const OscalPropsTag = "oscal-props"

// CarriedProp is one entry of the oscal-props tag (ADR-0014 §3.3): an OSCAL prop
// preserved losslessly through HDF, plus the object it was attached to. On, Name
// and Value are always present; the rest are present exactly when the source
// prop has them, so re-export reproduces the prop unchanged.
type CarriedProp struct {
	On      string `json:"on"`
	Name    string `json:"name"`
	Value   string `json:"value"`
	Ns      string `json:"ns,omitempty"`
	Class   string `json:"class,omitempty"`
	Group   string `json:"group,omitempty"`
	UUID    string `json:"uuid,omitempty"`
	Remarks string `json:"remarks,omitempty"`
}

// CarryForeignProps appends a carriage entry for every prop in props that HDF
// does not consume (ADR-0014 §3.1: HDF-namespaced and legacy-matched props are
// consumed and never carried; everything else, foreign or third-party, is
// carried). on is the OSCAL object the props hang on. Source order is preserved.
func CarryForeignProps(entries []CarriedProp, on string, props []Property) []CarriedProp {
	for i := range props {
		p := props[i]
		if ConsumedVocabularyProp(p) {
			continue
		}
		entries = append(entries, CarriedProp{
			On:      on,
			Name:    p.Name,
			Value:   p.Value,
			Ns:      p.Ns,
			Class:   p.Class,
			Group:   p.Group,
			UUID:    p.UUID,
			Remarks: p.Remarks,
		})
	}
	return entries
}

// carriageOn is the set of OSCAL objects a carried prop may have hung on.
var carriageOn = map[string]bool{"finding": true, "observation": true, "risk": true}

// carriageOptionalMembers are the entry members present exactly when the source
// prop has them; each is a string when present.
var carriageOptionalMembers = []string{"ns", "class", "group", "uuid", "remarks"}

// carriageMembers is the closed set of entry members the tag admits.
var carriageMembers = func() map[string]bool {
	m := map[string]bool{"on": true, "name": true, "value": true}
	for _, k := range carriageOptionalMembers {
		m[k] = true
	}
	return m
}()

// ValidCarriedProp reports whether one decoded oscal-props entry conforms to
// shared/oscal-props.schema.json. A foreign document may put anything in the tag,
// and an entry the emitter would turn into a non-string OSCAL prop member, or
// place on no object at all, is not carriage but corruption.
func ValidCarriedProp(entry interface{}) bool {
	_, ok := carriedPropMap(entry)
	return ok
}

// carriedPropMap returns the entry's members when it conforms to the carriage
// schema. The predicate is written against the schema member by member so the
// two stay pinned together by the shared case table rather than by comment.
func carriedPropMap(entry interface{}) (map[string]interface{}, bool) {
	m, ok := entry.(map[string]interface{})
	if !ok {
		return nil, false
	}
	for k := range m {
		if !carriageMembers[k] {
			return nil, false
		}
	}
	if on, ok := m["on"].(string); !ok || !carriageOn[on] {
		return nil, false
	}
	if name, ok := m["name"].(string); !ok || name == "" {
		return nil, false
	}
	if _, ok := m["value"].(string); !ok {
		return nil, false
	}
	for _, k := range carriageOptionalMembers {
		if v, present := m[k]; present {
			if _, ok := v.(string); !ok {
				return nil, false
			}
		}
	}
	return m, true
}

// ReadCarriedProps returns the oscal-props entries stored on requirement
// requirementID's tags, decoded from the map[string]interface{} the HDF reader
// leaves them as. Carriage is best-effort preservation, so reading is per-entry
// tolerant: a conforming entry is kept, a malformed one is dropped, and the
// requirement's drops are reported once.
func ReadCarriedProps(tags map[string]interface{}, requirementID string) []CarriedProp {
	raw, ok := tags[OscalPropsTag]
	if !ok {
		return nil
	}
	list, ok := carriageList(raw)
	if !ok {
		log.Printf("WARNING: Dropping the oscal-props tag on requirement %q: it is not an array", requirementID)
		return nil
	}

	var entries []CarriedProp
	dropped := 0
	for _, item := range list {
		m, ok := carriedPropMap(item)
		if !ok {
			dropped++
			continue
		}
		entries = append(entries, carriedPropFrom(m))
	}
	if dropped > 0 {
		log.Printf("WARNING: Dropping %d malformed oscal-props %s on requirement %q", dropped, carriageEntryNoun(dropped), requirementID)
	}
	return entries
}

// carriageList decodes the tag's value as a JSON array, which also normalizes a
// []CarriedProp an in-process caller stored directly.
func carriageList(raw interface{}) ([]interface{}, bool) {
	if raw == nil {
		return nil, false
	}
	data, err := json.Marshal(raw)
	if err != nil {
		return nil, false
	}
	var list []interface{}
	if err := json.Unmarshal(data, &list); err != nil {
		return nil, false
	}
	return list, true
}

func carriedPropFrom(m map[string]interface{}) CarriedProp {
	str := func(k string) string {
		s, _ := m[k].(string)
		return s
	}
	return CarriedProp{
		On:      str("on"),
		Name:    str("name"),
		Value:   str("value"),
		Ns:      str("ns"),
		Class:   str("class"),
		Group:   str("group"),
		UUID:    str("uuid"),
		Remarks: str("remarks"),
	}
}

func carriageEntryNoun(n int) string {
	if n == 1 {
		return "entry"
	}
	return "entries"
}

// CarriedFor returns the entries whose On matches on, in carried order.
func CarriedFor(entries []CarriedProp, on string) []CarriedProp {
	var out []CarriedProp
	for _, e := range entries {
		if e.On == on {
			out = append(out, e)
		}
	}
	return out
}

// AppendCarriedProps re-emits carried entries onto an object's props after its
// own props (ADR-0014 §3.4), skipping any entry whose (ns, name, value) is
// already present — an absent ns compares equal to NIST's default namespace.
func AppendCarriedProps(props []Property, entries []CarriedProp) []Property {
	seen := make(map[[3]string]bool)
	for i := range props {
		seen[carriageKey(props[i].Ns, props[i].Name, props[i].Value)] = true
	}
	for _, e := range entries {
		key := carriageKey(e.Ns, e.Name, e.Value)
		if seen[key] {
			continue
		}
		seen[key] = true
		props = append(props, Property{
			Name:    e.Name,
			Value:   e.Value,
			Ns:      e.Ns,
			Class:   e.Class,
			Group:   e.Group,
			UUID:    e.UUID,
			Remarks: e.Remarks,
		})
	}
	return props
}

func carriageKey(ns, name, value string) [3]string {
	if ns == "" {
		ns = vocabulary.DefaultNamespace
	}
	return [3]string{ns, name, value}
}
