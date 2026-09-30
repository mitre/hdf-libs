package oscal

import "encoding/json"

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

// ReadCarriedProps returns the oscal-props entries stored on an HDF
// requirement's tags, decoded from the map[string]interface{} the HDF reader
// leaves them as. It returns nil when the tag is absent or unreadable.
func ReadCarriedProps(tags map[string]interface{}) []CarriedProp {
	raw, ok := tags[OscalPropsTag]
	if !ok {
		return nil
	}
	data, err := json.Marshal(raw)
	if err != nil {
		return nil
	}
	var entries []CarriedProp
	if err := json.Unmarshal(data, &entries); err != nil {
		return nil
	}
	return entries
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
