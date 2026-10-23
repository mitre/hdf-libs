package hdfdoc

import (
	"encoding/json"
	"fmt"
)

// MetadataScope identifies the owner of labels and external IDs. Metadata never
// propagates between document and component owners.
type MetadataScope string

const (
	ComponentScope MetadataScope = "component"
	DocumentScope  MetadataScope = "document"
)

// MetadataChanges describes a merge or removal of string metadata. Callers
// validate the document schema and command arguments before applying changes.
type MetadataChanges struct {
	Labels            map[string]string
	ExternalIDs       map[string]string
	RemoveLabels      []string
	RemoveExternalIDs []string
}

// UpdateMetadata changes metadata on the selected owner. ComponentName selects
// only external IDs; labels apply to every component, as in ApplyLabels.
// Document scope accepts no component selector.
func UpdateMetadata(data []byte, scope MetadataScope, componentName string, changes MetadataChanges) ([]byte, error) {
	if scope != DocumentScope && scope != ComponentScope {
		return nil, fmt.Errorf("invalid metadata scope %q", scope)
	}
	if scope == DocumentScope && componentName != "" {
		return nil, fmt.Errorf("document scope does not accept a component name")
	}
	if len(changes.Labels)+len(changes.ExternalIDs)+len(changes.RemoveLabels)+len(changes.RemoveExternalIDs) == 0 {
		return data, nil
	}
	var doc map[string]interface{}
	var owners []map[string]interface{}
	if scope == ComponentScope {
		var err error
		doc, owners, err = parseComponents(data)
		if err != nil {
			return nil, err
		}
		if len(owners) == 0 && len(changes.ExternalIDs) > 0 {
			return nil, fmt.Errorf("%w to set external IDs on", ErrNoComponents)
		}
		if owners == nil {
			return data, nil
		}
	} else {
		if err := json.Unmarshal(data, &doc); err != nil {
			return nil, fmt.Errorf("failed to parse JSON: %w", err)
		}
		if doc == nil {
			return nil, fmt.Errorf("document must be an object")
		}
		owners = []map[string]interface{}{doc}
	}
	selected := owners
	if len(changes.ExternalIDs)+len(changes.RemoveExternalIDs) > 0 && scope == ComponentScope {
		var err error
		selected, err = selectComponents(owners, componentName)
		if err != nil {
			return nil, err
		}
	}
	for _, owner := range owners {
		updateStringMap(owner, "labels", changes.Labels, changes.RemoveLabels, false)
	}
	for _, owner := range selected {
		updateStringMap(owner, "externalIds", changes.ExternalIDs, changes.RemoveExternalIDs, true)
	}
	return json.MarshalIndent(doc, "", "  ")
}

func updateStringMap(owner map[string]interface{}, field string, values map[string]string, remove []string, dropEmpty bool) {
	if len(values)+len(remove) == 0 {
		return
	}
	existing, ok := owner[field].(map[string]interface{})
	if !ok {
		if len(values) == 0 {
			return
		}
		existing = make(map[string]interface{}, len(values))
	}
	for key, value := range values {
		existing[key] = value
	}
	for _, key := range remove {
		delete(existing, key)
	}
	if dropEmpty && len(existing) == 0 {
		delete(owner, field)
	} else {
		owner[field] = existing
	}
}
