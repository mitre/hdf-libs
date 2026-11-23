package generators

import (
	"fmt"
	"slices"
	"strings"

	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
)

// idTypes are the identifiers a control can be keyed on: the rule id the
// baseline carries, the STIG group id (tags.gid) or the STIG id (tags.stig_id).
var idTypes = []string{"rule", "group", "version"}

func idOf(req hdf.BaselineRequirement, idType string) string {
	switch idType {
	case "group":
		return tagString(req, "gid")
	case "version":
		return tagString(req, "stig_id")
	default:
		return req.ID
	}
}

func tagString(req hdf.BaselineRequirement, key string) string {
	s, _ := req.Tags[key].(string)
	return strings.TrimSpace(s)
}

var idTypeTag = map[string]string{"group": "tags.gid", "version": "tags.stig_id"}

// controlFilename is the per-control file for id, with path separators and
// traversal removed so no id can write outside controls/.
func controlFilename(id string) string {
	safe := strings.NewReplacer("..", "", "/", "", `\`, "").Replace(id)
	if safe == "" {
		safe = "unknown"
	}
	return "controls/" + safe + ".rb"
}

// keyRequirements returns the requirements with each ID replaced by the chosen
// identifier. It fails when a requirement lacks it, or when two requirements
// would share a control id or, with perFile, a control file.
func keyRequirements(reqs []hdf.BaselineRequirement, idType string, perFile bool) ([]hdf.BaselineRequirement, error) {
	if idType == "" {
		idType = "rule"
	}
	if !slices.Contains(idTypes, idType) {
		return nil, fmt.Errorf("unknown id type %q; use rule, group or version", idType)
	}

	var missing []string
	keyed := make([]hdf.BaselineRequirement, len(reqs))
	for i, req := range reqs {
		keyed[i] = req
		keyed[i].ID = idOf(req, idType)
		if keyed[i].ID == "" {
			missing = append(missing, req.ID)
		}
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("id type %s: %d requirements have no %s id (%s): %s",
			idType, len(missing), idType, idTypeTag[idType], strings.Join(missing, ", "))
	}

	var problems []string
	problems = append(problems, duplicates(reqs, keyed, func(r hdf.BaselineRequirement) string { return r.ID },
		func(key string, members []hdf.BaselineRequirement) string {
			described := make([]string, len(members))
			for i, m := range members {
				described[i] = fmt.Sprintf("%s (group %s, version %s)", m.ID, idOf(m, "group"), idOf(m, "version"))
			}
			return fmt.Sprintf("%d requirements resolve to control id %s: %s; %s",
				len(members), key, strings.Join(described, ", "), separatingTypes(members, idType))
		})...)
	if perFile && len(problems) == 0 {
		problems = append(problems, duplicates(reqs, keyed, func(r hdf.BaselineRequirement) string { return controlFilename(r.ID) },
			func(key string, members []hdf.BaselineRequirement) string {
				ids := make([]string, len(members))
				for i, m := range members {
					ids[i] = idOf(m, idType)
				}
				return fmt.Sprintf("%d requirements resolve to file %s: %s", len(members), key, strings.Join(ids, ", "))
			})...)
	}
	if len(problems) > 0 {
		return nil, fmt.Errorf("id type %s: %s", idType, strings.Join(problems, "\n"))
	}
	return keyed, nil
}

// duplicates groups the original requirements by key(keyed[i]) and describes
// each group with more than one member, in first-seen order.
func duplicates(reqs, keyed []hdf.BaselineRequirement, key func(hdf.BaselineRequirement) string,
	describe func(string, []hdf.BaselineRequirement) string) []string {
	groups := map[string][]hdf.BaselineRequirement{}
	var order []string
	for i, k := range keyed {
		kk := key(k)
		if _, seen := groups[kk]; !seen {
			order = append(order, kk)
		}
		groups[kk] = append(groups[kk], reqs[i])
	}
	var out []string
	for _, kk := range order {
		if len(groups[kk]) > 1 {
			out = append(out, describe(kk, groups[kk]))
		}
	}
	return out
}

// separatingTypes names the other id types under which every member has a
// distinct, present identifier, or the remedy when there is none.
func separatingTypes(members []hdf.BaselineRequirement, current string) string {
	var ok []string
	for _, t := range idTypes {
		if t == current {
			continue
		}
		seen := map[string]bool{}
		distinct := true
		for _, m := range members {
			id := idOf(m, t)
			if id == "" || seen[id] {
				distinct = false
				break
			}
			seen[id] = true
		}
		if distinct {
			ok = append(ok, t)
		}
	}
	if len(ok) == 0 {
		return "no id type tells them apart: convert to an HDF baseline, give one requirement a distinct id, and generate from that file"
	}
	return "id type " + strings.Join(ok, " or ") + " tells them apart"
}
