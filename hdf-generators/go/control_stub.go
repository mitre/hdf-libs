package generators

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
)

// fullControlBlockRegex detects when a code string already starts with
// `control 'ID' do` (any quote style), meaning it's a complete InSpec
// control file — not a body fragment. ID is captured for verification.
var fullControlBlockRegex = regexp.MustCompile(`^\s*control\s+['"]([^'"]+)['"]\s+do\b`)

// GenerateControlStub generates a Ruby InSpec control stub from an HDF BaselineRequirement.
//
// Output follows the InSpec DSL ordering convention:
//
//	control 'ID' do
//	  title ...
//	  desc ...
//	  desc 'check', ...
//	  impact ...
//	  tag key: value
//	  <code or stub comment>
//	end
func GenerateControlStub(req hdf.BaselineRequirement) string {
	// If code is already a complete `control 'ID' do ... end` block (e.g.
	// from `-c controls/` reading whole .rb files), emit it as-is — wrapping
	// it again would produce nested control blocks, which InSpec rejects.
	// When the inner ID differs from req.ID (e.g. an upgrade rename match
	// where current's code was carried into a renamed requirement), rewrite
	// the wrapper to match req.ID so the file remains valid InSpec.
	if req.Code != nil {
		if m := fullControlBlockRegex.FindStringSubmatchIndex(*req.Code); m != nil {
			innerID := (*req.Code)[m[2]:m[3]]
			if innerID == req.ID {
				return *req.Code
			}
			rewritten := (*req.Code)[:m[2]] + req.ID + (*req.Code)[m[3]:]
			return rewritten
		}
	}

	var lines []string

	lines = append(lines, fmt.Sprintf("control '%s' do", req.ID))

	// Title
	if req.Title != nil {
		lines = append(lines, fmt.Sprintf("  title %s", EscapeQuotes(*req.Title)))
	}

	// Descriptions: default first (as bare `desc`), then labeled
	seenDefault := false
	for _, d := range req.Descriptions {
		if d.Label == "default" && !seenDefault {
			lines = append(lines, fmt.Sprintf("  desc %s", EscapeQuotes(d.Data)))
			seenDefault = true
		}
	}

	for _, d := range req.Descriptions {
		if d.Label == "default" {
			continue
		}
		lines = append(lines, fmt.Sprintf("  desc '%s', %s", d.Label, EscapeQuotes(d.Data)))
	}

	// Impact — always render with at least one decimal place for whole numbers
	impact := req.Impact
	if impact == float64(int64(impact)) {
		lines = append(lines, fmt.Sprintf("  impact %.1f", impact))
	} else {
		lines = append(lines, fmt.Sprintf("  impact %s", formatFloat(impact)))
	}

	// Tags — sorted for deterministic output
	tagKeys := make([]string, 0, len(req.Tags))
	for k := range req.Tags {
		tagKeys = append(tagKeys, k)
	}
	sort.Strings(tagKeys)

	for _, key := range tagKeys {
		lines = append(lines, "  "+formatTag(key, req.Tags[key]))
	}

	// Code body or stub placeholder
	lines = append(lines, "")
	if req.Code != nil {
		lines = append(lines, *req.Code)
	} else {
		lines = append(lines, "  # TODO: Add InSpec test code here")
	}

	lines = append(lines, "end")
	lines = append(lines, "") // trailing newline

	return strings.Join(lines, "\n")
}

// formatTag formats a single tag key-value pair as Ruby DSL.
func formatTag(key string, value interface{}) string {
	if value == nil {
		return fmt.Sprintf("tag %s: nil", key)
	}

	switch v := value.(type) {
	case []interface{}:
		items := make([]string, len(v))
		for i, item := range v {
			items[i] = fmt.Sprintf("'%s'", fmt.Sprint(item))
		}
		return fmt.Sprintf("tag %s: [%s]", key, strings.Join(items, ", "))
	case []string:
		items := make([]string, len(v))
		for i, item := range v {
			items[i] = fmt.Sprintf("'%s'", item)
		}
		return fmt.Sprintf("tag %s: [%s]", key, strings.Join(items, ", "))
	case bool:
		return fmt.Sprintf("tag %s: %t", key, v)
	case string:
		return fmt.Sprintf("tag %s: %s", key, EscapeQuotes(v))
	case float64:
		return fmt.Sprintf("tag %s: %s", key, formatFloat(v))
	default:
		return fmt.Sprintf("tag %s: %v", key, v)
	}
}

// formatFloat formats a float64 without unnecessary trailing zeros.
func formatFloat(f float64) string {
	s := fmt.Sprintf("%g", f)
	return s
}
