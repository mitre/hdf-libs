// Package outnames derives the output file name for each input of a multi-file
// conversion. The CLI's `convert -o <dir>` and the MCP hdf_convert batch share
// it, so the two surfaces never name the same conversion differently.
package outnames

import (
	"fmt"
	"path"
	"strings"
)

// Names returns one output file name per input, in input order, in the
// bulk-convert convention <stem>.hdf.json (or .hdf.<toFormat> for a non-HDF
// target).
//
// Inputs sharing a stem would otherwise land on one file and lose a conversion,
// so every member of a colliding group is numbered 1-based in input order
// (a/results.json, b/results.json → results.1.hdf.json, results.2.hdf.json).
// The number is positional and carries no provenance, so both callers report
// which input produced which file; Plain tells a caller which names were
// numbered. An index already claimed by an input whose name needs no number is
// skipped, so numbering cannot manufacture a fresh collision. Repeats of one
// input are the same conversion and keep one unnumbered name.
//
// Inputs are slash-separated (filepath.ToSlash a native path first). The results
// are file names, which each caller joins with its own output directory.
func Names(inputs []string, toFormat string) ([]string, error) {
	suffix := suffixFor(toFormat)

	cleaned := make([]string, len(inputs))
	plain := make([]string, len(inputs))
	stems := make([]string, len(inputs))
	for i, in := range inputs {
		stem, ok := stemOf(in)
		if !ok {
			return nil, fmt.Errorf("input %q has no file name to derive an output name from", in)
		}
		cleaned[i], stems[i], plain[i] = path.Clean(in), stem, stem+suffix
	}

	// A group is counted by DISTINCT paths: two spellings of one file are one
	// conversion and must not number each other.
	members := map[string]map[string]bool{}
	for i := range inputs {
		if members[plain[i]] == nil {
			members[plain[i]] = map[string]bool{}
		}
		members[plain[i]][cleaned[i]] = true
	}

	// Reserve every name that will be used unnumbered before handing out any
	// index, so a literal results.1.json keeps results.1.hdf.json wherever it
	// sits in the input order and the numbered group skips that index.
	taken := map[string]bool{}
	for name, paths := range members {
		if len(paths) == 1 {
			taken[name] = true
		}
	}

	nextIndex := map[string]int{}
	assigned := map[string]string{}
	names := make([]string, len(inputs))
	for i := range inputs {
		if name, ok := assigned[cleaned[i]]; ok {
			names[i] = name
			continue
		}
		name := plain[i]
		if len(members[name]) > 1 {
			name = nextFreeName(stems[i], suffix, nextIndex, taken)
		}
		taken[name] = true
		assigned[cleaned[i]] = name
		names[i] = name
	}
	return names, nil
}

// Plain returns the unnumbered output name for one input — what Names returns
// for every input no other input collides with. A caller compares against it to
// find the names that were numbered, which are the ones it has to report.
// Returns "" for an input that names no file, which Names rejects outright.
func Plain(input, toFormat string) string {
	stem, ok := stemOf(input)
	if !ok {
		return ""
	}
	return stem + suffixFor(toFormat)
}

func suffixFor(toFormat string) string {
	if toFormat == "" || toFormat == "hdf" {
		return ".hdf.json"
	}
	return ".hdf." + toFormat
}

// stemOf returns the input's file name without its last extension. ok is false
// when the path names no file at all.
func stemOf(input string) (string, bool) {
	base := path.Base(path.Clean(input))
	if base == "/" || base == "." || base == ".." {
		return "", false
	}
	return strings.TrimSuffix(base, path.Ext(base)), true
}

// nextFreeName returns <stem>.<n><suffix> for the lowest n not already claimed,
// advancing the stem's counter so the next member of the group takes the one
// after it.
func nextFreeName(stem, suffix string, nextIndex map[string]int, taken map[string]bool) string {
	for {
		nextIndex[stem]++
		candidate := fmt.Sprintf("%s.%d%s", stem, nextIndex[stem], suffix)
		if !taken[candidate] {
			return candidate
		}
	}
}
