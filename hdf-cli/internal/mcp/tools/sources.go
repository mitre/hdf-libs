package tools

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/mitre/hdf-libs/hdf-cli/v3/internal/mcp/handle"
	"github.com/mitre/hdf-libs/hdf-cli/v3/internal/mcp/loader"
	"github.com/mitre/hdf-libs/hdf-cli/v3/internal/mcp/mcperr"
	hdfengine "github.com/mitre/hdf-libs/hdf-engine/go/v3"
	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
)

// This file is the one load-and-combine path every multi-document read tool
// uses (ADR-0016 §1, §7). A set of results documents is combined through the
// engine's Merge in memory, per call — one baseline per input baseline, named
// <tool>/<original> and labelled with its provenance — and the tool computes
// over that view exactly as it would over one document. Nothing here persists
// or returns the combined document; only the tool's own answer leaves.

// sourceMember names one member of a multi-source view in a response envelope:
// its position in sources[] and the handle it resolved to. Its document type is
// not repeated per member — a multi-source view is results documents only, and
// the envelope's docType says so once (owner decision 2026-09-17: the field
// cost tokens on every turn and never varied).
type sourceMember struct {
	Index  int    `json:"index"`
	Handle string `json:"handle"`
}

// loadedSource is one resolved, requirement-bearing document projected to the
// shape the engine filters, with the name it is recorded under in a view.
type loadedSource struct {
	Resolved *Resolved
	Results  hdf.HDFResults
	Label    string
}

// loadSource resolves one {path|handle}, requires a document type in accept and
// a schema-valid document, and projects it to the engine's results shape. slot
// names the input field in every error ("source", "sources[2]"); verb says what
// the caller was going to do with the document ("aggregated", "combined").
func loadSource(src handle.Source, ldr *loader.Loader, slot string, accept []string, verb string) (*loadedSource, *mcperr.Error) {
	resolved, terr := resolveSource(src, ldr, slot)
	if terr != nil {
		return nil, terr
	}
	docType := resolved.Load.DocType
	toResults, ok := queryDispatch[docType]
	if !ok || !containsString(accept, docType) {
		return nil, mcperr.New(mcperr.WrongDocType,
			fmt.Sprintf("%s is a %s document; only %s documents can be %s", slot, docType, strings.Join(accept, " or "), verb),
			map[string]any{"slot": slot, "docType": docType}).
			WithNextCall("call hdf_inspect to view this document's structure, or pass it alone as source")
	}
	if !resolved.Load.Valid {
		return nil, mcperr.New(mcperr.SchemaInvalid,
			fmt.Sprintf("%s is %s but failed schema validation, so it cannot be %s", slot, docType, verb),
			map[string]any{"slot": slot, "docType": docType})
	}
	label := src.Path
	if label == "" {
		label = resolved.Handle.Path
	}
	if label == "" {
		label = slot
	}
	return &loadedSource{Resolved: resolved, Results: toResults(resolved.Load), Label: label}, nil
}

// sourceLabel names a source for a per-member failure record before (or
// without) resolving it: its path, else the path its handle carries, else
// empty (a content-addressed handle names no file). A failure record must
// still say which document it is about when the caller passed a handle.
func sourceLabel(src handle.Source) string {
	if src.Path != "" {
		return src.Path
	}
	if h, err := handle.Decode(src.Handle); err == nil {
		return h.Path
	}
	return ""
}

func containsString(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// sourceView is what a read tool computes over: one document as loaded, or the
// engine Merge of several. Exactly one of Handle (single) and Members (multi)
// is set, which is also how the response envelope tells the two apart.
type sourceView struct {
	Results             hdf.HDFResults
	DocType             string
	EngineSchemaVersion string
	Handle              string
	Members             []sourceMember
	Warnings            []hdfengine.MergeWarning
}

// singleSourceErrors lets a tool keep its own wording for the two single-source
// refusals, so adding sources[] changes nothing about a single-source call.
type singleSourceErrors struct {
	WrongDocType  func(docType string) *mcperr.Error
	SchemaInvalid func(docType string) *mcperr.Error
}

// resolveView turns a tool's source / sources[] arguments into the view it
// computes over. Exactly one of the two must be given; a one-element sources[]
// is the single-source call (nothing is combined, so nothing is renamed). A
// multi-source view is results documents only, and any member that fails to
// load, is not a results document, or is schema-invalid refuses the whole set
// naming its index — a partial view would report numbers over an unstated
// subset. The first return is the view, the second a taxonomy error for the
// caller, the third a Go error (an engine or encoding invariant violation).
func resolveView(single handle.Source, many []handle.Source, ldr *loader.Loader, errs singleSourceErrors) (*sourceView, *mcperr.Error, error) {
	singleSet := single.Path != "" || single.Handle != ""
	switch {
	case singleSet && len(many) > 0:
		return nil, mcperr.Arg("the call sets both source and sources", "pass exactly one of source or sources[]"), nil
	case !singleSet && len(many) == 1:
		single, many = many[0], nil
	}

	if len(many) == 0 {
		resolved, terr := resolveSource(single, ldr, "source")
		if terr != nil {
			return nil, terr, nil
		}
		encoded, err := handle.Encode(resolved.Handle)
		if err != nil {
			return nil, nil, fmt.Errorf("encoding handle: %w", err)
		}
		toResults, ok := queryDispatch[resolved.Load.DocType]
		if !ok {
			return nil, errs.WrongDocType(resolved.Load.DocType), nil
		}
		if !resolved.Load.Valid {
			return nil, errs.SchemaInvalid(resolved.Load.DocType), nil
		}
		return &sourceView{
			Results: toResults(resolved.Load), DocType: resolved.Load.DocType,
			EngineSchemaVersion: resolved.Handle.EngineSchemaVersion, Handle: encoded,
		}, nil, nil
	}

	members := make([]sourceMember, 0, len(many))
	inputs := make([]hdfengine.MergeSource, 0, len(many))
	version := ""
	for i, src := range many {
		slot := fmt.Sprintf("sources[%d]", i)
		ls, terr := loadSource(src, ldr, slot, []string{"results"}, "combined")
		if terr != nil {
			return nil, terr, nil
		}
		encoded, err := handle.Encode(ls.Resolved.Handle)
		if err != nil {
			return nil, nil, fmt.Errorf("encoding handle for %s: %w", slot, err)
		}
		members = append(members, sourceMember{Index: i, Handle: encoded})
		inputs = append(inputs, hdfengine.MergeSource{Name: ls.Label, Doc: ls.Results})
		version = ls.Resolved.Handle.EngineSchemaVersion
	}
	merged, warnings, err := mergeSources(inputs)
	if err != nil {
		return nil, nil, err
	}
	return &sourceView{
		Results: merged, DocType: "results", EngineSchemaVersion: version,
		Members: members, Warnings: warnings,
	}, nil, nil
}

// mergeSources combines loaded documents through the engine Merge — the single
// definition of "these documents combined" (ADR-0016 §1). Nothing loaded is the
// empty set. Merge errors only on an empty input, which is excluded here, so a
// returned error is an engine invariant violation and is propagated as a Go
// error rather than zeroed into a result (a silent all-zero rollup beside a
// non-zero total would be a lie).
func mergeSources(inputs []hdfengine.MergeSource) (hdf.HDFResults, []hdfengine.MergeWarning, error) {
	if len(inputs) == 0 {
		return hdf.HDFResults{}, nil, nil
	}
	merged, warnings, err := hdfengine.Merge(inputs)
	if err != nil {
		return hdf.HDFResults{}, nil, fmt.Errorf("combining %d sources: %w", len(inputs), err)
	}
	return merged, warnings, nil
}

// mergeWarningsNotice renders the engine's merge warnings for a response notice,
// so a caller learns that two baselines in the view share a name (read tools
// key on position, so the answer is correct; a name-keyed consumer would not
// be) or that a provenance label was replaced.
func mergeWarningsNotice(ws []hdfengine.MergeWarning) string {
	if len(ws) == 0 {
		return ""
	}
	parts := make([]string, 0, len(ws))
	for _, w := range ws {
		idx := make([]string, len(w.Indices))
		for i, n := range w.Indices {
			idx[i] = strconv.Itoa(n)
		}
		switch w.Kind {
		case hdfengine.WarnLabelOverwritten:
			parts = append(parts, fmt.Sprintf("%s: label %q at baseline %s", w.Kind, w.Label, strings.Join(idx, ",")))
		case hdfengine.WarnDuplicateBaselineName:
			parts = append(parts, fmt.Sprintf("%s: %q at baselines %s", w.Kind, w.Name, strings.Join(idx, ",")))
		default:
			parts = append(parts, fmt.Sprintf("%s: %q at %s", w.Kind, w.Name, strings.Join(idx, ",")))
		}
	}
	return "Combining the sources produced warnings — " + strings.Join(parts, "; ") +
		". Rows and groups are keyed by baseline position, so the answer is correct; only name-keyed consumers cannot tell same-named baselines apart."
}

// joinNotice concatenates two notices, either of which may be empty.
func joinNotice(a, b string) string {
	return strings.TrimSpace(a + " " + b)
}
