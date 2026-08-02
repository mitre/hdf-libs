package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	shared "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go"
	diff "github.com/mitre/hdf-libs/hdf-diff/go/v3"
	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	validators "github.com/mitre/hdf-libs/hdf-validators/go/v3"
	"github.com/spf13/cobra"
)

// eventsNamespace is the fixed UUIDv5 namespace for batch event identity:
// identical inputs always mint identical eventIds (replay/parity testing
// depends on byte-identical output), while any change to the identity tuple
// or observation time yields a distinct id.
var eventsNamespace = uuid.NewSHA1(uuid.NameSpaceURL,
	[]byte("https://mitre.github.io/hdf-libs/schemas/hdf-requirement-change-event/"))

const eventsDefaultSource = "urn:mitre:hdf:events:hdf-cli"

// NewEventsCmd creates the `hdf events` command group: batch wrappers over
// the hdf-diff change-event kernel (derive/fold/apply). Stateless and
// deterministic per invocation — sequencing state and cadence belong to the
// caller, never the CLI.
func NewEventsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "events",
		Short: "Derive, fold, and apply requirement-change events",
		Long: `Batch operations over the HDF requirement-change-event stream (ADR-0005).

derive  compares two same-target hdf-results documents and emits one NDJSON
        Requirement_Change_Event per changed requirement.
fold    materializes a change-event batch into a systemDrift hdf-comparison
        against a seed document.
apply   reassembles the current posture: seed document + events → reconciled
        hdf-results with a derivation block.

Each invocation is stateless and deterministic: event identity is derived
from the input documents (UUIDv5 + the next document's timestamp), never
from the wall clock.`,
	}
	cmd.AddCommand(newEventsDeriveCmd())
	cmd.AddCommand(newEventsFoldCmd())
	cmd.AddCommand(newEventsApplyCmd())
	return cmd
}

func newEventsDeriveCmd() *cobra.Command {
	var prevPath, nextPath, outputPath, source, systemRef, componentID, schemaRef string
	var startSequence int64

	cmd := &cobra.Command{
		Use:   "derive --prev <results.json> --next <results.json>",
		Short: "Emit NDJSON change events between two same-target results documents",
		Example: `  hdf events derive --prev monday.hdf.json --next tuesday.hdf.json \
    --system-ref prod.hdf-system.json > events.ndjson`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if startSequence < 0 {
				return fmt.Errorf("--start-sequence must be >= 0 (the event schema's sequence minimum); got %d", startSequence)
			}
			prevDoc, err := loadEventsResults(prevPath, "--prev")
			if err != nil {
				return err
			}
			nextDoc, err := loadEventsResults(nextPath, "--next")
			if err != nil {
				return err
			}
			if nextDoc.Timestamp == nil {
				return fmt.Errorf("--next document has no timestamp; cannot assign a deterministic event occurrence")
			}
			resolvedComponent, err := resolveEventComponentID(componentID, nextDoc)
			if err != nil {
				return err
			}
			events := deriveEventStream(prevDoc, nextDoc, eventsDeriveIdentity{
				source:        source,
				systemRef:     systemRef,
				componentID:   resolvedComponent,
				schemaRef:     schemaRef,
				startSequence: startSequence,
			})
			var buf bytes.Buffer
			for _, ev := range events {
				line, mErr := json.Marshal(ev)
				if mErr != nil {
					return fmt.Errorf("failed to encode event for %s: %w", ev.RequirementID, mErr)
				}
				buf.Write(line)
				buf.WriteByte('\n')
			}
			return writeEventsOutput(cmd, outputPath, buf.Bytes())
		},
	}

	cmd.Flags().StringVar(&prevPath, "prev", "", "Prior hdf-results document (required)")
	cmd.Flags().StringVar(&nextPath, "next", "", "Next hdf-results document (required)")
	cmd.Flags().StringVarP(&outputPath, "output", "o", "", "Output file (default: stdout)")
	cmd.Flags().StringVar(&source, "source", eventsDefaultSource, "Event-stream producer URI recorded in the envelope")
	cmd.Flags().StringVar(&systemRef, "system-ref", "", "System document reference for the entity key (required)")
	cmd.Flags().StringVar(&componentID, "component-id", "", "Component UUID for the entity key (default: the next document's sole component)")
	cmd.Flags().StringVar(&schemaRef, "schema-ref", "", "Optional schemaRef URI stamped on every event")
	cmd.Flags().Int64Var(&startSequence, "start-sequence", 1, "Sequence number assigned to the first emitted event")
	_ = cmd.MarkFlagRequired("prev")
	_ = cmd.MarkFlagRequired("next")
	_ = cmd.MarkFlagRequired("system-ref")
	return cmd
}

func newEventsFoldCmd() *cobra.Command {
	var seedPath, outputPath string

	cmd := &cobra.Command{
		Use:   "fold --seed <results.json> [events.ndjson ...]",
		Short: "Materialize a change-event batch into a systemDrift hdf-comparison",
		Example: `  hdf events fold --seed monday.hdf.json events.ndjson -o drift.comparison.json
  hdf events fold --seed monday.hdf.json batch-1.ndjson batch-2.ndjson
  cat events.ndjson | hdf events fold --seed monday.hdf.json`,
		Args: cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			seedData, err := loadEventsSeed(seedPath)
			if err != nil {
				return err
			}
			events, err := loadChangeEventsArgs(args)
			if err != nil {
				return err
			}
			result, err := diff.FoldChangeEventsIntoComparison(seedData, events)
			if err != nil {
				return err
			}
			printEventWarnings(cmd, result.Warnings)
			out, err := json.MarshalIndent(result.Comparison, "", "  ")
			if err != nil {
				return fmt.Errorf("failed to encode comparison: %w", err)
			}
			return writeEventsOutput(cmd, outputPath, append(out, '\n'))
		},
	}

	cmd.Flags().StringVar(&seedPath, "seed", "", "Seed hdf-results document the events chain from (required)")
	cmd.Flags().StringVarP(&outputPath, "output", "o", "", "Output file (default: stdout)")
	_ = cmd.MarkFlagRequired("seed")
	return cmd
}

func newEventsApplyCmd() *cobra.Command {
	var seedPath, outputPath, seedURI, source string

	cmd := &cobra.Command{
		Use:   "apply --seed <results.json> [events.ndjson ...]",
		Short: "Reassemble the reconciled hdf-results from a seed plus change events",
		Example: `  hdf events apply --seed monday.hdf.json events.ndjson -o reconciled.hdf.json
  hdf events apply --seed monday.hdf.json batch-1.ndjson batch-2.ndjson -o reconciled.hdf.json
  cat events.ndjson | hdf events apply --seed monday.hdf.json`,
		Args: cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			seedData, err := loadEventsSeed(seedPath)
			if err != nil {
				return err
			}
			events, err := loadChangeEventsArgs(args)
			if err != nil {
				return err
			}
			resolvedURI := seedURI
			if resolvedURI == "" {
				resolvedURI = seedURIFromPath(seedPath)
			}
			resolvedSource := source
			if resolvedSource == "" && len(events) > 0 {
				resolvedSource = events[0].Source
			}
			if resolvedSource == "" {
				resolvedSource = eventsDefaultSource
			}
			result, err := diff.ApplyChangeEvents(seedData, events, diff.ApplyInputs{
				Generator: hdf.Generator{Name: "hdf-cli", Version: version},
				SeedURI:   resolvedURI,
				Source:    resolvedSource,
			})
			if err != nil {
				return err
			}
			printEventWarnings(cmd, result.Warnings)
			return writeEventsOutput(cmd, outputPath, append(result.Results, '\n'))
		},
	}

	cmd.Flags().StringVar(&seedPath, "seed", "", "Seed hdf-results document the events chain from (required)")
	cmd.Flags().StringVarP(&outputPath, "output", "o", "", "Output file (default: stdout)")
	cmd.Flags().StringVar(&seedURI, "seed-uri", "", "Seed URI recorded in the derivation block (default: the --seed path)")
	cmd.Flags().StringVar(&source, "source", "", "Event-stream source recorded in the derivation block (default: the first event's source)")
	_ = cmd.MarkFlagRequired("seed")
	return cmd
}

// loadChangeEventsArgs reads the event batch from the given files, or stdin
// when none are given (files XOR stdin). Batches are concatenated raw: the
// fold contract's (source, eventId) dedup and per-key sequence ordering make
// multi-batch delivery order-independent, so no merge logic belongs here.
func loadChangeEventsArgs(paths []string) ([]*hdf.HDFRequirementChangeEvent, error) {
	if len(paths) == 0 {
		return loadChangeEvents("")
	}
	var events []*hdf.HDFRequirementChangeEvent
	for _, p := range paths {
		batch, err := loadChangeEvents(p)
		if err != nil {
			return nil, err
		}
		events = append(events, batch...)
	}
	return events, nil
}

// loadEventsResults reads and boundary-validates an hdf-results input,
// naming the offending flag and diagnosing the common wrong-type mistakes.
func loadEventsResults(path, role string) (*hdf.HDFResults, error) {
	data, err := loadEventsSeed(path)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", role, err)
	}
	var doc hdf.HDFResults
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("%s: failed to parse results document: %w", role, err)
	}
	return &doc, nil
}

// loadEventsSeed reads and boundary-validates raw hdf-results bytes.
func loadEventsSeed(path string) ([]byte, error) {
	data, err := readInputFile(path)
	if err != nil {
		return nil, err
	}
	if err := shared.ValidateJSONSize(data, "results input", int(getMaxFileSize())); err != nil {
		return nil, err
	}
	if result := validators.ValidateResults(data); !result.Valid {
		hint := ""
		if looksLikeChangeEvent(data) {
			hint = " (this looks like a change-event stream — pass it as the events input instead)"
		}
		return nil, fmt.Errorf("not a valid hdf-results document%s: %s", hint, firstValidationError(result))
	}
	return data, nil
}

// looksLikeChangeEvent detects the most likely wrong-input mistake: an
// events file where a results document was expected.
func looksLikeChangeEvent(data []byte) bool {
	line := data
	if idx := bytes.IndexByte(data, '\n'); idx > 0 {
		line = data[:idx]
	}
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(line, &probe); err != nil {
		return false
	}
	_, hasEventID := probe["eventId"]
	_, hasState := probe["state"]
	return hasEventID && hasState
}

func firstValidationError(result validators.ValidationResult) string {
	if len(result.Errors) == 0 {
		return "schema validation failed"
	}
	first := result.Errors[0]
	if first.Field != "" {
		return fmt.Sprintf("%s: %s", first.Field, first.Description)
	}
	return first.Description
}

// loadChangeEvents reads one event batch source (NDJSON, single object, or
// JSON array; file or stdin) and boundary-validates every event.
func loadChangeEvents(path string) ([]*hdf.HDFRequirementChangeEvent, error) {
	label := path
	if path == "" || path == "-" {
		label = "events input"
	}
	data, err := readInput(path, false)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", label, err)
	}
	if err := shared.ValidateJSONSize(data, label, int(getMaxFileSize())); err != nil {
		return nil, err
	}

	trimmed := bytes.TrimSpace(data)
	var raws [][]byte
	unit := "line"
	if len(trimmed) > 0 && trimmed[0] == '[' {
		unit = "event"
		var arr []json.RawMessage
		if err := json.Unmarshal(trimmed, &arr); err != nil {
			return nil, fmt.Errorf("%s: failed to parse JSON array: %w", label, err)
		}
		for _, raw := range arr {
			raws = append(raws, raw)
		}
	} else {
		for _, line := range bytes.Split(data, []byte("\n")) {
			if len(bytes.TrimSpace(line)) == 0 {
				continue
			}
			raws = append(raws, line)
		}
	}

	events := make([]*hdf.HDFRequirementChangeEvent, 0, len(raws))
	for i, raw := range raws {
		if result := validators.ValidateRequirementChangeEvent(raw); !result.Valid {
			return nil, fmt.Errorf("%s: %s %d is not a valid hdf-requirement-change-event: %s",
				label, unit, i+1, firstValidationError(result))
		}
		var ev hdf.HDFRequirementChangeEvent
		if err := json.Unmarshal(raw, &ev); err != nil {
			return nil, fmt.Errorf("%s: %s %d: %w", label, unit, i+1, err)
		}
		events = append(events, &ev)
	}
	return events, nil
}

// resolveEventComponentID applies the sole-component default: an explicit
// flag always wins; otherwise the next document must determine the identity
// unambiguously.
func resolveEventComponentID(flagValue string, doc *hdf.HDFResults) (string, error) {
	if flagValue != "" {
		return flagValue, nil
	}
	var ids []string
	for _, c := range doc.Components {
		if c.ComponentID != nil && *c.ComponentID != "" {
			ids = append(ids, *c.ComponentID)
		}
	}
	if len(ids) == 1 {
		return ids[0], nil
	}
	return "", fmt.Errorf("cannot infer the component identity from the --next document (%d components); pass --component-id", len(ids))
}

// eventsDeriveIdentity carries the caller-supplied envelope identity for a
// derive run.
type eventsDeriveIdentity struct {
	source        string
	systemRef     string
	componentID   string
	schemaRef     string
	startSequence int64
}

// deriveEventStream compares two same-target documents through the
// detection kernel: next-document order for content-bearing keys, then
// removed keys sorted by id. Sequences are contiguous from startSequence;
// every identity input is derived from the documents, never the wall clock.
func deriveEventStream(prevDoc, nextDoc *hdf.HDFResults, id eventsDeriveIdentity) []*hdf.HDFRequirementChangeEvent {
	refTs := nextDoc.Timestamp.UTC().Format(time.RFC3339Nano)
	prevRefTs := refTs
	if prevDoc.Timestamp != nil {
		prevRefTs = prevDoc.Timestamp.UTC().Format(time.RFC3339Nano)
	}
	occurred := nextDoc.Timestamp.UTC()

	type prevEntry struct {
		state diff.KeyState
		req   hdf.EvaluatedRequirement
	}
	prevByKey := map[string]prevEntry{}
	for _, b := range prevDoc.Baselines {
		for _, r := range b.Requirements {
			cs := diff.ComputeEffectiveChecksum(r, refTs)
			if cs == nil {
				continue
			}
			prevByKey[r.ID] = prevEntry{
				state: diff.KeyState{
					EffectiveStatus: diff.ComputeEffectiveStatus(r, refTs),
					EffectiveImpact: diff.ComputeEffectiveImpact(r, refTs),
					Checksum:        *cs,
				},
				req: r,
			}
		}
	}

	seq := id.startSequence
	mkInputs := func(reqID string) diff.EventInputs {
		name := strings.Join([]string{
			id.systemRef, id.componentID, reqID, strconv.FormatInt(seq, 10), refTs,
		}, "\x1f")
		return diff.EventInputs{
			EventID:                uuid.NewSHA1(eventsNamespace, []byte(name)).String(),
			Source:                 id.source,
			Sequence:               seq,
			SystemRef:              id.systemRef,
			ComponentID:            id.componentID,
			RequirementID:          reqID,
			Timestamp:              occurred,
			ReferenceTimestamp:     refTs,
			PrevReferenceTimestamp: prevRefTs,
			SchemaRef:              id.schemaRef,
		}
	}

	var events []*hdf.HDFRequirementChangeEvent
	emit := func(prev *diff.KeyState, newReq, prevReq *hdf.EvaluatedRequirement, reqID string) {
		if ev := diff.ChangeEventFromPrevious(prev, newReq, prevReq, mkInputs(reqID)); ev != nil {
			events = append(events, ev)
			seq++
		}
	}

	for _, b := range nextDoc.Baselines {
		for i := range b.Requirements {
			r := b.Requirements[i]
			var prevState *diff.KeyState
			var prevReq *hdf.EvaluatedRequirement
			if entry, ok := prevByKey[r.ID]; ok {
				s, q := entry.state, entry.req
				prevState, prevReq = &s, &q
				delete(prevByKey, r.ID)
			}
			emit(prevState, &r, prevReq, r.ID)
		}
	}
	removed := make([]string, 0, len(prevByKey))
	for reqID := range prevByKey {
		removed = append(removed, reqID)
	}
	sort.Strings(removed)
	for _, reqID := range removed {
		entry := prevByKey[reqID]
		s, q := entry.state, entry.req
		emit(&s, nil, &q, reqID)
	}
	return events
}

// seedURIFromPath renders a filesystem path as a valid RFC 3986
// URI-reference for the derivation block's default seed URI. POSIX-style
// paths are already valid path references and pass through slash-normalized;
// Windows drive and UNC forms are not (drive colons and backslashes fail the
// schema's uri-reference format) and get the file scheme. Pure string shape
// detection — never runtime.GOOS — so both branches are testable on any OS.
// An explicit --seed-uri is always taken verbatim.
func seedURIFromPath(p string) string {
	// Backslash is a legal POSIX filename character, so it is rewritten as a
	// separator only inside the provably-Windows shapes below.
	isDrive := len(p) >= 2 && p[1] == ':' &&
		(('a' <= p[0] && p[0] <= 'z') || ('A' <= p[0] && p[0] <= 'Z'))
	if isDrive {
		// Drive-letter absolute (C:\... or C:/...): net/url percent-escapes
		// into a proper file URI.
		u := url.URL{Scheme: "file", Path: "/" + strings.ReplaceAll(p, `\`, "/")}
		return u.String()
	}
	if strings.HasPrefix(p, `\\`) {
		// UNC \\host\share\... becomes file://host/share/...
		slashed := strings.ReplaceAll(p, `\`, "/")
		host, rest := slashed[2:], "/"
		if i := strings.Index(host, "/"); i >= 0 {
			host, rest = host[:i], host[i:]
		}
		u := url.URL{Scheme: "file", Host: host, Path: rest}
		return u.String()
	}
	return filepath.ToSlash(p)
}

// printEventWarnings surfaces fold-contract anomalies on stderr: warnings
// never abort the fold, but they are never silent either.
func printEventWarnings(cmd *cobra.Command, warnings []diff.ApplyWarning) {
	for _, w := range warnings {
		fmt.Fprintf(cmd.ErrOrStderr(), "warning: %s %s: %s\n", w.Kind, w.RequirementID, w.Message)
	}
}

// writeEventsOutput writes to the output file or stdout.
func writeEventsOutput(cmd *cobra.Command, path string, data []byte) error {
	if path == "" {
		_, err := cmd.OutOrStdout().Write(data)
		return err
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("failed to write output: %w", err)
	}
	return nil
}
