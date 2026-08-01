package cmd

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	validators "github.com/mitre/hdf-libs/hdf-validators/go/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	eventsTestSystemRef   = "fixture.hdf-system.json"
	eventsTestComponentID = "6e0f2a3b-9c01-4d5e-8f7a-1b2c3d4e5f60"
)

// eventsFixturePath resolves a shared same-target scan fixture from
// hdf-diff/test/fixtures (the pair the kernel's parity law is proven on).
func eventsFixturePath(t *testing.T, name string) string {
	t.Helper()
	path := filepath.Join("..", "..", "..", "..", "hdf-diff", "test", "fixtures", name)
	absPath, err := filepath.Abs(path)
	require.NoError(t, err)
	if _, err := os.Stat(absPath); os.IsNotExist(err) {
		t.Skipf("fixture not found: %s", absPath)
	}
	return absPath
}

// executeCommandWithStdin runs a command with the given bytes as stdin.
func executeCommandWithStdin(t *testing.T, stdin []byte, args ...string) (string, string, error) {
	t.Helper()
	tmp := filepath.Join(t.TempDir(), "stdin.ndjson")
	require.NoError(t, os.WriteFile(tmp, stdin, 0o600))
	f, err := os.Open(tmp)
	require.NoError(t, err)
	defer func() { _ = f.Close() }()
	orig := os.Stdin
	os.Stdin = f
	defer func() { os.Stdin = orig }()
	return executeCommand(args...)
}

// deriveScanPair runs `hdf events derive` over the shared scan-before →
// scan-after pair and returns the NDJSON stdout.
func deriveScanPair(t *testing.T, extra ...string) string {
	t.Helper()
	args := append([]string{
		"events", "derive",
		"--prev", eventsFixturePath(t, "scan-before.json"),
		"--next", eventsFixturePath(t, "scan-after.json"),
		"--system-ref", eventsTestSystemRef,
		"--component-id", eventsTestComponentID,
	}, extra...)
	stdout, stderr, err := executeCommand(args...)
	require.NoError(t, err, "stderr: %s", stderr)
	return stdout
}

// parseNDJSONEvents decodes NDJSON output into typed events.
func parseNDJSONEvents(t *testing.T, ndjson string) []*hdf.HDFRequirementChangeEvent {
	t.Helper()
	var events []*hdf.HDFRequirementChangeEvent
	for _, line := range strings.Split(strings.TrimSpace(ndjson), "\n") {
		if line == "" {
			continue
		}
		var ev hdf.HDFRequirementChangeEvent
		require.NoError(t, json.Unmarshal([]byte(line), &ev))
		events = append(events, &ev)
	}
	return events
}

func TestEventsDerive_EmitsOnlyChangedKeys(t *testing.T) {
	stdout := deriveScanPair(t)
	events := parseNDJSONEvents(t, stdout)

	// SV-002 changed only in volatile result timestamps — the effective
	// posture is unchanged, so it must emit no event.
	states := map[string]string{}
	for _, ev := range events {
		states[ev.RequirementID] = string(ev.State)
	}
	assert.Equal(t, map[string]string{
		"SV-001": "fixed",
		"SV-003": "regressed",
		"SV-005": "updated",
		"SV-006": "new",
		"SV-004": "absent",
	}, states)

	// Every emitted line is a schema-valid Requirement_Change_Event.
	for i, line := range strings.Split(strings.TrimSpace(stdout), "\n") {
		result := validators.ValidateRequirementChangeEvent([]byte(line))
		assert.True(t, result.Valid, "line %d invalid: %v", i+1, result.Errors)
	}
}

func TestEventsDerive_EnvelopeIdentity(t *testing.T) {
	events := parseNDJSONEvents(t, deriveScanPair(t))
	require.Len(t, events, 5)

	// Emission order: next-doc order for content-bearing keys, then removed
	// keys sorted; sequences are contiguous from --start-sequence's default.
	wantOrder := []string{"SV-001", "SV-003", "SV-005", "SV-006", "SV-004"}
	for i, ev := range events {
		assert.Equal(t, wantOrder[i], ev.RequirementID)
		assert.Equal(t, int64(i+1), ev.Sequence)
		assert.Equal(t, eventsTestSystemRef, ev.SystemRef)
		assert.Equal(t, eventsTestComponentID, ev.ComponentID)
		// Occurrence = the next document's own timestamp, never wall clock.
		assert.Equal(t, "2024-02-01T00:00:00Z", ev.Timestamp.UTC().Format("2006-01-02T15:04:05Z07:00"))
	}

	// SV-005's posture moved via impact only.
	for _, ev := range events {
		if ev.RequirementID == "SV-005" {
			require.Len(t, ev.ChangeReasons, 1)
			assert.Equal(t, "impactChanged", string(ev.ChangeReasons[0]))
		}
	}
}

func TestEventsDerive_Deterministic(t *testing.T) {
	first := deriveScanPair(t)
	second := deriveScanPair(t)
	assert.Equal(t, first, second, "identical inputs must produce byte-identical events")
	assert.NotEmpty(t, first)
}

func TestEventsDerive_StartSequence(t *testing.T) {
	events := parseNDJSONEvents(t, deriveScanPair(t, "--start-sequence", "10"))
	require.Len(t, events, 5)
	assert.Equal(t, int64(10), events[0].Sequence)
	assert.Equal(t, int64(14), events[4].Sequence)

	// eventId is derived from the identity tuple, so shifting the sequence
	// deterministically changes it.
	base := parseNDJSONEvents(t, deriveScanPair(t))
	assert.NotEqual(t, base[0].EventID, events[0].EventID)
	again := parseNDJSONEvents(t, deriveScanPair(t, "--start-sequence", "10"))
	assert.Equal(t, events[0].EventID, again[0].EventID)
}

func TestEventsDerive_OutputFile(t *testing.T) {
	out := filepath.Join(t.TempDir(), "events.ndjson")
	deriveScanPair(t, "-o", out)
	data, err := os.ReadFile(out)
	require.NoError(t, err)
	assert.Len(t, parseNDJSONEvents(t, string(data)), 5)
}

func TestEventsDerive_RejectsNonResultsInput(t *testing.T) {
	events := filepath.Join(t.TempDir(), "events.ndjson")
	require.NoError(t, os.WriteFile(events, []byte(deriveScanPair(t)), 0o600))

	_, stderr, err := executeCommand(
		"events", "derive",
		"--prev", events,
		"--next", eventsFixturePath(t, "scan-after.json"),
		"--system-ref", eventsTestSystemRef,
		"--component-id", eventsTestComponentID,
	)
	require.Error(t, err)
	combined := err.Error() + stderr
	assert.Contains(t, combined, "hdf-results")
}

func TestEventsDerive_RequiresComponentIDWhenUnresolvable(t *testing.T) {
	// The scan fixtures carry no components[], so the id cannot be defaulted.
	_, _, err := executeCommand(
		"events", "derive",
		"--prev", eventsFixturePath(t, "scan-before.json"),
		"--next", eventsFixturePath(t, "scan-after.json"),
		"--system-ref", eventsTestSystemRef,
	)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--component-id")
}

func TestEventsFold_ProducesValidComparison(t *testing.T) {
	eventsFile := filepath.Join(t.TempDir(), "events.ndjson")
	require.NoError(t, os.WriteFile(eventsFile, []byte(deriveScanPair(t)), 0o600))

	stdout, stderr, err := executeCommand(
		"events", "fold",
		"--seed", eventsFixturePath(t, "scan-before.json"),
		eventsFile,
	)
	require.NoError(t, err, "stderr: %s", stderr)

	result := validators.ValidateComparison([]byte(stdout))
	require.True(t, result.Valid, "fold output must be a schema-valid hdf-comparison: %v", result.Errors)

	var comparison map[string]interface{}
	require.NoError(t, json.Unmarshal([]byte(stdout), &comparison))
	assert.Equal(t, "systemDrift", comparison["comparisonMode"])

	diffs, ok := comparison["requirementDiffs"].([]interface{})
	require.True(t, ok)
	states := map[string]string{}
	for _, dRaw := range diffs {
		d, dok := dRaw.(map[string]interface{})
		require.True(t, dok)
		id, _ := d["id"].(string)
		state, _ := d["state"].(string)
		states[id] = state
	}
	assert.Equal(t, map[string]string{
		"SV-001": "fixed",
		"SV-003": "regressed",
		"SV-004": "absent",
		"SV-005": "updated",
		"SV-006": "new",
	}, states)
}

func TestEventsFold_AcceptsStdinEvents(t *testing.T) {
	ndjson := deriveScanPair(t)
	stdout, stderr, err := executeCommandWithStdin(t, []byte(ndjson),
		"events", "fold",
		"--seed", eventsFixturePath(t, "scan-before.json"),
	)
	require.NoError(t, err, "stderr: %s", stderr)
	assert.True(t, validators.ValidateComparison([]byte(stdout)).Valid)
}

func TestEventsFold_RejectsInvalidEventLine(t *testing.T) {
	bogus := filepath.Join(t.TempDir(), "bogus.ndjson")
	seed, err := os.ReadFile(eventsFixturePath(t, "scan-before.json"))
	require.NoError(t, err)
	var compact bytes.Buffer
	require.NoError(t, json.Compact(&compact, seed))
	require.NoError(t, os.WriteFile(bogus, append(compact.Bytes(), '\n'), 0o600))

	_, _, cmdErr := executeCommand(
		"events", "fold",
		"--seed", eventsFixturePath(t, "scan-before.json"),
		bogus,
	)
	require.Error(t, cmdErr)
	assert.Contains(t, cmdErr.Error(), "line 1")
	assert.Contains(t, cmdErr.Error(), "change-event")
}

func TestEventsApply_ReassemblesNextPosture(t *testing.T) {
	eventsFile := filepath.Join(t.TempDir(), "events.ndjson")
	require.NoError(t, os.WriteFile(eventsFile, []byte(deriveScanPair(t)), 0o600))
	out := filepath.Join(t.TempDir(), "reconciled.hdf.json")

	_, stderr, err := executeCommand(
		"events", "apply",
		"--seed", eventsFixturePath(t, "scan-before.json"),
		eventsFile,
		"-o", out,
	)
	require.NoError(t, err, "stderr: %s", stderr)

	data, err := os.ReadFile(out)
	require.NoError(t, err)
	result := validators.ValidateResults(data)
	require.True(t, result.Valid, "reconciled output must be schema-valid hdf-results: %v", result.Errors)

	var doc hdf.HDFResults
	require.NoError(t, json.Unmarshal(data, &doc))

	// The reconciled key set matches the next observation.
	var ids []string
	byID := map[string]hdf.EvaluatedRequirement{}
	for _, b := range doc.Baselines {
		for _, r := range b.Requirements {
			ids = append(ids, r.ID)
			byID[r.ID] = r
		}
	}
	assert.ElementsMatch(t, []string{"SV-001", "SV-002", "SV-003", "SV-005", "SV-006"}, ids)

	// Changed keys carry the next document's full content.
	var next hdf.HDFResults
	nextBytes, err := os.ReadFile(eventsFixturePath(t, "scan-after.json"))
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(nextBytes, &next))
	nextByID := map[string]hdf.EvaluatedRequirement{}
	for _, b := range next.Baselines {
		for _, r := range b.Requirements {
			nextByID[r.ID] = r
		}
	}
	for _, id := range []string{"SV-001", "SV-003", "SV-005", "SV-006"} {
		got, gErr := json.Marshal(byID[id])
		require.NoError(t, gErr)
		want, wErr := json.Marshal(nextByID[id])
		require.NoError(t, wErr)
		assert.JSONEq(t, string(want), string(got), "reassembled %s must equal the next observation", id)
	}

	// Lineage: reconciled output never masquerades as scanner output.
	require.NotNil(t, doc.Generator)
	assert.Equal(t, "hdf-cli", doc.Generator.Name)
	require.NotNil(t, doc.Derivation)
	assert.Equal(t, int64(5), doc.Derivation.ThroughSequence)
	assert.Equal(t, int64(5), doc.Derivation.EventsApplied)
	// The default seed URI is the --seed path normalized to a valid
	// URI-reference (identity on POSIX; file scheme for Windows shapes).
	assert.Equal(t, seedURIFromPath(eventsFixturePath(t, "scan-before.json")), doc.Derivation.Seed.URI)
}

func TestEventsApply_SurfacesChainWarningsOnStderr(t *testing.T) {
	// An updated-state chain for a key the seed does not carry is a chain
	// gap: warned on stderr, still applied last-value-wins.
	orphan := strings.Replace(deriveScanPair(t), `"requirementId":"SV-005"`, `"requirementId":"SV-999"`, 1)
	var orphanLine string
	for _, line := range strings.Split(strings.TrimSpace(orphan), "\n") {
		if strings.Contains(line, "SV-999") {
			orphanLine = line
		}
	}
	require.NotEmpty(t, orphanLine)

	out := filepath.Join(t.TempDir(), "reconciled.hdf.json")
	_, stderr, err := executeCommandWithStdin(t, []byte(orphanLine+"\n"),
		"events", "apply",
		"--seed", eventsFixturePath(t, "scan-before.json"),
		"-o", out,
	)
	require.NoError(t, err, "warnings never abort the fold")
	assert.Contains(t, stderr, "chainGap")
	assert.Contains(t, stderr, "SV-999")

	_, statErr := os.Stat(out)
	assert.NoError(t, statErr, "output must still be written when warnings occur")
}

// splitEventStream writes the derived stream into two batch files (3 + 2
// events) plus the combined single file, returning the three paths.
func splitEventStream(t *testing.T) (first, second, combined string) {
	t.Helper()
	lines := strings.Split(strings.TrimSpace(deriveScanPair(t)), "\n")
	require.Len(t, lines, 5)
	dir := t.TempDir()
	first = filepath.Join(dir, "b1.ndjson")
	second = filepath.Join(dir, "b2.ndjson")
	combined = filepath.Join(dir, "all.ndjson")
	require.NoError(t, os.WriteFile(first, []byte(strings.Join(lines[:3], "\n")+"\n"), 0o600))
	require.NoError(t, os.WriteFile(second, []byte(strings.Join(lines[3:], "\n")+"\n"), 0o600))
	require.NoError(t, os.WriteFile(combined, []byte(strings.Join(lines, "\n")+"\n"), 0o600))
	return first, second, combined
}

func TestEventsApply_MultipleBatchFiles(t *testing.T) {
	first, second, combined := splitEventStream(t)
	seed := eventsFixturePath(t, "scan-before.json")
	dir := t.TempDir()

	runApply := func(name string, events ...string) []byte {
		out := filepath.Join(dir, name)
		args := append([]string{"events", "apply", "--seed", seed}, events...)
		args = append(args, "-o", out)
		_, stderr, err := executeCommand(args...)
		require.NoError(t, err, "stderr: %s", stderr)
		data, rErr := os.ReadFile(out)
		require.NoError(t, rErr)
		return data
	}

	baseline := runApply("baseline.json", combined)
	assert.Equal(t, baseline, runApply("split.json", first, second),
		"two batch files must fold identically to their concatenation")
	assert.Equal(t, baseline, runApply("reversed.json", second, first),
		"file order must not matter: sequence is the only ordering authority")
}

func TestEventsFold_MultipleBatchFiles(t *testing.T) {
	first, second, combined := splitEventStream(t)
	seed := eventsFixturePath(t, "scan-before.json")

	baseline, stderr, err := executeCommand("events", "fold", "--seed", seed, combined)
	require.NoError(t, err, "stderr: %s", stderr)
	split, stderr, err := executeCommand("events", "fold", "--seed", seed, first, second)
	require.NoError(t, err, "stderr: %s", stderr)
	assert.Equal(t, baseline, split)
	assert.True(t, validators.ValidateComparison([]byte(split)).Valid)
}

func TestEventsMultiFile_ErrorNamesOffendingFile(t *testing.T) {
	first, _, _ := splitEventStream(t)
	bogus := filepath.Join(t.TempDir(), "bogus.ndjson")
	require.NoError(t, os.WriteFile(bogus, []byte("{\"notAn\":\"event\"}\n"), 0o600))

	_, _, err := executeCommand(
		"events", "apply",
		"--seed", eventsFixturePath(t, "scan-before.json"),
		first, bogus,
	)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "bogus.ndjson")
	assert.Contains(t, err.Error(), "line 1")
}

func TestEventsApply_RejectsEventsFileAsSeed(t *testing.T) {
	eventsFile := filepath.Join(t.TempDir(), "events.ndjson")
	require.NoError(t, os.WriteFile(eventsFile, []byte(deriveScanPair(t)), 0o600))

	_, _, err := executeCommand(
		"events", "apply",
		"--seed", eventsFile,
		eventsFile,
	)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "hdf-results")
}

func TestSeedURIFromPath(t *testing.T) {
	cases := []struct{ name, in, want string }{
		// The exact shape that failed schema validation in Windows CI.
		{"windows drive absolute", `D:\a\hdf-libs\hdf-libs\hdf-diff\test\fixtures\scan-before.json`,
			"file:///D:/a/hdf-libs/hdf-libs/hdf-diff/test/fixtures/scan-before.json"},
		{"windows drive with space", `C:\scan results\seed.hdf.json`,
			"file:///C:/scan%20results/seed.hdf.json"},
		{"UNC share", `\\fileserver\scans\seed.hdf.json`,
			"file://fileserver/scans/seed.hdf.json"},
		// POSIX shapes are already valid URI-references: preserved verbatim.
		{"posix absolute", "/Users/x/scan-before.json", "/Users/x/scan-before.json"},
		{"relative", "state/seed.hdf.json", "state/seed.hdf.json"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, seedURIFromPath(tc.in))
		})
	}
}
