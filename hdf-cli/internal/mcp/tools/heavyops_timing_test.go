package tools

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"strconv"
	"testing"
	"time"

	shared "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go"
	diff "github.com/mitre/hdf-libs/hdf-diff/go/v3"
	hdfengine "github.com/mitre/hdf-libs/hdf-engine/go/v3"
	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	validators "github.com/mitre/hdf-libs/hdf-validators/go/v3"
)

// heavyOpThreshold is the async cutoff from ADR-0007 §16: an op that exceeds it
// against the largest realistic fixture is a candidate to defer to a Tasks handle.
const heavyOpThreshold = 10 * time.Second

func loadBig(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("fixture %s unavailable: %v", path, err)
	}
	return data
}

// TestBenchHeavyOps times the five candidate ops the Tasks extension may defer
// (>10s -> task handle). It is a TIMING HARNESS, not a pass/fail gate: the
// recorded durations are the artifact (transcribed into ADR-0007 §16 + the card).
// It fails only if an op errors. Gated behind HDF_BENCH so it never slows the
// normal suite; run with: HDF_BENCH=1 go test -run TestBenchHeavyOps -v -timeout 300s
// fixtureLabel describes a fixture by what it actually contains. The harness is
// the tripwire for "has a >10s workload appeared", so it must never report a
// size the file stopped having — the grype fixture shrank from 14 MB to 200 KB
// in 2026-09 and the hardcoded labels kept claiming the old figure.
func fixtureLabel(raw []byte) string {
	var doc hdf.HDFResults
	if json.Unmarshal(raw, &doc) != nil {
		return byteLabel(len(raw))
	}
	return byteLabel(len(raw)) + "/" + strconv.Itoa(countReqs(doc)) + "req"
}

func byteLabel(n int) string {
	switch {
	case n >= 1<<20:
		return strconv.FormatFloat(float64(n)/(1<<20), 'f', 1, 64) + "MB"
	default:
		return strconv.Itoa(n/1024) + "KB"
	}
}

func countReqs(doc hdf.HDFResults) int {
	n := 0
	for i := range doc.Baselines {
		n += len(doc.Baselines[i].Requirements)
	}
	return n
}

// largestOf returns the biggest of the given fixtures, so the fan-out measures
// the heaviest hash available rather than whichever file used to be heaviest.
func largestOf(paths ...string) ([]byte, error) {
	var best []byte
	var err error
	for _, p := range paths {
		b, e := os.ReadFile(p) // #nosec G304 -- repo-relative test fixture
		if e != nil {
			err = e
			continue
		}
		if len(b) > len(best) {
			best = b
		}
	}
	if best == nil {
		return nil, err
	}
	return best, nil
}

func TestBenchHeavyOps(t *testing.T) {
	if os.Getenv("HDF_BENCH") == "" {
		t.Skip("set HDF_BENCH=1 to run the heavy-op timing harness")
	}
	const (
		// Real converter-output HDF results (proper trimmed-UTC timestamps).
		grypeHDF  = "../../../../hdf-converters/converters/grype-to-hdf/fixtures/expected/tensorflow.json.hdf.json"
		legacyHDF = "../../../../hdf-converters/converters/legacyhdf-to-hdf/fixtures/expected/wrapper.json.hdf.json"
		grypeSrc  = "../../../../hdf-converters/converters/grype-to-hdf/fixtures/input/tensorflow.json"
	)
	ctx := context.Background()

	type timing struct {
		name string
		dur  time.Duration
	}
	var recorded []timing
	record := func(name string, start time.Time) {
		d := time.Since(start)
		recorded = append(recorded, timing{name, d})
		flag := ""
		if d >= heavyOpThreshold {
			flag = "   <<< EXCEEDS 10s"
		}
		t.Logf("%-46s %9.3fs%s", name, d.Seconds(), flag)
	}

	// Labels are computed, never hardcoded: fixtures get trimmed, and a harness
	// that prints a size the file no longer has turns a tripwire into a lie.
	for _, path := range []string{grypeHDF, legacyHDF} {
		raw := loadBig(t, path)
		fx := struct{ label, path string }{fixtureLabel(raw), path}
		var doc hdf.HDFResults
		if err := json.Unmarshal(raw, &doc); err != nil {
			t.Logf("skip %s (unmarshal): %v", fx.path, err)
			continue
		}

		st := time.Now()
		matches := hdfengine.Filter(ctx, doc, hdfengine.Options{Count: true, StatusOf: shared.RequirementEffectiveStatus})
		rows := projectRows(doc, matches, "full", nil)
		record("query full-verbosity ("+fx.label+", "+strconv.Itoa(len(rows))+" rows)", st)

		st = time.Now()
		comp, err := diff.DiffHdf(ctx, doc, []hdf.HDFResults{doc}, diff.Options{ComparisonMode: diff.ModeTemporal})
		if err != nil {
			t.Fatalf("diff: %v", err)
		}
		record("temporal diff ("+fx.label+")", st)

		st = time.Now()
		b, err := json.Marshal(comp)
		if err != nil {
			t.Fatalf("marshal comparison: %v", err)
		}
		_ = validators.Validate(b, validators.TypeComparison).Valid
		_ = sha256.Sum256(b)
		record("emit marshal+validate+sha256 ("+fx.label+")", st)

		st = time.Now()
		_ = validators.Validate(raw, validators.TypeResults).Valid
		record("validate schema ("+fx.label+")", st)
	}

	graw := loadBig(t, grypeSrc)
	conv, terr := resolveConverter("grype", graw)
	if terr != nil {
		t.Fatalf("resolve grype converter: %v", terr)
	}
	st := time.Now()
	if _, err := conv.Convert(graw); err != nil {
		t.Fatalf("convert grype: %v", err)
	}
	record("convert grype ("+byteLabel(len(graw))+" source)", st)

	// --- The two realistic >10s candidates (huzc.1 re-scope). ---

	// Fleet diff is O(systems): DiffHdf ModeFleet runs one comparePair per system.
	if raw, err := os.ReadFile(legacyHDF); err == nil {
		var doc hdf.HDFResults
		if err := json.Unmarshal(raw, &doc); err == nil {
			for _, n := range []int{100, 500} {
				systems := make([]hdf.HDFResults, n)
				for i := range systems {
					systems[i] = doc
				}
				st := time.Now()
				if _, err := diff.DiffHdf(ctx, doc, systems, diff.Options{ComparisonMode: diff.ModeFleet}); err != nil {
					t.Fatalf("fleet diff n=%d: %v", n, err)
				}
				record("fleet diff ("+strconv.Itoa(n)+" systems x "+strconv.Itoa(countReqs(doc))+" req)", st)
			}
		}
	}

	// Evidence-package checksum fan-out: VerifyChecksums hashes each referenced
	// file. Cost is dominated by hashing file bytes x referenced-file count.
	if blob, err := largestOf(grypeHDF, legacyHDF); err == nil {
		sum := sha256.Sum256(blob)
		hexsum := hex.EncodeToString(sum[:])
		fetch := func(string) ([]byte, error) { return blob, nil }
		for _, n := range []int{100, 500} {
			contents := make([]hdfengine.EvidenceContent, n)
			for i := range contents {
				contents[i] = hdfengine.EvidenceContent{URI: "f" + strconv.Itoa(i), Type: "results", Checksum: hexsum}
			}
			st := time.Now()
			_ = hdfengine.VerifyChecksums(contents, fetch)
			record("checksum fan-out ("+strconv.Itoa(n)+" files x "+byteLabel(len(blob))+")", st)
		}
	}

	var heavy []string
	for _, r := range recorded {
		if r.dur >= heavyOpThreshold {
			heavy = append(heavy, r.name)
		}
	}
	if len(heavy) == 0 {
		t.Logf(">>> NO op exceeded 10s on the largest fixtures — the durable-task path (huzc.2/huzc.5) is not justified by CURRENT workloads. Surface to Will.")
	} else {
		t.Logf(">>> ops exceeding 10s (wire to Tasks in huzc.5): %v", heavy)
	}
}
