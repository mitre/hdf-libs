package hdfutil

import (
	"testing"
	"time"
)

var (
	statusRef  = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	farFuture  = time.Date(2099, 12, 31, 0, 0, 0, 0, time.UTC)
	longAgo    = time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	appliedOld = time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	appliedNew = time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC)
)

func TestStatusRank(t *testing.T) {
	// Canonical ordering per status-determination.md: higher rank = worse.
	cases := []struct {
		status string
		rank   int
	}{
		{"error", 4},
		{"failed", 3},
		{"passed", 2},
		{"notApplicable", 1},
		{"notReviewed", 0},
	}
	for _, c := range cases {
		if got := StatusRank(c.status); got != c.rank {
			t.Errorf("StatusRank(%q) = %d, want %d", c.status, got, c.rank)
		}
	}
	if got := StatusRank("bogus"); got != -1 {
		t.Errorf("StatusRank(bogus) = %d, want -1", got)
	}
}

func TestWorstStatus(t *testing.T) {
	cases := []struct {
		name     string
		statuses []string
		want     string
	}{
		{"empty", nil, "notReviewed"},
		{"single passed", []string{"passed"}, "passed"},
		{"failed beats passed", []string{"passed", "failed"}, "failed"},
		{"error beats failed", []string{"failed", "error", "passed"}, "error"},
		{"passed beats notReviewed", []string{"notReviewed", "passed"}, "passed"},
		{"notApplicable beats notReviewed", []string{"notReviewed", "notApplicable"}, "notApplicable"},
		{"all notReviewed", []string{"notReviewed", "notReviewed"}, "notReviewed"},
		{"unknown statuses ignored", []string{"bogus", "passed"}, "passed"},
		{"only unknown statuses", []string{"bogus"}, "notReviewed"},
	}
	for _, c := range cases {
		if got := WorstStatus(c.statuses); got != c.want {
			t.Errorf("%s: WorstStatus(%v) = %q, want %q", c.name, c.statuses, got, c.want)
		}
	}
}

func TestGoverningStatusOverride(t *testing.T) {
	waived := "notApplicable"
	failedStr := "failed"

	t.Run("most recent AppliedAt wins among non-expired", func(t *testing.T) {
		overrides := []StatusOverrideInput{
			{Status: waived, AppliedAt: appliedOld, ExpiresAt: farFuture},
			{Status: failedStr, AppliedAt: appliedNew, ExpiresAt: farFuture},
		}
		got := GoverningStatusOverride(overrides, statusRef)
		if got == nil || got.Status != failedStr {
			t.Fatalf("got %+v, want the later-applied override", got)
		}
	})

	t.Run("expired overrides are skipped", func(t *testing.T) {
		overrides := []StatusOverrideInput{
			{Status: failedStr, AppliedAt: appliedNew, ExpiresAt: longAgo},
			{Status: waived, AppliedAt: appliedOld, ExpiresAt: farFuture},
		}
		got := GoverningStatusOverride(overrides, statusRef)
		if got == nil || got.Status != waived {
			t.Fatalf("got %+v, want the non-expired override", got)
		}
	})

	t.Run("zero ExpiresAt never expires", func(t *testing.T) {
		overrides := []StatusOverrideInput{{Status: waived, AppliedAt: appliedOld}}
		if got := GoverningStatusOverride(overrides, statusRef); got == nil {
			t.Fatal("zero ExpiresAt must count as non-expired")
		}
	})

	t.Run("all expired yields nil", func(t *testing.T) {
		overrides := []StatusOverrideInput{{Status: waived, AppliedAt: appliedOld, ExpiresAt: longAgo}}
		if got := GoverningStatusOverride(overrides, statusRef); got != nil {
			t.Fatalf("got %+v, want nil", got)
		}
	})

	t.Run("statusless overrides are not governing", func(t *testing.T) {
		overrides := []StatusOverrideInput{{AppliedAt: appliedNew, ExpiresAt: farFuture}}
		if got := GoverningStatusOverride(overrides, statusRef); got != nil {
			t.Fatalf("got %+v, want nil for override without status", got)
		}
	})
}

func TestGoverningOverrideIndex(t *testing.T) {
	all := func(int) bool { return true }

	t.Run("most recent AppliedAt wins among eligible non-expired", func(t *testing.T) {
		overrides := []StatusOverrideInput{
			{AppliedAt: appliedOld, ExpiresAt: farFuture},
			{AppliedAt: appliedNew, ExpiresAt: farFuture},
		}
		if got := GoverningOverrideIndex(overrides, all, statusRef); got != 1 {
			t.Fatalf("got %d, want 1 (later-applied)", got)
		}
	})

	t.Run("ineligible overrides are skipped", func(t *testing.T) {
		overrides := []StatusOverrideInput{
			{AppliedAt: appliedOld, ExpiresAt: farFuture},
			{AppliedAt: appliedNew, ExpiresAt: farFuture},
		}
		onlyFirst := func(i int) bool { return i == 0 }
		if got := GoverningOverrideIndex(overrides, onlyFirst, statusRef); got != 0 {
			t.Fatalf("got %d, want 0 (only eligible)", got)
		}
	})

	t.Run("expired overrides are skipped", func(t *testing.T) {
		overrides := []StatusOverrideInput{
			{AppliedAt: appliedNew, ExpiresAt: longAgo},
			{AppliedAt: appliedOld, ExpiresAt: farFuture},
		}
		if got := GoverningOverrideIndex(overrides, all, statusRef); got != 1 {
			t.Fatalf("got %d, want 1 (non-expired)", got)
		}
	})

	t.Run("zero ExpiresAt never expires", func(t *testing.T) {
		overrides := []StatusOverrideInput{{AppliedAt: appliedOld}}
		if got := GoverningOverrideIndex(overrides, all, statusRef); got != 0 {
			t.Fatalf("got %d, want 0", got)
		}
	})

	t.Run("none eligible yields -1", func(t *testing.T) {
		overrides := []StatusOverrideInput{{AppliedAt: appliedOld, ExpiresAt: farFuture}}
		none := func(int) bool { return false }
		if got := GoverningOverrideIndex(overrides, none, statusRef); got != -1 {
			t.Fatalf("got %d, want -1", got)
		}
	})
}

func TestComputeEffectiveStatus(t *testing.T) {
	waived := "notApplicable"

	t.Run("impact never reaches the status", func(t *testing.T) {
		// Not-applicable is a claim about scope, which belongs in results[] or
		// in an override. Impact is a severity band. The same results therefore
		// roll up to the same status at every impact, including 0 — a source
		// whose convention conflates the two translates it at import.
		for _, c := range []struct {
			statuses []string
			want     string
		}{
			{[]string{"notReviewed"}, "notReviewed"},
			{nil, "notReviewed"},
			{[]string{"failed"}, "failed"},
			{[]string{"passed"}, "passed"},
			{[]string{"notApplicable"}, "notApplicable"},
		} {
			for _, impact := range []float64{0, 0.3, 0.5, 1} {
				got := ComputeEffectiveStatus(EffectiveStatusInput{
					Impact:         impact,
					ResultStatuses: c.statuses,
				}, statusRef)
				if got != c.want {
					t.Errorf("results %v at impact %v: got %q, want %q", c.statuses, impact, got, c.want)
				}
			}
		}
	})

	t.Run("an errored result reports error at impact 0", func(t *testing.T) {
		// error outranks every other status in the worst-wins order, so this
		// holds without a dedicated rung. Kept because it is the case a reader
		// expects to find: an execution error means the check never ran, which
		// matches InSpec EnhancedOutcomes and Heimdall inspecjs.
		for _, statuses := range [][]string{{"error"}, {"passed", "error"}} {
			got := ComputeEffectiveStatus(EffectiveStatusInput{
				Impact:         0,
				ResultStatuses: statuses,
			}, statusRef)
			if got != "error" {
				t.Errorf("results %v: got %q, want error", statuses, got)
			}
		}
	})

	t.Run("governing override still adjudicates an errored impact-0 requirement", func(t *testing.T) {
		// Overrides rank above the raw roll-up everywhere else; an explicit
		// non-expired override on a crashed impact-0 check governs the same
		// way. "passed" (a falsePositive adjudication) distinguishes the
		// override branch from the error roll-up.
		got := ComputeEffectiveStatus(EffectiveStatusInput{
			Impact:         0,
			ResultStatuses: []string{"error"},
			Overrides: []StatusOverrideInput{
				{Status: "passed", AppliedAt: appliedOld, ExpiresAt: farFuture},
			},
		}, statusRef)
		if got != "passed" {
			t.Errorf("got %q, want passed", got)
		}
	})

	t.Run("governing override wins over results", func(t *testing.T) {
		got := ComputeEffectiveStatus(EffectiveStatusInput{
			Impact:         0.7,
			ResultStatuses: []string{"failed"},
			Overrides: []StatusOverrideInput{
				{Status: waived, AppliedAt: appliedOld, ExpiresAt: farFuture},
			},
		}, statusRef)
		if got != waived {
			t.Errorf("got %q, want %q", got, waived)
		}
	})

	t.Run("governing override adjudicates an impact-0 requirement regardless of termination", func(t *testing.T) {
		// The override sits at the top of the ladder: whether the check
		// failed, passed, or errored, a signed non-expired override governs
		// uniformly — impact 0 does not silence it.
		for _, statuses := range [][]string{{"failed"}, {"passed"}, {"error"}} {
			got := ComputeEffectiveStatus(EffectiveStatusInput{
				Impact:         0,
				ResultStatuses: statuses,
				Overrides: []StatusOverrideInput{
					{Status: "passed", AppliedAt: appliedOld, ExpiresAt: farFuture},
				},
			}, statusRef)
			if got != "passed" {
				t.Errorf("results %v: got %q, want passed (override governs)", statuses, got)
			}
		}
	})

	t.Run("error roll-up wins when no overrides govern", func(t *testing.T) {
		// An execution error means the check never ran; absent a governing
		// override the ladder reports it at any impact.
		for _, impact := range []float64{0, 0.7} {
			got := ComputeEffectiveStatus(EffectiveStatusInput{
				Impact:         impact,
				ResultStatuses: []string{"error"},
			}, statusRef)
			if got != "error" {
				t.Errorf("impact %v: got %q, want error", impact, got)
			}
		}
	})

	t.Run("expired overrides yield the roll-up", func(t *testing.T) {
		got := ComputeEffectiveStatus(EffectiveStatusInput{
			Impact:         0.7,
			ResultStatuses: []string{"failed"},
			Overrides: []StatusOverrideInput{
				{Status: waived, AppliedAt: appliedOld, ExpiresAt: longAgo},
			},
		}, statusRef)
		if got != "failed" {
			t.Errorf("got %q, want failed (no governing override)", got)
		}
	})

	t.Run("rollup worst-wins", func(t *testing.T) {
		got := ComputeEffectiveStatus(EffectiveStatusInput{
			Impact:         0.5,
			ResultStatuses: []string{"passed", "error", "failed"},
		}, statusRef)
		if got != "error" {
			t.Errorf("got %q, want error", got)
		}
	})

	t.Run("no results notReviewed", func(t *testing.T) {
		got := ComputeEffectiveStatus(EffectiveStatusInput{Impact: 0.5}, statusRef)
		if got != "notReviewed" {
			t.Errorf("got %q, want notReviewed", got)
		}
	})

	t.Run("zero reference time uses wall clock", func(t *testing.T) {
		// A far-future expiry must be non-expired against the wall clock too.
		got := ComputeEffectiveStatus(EffectiveStatusInput{
			Impact:         0.7,
			ResultStatuses: []string{"failed"},
			Overrides: []StatusOverrideInput{
				{Status: waived, AppliedAt: appliedOld, ExpiresAt: farFuture},
			},
		}, time.Time{})
		if got != waived {
			t.Errorf("got %q, want %q", got, waived)
		}
	})
}

// The schema defines effectiveImpact as "the most recent non-expired override
// with an impact field", and GoverningOverrideIndex was generalized for exactly
// that — but nothing ever computed it, so a riskAdjustment was invisible to every
// consumer that asked about impact. This is the ladder's impact twin.
func TestComputeEffectiveImpact(t *testing.T) {
	adjustment := func(value float64, applied, expires time.Time) StatusOverrideInput {
		return StatusOverrideInput{AppliedAt: applied, ExpiresAt: expires, Impact: &value}
	}
	zero := time.Time{}

	for name, tc := range map[string]struct {
		input EffectiveStatusInput
		want  float64
	}{
		"no overrides falls back to the raw impact": {
			EffectiveStatusInput{Impact: 0.9}, 0.9,
		},
		"a governing adjustment wins": {
			EffectiveStatusInput{Impact: 0.9, Overrides: []StatusOverrideInput{
				adjustment(0.3, appliedOld, farFuture),
			}}, 0.3,
		},
		"an expired adjustment does not": {
			EffectiveStatusInput{Impact: 0.9, Overrides: []StatusOverrideInput{
				adjustment(0.3, appliedOld, longAgo),
			}}, 0.9,
		},
		"the most recently applied of several wins": {
			EffectiveStatusInput{Impact: 0.9, Overrides: []StatusOverrideInput{
				adjustment(0.3, appliedOld, zero),
				adjustment(0.5, appliedNew, zero),
			}}, 0.5,
		},
		"an override carrying no impact is not eligible": {
			EffectiveStatusInput{Impact: 0.9, Overrides: []StatusOverrideInput{
				{Status: "passed", AppliedAt: appliedNew},
			}}, 0.9,
		},
		"a status override newer than the impact one does not displace it": {
			// Eligibility is per-field: a waiver adjudicates status and says
			// nothing about impact, so the older adjustment still governs impact.
			EffectiveStatusInput{Impact: 0.9, Overrides: []StatusOverrideInput{
				adjustment(0.3, appliedOld, zero),
				{Status: "passed", AppliedAt: appliedNew},
			}}, 0.3,
		},
		"an adjustment to zero is honoured, not treated as absent": {
			// The reason Impact is a pointer: 0 is a legitimate re-score meaning
			// "no longer applicable", and a value type could not tell it from
			// "this override carries no impact".
			EffectiveStatusInput{Impact: 0.9, Overrides: []StatusOverrideInput{
				adjustment(0, appliedOld, zero),
			}}, 0,
		},
	} {
		t.Run(name, func(t *testing.T) {
			got := ComputeEffectiveImpact(tc.input, statusRef)
			if diff := got - tc.want; diff > 0.0001 || diff < -0.0001 {
				t.Errorf("ComputeEffectiveImpact() = %v, want %v", got, tc.want)
			}
		})
	}
}

// Status answers "what did the assessment establish" and impact answers "how
// much risk if it is realized". Neither an authored impact nor an impact
// override reaches the status, so the two can never disagree: a riskAdjustment
// re-scoring a finding to 0.0 leaves it failed, and an adjustment away from 0
// cannot bring a control into scope. Only an override carrying a status makes a
// scope claim, and it governs through the ladder's first rung.
//
// The schema pins the same rule from the other side: riskAdjustment "does not
// change pass/fail status, only impact". FedRAMP, whose deviation-request
// categories the enum is aligned to, keeps a risk-adjusted finding open on the
// POA&M and closes only a validated false positive. See
// status-determination.md, "Settled — impact never reaches the status".
func TestComputeEffectiveStatus_ImpactNeverReachesStatus(t *testing.T) {
	adjust := func(v float64) StatusOverrideInput {
		return StatusOverrideInput{Impact: &v, AppliedAt: appliedOld, ExpiresAt: farFuture}
	}
	waived := StatusOverrideInput{Status: "notApplicable", AppliedAt: appliedOld, ExpiresAt: farFuture}

	cases := []struct {
		name  string
		input EffectiveStatusInput
		want  string
	}{
		{
			// An impact of 0 is a severity band, not a scope claim. A source
			// whose convention says otherwise — InSpec supplies no pass/fail for
			// an impact-0 control — states the claim in results[] at import
			// instead, where every consumer can see it.
			"an authored impact of 0 with no results is notReviewed, not notApplicable",
			EffectiveStatusInput{Impact: 0},
			"notReviewed",
		},
		{
			"an adjustment to 0 leaves a real finding failing — it is re-scored, not closed",
			EffectiveStatusInput{Impact: 0.7, ResultStatuses: []string{"failed"}, Overrides: []StatusOverrideInput{adjust(0)}},
			"failed",
		},
		{
			"an adjustment away from 0 does not change the status either",
			EffectiveStatusInput{Impact: 0, Overrides: []StatusOverrideInput{adjust(0.9)}},
			"notReviewed",
		},
		{
			// An override that DOES carry a status is making a scope claim, and
			// rung 1 lets it win — that is the sanctioned way to say this.
			"a status-carrying override outranks the roll-up",
			EffectiveStatusInput{Impact: 0.7, ResultStatuses: []string{"failed"}, Overrides: []StatusOverrideInput{waived}},
			"notApplicable",
		},
		{
			// The translated shape the InSpec importer now emits: the scope
			// claim is a result, so it survives without help from the ladder.
			"an explicit notApplicable result reports notApplicable at impact 0",
			EffectiveStatusInput{Impact: 0, ResultStatuses: []string{"notReviewed", "notApplicable"}},
			"notApplicable",
		},
	}
	for _, c := range cases {
		if got := ComputeEffectiveStatus(c.input, statusRef); got != c.want {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}
}
