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

	t.Run("impact zero always notApplicable", func(t *testing.T) {
		got := ComputeEffectiveStatus(EffectiveStatusInput{
			Impact:         0,
			ResultStatuses: []string{"failed"},
		}, statusRef)
		if got != "notApplicable" {
			t.Errorf("got %q, want notApplicable", got)
		}
	})

	t.Run("governing override wins over results and effectiveStatus", func(t *testing.T) {
		got := ComputeEffectiveStatus(EffectiveStatusInput{
			Impact:          0.7,
			EffectiveStatus: "failed",
			ResultStatuses:  []string{"failed"},
			Overrides: []StatusOverrideInput{
				{Status: waived, AppliedAt: appliedOld, ExpiresAt: farFuture},
			},
		}, statusRef)
		if got != waived {
			t.Errorf("got %q, want %q", got, waived)
		}
	})

	t.Run("effectiveStatus honored only when no overrides present", func(t *testing.T) {
		got := ComputeEffectiveStatus(EffectiveStatusInput{
			Impact:          0.7,
			EffectiveStatus: "passed",
			ResultStatuses:  []string{"failed"},
		}, statusRef)
		if got != "passed" {
			t.Errorf("got %q, want passed", got)
		}
	})

	t.Run("expired overrides invalidate stale effectiveStatus", func(t *testing.T) {
		// effectiveStatus is derived state; when its overrides have all
		// expired it goes stale, so the result rollup wins.
		got := ComputeEffectiveStatus(EffectiveStatusInput{
			Impact:          0.7,
			EffectiveStatus: "passed",
			ResultStatuses:  []string{"failed"},
			Overrides: []StatusOverrideInput{
				{Status: waived, AppliedAt: appliedOld, ExpiresAt: longAgo},
			},
		}, statusRef)
		if got != "failed" {
			t.Errorf("got %q, want failed (stale effectiveStatus recomputed)", got)
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
