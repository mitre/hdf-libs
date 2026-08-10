package nist

import (
	"reflect"
	"testing"
)

func TestTranslateIdentity(t *testing.T) {
	for _, id := range []string{"AC-1", "AC-2", "IA-2(1)", "SC-7(5)"} {
		tr := Translate(id, 4, 5)
		if tr.Relation != RelationIdentity {
			t.Errorf("Translate(%q, 4, 5) relation = %q, want identity", id, tr.Relation)
		}
		if !reflect.DeepEqual(tr.Targets, []string{id}) {
			t.Errorf("Translate(%q, 4, 5) targets = %v, want [%s]", id, tr.Targets, id)
		}
	}
	// Identity holds in both directions.
	tr := Translate("AC-1", 5, 4)
	if tr.Relation != RelationIdentity || !reflect.DeepEqual(tr.Targets, []string{"AC-1"}) {
		t.Errorf("Translate(AC-1, 5, 4) = %+v, want identity [AC-1]", tr)
	}
}

func TestTranslateMoved(t *testing.T) {
	tr := Translate("IR-10", 4, 5)
	if tr.Relation != RelationMoved {
		t.Errorf("IR-10 relation = %q, want moved", tr.Relation)
	}
	if !reflect.DeepEqual(tr.Targets, []string{"IR-4(11)"}) {
		t.Errorf("IR-10 targets = %v, want [IR-4(11)]", tr.Targets)
	}
}

func TestTranslateIncorporated(t *testing.T) {
	tr := Translate("IA-2(11)", 4, 5)
	if tr.Relation != RelationIncorporated {
		t.Errorf("IA-2(11) relation = %q, want incorporated", tr.Relation)
	}
	if !reflect.DeepEqual(tr.Targets, []string{"IA-2(6)"}) {
		t.Errorf("IA-2(11) targets = %v, want [IA-2(6)]", tr.Targets)
	}
}

func TestTranslateMultiTarget(t *testing.T) {
	// "Moved to SR-4(1), SR-4(2)"
	tr := Translate("SA-12(14)", 4, 5)
	if !reflect.DeepEqual(tr.Targets, []string{"SR-4(1)", "SR-4(2)"}) {
		t.Errorf("SA-12(14) targets = %v, want [SR-4(1) SR-4(2)]", tr.Targets)
	}
	// "Incorporated into IA-2(1) and IA-2(2)"
	tr = Translate("IA-5(11)", 4, 5)
	if !reflect.DeepEqual(tr.Targets, []string{"IA-2(1)", "IA-2(2)"}) {
		t.Errorf("IA-5(11) targets = %v, want [IA-2(1) IA-2(2)]", tr.Targets)
	}
}

func TestTranslateStatementPartTargetNormalized(t *testing.T) {
	// "Incorporated into AC-2k" — statement part normalizes to the base control,
	// raw text retained in Detail.
	tr := Translate("AC-2(10)", 4, 5)
	if !reflect.DeepEqual(tr.Targets, []string{"AC-2"}) {
		t.Errorf("AC-2(10) targets = %v, want [AC-2]", tr.Targets)
	}
	if tr.Detail == "" {
		t.Error("AC-2(10) detail should preserve the raw NIST text")
	}
}

func TestTranslateWithdrawnNoSuccessor(t *testing.T) {
	// SC-19 is withdrawn in Rev 5 with no successor control.
	tr := Translate("SC-19", 4, 5)
	if tr.Relation != RelationNone {
		t.Errorf("SC-19 relation = %q, want none", tr.Relation)
	}
	if len(tr.Targets) != 0 {
		t.Errorf("SC-19 targets = %v, want empty", tr.Targets)
	}
}

func TestTranslateFamilyLevel(t *testing.T) {
	// SA-12 "Incorporated into SR family" — family marker, never expanded.
	tr := Translate("SA-12", 4, 5)
	if tr.Relation != RelationFamily {
		t.Errorf("SA-12 relation = %q, want family", tr.Relation)
	}
	if len(tr.Targets) != 0 {
		t.Errorf("SA-12 targets = %v, want empty (family is a marker, not an expansion)", tr.Targets)
	}
	if tr.Family != "SR" {
		t.Errorf("SA-12 family = %q, want SR", tr.Family)
	}
}

func TestTranslateAppendixJPointer(t *testing.T) {
	tr := Translate("AP-1", 4, 5)
	if tr.Relation != RelationPointer {
		t.Errorf("AP-1 relation = %q, want pointer", tr.Relation)
	}
	if !reflect.DeepEqual(tr.Targets, []string{"PT-2"}) {
		t.Errorf("AP-1 targets = %v, want [PT-2]", tr.Targets)
	}
	// AR-7 has no Rev 5 equivalent per NIST's own comparison.
	tr = Translate("AR-7", 4, 5)
	if tr.Relation != RelationNone || len(tr.Targets) != 0 {
		t.Errorf("AR-7 = %+v, want none/empty", tr)
	}
}

func TestTranslateNewInRev5(t *testing.T) {
	// AC-3(15) is new in Rev 5: no Rev 4 equivalent.
	tr := Translate("AC-3(15)", 5, 4)
	if tr.Relation != RelationNone || len(tr.Targets) != 0 {
		t.Errorf("AC-3(15) r5->r4 = %+v, want none/empty", tr)
	}
}

func TestTranslateRev5OriginFromInverse(t *testing.T) {
	// SR-5 is new in Rev 5 but SA-12(1) moved to it: the inverse edge gives r5->r4.
	tr := Translate("SR-5", 5, 4)
	if tr.Relation != RelationMoved {
		t.Errorf("SR-5 r5->r4 relation = %q, want moved", tr.Relation)
	}
	if !reflect.DeepEqual(tr.Targets, []string{"SA-12(1)"}) {
		t.Errorf("SR-5 r5->r4 targets = %v, want [SA-12(1)]", tr.Targets)
	}
}

func TestTranslatePreviouslyWithdrawnInRev4(t *testing.T) {
	// AC-13 was withdrawn in Rev 4 itself ("Previously withdrawn in Rev4;
	// Incorporated into AC-2 and AU-6"). It is a valid control at neither
	// revision, but stale tags referencing it still translate to its
	// incorporation targets from either direction.
	for _, from := range []int{4, 5} {
		to := 9 - from
		tr := Translate("AC-13", from, to)
		if tr.Relation != RelationIncorporated {
			t.Errorf("AC-13 %d->%d relation = %q, want incorporated", from, to, tr.Relation)
		}
		if !reflect.DeepEqual(tr.Targets, []string{"AC-2", "AU-6"}) {
			t.Errorf("AC-13 %d->%d targets = %v, want [AC-2 AU-6]", from, to, tr.Targets)
		}
	}
}

func TestTranslateUnknownControl(t *testing.T) {
	tr := Translate("ZZ-99", 4, 5)
	if tr.Relation != RelationUnknown || len(tr.Targets) != 0 {
		t.Errorf("ZZ-99 = %+v, want unknown/empty", tr)
	}
	tr = Translate("", 4, 5)
	if tr.Relation != RelationUnknown {
		t.Errorf("empty control relation = %q, want unknown", tr.Relation)
	}
}

func TestTranslateUnsupportedRevisions(t *testing.T) {
	if tr := Translate("AC-1", 4, 6); tr.Relation != RelationUnknown {
		t.Errorf("unsupported to-rev relation = %q, want unknown", tr.Relation)
	}
	if tr := Translate("AC-1", 3, 5); tr.Relation != RelationUnknown {
		t.Errorf("unsupported from-rev relation = %q, want unknown", tr.Relation)
	}
	if tr := Translate("AC-1", 4, 4); tr.Relation != RelationIdentity {
		t.Errorf("same-rev relation = %q, want identity", tr.Relation)
	}
}

func TestTranslateStatementLetterInput(t *testing.T) {
	// A statement-letter tag on a carried control passes through unchanged.
	tr := Translate("AC-2(j)", 4, 5)
	if tr.Relation != RelationIdentity || !reflect.DeepEqual(tr.Targets, []string{"AC-2(j)"}) {
		t.Errorf("AC-2(j) = %+v, want identity [AC-2(j)]", tr)
	}
	// On a redirected control the letter part is dropped with the redirect.
	tr = Translate("IR-10(a)", 4, 5)
	if !reflect.DeepEqual(tr.Targets, []string{"IR-4(11)"}) {
		t.Errorf("IR-10(a) targets = %v, want [IR-4(11)]", tr.Targets)
	}
}

func TestTranslateControlsBulk(t *testing.T) {
	translated, unmapped := TranslateControls([]string{"AC-1", "IR-10", "SC-19", "AC-3(15)"}, 4, 5)
	if !reflect.DeepEqual(translated, []string{"AC-1", "IR-4(11)"}) {
		t.Errorf("translated = %v, want [AC-1 IR-4(11)]", translated)
	}
	// SC-19 (withdrawn, no successor) and AC-3(15) (not a Rev 4 control) are unmapped.
	if len(unmapped) != 2 {
		t.Fatalf("unmapped = %+v, want 2 entries", unmapped)
	}
	if unmapped[0].Control != "SC-19" || unmapped[0].Relation != RelationNone {
		t.Errorf("unmapped[0] = %+v, want SC-19/none", unmapped[0])
	}
	if unmapped[1].Control != "AC-3(15)" || unmapped[1].Relation != RelationUnknown {
		t.Errorf("unmapped[1] = %+v, want AC-3(15)/unknown", unmapped[1])
	}
}

func TestTranslateControlsDedup(t *testing.T) {
	// IA-2(7) and IA-2(11) both incorporate into IA-2(6): the bulk helper dedups.
	translated, unmapped := TranslateControls([]string{"IA-2(7)", "IA-2(11)"}, 4, 5)
	if !reflect.DeepEqual(translated, []string{"IA-2(6)"}) {
		t.Errorf("translated = %v, want [IA-2(6)]", translated)
	}
	if len(unmapped) != 0 {
		t.Errorf("unmapped = %+v, want empty", unmapped)
	}
}

func TestAtRevision(t *testing.T) {
	// Same revision (or unsupported) is a no-op.
	in := []string{"AC-1", "UM-1"}
	if got := AtRevision(in, 4, 4); !reflect.DeepEqual(got, in) {
		t.Errorf("same-rev = %v, want unchanged", got)
	}
	if got := AtRevision(in, 3, 5); !reflect.DeepEqual(got, in) {
		t.Errorf("unsupported native rev = %v, want unchanged", got)
	}
	// Redirects follow the crosswalk; identity passes through.
	got := AtRevision([]string{"AC-1", "AU-8(1)"}, 4, 5)
	if !reflect.DeepEqual(got, []string{"AC-1", "SC-45(1)"}) {
		t.Errorf("got %v, want [AC-1 SC-45(1)]", got)
	}
	// Statement-style suffixes: kept on identity, dropped with redirects;
	// no-equivalent bases drop the whole reference.
	got = AtRevision([]string{"AC-1 a", "TR-1 a", "SC-19 a", "SA-12.1 (i)"}, 4, 5)
	if !reflect.DeepEqual(got, []string{"AC-1 a", "PT-5", "PT-5(1)"}) {
		t.Errorf("got %v, want [AC-1 a PT-5 PT-5(1)]", got)
	}
	// Family-level incorporation drops (no expansion), none drops, and
	// non-NIST placeholders pass through untouched.
	got = AtRevision([]string{"SA-12", "SC-19", "UM-1"}, 4, 5)
	if !reflect.DeepEqual(got, []string{"UM-1"}) {
		t.Errorf("got %v, want [UM-1]", got)
	}
	// Convergent redirects dedup, preserving first-seen order.
	got = AtRevision([]string{"IA-2(7)", "IA-2(11)", "IA-2(6)"}, 4, 5)
	if !reflect.DeepEqual(got, []string{"IA-2(6)"}) {
		t.Errorf("got %v, want [IA-2(6)]", got)
	}
}

func TestRosterCounts(t *testing.T) {
	// Sanity floor: ~1008 Rev 5 IDs and ~856 Rev 4 IDs (incl. Appendix J) per the
	// NIST comparison workbooks. Guards against a truncated or partially-parsed
	// source artifact slipping through regeneration.
	r4, r5 := RosterSize(4), RosterSize(5)
	if r5 < 1000 {
		t.Errorf("rev 5 roster = %d, expected >= 1000", r5)
	}
	if r4 < 850 {
		t.Errorf("rev 4 roster = %d, expected >= 850", r4)
	}
	if RosterSize(6) != 0 {
		t.Errorf("unsupported rev roster = %d, want 0", RosterSize(6))
	}
}
