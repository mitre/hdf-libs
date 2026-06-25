package nist

import "testing"

func TestDefaultRevision(t *testing.T) {
	ResetRevision()
	if Revision() != DefaultRevision {
		t.Errorf("expected default revision %d, got %d", DefaultRevision, Revision())
	}
	if DefaultRevision != 5 {
		t.Errorf("expected DefaultRevision to be 5, got %d", DefaultRevision)
	}
}

func TestSetRevision(t *testing.T) {
	defer ResetRevision()

	if err := SetRevision(5); err != nil {
		t.Fatalf("SetRevision(5) returned error: %v", err)
	}
	if Revision() != 5 {
		t.Errorf("expected revision 5 after SetRevision(5), got %d", Revision())
	}

	if err := SetRevision(4); err != nil {
		t.Fatalf("SetRevision(4) returned error: %v", err)
	}
	if Revision() != 4 {
		t.Errorf("expected revision 4 after SetRevision(4), got %d", Revision())
	}
}

func TestSetRevisionRejectsUnsupported(t *testing.T) {
	defer ResetRevision()

	if err := SetRevision(99); err == nil {
		t.Error("expected error for unsupported revision 99, got nil")
	}
	// An invalid SetRevision must not mutate the current revision.
	if Revision() != DefaultRevision {
		t.Errorf("revision changed after failed SetRevision: got %d", Revision())
	}
}

func TestResetRevision(t *testing.T) {
	if err := SetRevision(5); err != nil {
		t.Fatalf("SetRevision(5) returned error: %v", err)
	}
	ResetRevision()
	if Revision() != DefaultRevision {
		t.Errorf("expected revision to reset to %d, got %d", DefaultRevision, Revision())
	}
}

func TestStrict(t *testing.T) {
	defer SetStrict(false)

	if Strict() {
		t.Error("expected strict to default to false")
	}
	SetStrict(true)
	if !Strict() {
		t.Error("expected Strict() to be true after SetStrict(true)")
	}
	SetStrict(false)
	if Strict() {
		t.Error("expected Strict() to be false after SetStrict(false)")
	}
}

func TestSupportedRevisions(t *testing.T) {
	revs := SupportedRevisions()
	if len(revs) != 2 || revs[0] != 4 || revs[1] != 5 {
		t.Errorf("expected supported revisions [4 5], got %v", revs)
	}
	// The returned slice must be a copy; mutating it must not affect internal state.
	revs[0] = 0
	if SupportedRevisions()[0] != 4 {
		t.Error("SupportedRevisions returned a slice that aliases internal state")
	}
}
