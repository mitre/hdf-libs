package hdfutil

import (
	"errors"
	"strings"
	"testing"
	"testing/iotest"
)

func TestReadAtMost_ReturnsInputWithinTheLimit(t *testing.T) {
	const limit = 16
	exact := strings.Repeat("a", limit)

	data, err := ReadAtMost(strings.NewReader(exact), limit, "scan.json")
	if err != nil {
		t.Fatalf("input of exactly the limit: unexpected error: %v", err)
	}
	if string(data) != exact {
		t.Fatalf("input of exactly the limit: got %d bytes, want all %d", len(data), limit)
	}

	data, err = ReadAtMost(strings.NewReader(""), limit, "scan.json")
	if err != nil || len(data) != 0 {
		t.Fatalf("empty input: got %d bytes / %v, want none and no error", len(data), err)
	}
}

func TestReadAtMost_RejectsOneByteOverTheLimit(t *testing.T) {
	const limit = 16
	data, err := ReadAtMost(strings.NewReader(strings.Repeat("a", limit+1)), limit, "scan.json")
	if err == nil {
		t.Fatalf("input one byte over the limit: got %d bytes and no error, want an error", len(data))
	}
	if data != nil {
		t.Errorf("input one byte over the limit: got %d bytes alongside the error, want none", len(data))
	}
	if !errors.Is(err, ErrInputTooLarge) {
		t.Errorf("error %q should wrap ErrInputTooLarge", err)
	}
	for _, want := range []string{"scan.json", "16"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q should contain %q", err, want)
		}
	}
}

func TestReadAtMost_StopsReadingPastTheLimit(t *testing.T) {
	// An endless reader proves the limit bounds what is read, not just what is returned.
	endless := iotest.OneByteReader(strings.NewReader(strings.Repeat("z", 4096)))
	_, err := ReadAtMost(endless, 8, "stream")
	if !errors.Is(err, ErrInputTooLarge) {
		t.Fatalf("want ErrInputTooLarge, got %v", err)
	}
}

func TestReadAtMost_ReportsAReadFailureWithItsSource(t *testing.T) {
	cause := errors.New("disk fell over")
	data, err := ReadAtMost(iotest.ErrReader(cause), 16, "scan.json")
	if data != nil {
		t.Errorf("got %d bytes alongside the error, want none", len(data))
	}
	if !errors.Is(err, cause) {
		t.Fatalf("error %v should wrap the read failure %v", err, cause)
	}
	if errors.Is(err, ErrInputTooLarge) {
		t.Errorf("a read failure must not read as too large: %v", err)
	}
	if !strings.Contains(err.Error(), "failed to read scan.json") {
		t.Errorf("error %q should name the source", err)
	}
}
