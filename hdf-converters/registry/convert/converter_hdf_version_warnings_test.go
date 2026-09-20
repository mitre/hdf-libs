package convert

import (
	"bytes"
	"strings"
	"testing"
)

// The downgrade warning slice is heterogeneous: a components[] passthrough-carrier
// notice is NOT an amendment, so the header must not call every item one. Issue
// #325 asked the notice to name what was affected; the old header re-genericized
// it into the wrong category ("amendment(s)"), so CI greps saw a phantom amendment
// failure.
func TestWriteTransformWarnings_HeaderIsCategoryNeutral(t *testing.T) {
	var buf bytes.Buffer
	writeTransformWarnings(&buf, []string{
		"components[]: all 2 component(s) carried via passthrough.hdf_components for lossless round-trip; Heimdall renders only the first (name/OS) via platform",
	})
	out := buf.String()

	if strings.Contains(out, "amendment") {
		t.Errorf("header miscategorizes a non-amendment warning as an amendment:\n%s", out)
	}
	if !strings.Contains(out, "1 item(s) could not be fully represented in the target HDF version:") {
		t.Errorf("expected the category-neutral header with the item count; got:\n%s", out)
	}
	if !strings.Contains(out, "  - components[]:") {
		t.Errorf("the per-item body must still be printed beneath the header; got:\n%s", out)
	}
}

// An empty slice prints nothing — a downgrade with no lossy items is silent.
func TestWriteTransformWarnings_EmptyIsSilent(t *testing.T) {
	var buf bytes.Buffer
	writeTransformWarnings(&buf, nil)
	if buf.Len() != 0 {
		t.Errorf("expected no output for zero warnings; got:\n%s", buf.String())
	}
}
