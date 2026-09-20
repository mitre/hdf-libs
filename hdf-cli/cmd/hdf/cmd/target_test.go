package cmd

import (
	"encoding/json"
	"testing"
)

// set records a {id,type,boundary} descriptor as a v3 cloudAccount component
// (via the shared normalizer), the write passes schema validation, and get
// reads the identity back — attribution without saf-cli (#235).
func TestTargetSetRecordsComponentAndGetRoundTrips(t *testing.T) {
	path := writeV3Results(t) // reuses the schema-valid fixture from passthrough_test.go

	mustRun(t, "target", "set", path,
		"--data", `{"id":"prod-account","type":"cloudAccount","boundary":"sparc"}`)

	stdout, stderr, err := executeCommand("target", "get", path)
	if err != nil {
		t.Fatalf("target get failed: %v (stderr: %s)", err, stderr)
	}
	var comps []map[string]any
	if err := json.Unmarshal([]byte(stdout), &comps); err != nil {
		t.Fatalf("target get output not JSON: %v (%q)", err, stdout)
	}
	if len(comps) != 1 {
		t.Fatalf("expected one cloudAccount target component; got %d (%v)", len(comps), comps)
	}
	c := comps[0]
	if c["type"] != "cloudAccount" {
		t.Errorf("expected type cloudAccount; got %v", c["type"])
	}
	if c["accountId"] != "prod-account" {
		t.Errorf("expected accountId prod-account; got %v", c["accountId"])
	}
	if labels, _ := c["labels"].(map[string]any); labels["boundary"] != "sparc" {
		t.Errorf("expected labels.boundary sparc; got %v", c["labels"])
	}
}

// A malformed target descriptor (type not in the component enum) must not write a
// schema-invalid document — the write is gated by output validation.
func TestTargetSetRejectsInvalidType(t *testing.T) {
	path := writeV3Results(t)
	_, _, err := executeCommand("target", "set", path, "--data", `{"id":"x","type":"not-a-real-type"}`)
	if err == nil {
		t.Fatal("expected an error writing a target with an invalid component type")
	}
}
