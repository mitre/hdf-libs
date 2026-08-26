package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	validators "github.com/mitre/hdf-libs/hdf-validators/go/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func readOpenVexFixture(t *testing.T, name string) []byte {
	t.Helper()
	p := filepath.Join("..", "..", "..", "..", "hdf-converters", "converters", "openvex-to-hdf", "fixtures", "input", name)
	b, err := os.ReadFile(p)
	if err != nil {
		t.Skipf("openvex fixture %s unavailable: %v", name, err)
	}
	return b
}

// The card's designated first-failing test.
func TestAmendFromVex_MapsStatusesAndStampsSystem(t *testing.T) {
	data := readOpenVexFixture(t, "multi-status.openvex.json")
	expiry := time.Date(2099, 12, 31, 0, 0, 0, 0, time.UTC)

	doc, err := amendmentsFromVex(data, expiry, "test")
	require.NoError(t, err)

	// multi-status: not_affected→falsePositive, fixed→poam, affected &
	// under_investigation → no override. So exactly two overrides.
	require.Len(t, doc.Overrides, 2)
	types := map[hdf.OverrideType]bool{}
	for _, o := range doc.Overrides {
		types[o.Type] = true
		assert.Equal(t, hdf.IdentityTypeSystem, o.AppliedBy.Type, "every from-vex override must be system-attributed, not %q", o.AppliedBy.Type)
		assert.True(t, o.ExpiresAt.Equal(expiry), "expiresAt should be the caller value, got %s", o.ExpiresAt)
	}
	assert.True(t, types[hdf.FalsePositive], "not_affected should map to falsePositive")
	assert.True(t, types[hdf.Poam], "fixed should map to poam")
}

func TestAmendFromVex_OutputIsSchemaValid(t *testing.T) {
	data := readOpenVexFixture(t, "multi-status.openvex.json")
	doc, err := amendmentsFromVex(data, time.Date(2099, 12, 31, 0, 0, 0, 0, time.UTC), "test")
	require.NoError(t, err)
	out, err := json.MarshalIndent(doc, "", "  ")
	require.NoError(t, err)
	res := validators.ValidateAmendments(out)
	assert.True(t, res.Valid, "from-vex amendments must be schema-valid: %s", res.Error())
}

func TestAmendFromVex_NoOverridesIsError(t *testing.T) {
	// empty.openvex.json carries only affected + under_investigation → nothing maps.
	data := readOpenVexFixture(t, "empty.openvex.json")
	_, err := amendmentsFromVex(data, time.Date(2099, 12, 31, 0, 0, 0, 0, time.UTC), "test")
	require.Error(t, err)
	// A VEX with only affected/under_investigation statements yields nothing to amend.
	assert.Contains(t, err.Error(), "actionable")
}

func TestAmendFromVex_InvalidVexIsError(t *testing.T) {
	_, err := amendmentsFromVex([]byte(`{"not":"vex"}`), time.Date(2099, 12, 31, 0, 0, 0, 0, time.UTC), "test")
	require.Error(t, err)
}

func TestAmendFromVex_Command_RequiresExpiry(t *testing.T) {
	fixture := filepath.Join("..", "..", "..", "..", "hdf-converters", "converters", "openvex-to-hdf", "fixtures", "input", "multi-status.openvex.json")
	if _, err := os.Stat(fixture); err != nil {
		t.Skip("openvex fixture unavailable")
	}
	_, _, err := executeCommand("amend", "create", "--from-vex", fixture)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "expires")
}

func vexFixturePath(t *testing.T) string {
	t.Helper()
	p := filepath.Join("..", "..", "..", "..", "hdf-converters", "converters", "openvex-to-hdf", "fixtures", "input", "multi-status.openvex.json")
	if _, err := os.Stat(p); err != nil {
		t.Skip("openvex fixture unavailable")
	}
	return p
}

func TestAmendFromVex_Command_InvalidExpiry(t *testing.T) {
	_, _, err := executeCommand("amend", "create", "--from-vex", vexFixturePath(t), "--expires", "not-a-date")
	require.Error(t, err)
}

func TestAmendFromVex_Command_MissingFile(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "nope.openvex.json")
	_, _, err := executeCommand("amend", "create", "--from-vex", missing, "--expires", "2099-12-31T00:00:00Z")
	require.Error(t, err)
}

func TestAmendFromVex_Command_Stdout(t *testing.T) {
	stdout, _, err := executeCommand("amend", "create", "--from-vex", vexFixturePath(t), "--expires", "2099-12-31T00:00:00Z")
	require.NoError(t, err)
	assert.True(t, validators.ValidateAmendments([]byte(stdout)).Valid, "stdout amendments must be schema-valid")
}

func TestAmendFromVex_Command_InvalidVexFile(t *testing.T) {
	f := filepath.Join(t.TempDir(), "bad.json")
	require.NoError(t, os.WriteFile(f, []byte(`{"not":"vex"}`), 0o600))
	_, _, err := executeCommand("amend", "create", "--from-vex", f, "--expires", "2099-12-31T00:00:00Z")
	require.Error(t, err)
}

func TestAmendFromVex_Command_UnwritableOutput(t *testing.T) {
	out := filepath.Join(t.TempDir(), "no-such-dir", "x.json")
	_, _, err := executeCommand("amend", "create", "--from-vex", vexFixturePath(t), "--expires", "2099-12-31T00:00:00Z", "-o", out)
	require.Error(t, err)
}

func TestAmendFromVex_Command_WritesValidFile(t *testing.T) {
	fixture := filepath.Join("..", "..", "..", "..", "hdf-converters", "converters", "openvex-to-hdf", "fixtures", "input", "multi-status.openvex.json")
	if _, err := os.Stat(fixture); err != nil {
		t.Skip("openvex fixture unavailable")
	}
	out := filepath.Join(t.TempDir(), "vex-amendments.json")
	_, _, err := executeCommand("amend", "create", "--from-vex", fixture, "--expires", "2099-12-31T00:00:00Z", "-o", out)
	require.NoError(t, err)

	data, err := os.ReadFile(out)
	require.NoError(t, err)
	require.True(t, validators.ValidateAmendments(data).Valid)

	var doc hdf.HDFAmendments
	require.NoError(t, json.Unmarshal(data, &doc))
	require.Len(t, doc.Overrides, 2)
	for _, o := range doc.Overrides {
		assert.Equal(t, hdf.IdentityTypeSystem, o.AppliedBy.Type)
		assert.False(t, o.ExpiresAt.IsZero(), "expiresAt must be populated")
	}
}
