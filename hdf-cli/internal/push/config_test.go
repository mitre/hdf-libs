package push_test

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/mitre/hdf-libs/hdf-cli/v3/internal/push"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const secretValue = "s3cr3t-not-a-real-key" //nolint:gosec // test literal, not a credential

func spec() push.ConfigSpec {
	return push.ConfigSpec{
		BaseURLVar: "TESTTARGET_BASE_URL",
		SecretVars: []string{"TESTTARGET_API_KEY"},
		PlainVars:  []string{"TESTTARGET_USER_UID"},
	}
}

func env(pairs map[string]string) func(string) (string, bool) {
	return func(k string) (string, bool) {
		v, ok := pairs[k]
		return v, ok
	}
}

func TestResolve_ReadsBaseURLAndSecretsFromTheEnvironment(t *testing.T) {
	cfg, err := push.Resolve(spec(), env(map[string]string{
		"TESTTARGET_BASE_URL": "https://target.example.mil",
		"TESTTARGET_API_KEY":  secretValue,
		"TESTTARGET_USER_UID": "operator-1",
	}))
	require.NoError(t, err)

	assert.Equal(t, "https://target.example.mil", cfg.BaseURL())
	assert.Equal(t, secretValue, cfg.Secret("TESTTARGET_API_KEY"))
	assert.Equal(t, "operator-1", cfg.Plain("TESTTARGET_USER_UID"))
}

func TestResolve_MissingBaseURLOrSecretIsAnError(t *testing.T) {
	t.Run("missing base URL", func(t *testing.T) {
		_, err := push.Resolve(spec(), env(map[string]string{"TESTTARGET_API_KEY": secretValue}))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "TESTTARGET_BASE_URL")
	})

	t.Run("missing secret names the variable, never a value", func(t *testing.T) {
		_, err := push.Resolve(spec(), env(map[string]string{"TESTTARGET_BASE_URL": "https://x"}))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "TESTTARGET_API_KEY")
		assert.NotContains(t, err.Error(), secretValue)
	})
}

// What is actually guaranteed: every field is unexported and Resolve is the only
// constructor, so no caller can assign a secret into a Config — a flag value
// cannot become one. Where the values come from is the lookup's business, and
// this file's own helper proves a literal map works; the command layer is the
// only place that binds it to the environment.
func TestConfig_HasNoFieldAFlagValueCouldBeAssignedTo(t *testing.T) {
	typ := reflect.TypeOf(push.Config{})
	require.Positive(t, typ.NumField(), "a Config with no fields would make this test vacuous")
	for i := range typ.NumField() {
		field := typ.Field(i)
		assert.False(t, field.IsExported(),
			"field %s is exported, so a flag value could be assigned straight into a Config", field.Name)
	}
}

// A secret must not reach a log line, an error, --format json, or a panic dump.
func TestConfig_NeverRendersASecret(t *testing.T) {
	cfg, err := push.Resolve(spec(), env(map[string]string{
		"TESTTARGET_BASE_URL": "https://target.example.mil",
		"TESTTARGET_API_KEY":  secretValue,
		"TESTTARGET_USER_UID": "operator-1",
	}))
	require.NoError(t, err)

	renderings := map[string]string{
		"String":    cfg.String(),
		"%v":        fmt.Sprintf("%v", cfg),
		"Sprint":    fmt.Sprint(cfg),
		"%+v":       fmt.Sprintf("%+v", cfg),
		"%#v":       fmt.Sprintf("%#v", cfg),
		"error":     fmt.Errorf("pushing to %v failed", cfg).Error(),
		"as an arg": fmt.Sprint([]any{cfg}...),
	}
	marshalled, err := json.Marshal(cfg)
	require.NoError(t, err)
	renderings["json.Marshal"] = string(marshalled)

	for label, rendered := range renderings {
		assert.NotContains(t, rendered, secretValue, "%s leaked the secret", label)
		assert.Contains(t, rendered, "https://target.example.mil",
			"%s should still show the address, so an operator can see which instance was targeted", label)
	}
}

// The redaction must not depend on the secret looking like a secret. There is
// no empty case: Resolve rejects a blank secret rather than redacting one.
func TestConfig_RedactsASecretOfAnyLength(t *testing.T) {
	// The base URL must not itself contain the secret, or the assertion below
	// matches the address rather than a leak.
	for _, value := range []string{"q", strings.Repeat("y", 200)} {
		cfg, err := push.Resolve(spec(), env(map[string]string{
			"TESTTARGET_BASE_URL": "https://target.example.mil",
			"TESTTARGET_API_KEY":  value,
			"TESTTARGET_USER_UID": "u",
		}))
		require.NoError(t, err)
		assert.NotContains(t, cfg.String(), value)
		assert.NotContains(t, fmt.Sprintf("%#v", cfg), value)
	}
}

// An empty secret is a misconfiguration, not a valid credential: a variable that
// is set but blank must fail rather than push unauthenticated.
func TestResolve_EmptySecretIsRejected(t *testing.T) {
	_, err := push.Resolve(spec(), env(map[string]string{
		"TESTTARGET_BASE_URL": "https://x",
		"TESTTARGET_API_KEY":  "",
		"TESTTARGET_USER_UID": "u",
	}))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "TESTTARGET_API_KEY")
}
