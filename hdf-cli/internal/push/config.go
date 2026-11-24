package push

import (
	"encoding/json"
	"fmt"
	"strings"
)

// redacted is what stands in for a secret everywhere a Config is rendered.
const redacted = "[redacted]"

// ConfigSpec is what an adapter declares it needs from the environment. The
// names live with the adapter, which is what keeps this package free of any one
// target's variables.
type ConfigSpec struct {
	// BaseURLVar names the variable holding the target's address. It comes from
	// the environment like a credential does, because pointing a write at the
	// wrong instance is its own incident — but unlike a credential it is rendered
	// rather than redacted, so an operator can see which instance was targeted.
	BaseURLVar string
	// SecretVars name variables whose values must never be rendered.
	SecretVars []string
	// PlainVars name variables that are safe to show, such as a user id.
	PlainVars []string
}

// Config carries a resolved target configuration.
//
// Every field is unexported and Resolve is the only constructor, so no caller
// can assign a secret into a Config — a flag value cannot become one. The values
// themselves come from whatever lookup is passed, which the command layer binds
// to os.LookupEnv and the tests bind to a literal map. The tests assert the
// field guarantee by reflection, so a later exported field fails the test run.
type Config struct {
	baseURL string
	secrets map[string]string
	plain   map[string]string
}

// Resolve reads a spec from the environment. lookup is injected so the resolver
// is testable without mutating the process environment; the command layer passes
// os.LookupEnv.
func Resolve(spec ConfigSpec, lookup func(string) (string, bool)) (Config, error) {
	if spec.BaseURLVar == "" {
		return Config{}, fmt.Errorf("adapter declared no base URL variable")
	}

	baseURL, ok := lookup(spec.BaseURLVar)
	if !ok || strings.TrimSpace(baseURL) == "" {
		return Config{}, fmt.Errorf("%s is not set: the target address comes from the environment, never from a flag", spec.BaseURLVar)
	}

	cfg := Config{
		baseURL: baseURL,
		secrets: make(map[string]string, len(spec.SecretVars)),
		plain:   make(map[string]string, len(spec.PlainVars)),
	}
	for _, name := range spec.SecretVars {
		value, ok := lookup(name)
		// A variable that is set but blank is a misconfiguration: pushing
		// unauthenticated is worse than refusing.
		if !ok || value == "" {
			return Config{}, fmt.Errorf("%s is not set: credentials come from the environment, never from a flag", name)
		}
		cfg.secrets[name] = value
	}
	for _, name := range spec.PlainVars {
		if value, ok := lookup(name); ok {
			cfg.plain[name] = value
		}
	}
	return cfg, nil
}

// BaseURL is the target's address.
func (c Config) BaseURL() string { return c.baseURL }

// Secret returns a resolved secret by variable name, for the adapter to put on a
// request. It is deliberately a lookup rather than a field, so a secret is read
// at the point of use and not carried around in a printable struct.
func (c Config) Secret(name string) string { return c.secrets[name] }

// Plain returns a non-sensitive resolved value.
func (c Config) Plain(name string) string { return c.plain[name] }

// String renders the config with every secret replaced. It exists so that a
// Config landing in a log line, an error or a %v is safe by default rather than
// by the caller remembering.
func (c Config) String() string {
	names := make([]string, 0, len(c.secrets))
	for name := range c.secrets {
		names = append(names, name+"="+redacted)
	}
	return fmt.Sprintf("target %s (%s)", c.baseURL, strings.Join(names, " "))
}

// GoString covers %#v, which would otherwise dump the struct's fields.
func (c Config) GoString() string { return c.String() }

// MarshalJSON covers --format json and any structured logger.
func (c Config) MarshalJSON() ([]byte, error) {
	secrets := make(map[string]string, len(c.secrets))
	for name := range c.secrets {
		secrets[name] = redacted
	}
	return json.Marshal(struct {
		BaseURL string            `json:"baseUrl"`
		Secrets map[string]string `json:"secrets,omitempty"`
		Plain   map[string]string `json:"plain,omitempty"`
	}{BaseURL: c.baseURL, Secrets: secrets, Plain: c.plain})
}
