package hdfengine

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// vocabularyCases is the shared cross-language contract for what a filter value
// may be. test/query.test.ts reads the SAME file, so the two languages cannot
// disagree about a legal value or about which spellings mean the same thing.
type vocabularyCases struct {
	StatusValues      []string `json:"statusValues"`
	SeverityValues    []string `json:"severityValues"`
	DispositionValues []string `json:"dispositionValues"`
	PoamsValues       []string `json:"poamsValues"`
	Aliases           []struct {
		Field    string `json:"field"`
		Spelling string `json:"spelling"`
		Means    string `json:"means"`
	} `json:"aliases"`
	Rejected []struct {
		Field    string `json:"field"`
		Spelling string `json:"spelling"`
	} `json:"rejected"`
}

func loadVocabulary(t *testing.T) vocabularyCases {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "testdata", "filter-vocabulary-cases.json"))
	require.NoError(t, err)
	var table vocabularyCases
	require.NoError(t, json.Unmarshal(data, &table))
	require.NotEmpty(t, table.Aliases, "an empty table would pass vacuously")
	return table
}

// validatorFor is the check a caller runs before filtering, so an unrecognized
// value is refused rather than matching nothing and reporting a clean run.
func validatorFor(field string) func(string) bool {
	switch field {
	case "status":
		return ValidStatus
	case "severity":
		return ValidSeverity
	case "disposition":
		return ValidDisposition
	case "poams":
		return ValidPoamFilter
	}
	return nil
}

func TestFilterVocabulariesMatchTheSharedTable(t *testing.T) {
	table := loadVocabulary(t)
	for field, want := range map[string][]string{
		"status":      table.StatusValues,
		"severity":    table.SeverityValues,
		"disposition": table.DispositionValues,
		"poams":       table.PoamsValues,
	} {
		t.Run(field, func(t *testing.T) {
			require.NotEmpty(t, want, "an empty list would pass vacuously")
			// Compared BOTH ways: iterating the table only proves the validator
			// accepts what is listed, so an extra or renamed member in the Go
			// list would be invisible.
			if declared, ok := map[string][]string{
				"status": StatusValues, "severity": SeverityValues,
				"disposition": DispositionValues, "poams": {PoamValid, PoamNoneValid},
			}[field]; ok {
				assert.ElementsMatch(t, want, declared, "%s: the table and the declared list must agree", field)
			}
			valid := validatorFor(field)
			require.NotNil(t, valid, "no validator for %q", field)
			for _, value := range want {
				assert.True(t, valid(value), "%s: %q is in the table and must be accepted", field, value)
			}
		})
	}
}

// An alias is a spelling that arrived under two names historically. Normalizing
// in the ENGINE rather than in one caller is what makes a threshold rule and an
// hdf query invocation mean the same thing.
func TestFilterAliasesNormalizeToTheirCanonicalValue(t *testing.T) {
	table := loadVocabulary(t)
	for _, alias := range table.Aliases {
		t.Run(alias.Field+"/"+alias.Spelling, func(t *testing.T) {
			valid := validatorFor(alias.Field)
			require.NotNil(t, valid)
			assert.True(t, valid(alias.Spelling), "an accepted alias must validate")
			assert.Equal(t, alias.Means, NormalizeFilterValue(alias.Field, alias.Spelling),
				"%q must normalize onto the value it names", alias.Spelling)
		})
	}
}

// A value outside the vocabulary can only ever match nothing, which reads as a
// clean run over a filter that never applied.
func TestFilterRejectsValuesOutsideTheVocabulary(t *testing.T) {
	table := loadVocabulary(t)
	for _, bad := range table.Rejected {
		t.Run(bad.Field+"/"+bad.Spelling, func(t *testing.T) {
			valid := validatorFor(bad.Field)
			require.NotNil(t, valid)
			assert.False(t, valid(bad.Spelling), "%q must be refused", bad.Spelling)
		})
	}
}

// The point of normalizing is not that a validator accepts an alias but that the
// FILTER selects the same requirements for it. A rule written with the schema
// spelling and an `hdf query` written with the CLI's must answer identically, or
// ji20j's "prototype with query, paste into a spec" promise is false.
func TestFilterAliasesSelectTheSameRequirements(t *testing.T) {
	table := loadVocabulary(t)
	results := loadQueryFixture(t)
	// Returns canonical schema values, which is what the threshold path's
	// resolver produces; the CLI's display vocabulary is the other spelling the
	// aliases exist to reconcile.
	schemaStatus := func(c hdf.EvaluatedRequirement) string {
		if len(c.Results) == 0 {
			return string(hdf.NotReviewed)
		}
		return string(c.Results[0].Status)
	}

	// Disposition needs a document carrying a governing override, which the query
	// fixture has none of; the amendment fixture exists for exactly that.
	amendments := loadAmendmentCases(t).Fixture

	for _, alias := range table.Aliases {
		t.Run(alias.Field+"/"+alias.Spelling, func(t *testing.T) {
			subject := results
			aliasOpts := Options{StatusOf: schemaStatus}
			canonOpts := Options{StatusOf: schemaStatus}
			switch alias.Field {
			case "status":
				aliasOpts.Status = []string{alias.Spelling}
				canonOpts.Status = []string{alias.Means}
			case "severity":
				aliasOpts.Severity = []string{alias.Spelling}
				canonOpts.Severity = []string{alias.Means}
			case "disposition":
				subject = amendments
				aliasOpts.Disposition = []string{alias.Spelling}
				canonOpts.Disposition = []string{alias.Means}
			default:
				t.Skipf("no filter-selection shape for field %q", alias.Field)
			}
			canon := ids(Filter(context.Background(), subject, canonOpts))
			require.NotEmpty(t, canon,
				"the canonical spelling must select something, or this proves nothing")
			assert.Equal(t, canon, ids(Filter(context.Background(), subject, aliasOpts)),
				"%q must select exactly what %q selects", alias.Spelling, alias.Means)
		})
	}
}
