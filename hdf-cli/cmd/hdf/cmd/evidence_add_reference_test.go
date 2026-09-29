package cmd

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// referencePackage builds a minimal valid evidence package to attach references to.
func referencePackage(t *testing.T) (dir, pkgPath string) {
	t.Helper()
	dir = t.TempDir()
	for _, name := range []string{"system.json", "rhel9-results.json"} {
		src, err := os.ReadFile(filepath.Join(evidenceFixtureDir, name))
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(filepath.Join(dir, name), src, 0o600))
	}
	pkgPath = filepath.Join(dir, "pkg.json")
	_, _, err := executeCommand("evidence", "build",
		"--system", filepath.Join(dir, "system.json"),
		"--results", filepath.Join(dir, "rhel9-results.json"),
		"-o", pkgPath)
	require.NoError(t, err)
	return dir, pkgPath
}

func readPackage(t *testing.T, path string) map[string]any {
	t.Helper()
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	var doc map[string]any
	require.NoError(t, json.Unmarshal(data, &doc))
	return doc
}

// The whole point of the command: a STIX bundle is inert context and belongs in
// externalReferences[], not in externalEvidence[] where add-evidence would put it.
// Reaching for add-evidence with a STIX bundle misled this epic's author twice.
func TestEvidenceAddReference_WritesExternalReferences(t *testing.T) {
	_, pkgPath := referencePackage(t)

	_, _, err := executeCommand("evidence", "add-reference", pkgPath,
		"--source-name", "stix",
		"--kind", "threat-intel",
		"--href", "https://cti.example/bundle.json",
		"-o", pkgPath)
	require.NoError(t, err)

	doc := readPackage(t, pkgPath)
	refs, ok := doc["externalReferences"].([]any)
	require.True(t, ok, "the entry must land in externalReferences[]")
	require.Len(t, refs, 1)
	entry := refs[0].(map[string]any)
	assert.Equal(t, "stix", entry["sourceName"])
	assert.Equal(t, "threat-intel", entry["kind"])
	assert.Equal(t, "https://cti.example/bundle.json", entry["href"])

	// The sibling array must be untouched — that confusion is why this command exists.
	assert.NotContains(t, doc, "externalEvidence",
		"inert context must never land in externalEvidence[]")

	_, _, err = executeCommand("validate", pkgPath)
	require.NoError(t, err, "the package must still validate after the write")
}

// add-ref must be a true alias, not a second code path.
func TestEvidenceAddReference_AliasBehavesIdentically(t *testing.T) {
	_, longPkg := referencePackage(t)
	_, aliasPkg := referencePackage(t)
	args := []string{"--source-name", "cve", "--external-id", "CVE-2021-44228", "--rel", "reference"}

	_, _, err := executeCommand(append([]string{"evidence", "add-reference", longPkg}, append(args, "-o", longPkg)...)...)
	require.NoError(t, err)
	_, _, err = executeCommand(append([]string{"evidence", "add-ref", aliasPkg}, append(args, "-o", aliasPkg)...)...)
	require.NoError(t, err)

	assert.Equal(t, readPackage(t, longPkg)["externalReferences"], readPackage(t, aliasPkg)["externalReferences"],
		"the alias must produce a byte-identical entry, not a parallel implementation")
}

// sourceName is the schema's only required field on External_Reference, and it carries
// minLength 1 — so a blank one is refused at the boundary, not left to the validator.
func TestEvidenceAddReference_RequiresANonBlankSourceName(t *testing.T) {
	for _, tc := range []struct{ name, value string }{
		{"absent", ""},
		{"whitespace only", "   "},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, pkgPath := referencePackage(t)
			before, err := os.ReadFile(pkgPath)
			require.NoError(t, err)

			argv := []string{"evidence", "add-reference", pkgPath}
			if tc.value != "" {
				argv = append(argv, "--source-name", tc.value)
			}
			_, _, err = executeCommand(argv...)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "--source-name is required")

			after, err := os.ReadFile(pkgPath)
			require.NoError(t, err)
			assert.Equal(t, before, after, "a refused add must not touch the package")
		})
	}
}

// kind and rel are OPEN in the schema: kind carries only minLength 1, rel carries no
// constraint at all — no pattern, no enum. The command must not invent validation the
// schema does not have. (The card originally demanded an error naming "the actual
// pattern", carried over from add-evidence's --format, whose External_Evidence_Format
// genuinely has one. External_Reference does not; recorded as a card defect.)
func TestEvidenceAddReference_AcceptsTheOpenKindAndRelVocabularies(t *testing.T) {
	for _, tc := range []struct{ kind, rel string }{
		{"threat-intel", "reference"},       // documented starter vocabulary
		{"annotation", "definition"},        // ditto
		{"x-vendor-feed", "x-supersedes"},   // x- customs
		{"totally-made-up", "also-made-up"}, // neither is constrained, so both are valid
	} {
		t.Run(tc.kind+"/"+tc.rel, func(t *testing.T) {
			_, pkgPath := referencePackage(t)
			_, _, err := executeCommand("evidence", "add-reference", pkgPath,
				"--source-name", "x-feed", "--external-id", "FEED-1",
				"--kind", tc.kind, "--rel", tc.rel, "-o", pkgPath)
			require.NoError(t, err, "the schema constrains neither field, so neither may be refused")

			entry := readPackage(t, pkgPath)["externalReferences"].([]any)[0].(map[string]any)
			assert.Equal(t, tc.kind, entry["kind"])
			assert.Equal(t, tc.rel, entry["rel"])
		})
	}
}

// A local href is hashed at attach time; a URL is left unhashed. Both behaviours come
// from add-evidence's resolveEvidenceChecksum, reused rather than reimplemented.
func TestEvidenceAddReference_ChecksumsALocalHrefAndLeavesAURLAlone(t *testing.T) {
	dir, pkgPath := referencePackage(t)
	local := filepath.Join(dir, "bundle.json")
	const body = `{"type":"bundle","objects":[]}` + "\n"
	require.NoError(t, os.WriteFile(local, []byte(body), 0o600))

	_, _, err := executeCommand("evidence", "add-reference", pkgPath,
		"--source-name", "stix", "--href", local, "-o", pkgPath)
	require.NoError(t, err)
	_, _, err = executeCommand("evidence", "add-reference", pkgPath,
		"--source-name", "nvd", "--href", "https://nvd.nist.gov/vuln/detail/CVE-2021-44228", "-o", pkgPath)
	require.NoError(t, err)

	refs := readPackage(t, pkgPath)["externalReferences"].([]any)
	require.Len(t, refs, 2)
	localEntry, remoteEntry := refs[0].(map[string]any), refs[1].(map[string]any)

	sum, ok := localEntry["checksum"].(map[string]any)
	require.True(t, ok, "a local href must be hashed at attach time")
	assert.Equal(t, "sha256", sum["algorithm"])
	assert.Equal(t, fmt.Sprintf("%x", sha256.Sum256([]byte(body))), sum["value"],
		"and the digest must be of the real bytes")

	assert.NotContains(t, remoteEntry, "checksum",
		"a URL is referenced, never fetched, so there is nothing to hash")
}

// --checksum and --media-type describe the artifact at --href. Without one they are
// meaningless, and the schema says so of mediaType ("Meaningful only with href").
func TestEvidenceAddReference_RefusesHrefOnlyFlagsWithoutAnHref(t *testing.T) {
	for _, tc := range []struct{ flag, value, want string }{
		{"--checksum", strings.Repeat("a", 64), "--checksum records the digest of the artifact at --href"},
		{"--media-type", "application/json", "--media-type describes the artifact at --href"},
	} {
		t.Run(tc.flag, func(t *testing.T) {
			_, pkgPath := referencePackage(t)
			_, _, err := executeCommand("evidence", "add-reference", pkgPath,
				"--source-name", "stix", "--external-id", "X-1", tc.flag, tc.value, "-o", pkgPath)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.want)
		})
	}
}

// Both commands' help must name the array it writes and point at the other, because
// reaching for the wrong one is the mistake this command exists to prevent.
func TestEvidenceAddReference_HelpNamesBothArrays(t *testing.T) {
	refHelp, _, err := executeCommand("evidence", "add-reference", "--help")
	require.NoError(t, err)
	assert.Contains(t, refHelp, "externalReferences[]", "must name the array it writes")
	assert.Contains(t, refHelp, "externalEvidence[]", "and point at the sibling")
	assert.Contains(t, refHelp, "add-evidence", "by name")

	evHelp, _, err := executeCommand("evidence", "add-evidence", "--help")
	require.NoError(t, err)
	assert.Contains(t, evHelp, "externalEvidence[]", "must name the array it writes")
	assert.Contains(t, evHelp, "externalReferences[]", "and point at the sibling")
	// Naming the ARRAY is not naming the COMMAND. Asserting only the array name passed
	// against help that said "The evidence package's own externalReferences[] has no
	// command yet" — true when written, false once this card shipped, and a user reading
	// it would conclude no command exists.
	assert.Contains(t, evHelp, "add-reference",
		"the sibling must be named by command, not only by the array it writes")
	assert.NotContains(t, evHelp, "no command yet",
		"and must not claim the command it points at does not exist")

	// The at-least-one rule is mandatory, so the help must state it — the README did
	// while the help did not, which is how a user learns it from an error instead.
	assert.Contains(t, refHelp, "at least one of --external-id, --href or",
		"help must state the anyOf rule, not only that --source-name is required")
}

// Appending must preserve what is already recorded — including entries this command
// did not write.
func TestEvidenceAddReference_AppendsWithoutDisturbingExistingEntries(t *testing.T) {
	_, pkgPath := referencePackage(t)
	for _, src := range []string{"first", "second", "third"} {
		_, _, err := executeCommand("evidence", "add-reference", pkgPath,
			"--source-name", src, "--external-id", src+"-1", "-o", pkgPath)
		require.NoError(t, err)
	}
	refs := readPackage(t, pkgPath)["externalReferences"].([]any)
	require.Len(t, refs, 3)
	for i, want := range []string{"first", "second", "third"} {
		assert.Equal(t, want, refs[i].(map[string]any)["sourceName"], "order must be preserved")
	}
}

// External_Reference's anyOf requires ONE OF externalId | href | description alongside
// sourceName — the STIX 2.1 external_references rule. sourceName names the system; one of
// those three identifies or locates what is referenced within it, so a bare source name
// cites nothing. The rule is derived from the schema, not hardcoded, so it cannot drift.
func TestEvidenceAddReference_RequiresSomethingToIdentifyTheReference(t *testing.T) {
	t.Run("a bare source name is refused at the boundary", func(t *testing.T) {
		_, pkgPath := referencePackage(t)
		before, err := os.ReadFile(pkgPath)
		require.NoError(t, err)

		_, _, err = executeCommand("evidence", "add-reference", pkgPath,
			"--source-name", "stix", "-o", pkgPath)
		require.Error(t, err, "sourceName alone satisfies no anyOf branch")
		// The message must name every branch the schema offers, so the operator is not
		// left guessing which one to supply.
		for _, flag := range []string{"--description", "--external-id", "--href"} {
			assert.Contains(t, err.Error(), flag, "the error must name %s as a way to satisfy the rule", flag)
		}
		after, err := os.ReadFile(pkgPath)
		require.NoError(t, err)
		assert.Equal(t, before, after, "a refused add must not touch the package")
	})

	// Each branch on its own is sufficient.
	for _, tc := range []struct{ name, flag, value string }{
		{"externalId alone", "--external-id", "CVE-2021-44228"},
		{"href alone", "--href", "https://nvd.nist.gov/vuln/detail/CVE-2021-44228"},
		{"description alone", "--description", "Log4Shell advisory, cited for context"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, pkgPath := referencePackage(t)
			_, _, err := executeCommand("evidence", "add-reference", pkgPath,
				"--source-name", "cve", tc.flag, tc.value, "-o", pkgPath)
			require.NoError(t, err, "%s satisfies the anyOf on its own", tc.name)
			require.Len(t, readPackage(t, pkgPath)["externalReferences"].([]any), 1)
		})
	}
}

// The identity rule is read from the schema rather than hardcoded, so it survives a
// version bump that moves the bundled primitive's $defs path.
func TestEvidenceAddReference_DerivesTheIdentityRuleFromTheSchema(t *testing.T) {
	fields, err := externalReferenceIdentityFields()
	require.NoError(t, err, "the rule must be resolvable by following the schema's own $ref")
	assert.Equal(t, []string{"description", "externalId", "href"}, fields,
		"derived from External_Reference's anyOf, sorted; a schema change here should surface as a failure")
}

// The stderr receipt names the array it wrote, because reaching for the wrong array is
// the mistake this command exists to prevent — and it had no assertion at all, so the
// receipt could have named externalEvidence with the suite green.
func TestEvidenceAddReference_ReceiptNamesTheArrayItWrote(t *testing.T) {
	_, pkgPath := referencePackage(t)
	_, stderr, err := executeCommand("evidence", "add-reference", pkgPath,
		"--source-name", "stix", "--external-id", "bundle--1", "-o", pkgPath)
	require.NoError(t, err)

	assert.Contains(t, stderr, "externalReferences", "the receipt must name the array written")
	assert.NotContains(t, stderr, "externalEvidence",
		"naming the sibling array would be the exact confusion this command exists to prevent")
	assert.Contains(t, stderr, "stix", "and identify what was added")
}

// A blank --kind is refused: kind carries minLength 1, so a whitespace-only value would
// fail validation after the work. An EMPTY --kind is treated as unset, consistently with
// every other optional flag. This is the one behaviour the card's AC amendment named as
// checkable, and it had no test.
func TestEvidenceAddReference_RefusesABlankKindButTreatsEmptyAsUnset(t *testing.T) {
	t.Run("whitespace-only is refused", func(t *testing.T) {
		_, pkgPath := referencePackage(t)
		before, err := os.ReadFile(pkgPath)
		require.NoError(t, err)

		_, _, err = executeCommand("evidence", "add-reference", pkgPath,
			"--source-name", "stix", "--external-id", "X-1", "--kind", "   ", "-o", pkgPath)
		require.Error(t, err, "kind carries minLength 1, so a blank value cannot be written")
		assert.Contains(t, err.Error(), "--kind cannot be blank")

		after, err := os.ReadFile(pkgPath)
		require.NoError(t, err)
		assert.Equal(t, before, after, "a refused add must not touch the package")
	})

	t.Run("empty is treated as unset", func(t *testing.T) {
		_, pkgPath := referencePackage(t)
		_, _, err := executeCommand("evidence", "add-reference", pkgPath,
			"--source-name", "stix", "--external-id", "X-1", "--kind", "", "-o", pkgPath)
		require.NoError(t, err)
		entry := readPackage(t, pkgPath)["externalReferences"].([]any)[0].(map[string]any)
		assert.NotContains(t, entry, "kind", "an empty optional flag is omitted, not written blank")
	})
}

// Every optional field lands when given and is ABSENT when not. Writing an unset field as
// an empty string is a different claim from not recording it, and nothing asserted either
// half for mediaType or rel — mediaType could be discarded from every entry, or rel
// written as "", with the suite green.
func TestEvidenceAddReference_WritesOptionalFieldsAndOmitsUnsetOnes(t *testing.T) {
	dir, pkgPath := referencePackage(t)
	href := filepath.Join(dir, "runbook.json")
	require.NoError(t, os.WriteFile(href, []byte("{}\n"), 0o600))

	_, _, err := executeCommand("evidence", "add-reference", pkgPath,
		"--source-name", "x-vendor",
		"--href", href,
		"--external-id", "RB-7",
		"--kind", "annotation",
		"--rel", "definition",
		"--description", "vendor runbook",
		"--media-type", "application/json",
		"-o", pkgPath)
	require.NoError(t, err)

	full := readPackage(t, pkgPath)["externalReferences"].([]any)[0].(map[string]any)
	for field, want := range map[string]string{
		"sourceName":  "x-vendor",
		"externalId":  "RB-7",
		"kind":        "annotation",
		"rel":         "definition",
		"description": "vendor runbook",
		"mediaType":   "application/json",
	} {
		assert.Equal(t, want, full[field], "%s must land in the entry", field)
	}

	// Now the same reference with only what the schema demands: every other key absent.
	_, bare := referencePackage(t)
	_, _, err = executeCommand("evidence", "add-reference", bare,
		"--source-name", "x-vendor", "--external-id", "RB-7", "-o", bare)
	require.NoError(t, err)
	entry := readPackage(t, bare)["externalReferences"].([]any)[0].(map[string]any)
	for _, field := range []string{"kind", "rel", "description", "mediaType", "href", "checksum"} {
		assert.NotContains(t, entry, field,
			"%s was not given, so it must be absent rather than written empty", field)
	}
}

// An input that is already invalid is refused by the INPUT gate, before any work. Note
// which gate: this package fails on its own (contents[] requires minItems 1), so it never
// reaches the pre-write check — TestEvidenceAddReference_RefusesToWriteAnInvalidOutput
// pins that one. An earlier version of this comment claimed the pre-write check refused
// this, which was false and let the pre-write gate be deleted with the suite green.
func TestEvidenceAddReference_RefusesAnInvalidInputPackage(t *testing.T) {
	dir, pkgPath := referencePackage(t)
	doc := readPackage(t, pkgPath)
	doc["contents"] = []any{} // schema-invalid: contents requires at least one entry
	broken, err := json.Marshal(doc)
	require.NoError(t, err)
	brokenPath := filepath.Join(dir, "broken.json")
	require.NoError(t, os.WriteFile(brokenPath, broken, 0o600))

	out := filepath.Join(dir, "written.json")
	_, _, err = executeCommand("evidence", "add-reference", brokenPath,
		"--source-name", "stix", "--external-id", "X-1", "-o", out)
	require.Error(t, err, "an already-invalid package must be refused")
	assert.Contains(t, err.Error(), "input failed schema validation",
		"and refused by the INPUT gate, which is what this test pins")
	assert.NoFileExists(t, out, "with nothing written")
}

// The command validates its SERIALIZED OUTPUT before writing, as every other evidence
// subcommand does. Pinning that needs a VALID input whose write makes the package
// invalid — href carries format: uri-reference, so a malformed one passes the input gate
// and fails the pre-write gate. Driving it with an already-invalid input instead only
// proves "some validation exists somewhere", which is how the pre-write gate came to be
// deletable with the suite green.
func TestEvidenceAddReference_RefusesToWriteAnInvalidOutput(t *testing.T) {
	dir, pkgPath := referencePackage(t)
	before, err := os.ReadFile(pkgPath)
	require.NoError(t, err)
	// Precondition: the input is valid, so only the write can invalidate it.
	_, _, err = executeCommand("validate", pkgPath)
	require.NoError(t, err, "the input must be valid, or this pins the wrong gate")

	out := filepath.Join(dir, "written.json")
	_, _, err = executeCommand("evidence", "add-reference", pkgPath,
		"--source-name", "x", "--href", "http://[::1", "-o", out)
	require.Error(t, err, "a malformed href must not be written into the package")
	assert.Contains(t, err.Error(), "failed validation before write",
		"the PRE-WRITE gate must be what refuses, not the input read")
	assert.NoFileExists(t, out, "and nothing may be written")

	after, err := os.ReadFile(pkgPath)
	require.NoError(t, err)
	assert.Equal(t, before, after, "nor may the input be touched")
}

// A supplied --checksum is recorded for a remote href, and normalized to lowercase hex by
// the shared helper. The flag had no positive assertion at all: only its refusal without
// --href was tested, so it could have been silently discarded.
func TestEvidenceAddReference_RecordsASuppliedChecksumForARemoteHref(t *testing.T) {
	_, pkgPath := referencePackage(t)
	upper := strings.ToUpper(strings.Repeat("ab", 32))

	_, _, err := executeCommand("evidence", "add-reference", pkgPath,
		"--source-name", "nvd", "--href", "https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
		"--checksum", upper, "-o", pkgPath)
	require.NoError(t, err)

	entry := readPackage(t, pkgPath)["externalReferences"].([]any)[0].(map[string]any)
	sum, ok := entry["checksum"].(map[string]any)
	require.True(t, ok, "a supplied checksum must be recorded even though the href is remote")
	assert.Equal(t, "sha256", sum["algorithm"])
	assert.Equal(t, strings.ToLower(upper), sum["value"],
		"and normalized to lowercase hex by the shared helper")
}

// sourceName is trimmed on write, because " stix " and "stix" naming two different sources
// would be a trap. Documented in the flag help; nothing asserted it.
func TestEvidenceAddReference_TrimsTheSourceName(t *testing.T) {
	_, pkgPath := referencePackage(t)
	_, _, err := executeCommand("evidence", "add-reference", pkgPath,
		"--source-name", "  stix  ", "--external-id", "bundle--1", "-o", pkgPath)
	require.NoError(t, err)

	entry := readPackage(t, pkgPath)["externalReferences"].([]any)[0].(map[string]any)
	assert.Equal(t, "stix", entry["sourceName"],
		"surrounding whitespace is trimmed, as the flag help states")
}
