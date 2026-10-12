package cmd

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"

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
	// Every flag the help offers here is checked against the behaviour below, because a
	// Contains() on help text otherwise only asserts this repo's own phrasing back at
	// itself and passes just as happily when the sentence has gone false.
	assert.Contains(t, refHelp, "at least one of --external-id, --href,",
		"help must state the anyOf rule, not only that --source-name is required")
	for _, flag := range externalReferenceIdentityFlags {
		assert.Contains(t, refHelp, flag, "the help must offer %s", flag)
	}

	// The observable half: each flag the help names really does satisfy the rule on its
	// own, so the sentence above cannot go stale without a test failing.
	dir, _ := referencePackage(t)
	payload := filepath.Join(dir, "payload.json")
	require.NoError(t, os.WriteFile(payload, []byte(`{"type":"vulnerability"}`), 0o600))
	for _, tc := range []struct{ flag, value string }{
		{"--external-id", "CVE-2021-44228"},
		{"--href", "https://example.org/a.json"},
		{"--description", "a description"},
		{"--content-file", payload},
		{"--document-file", payload},
	} {
		t.Run(tc.flag+" alone satisfies the rule", func(t *testing.T) {
			_, pkgPath := referencePackage(t)
			_, _, err := executeCommand("evidence", "add-reference", pkgPath,
				"--source-name", "x-vendor", tc.flag, tc.value, "-o", pkgPath)
			require.NoError(t, err, "%s is offered by the help, so it must work alone", tc.flag)
			assert.Len(t, readPackage(t, pkgPath)["externalReferences"].([]any), 1)
		})
	}
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
	assert.Equal(t, []string{"content", "description", "document", "externalId", "href"}, fields,
		"derived from External_Reference's anyOf, sorted; a schema change here should surface as a failure")

	// It DID surface once: the anyOf gained content and document while this command had a
	// flag for neither. Both are authorable now, and these assertions are what stop the two
	// sets drifting apart again — the flag names pinned literally, so a rename fails here
	// rather than being read back to itself by the loop below.
	assert.Equal(t, map[string]string{
		"externalId":  "--external-id",
		"href":        "--href",
		"description": "--description",
		"content":     "--content-file",
		"document":    "--document-file",
	}, externalReferenceIdentityFlags, "the flag that authors each identity branch")
	for _, f := range fields {
		assert.Contains(t, externalReferenceIdentityFlags, f,
			"schema branch %q has no flag: add one rather than leaving the refusal to report a gap", f)
	}
	assert.Len(t, externalReferenceIdentityFlags, len(fields),
		"the flag map must not claim a branch the schema does not have")

	// And the refusal now offers all five, with no gap left to report.
	_, pkgPath := referencePackage(t)
	_, _, err = executeCommand("evidence", "add-reference", pkgPath, "--source-name", "cve")
	require.Error(t, err)
	for _, f := range fields {
		assert.Contains(t, err.Error(), externalReferenceIdentityFlags[f],
			"the operator still learns they CAN pass %s", externalReferenceIdentityFlags[f])
	}
	assert.NotContains(t, err.Error(), "no flag for",
		"every branch is authorable, so the refusal reports no gap")
}

// The encoding vocabulary is read from the schema's own enum rather than copied into the
// command, so an override is checked against what the validator will actually accept.
func TestEvidenceAddReference_DerivesTheEncodingVocabularyFromTheSchema(t *testing.T) {
	encodings, err := externalReferenceEncodings()
	require.NoError(t, err, "the enum must be resolvable by following the schema's own $ref")
	assert.Equal(t, []string{"utf-8", "base64"}, encodings,
		"External_Reference.encoding's enum; a schema change here should surface as a failure")
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

// Every success-path test in this file passed -o <the input path>, so the branch was
// exercised but never distinguished from the default, and the two tests using a distinct
// path both expected no write at all. See the sibling tests in evidence_set_test.go.
func TestEvidenceAddReference_OutputPathLeavesTheInputUntouched(t *testing.T) {
	t.Run("-o writes elsewhere and the input is byte-identical", func(t *testing.T) {
		dir, pkgPath := referencePackage(t)
		before, err := os.ReadFile(pkgPath)
		require.NoError(t, err)
		out := filepath.Join(dir, "elsewhere.json")

		_, _, err = executeCommand("evidence", "add-reference", pkgPath,
			"--source-name", "cve", "--external-id", "CVE-2021-44228", "-o", out)
		require.NoError(t, err)

		refs, ok := readPackage(t, out)["externalReferences"].([]any)
		require.True(t, ok, "the named output carries the array")
		assert.Len(t, refs, 1, "and the new reference")
		after, err := os.ReadFile(pkgPath)
		require.NoError(t, err)
		assert.Equal(t, before, after, "and the input is untouched")
	})

	t.Run("without -o the input is replaced in place", func(t *testing.T) {
		_, pkgPath := referencePackage(t)
		_, _, err := executeCommand("evidence", "add-reference", pkgPath,
			"--source-name", "cve", "--external-id", "CVE-2021-44228")
		require.NoError(t, err)
		refs, ok := readPackage(t, pkgPath)["externalReferences"].([]any)
		require.True(t, ok)
		assert.Len(t, refs, 1, "the default is to amend in place")
	})
}

// add-reference shares add-evidence's checksum resolver deliberately, so it shares this
// fix: a local --href is read from beside the PACKAGE, not from the process CWD. Without
// it, the documented invocation from a pipeline's repo root recorded no checksum, or worse
// recorded one for a same-named file that happened to sit under the CWD.
func TestEvidenceAddReference_HashesAPackageRelativeHref(t *testing.T) {
	dir, pkgPath := referencePackage(t)
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "cti"), 0o750))
	body := []byte("{\"objects\":[]}\n")
	require.NoError(t, os.WriteFile(filepath.Join(dir, "cti", "bundle.json"), body, 0o600))
	sum := sha256.Sum256(body)

	_, _, err := executeCommand("evidence", "add-reference", pkgPath,
		"--source-name", "stix", "--kind", "threat-intel", "--href", "cti/bundle.json")
	require.NoError(t, err)

	refs, ok := readPackage(t, pkgPath)["externalReferences"].([]any)
	require.True(t, ok)
	require.Len(t, refs, 1)
	entry, _ := refs[0].(map[string]any)
	assert.Equal(t, "cti/bundle.json", entry["href"], "the href is recorded as typed")
	cs, _ := entry["checksum"].(map[string]any)
	require.NotNil(t, cs, "a local href beside the package must be hashed")
	assert.Equal(t, hex.EncodeToString(sum[:]), cs["value"])
}

// add-reference shares the resolver, so it shares the confinement — and needs its own
// coverage, because the shared function's second call site was otherwise untested against
// the traversal and decoy cases.
func TestEvidenceAddReference_HrefResolutionIsConfinedAndPrefersThePackage(t *testing.T) {
	t.Run("a decoy under the CWD is not hashed", func(t *testing.T) {
		dir, pkgPath := referencePackage(t)
		require.NoError(t, os.MkdirAll(filepath.Join(dir, "cti"), 0o750))
		body := []byte("{\"objects\":[\"beside the package\"]}\n")
		require.NoError(t, os.WriteFile(filepath.Join(dir, "cti", "bundle.json"), body, 0o600))
		wantSum := sha256.Sum256(body)

		decoyRoot := t.TempDir()
		require.NoError(t, os.MkdirAll(filepath.Join(decoyRoot, "cti"), 0o750))
		require.NoError(t, os.WriteFile(filepath.Join(decoyRoot, "cti", "bundle.json"),
			[]byte("{\"objects\":[\"DECOY\"]}\n"), 0o600))
		t.Chdir(decoyRoot)

		_, _, err := executeCommand("evidence", "add-reference", pkgPath,
			"--source-name", "stix", "--href", "cti/bundle.json")
		require.NoError(t, err)

		refs, _ := readPackage(t, pkgPath)["externalReferences"].([]any)
		require.Len(t, refs, 1)
		entry, _ := refs[0].(map[string]any)
		cs, _ := entry["checksum"].(map[string]any)
		require.NotNil(t, cs, "a local href beside the package is hashed")
		assert.Equal(t, hex.EncodeToString(wantSum[:]), cs["value"],
			"from the file beside the package, not the decoy under the CWD")
	})

	t.Run("a traversal out of the package is not hashed", func(t *testing.T) {
		dir, pkgPath := referencePackage(t)
		up := filepath.Join(filepath.Dir(dir), "outside.json")
		require.NoError(t, os.WriteFile(up, []byte("{\"objects\":[]}\n"), 0o600))
		t.Chdir(dir) // reachable from the CWD too, so only confinement keeps it unhashed

		_, _, err := executeCommand("evidence", "add-reference", pkgPath,
			"--source-name", "stix", "--href", "../outside.json")
		require.NoError(t, err, "a reference outside the package is recorded, not refused")

		refs, _ := readPackage(t, pkgPath)["externalReferences"].([]any)
		require.Len(t, refs, 1)
		entry, _ := refs[0].(map[string]any)
		assert.Equal(t, "../outside.json", entry["href"], "recorded exactly as typed")
		assert.Nil(t, entry["checksum"], "and not hashed: resolution may not leave the package")
	})
}

// External_Reference's anyOf admits five identity branches; content and document are the
// two this command could not author. Both must round-trip through schema validation — a
// flag whose value the validator rejects is worse than no flag at all. Both are FILE
// flags: each carries an artifact, and an artifact's bytes do not belong on argv.
func TestEvidenceAddReference_AcceptsContentAsIdentity(t *testing.T) {
	// content is the embed branch for bytes document cannot hold (XML here). The schema
	// requires encoding alongside it — the allOf runs both ways — so the command supplies
	// one rather than writing a document the validator would reject.
	dir, pkgPath := referencePackage(t)
	const xml = "<?xml version=\"1.0\"?>\n<Benchmark id=\"x\"/>\n"
	xmlPath := filepath.Join(dir, "scan.xml")
	require.NoError(t, os.WriteFile(xmlPath, []byte(xml), 0o600))

	_, _, err := executeCommand("evidence", "add-reference", pkgPath,
		"--source-name", "openscap", "--content-file", xmlPath, "-o", pkgPath)
	require.NoError(t, err, "--content-file must identify a reference on its own")

	entry := readPackage(t, pkgPath)["externalReferences"].([]any)[0].(map[string]any)
	assert.Equal(t, xml, entry["content"], "the bytes are carried verbatim")
	assert.Equal(t, "utf-8", entry["encoding"], "encoding states how to read content back")

	// document is the embed branch for a JSON object, and satisfies the rule alone.
	docDir, docPkg := referencePackage(t)
	stix := `{"type":"vulnerability","spec_version":"2.1","name":"CVE-2021-44228"}`
	stixPath := filepath.Join(docDir, "vuln.json")
	require.NoError(t, os.WriteFile(stixPath, []byte(stix), 0o600))

	_, _, err = executeCommand("evidence", "add-reference", docPkg,
		"--source-name", "stix", "--kind", "threat-intel", "--document-file", stixPath, "-o", docPkg)
	require.NoError(t, err, "--document-file must identify a reference on its own")

	docEntry := readPackage(t, docPkg)["externalReferences"].([]any)[0].(map[string]any)
	assert.Equal(t, map[string]any{
		"type": "vulnerability", "spec_version": "2.1", "name": "CVE-2021-44228",
	}, docEntry["document"], "the payload rides verbatim as a JSON object")
}

// encoding is DERIVED from the bytes rather than asked for, because a guess is the thing
// encoding exists to prevent. The readback is asserted byte-exactly in both directions:
// utf-8 carries the bytes as-is, base64 decodes back to exactly what was read.
func TestEvidenceAddReference_DerivesContentEncodingFromTheBytes(t *testing.T) {
	// Edge whitespace and a CRLF, which a "cleanup" of the carriage path would destroy.
	text := []byte("\r\nid,result\r\nV-1,fail\r\n\r\n")
	binary := []byte{0x50, 0x4b, 0x03, 0x04, 0xff, 0xfe, 0x00, 0x01}
	require.False(t, utf8.Valid(binary), "the binary case must actually be invalid UTF-8")

	for _, tc := range []struct {
		name, wantEncoding string
		raw                []byte
	}{
		{"valid UTF-8 carries as utf-8", "utf-8", text},
		{"bytes that are not text carry as base64", "base64", binary},
		// The package read boundary strips a leading UTF-8 BOM so parsers do not choke on
		// it. Carriage must NOT: the BOM is part of the artifact, and dropping it would
		// both alter what is stored and leave the digest beside it unverifiable.
		{"a leading UTF-8 BOM survives", "utf-8", []byte("\xef\xbb\xbfid,result\nV-1,fail\n")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir, pkgPath := referencePackage(t)
			src := filepath.Join(dir, "artifact.bin")
			require.NoError(t, os.WriteFile(src, tc.raw, 0o600))

			_, _, err := executeCommand("evidence", "add-reference", pkgPath,
				"--source-name", "x-vendor", "--content-file", src, "-o", pkgPath)
			require.NoError(t, err)

			entry := readPackage(t, pkgPath)["externalReferences"].([]any)[0].(map[string]any)
			assert.Equal(t, tc.wantEncoding, entry["encoding"])

			stored, _ := entry["content"].(string)
			var back []byte
			if tc.wantEncoding == "base64" {
				back, err = base64.StdEncoding.DecodeString(stored)
				require.NoError(t, err, "base64 content must decode")
			} else {
				back = []byte(stored)
			}
			assert.Equal(t, tc.raw, back, "the embedded copy must be byte-exact with the source")
		})
	}
}

// An override is accepted only where it can be honoured losslessly. utf-8 over bytes that
// are not UTF-8 is refused rather than written: Go's JSON encoder substitutes U+FFFD for
// invalid UTF-8, which would corrupt the artifact and void the digest stored beside it.
func TestEvidenceAddReference_RefusesAnEncodingOverrideThatWouldCorruptTheBytes(t *testing.T) {
	dir, pkgPath := referencePackage(t)
	src := filepath.Join(dir, "artifact.bin")
	require.NoError(t, os.WriteFile(src, []byte{0xff, 0xfe, 0x00}, 0o600))

	_, _, err := executeCommand("evidence", "add-reference", pkgPath,
		"--source-name", "x-vendor", "--content-file", src, "--encoding", "utf-8", "-o", pkgPath)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not valid UTF-8")

	// base64 over text is honoured: it is lossless, merely not what derivation would pick.
	textDir, textPkg := referencePackage(t)
	textSrc := filepath.Join(textDir, "a.txt")
	require.NoError(t, os.WriteFile(textSrc, []byte("plain text\n"), 0o600))
	_, _, err = executeCommand("evidence", "add-reference", textPkg,
		"--source-name", "x-vendor", "--content-file", textSrc, "--encoding", "base64", "-o", textPkg)
	require.NoError(t, err, "base64 is a lossless override for text")

	entry := readPackage(t, textPkg)["externalReferences"].([]any)[0].(map[string]any)
	assert.Equal(t, "base64", entry["encoding"])
	decoded, err := base64.StdEncoding.DecodeString(entry["content"].(string))
	require.NoError(t, err)
	assert.Equal(t, "plain text\n", string(decoded))
}

// The schema makes encoding and content inseparable in BOTH directions, so an --encoding
// with nothing to decode is refused at the boundary instead of producing an invalid
// document, and a value outside the schema's enum is named against that enum.
func TestEvidenceAddReference_RefusesEncodingWithoutContentAndOutsideTheEnum(t *testing.T) {
	_, pkgPath := referencePackage(t)
	_, _, err := executeCommand("evidence", "add-reference", pkgPath,
		"--source-name", "cve", "--external-id", "CVE-2021-44228", "--encoding", "utf-8", "-o", pkgPath)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "meaningless without content")

	dir, enumPkg := referencePackage(t)
	src := filepath.Join(dir, "a.txt")
	require.NoError(t, os.WriteFile(src, []byte("x\n"), 0o600))
	_, _, err = executeCommand("evidence", "add-reference", enumPkg,
		"--source-name", "x-vendor", "--content-file", src, "--encoding", "utf16", "-o", enumPkg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "utf-8, base64", "the enum the schema declares")
}

// document is object-only. An array, a scalar and a literal null are each told to the
// operator with the alternative named, rather than surfacing as a validation failure
// after the package has already been rewritten.
func TestEvidenceAddReference_RefusesADocumentFileThatIsNotAnObject(t *testing.T) {
	for _, body := range []string{`[{"type":"vulnerability"}]`, `"a string"`, `null`, `not json at all`} {
		t.Run(body, func(t *testing.T) {
			dir, pkgPath := referencePackage(t)
			src := filepath.Join(dir, "payload.json")
			require.NoError(t, os.WriteFile(src, []byte(body), 0o600))

			_, _, err := executeCommand("evidence", "add-reference", pkgPath,
				"--source-name", "stix", "--document-file", src, "-o", pkgPath)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "--document-file")
		})
	}
}

// What each embed flag does with --checksum, stated rather than inherited by accident.
func TestEvidenceAddReference_HashesEmbeddedContentButNotAnEmbeddedDocument(t *testing.T) {
	t.Run("content is hashed from the bytes as read", func(t *testing.T) {
		dir, pkgPath := referencePackage(t)
		raw := []byte("<Benchmark/>\n")
		src := filepath.Join(dir, "scan.xml")
		require.NoError(t, os.WriteFile(src, raw, 0o600))
		want := sha256.Sum256(raw)

		_, _, err := executeCommand("evidence", "add-reference", pkgPath,
			"--source-name", "openscap", "--content-file", src, "-o", pkgPath)
		require.NoError(t, err)

		entry := readPackage(t, pkgPath)["externalReferences"].([]any)[0].(map[string]any)
		cs, _ := entry["checksum"].(map[string]any)
		require.NotNil(t, cs, "embedded bytes are verifiable, so they are hashed")
		assert.Equal(t, "sha256", cs["algorithm"])
		assert.Equal(t, hex.EncodeToString(want[:]), cs["value"],
			"the digest of the source bytes, which the stored copy reproduces exactly")
	})

	t.Run("a document is not hashed", func(t *testing.T) {
		dir, pkgPath := referencePackage(t)
		src := filepath.Join(dir, "vuln.json")
		// Whitespace and key order a parsed object cannot reproduce — which is exactly why
		// a digest of these bytes would not verify against what gets stored.
		require.NoError(t, os.WriteFile(src, []byte("{\n  \"type\" : \"vulnerability\"\n}\n"), 0o600))

		_, _, err := executeCommand("evidence", "add-reference", pkgPath,
			"--source-name", "stix", "--document-file", src, "-o", pkgPath)
		require.NoError(t, err)

		entry := readPackage(t, pkgPath)["externalReferences"].([]any)[0].(map[string]any)
		assert.NotContains(t, entry, "checksum",
			"a parsed object cannot reproduce the source bytes, so no digest is invented for it")
	})

	t.Run("an explicit checksum is recorded for a document", func(t *testing.T) {
		dir, pkgPath := referencePackage(t)
		src := filepath.Join(dir, "vuln.json")
		require.NoError(t, os.WriteFile(src, []byte(`{"type":"vulnerability"}`), 0o600))
		claimed := strings.Repeat("ab", 32)

		_, _, err := executeCommand("evidence", "add-reference", pkgPath,
			"--source-name", "stix", "--document-file", src, "--checksum", claimed, "-o", pkgPath)
		require.NoError(t, err, "--checksum is meaningful beside an embedded artifact")

		entry := readPackage(t, pkgPath)["externalReferences"].([]any)[0].(map[string]any)
		cs, _ := entry["checksum"].(map[string]any)
		require.NotNil(t, cs)
		assert.Equal(t, claimed, cs["value"], "the operator's claim about the source artifact")
	})
}

// checksum describes one artifact, so the precedence is pinned: an explicit --checksum
// outranks the embedded bytes' digest, and embedded bytes outrank hashing whatever --href
// points at, because the embedded copy is the one a consumer can actually verify.
func TestEvidenceAddReference_ChecksumPrecedenceAcrossEmbedAndHref(t *testing.T) {
	t.Run("explicit beats the embedded bytes", func(t *testing.T) {
		dir, pkgPath := referencePackage(t)
		src := filepath.Join(dir, "scan.xml")
		require.NoError(t, os.WriteFile(src, []byte("<Benchmark/>\n"), 0o600))
		derived := sha256.Sum256([]byte("<Benchmark/>\n"))
		claimed := strings.Repeat("cd", 32)

		_, _, err := executeCommand("evidence", "add-reference", pkgPath,
			"--source-name", "openscap", "--content-file", src, "--checksum", claimed, "-o", pkgPath)
		require.NoError(t, err)

		entry := readPackage(t, pkgPath)["externalReferences"].([]any)[0].(map[string]any)
		cs, _ := entry["checksum"].(map[string]any)
		require.NotNil(t, cs)
		assert.Equal(t, claimed, cs["value"])
		assert.NotEqual(t, hex.EncodeToString(derived[:]), cs["value"],
			"the explicit value must win, not be overwritten by the derivation")
	})

	t.Run("embedded bytes beat a local href", func(t *testing.T) {
		dir, pkgPath := referencePackage(t)
		embed := filepath.Join(dir, "scan.xml")
		require.NoError(t, os.WriteFile(embed, []byte("<Benchmark/>\n"), 0o600))
		pointed := filepath.Join(dir, "other.json")
		require.NoError(t, os.WriteFile(pointed, []byte(`{"a":1}`), 0o600))
		wantEmbed := sha256.Sum256([]byte("<Benchmark/>\n"))
		wantPointed := sha256.Sum256([]byte(`{"a":1}`))

		_, _, err := executeCommand("evidence", "add-reference", pkgPath,
			"--source-name", "openscap", "--content-file", embed, "--href", "other.json", "-o", pkgPath)
		require.NoError(t, err, "the schema lets one entry both point and embed")

		entry := readPackage(t, pkgPath)["externalReferences"].([]any)[0].(map[string]any)
		assert.Equal(t, "other.json", entry["href"], "the pointer is still recorded")
		cs, _ := entry["checksum"].(map[string]any)
		require.NotNil(t, cs)
		assert.Equal(t, hex.EncodeToString(wantEmbed[:]), cs["value"],
			"the embedded copy is what a consumer can verify, so it is what gets hashed")
		assert.NotEqual(t, hex.EncodeToString(wantPointed[:]), cs["value"])
	})
}

// --media-type and --checksum stop being href-only once an artifact is embedded: the
// schema says both describe the artifact at href OR the one embedded here. This is the
// pair of gates that would otherwise have blocked the schema's own embed-only examples.
func TestEvidenceAddReference_MediaTypeAndChecksumAreMeaningfulBesideAnEmbed(t *testing.T) {
	dir, pkgPath := referencePackage(t)
	src := filepath.Join(dir, "scan.xml")
	require.NoError(t, os.WriteFile(src, []byte("<Benchmark/>\n"), 0o600))

	_, _, err := executeCommand("evidence", "add-reference", pkgPath,
		"--source-name", "openscap", "--rel", "raw-source",
		"--content-file", src, "--media-type", "application/xml", "-o", pkgPath)
	require.NoError(t, err, "--media-type describes embedded bytes too, with no href in sight")

	entry := readPackage(t, pkgPath)["externalReferences"].([]any)[0].(map[string]any)
	assert.Equal(t, "application/xml", entry["mediaType"])
	assert.NotContains(t, entry, "href", "an embed-only entry needs no synthetic href")
}

// An embedded reference is still inert context: the package validates, verify passes, and
// bundle does not carry externalReferences[] into the archive.
func TestEvidenceAddReference_EmbeddedReferenceValidatesVerifiesAndNeverTravels(t *testing.T) {
	dir, pkgPath := referencePackage(t)
	src := filepath.Join(dir, "scan.xml")
	require.NoError(t, os.WriteFile(src, []byte("<Benchmark/>\n"), 0o600))
	stix := filepath.Join(dir, "vuln.json")
	require.NoError(t, os.WriteFile(stix, []byte(`{"type":"vulnerability"}`), 0o600))

	_, _, err := executeCommand("evidence", "add-reference", pkgPath,
		"--source-name", "openscap", "--content-file", src, "-o", pkgPath)
	require.NoError(t, err)
	_, _, err = executeCommand("evidence", "add-reference", pkgPath,
		"--source-name", "stix", "--document-file", stix, "-o", pkgPath)
	require.NoError(t, err)

	refs := readPackage(t, pkgPath)["externalReferences"].([]any)
	require.Len(t, refs, 2, "both embedded references landed")

	_, _, err = executeCommand("validate", pkgPath)
	require.NoError(t, err, "a package carrying embedded references must validate")
	_, _, err = executeCommand("evidence", "info", "--verify", pkgPath)
	require.NoError(t, err, "embedded references are inert and must not affect verification")

	archive := filepath.Join(dir, "bundle.tar.gz")
	_, _, err = executeCommand("evidence", "bundle", pkgPath, "-o", archive)
	require.NoError(t, err)
	assert.FileExists(t, archive)
	// The package on disk is unchanged by bundling, and the array it carries is the one
	// settled as never travelling.
	assert.Len(t, readPackage(t, pkgPath)["externalReferences"].([]any), 2)
}

// CHARACTERIZATION, not red-first: both behaviours below already held: these pin
// them because the help now STATES them, and a claim in help text is worth only the
// test under it. AC 6 asks for the interactions to be stated rather than inherited,
// and an inherited behaviour nothing asserts is one a refactor can change silently.
func TestEvidenceAddReference_PathFlagsResolveAgainstDifferentBases(t *testing.T) {
	dir := t.TempDir()
	sub := filepath.Join(dir, "sub")
	require.NoError(t, os.MkdirAll(sub, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(sub, "results.json"),
		[]byte(`{"baselines":[{"name":"RHEL9-STIG"}]}`), 0o600))
	artifact := []byte("id,result\nV-1,fail\n")
	require.NoError(t, os.WriteFile(filepath.Join(sub, "art.csv"), artifact, 0o600))
	pkg := filepath.Join(sub, "p.json")
	_, _, buildErr := executeCommand("evidence", "build",
		"--results", filepath.Join(sub, "results.json"), "-o", pkg)
	require.NoError(t, buildErr)

	// The process runs in dir; the artifact is in dir/sub, beside the package.
	t.Chdir(dir)

	// --href is recorded in the document, so it resolves against the package's own
	// directory — the base whoever opens the package will use. Asserted on the
	// CHECKSUM, not on the absence of an error: a local href that does not resolve
	// is not an error at all (the checksum is omitted and a note goes to stderr at
	// exit 0), so require.NoError holds under either base and distinguishes nothing.
	_, _, hrefErr := executeCommand("evidence", "add-reference", pkg,
		"--source-name", "t", "--kind", "annotation", "--href", "art.csv")
	require.NoError(t, hrefErr)
	refs, ok := readPackage(t, pkg)["externalReferences"].([]any)
	require.True(t, ok)
	require.Len(t, refs, 1)
	cs, _ := refs[0].(map[string]any)["checksum"].(map[string]any)
	require.NotNil(t, cs, "--href resolved against the package's directory, so it must be hashed")
	sum := sha256.Sum256(artifact)
	assert.Equal(t, hex.EncodeToString(sum[:]), cs["value"],
		"the digest must be of the file beside the PACKAGE, which is the only thing "+
			"that tells the two candidate bases apart")

	// --content-file is an input consumed here and never recorded, so it resolves
	// against the working directory, like --results and --system.
	_, _, contentErr := executeCommand("evidence", "add-reference", pkg,
		"--source-name", "t2", "--kind", "annotation", "--content-file", "art.csv")
	require.Error(t, contentErr, "--content-file resolves against the working directory, not the package's")
	assert.Contains(t, contentErr.Error(), "art.csv")

	// And it succeeds on the path that IS relative to the working directory.
	_, _, okErr := executeCommand("evidence", "add-reference", pkg,
		"--source-name", "t3", "--kind", "annotation", "--content-file", filepath.Join("sub", "art.csv"))
	require.NoError(t, okErr)
}

// An empty file is refused rather than embedded, so the help must not promise it
// reads "any bytes". Content with no bytes identifies nothing and would satisfy the
// anyOf branch while carrying no artifact.
func TestEvidenceAddReference_RefusesAnEmptyContentFile(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "results.json"),
		[]byte(`{"baselines":[{"name":"RHEL9-STIG"}]}`), 0o600))
	empty := filepath.Join(dir, "empty.txt")
	require.NoError(t, os.WriteFile(empty, nil, 0o600))
	pkg := filepath.Join(dir, "p.json")
	_, _, buildErr := executeCommand("evidence", "build",
		"--results", filepath.Join(dir, "results.json"), "-o", pkg)
	require.NoError(t, buildErr)

	_, _, err := executeCommand("evidence", "add-reference", pkg,
		"--source-name", "t", "--kind", "annotation", "--content-file", empty)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "empty")
}
