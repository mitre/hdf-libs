package xccdf

import (
	"bytes"
	"encoding/xml"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	"github.com/stretchr/testify/require"
)

// sourceProse is one Rule's prose as the XML parser hands it over: entities
// decoded and line endings folded to LF, which XML 1.0 §2.11 requires of every
// conforming parser, so LF-normalized text is the most any reader can recover.
type sourceProse struct {
	vulnDiscussion string
	fixtext        string
	checkContent   []string
}

// readSourceProse walks the document's tokens, independently of the converter's
// struct decoding, and returns each Rule's prose keyed by requirement id.
func readSourceProse(t *testing.T, doc []byte) map[string]*sourceProse {
	t.Helper()
	out := map[string]*sourceProse{}
	dec := xml.NewDecoder(bytes.NewReader(doc))
	var rule *sourceProse
	var field string
	var text strings.Builder
	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		require.NoError(t, err)
		switch el := tok.(type) {
		case xml.StartElement:
			switch el.Name.Local {
			case "Rule":
				for _, a := range el.Attr {
					if a.Name.Local == "id" {
						rule = &sourceProse{}
						out[extractRuleID(a.Value)] = rule
					}
				}
			case "description", "fixtext", "check-content":
				if rule != nil {
					field = el.Name.Local
					text.Reset()
				}
			}
		case xml.CharData:
			if field != "" {
				text.Write(el)
			}
		case xml.EndElement:
			if rule == nil {
				continue
			}
			switch el.Name.Local {
			case "Rule":
				rule = nil
			case field:
				s := text.String()
				switch field {
				case "description":
					start := strings.Index(s, "<VulnDiscussion>")
					end := strings.Index(s, "</VulnDiscussion>")
					if start >= 0 && end > start {
						rule.vulnDiscussion = s[start+len("<VulnDiscussion>") : end]
					}
				case "fixtext":
					rule.fixtext = s
				case "check-content":
					rule.checkContent = append(rule.checkContent, s)
				}
				field = ""
			}
		}
	}
	return out
}

func descriptionData(descs []hdf.Description, label string) (string, bool) {
	for _, d := range descs {
		if d.Label == label {
			return d.Data, true
		}
	}
	return "", false
}

// assertProseReadback compares each requirement's default, check and fix
// prose byte-for-byte with the source Rule's text, and returns how many
// multi-line values it compared so a fixture that loses its line breaks
// fails instead of passing vacuously.
func assertProseReadback(t *testing.T, src map[string]*sourceProse, id string, descs []hdf.Description) int {
	t.Helper()
	rule, ok := src[id]
	require.True(t, ok, "requirement %s has no source Rule", id)
	multiline := 0
	check := func(label, want string) {
		if want == "" {
			return
		}
		got, ok := descriptionData(descs, label)
		require.True(t, ok, "%s: no %q description", id, label)
		require.Equal(t, want, got, "%s: %q description is not the source text", id, label)
		if strings.Contains(want, "\n") {
			multiline++
		}
	}
	check("default", rule.vulnDiscussion)
	check("fix", rule.fixtext)
	if len(rule.checkContent) == 1 {
		check("check", rule.checkContent[0])
	}
	return multiline
}

func TestBenchmarkProsePreservesLineBreaks(t *testing.T) {
	doc, err := os.ReadFile(filepath.Join(fixtureDir(), "benchmark-stig-cisco-iosxe-router-ndm.xml"))
	require.NoError(t, err)
	src := readSourceProse(t, doc)

	rule := src["SV-215812"]
	require.NotNil(t, rule, "the fixture must keep SV-215812")
	require.Contains(t, rule.checkContent[0], "line vty 0 1\n access-class MANAGEMENT_NET in\n", "the fixture's check-content lost its line breaks")
	require.Contains(t, rule.fixtext, "MANAGEMENT_NET \nSW2(config-std-nacl)#permit", "the fixture's fixtext lost its trailing spaces or line breaks")
	require.True(t, strings.HasSuffix(src["SV-215844"].fixtext, "\n"), "the fixture's trailing-newline fixtext was trimmed")

	baseline, err := ConvertXccdfBenchmarkToHDF(doc, converterVersion)
	require.NoError(t, err)
	require.Len(t, baseline.Requirements, len(src))
	multiline := 0
	for _, req := range baseline.Requirements {
		multiline += assertProseReadback(t, src, req.ID, req.Descriptions)
	}
	require.GreaterOrEqual(t, multiline, 2*len(src), "expected multi-line check and fix text on every rule")
}

func TestResultsProsePreservesLineBreaks(t *testing.T) {
	doc, err := os.ReadFile(filepath.Join(fixtureDir(), "xccdf-results-scc-rhel8.xml"))
	require.NoError(t, err)
	src := readSourceProse(t, doc)

	results, err := ConvertXccdfResultsToHDF(doc, converterVersion)
	require.NoError(t, err)
	multiline, compared := 0, 0
	for _, b := range results.Baselines {
		for _, req := range b.Requirements {
			multiline += assertProseReadback(t, src, req.ID, req.Descriptions)
			compared++
		}
	}
	require.Positive(t, compared)
	require.Positive(t, multiline, "the fixture no longer carries multi-line prose")
}
