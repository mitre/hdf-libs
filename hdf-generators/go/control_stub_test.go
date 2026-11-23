package generators

import (
	"encoding/json"
	"strings"
	"testing"

	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func makeRequirement(id string, impact float64) hdf.BaselineRequirement {
	return hdf.BaselineRequirement{
		ID:           id,
		Impact:       impact,
		Tags:         map[string]interface{}{},
		Descriptions: []hdf.Description{{Label: "default", Data: "Test requirement"}},
	}
}

func ptr(s string) *string { return &s }

func TestGenerateControlStub_Minimal(t *testing.T) {
	req := makeRequirement("SV-001", 0.5)
	ruby := GenerateControlStub(req)
	assert.Contains(t, ruby, "control 'SV-001' do")
	assert.Contains(t, ruby, "impact 0.5")
	assert.Contains(t, ruby, "Test requirement")
	assert.True(t, strings.HasSuffix(ruby, "end\n"))
}

func TestGenerateControlStub_WithTitle(t *testing.T) {
	req := makeRequirement("SV-002", 0.5)
	req.Title = ptr("My Title")
	ruby := GenerateControlStub(req)
	assert.Contains(t, ruby, "title 'My Title'")
}

func TestGenerateControlStub_ImpactZero(t *testing.T) {
	req := makeRequirement("SV-003", 0.0)
	ruby := GenerateControlStub(req)
	assert.Contains(t, ruby, "impact 0.0")
	assert.NotContains(t, ruby, "impact 0\n")
}

func TestGenerateControlStub_ImpactOne(t *testing.T) {
	req := makeRequirement("SV-004", 1.0)
	ruby := GenerateControlStub(req)
	assert.Contains(t, ruby, "impact 1.0")
}

func TestGenerateControlStub_ImpactFractional(t *testing.T) {
	req := makeRequirement("SV-005", 0.7)
	ruby := GenerateControlStub(req)
	assert.Contains(t, ruby, "impact 0.7")
}

func TestGenerateControlStub_DefaultDescription(t *testing.T) {
	req := makeRequirement("SV-006", 0.5)
	req.Descriptions = []hdf.Description{{Label: "default", Data: "The main description"}}
	ruby := GenerateControlStub(req)
	assert.Contains(t, ruby, "desc 'The main description'")
}

func TestGenerateControlStub_LabeledDescriptions(t *testing.T) {
	req := makeRequirement("SV-007", 0.5)
	req.Descriptions = []hdf.Description{
		{Label: "default", Data: "Main desc"},
		{Label: "check", Data: "Check this thing"},
		{Label: "fix", Data: "Fix this thing"},
	}
	ruby := GenerateControlStub(req)
	assert.Contains(t, ruby, "desc 'check'")
	assert.Contains(t, ruby, "'Check this thing'")
	assert.Contains(t, ruby, "desc 'fix'")
	assert.Contains(t, ruby, "'Fix this thing'")
}

func TestGenerateControlStub_SkipDuplicateDefault(t *testing.T) {
	req := makeRequirement("SV-008", 0.5)
	req.Descriptions = []hdf.Description{
		{Label: "default", Data: "Main desc"},
		{Label: "default", Data: "Main desc"},
	}
	ruby := GenerateControlStub(req)
	count := strings.Count(ruby, "\n  desc ")
	assert.Equal(t, 1, count)
}

func TestGenerateControlStub_TagArrays(t *testing.T) {
	req := makeRequirement("SV-009", 0.5)
	req.Tags = map[string]interface{}{
		"cci":  []interface{}{"CCI-000068", "CCI-000197"},
		"nist": []interface{}{"AC-17 (2)", "IA-5 (1)"},
	}
	ruby := GenerateControlStub(req)
	assert.Contains(t, ruby, "tag cci: ['CCI-000068', 'CCI-000197']")
	assert.Contains(t, ruby, "tag nist: ['AC-17 (2)', 'IA-5 (1)']")
}

func TestGenerateControlStub_TagString(t *testing.T) {
	req := makeRequirement("SV-010", 0.5)
	req.Tags = map[string]interface{}{"severity": "medium"}
	ruby := GenerateControlStub(req)
	assert.Contains(t, ruby, "tag severity: 'medium'")
}

func TestGenerateControlStub_TagNil(t *testing.T) {
	req := makeRequirement("SV-011", 0.5)
	req.Tags = map[string]interface{}{"severity": nil}
	ruby := GenerateControlStub(req)
	assert.Contains(t, ruby, "tag severity: nil")
}

func TestGenerateControlStub_TagBoolean(t *testing.T) {
	req := makeRequirement("SV-012", 0.5)
	req.Tags = map[string]interface{}{"documentable": false}
	ruby := GenerateControlStub(req)
	assert.Contains(t, ruby, "tag documentable: false")
}

func TestGenerateControlStub_WithCode(t *testing.T) {
	req := makeRequirement("SV-013", 0.5)
	code := "  describe file(\"/etc/ssh/sshd_config\") do\n    it { should exist }\n  end"
	req.Code = &code
	ruby := GenerateControlStub(req)
	assert.Contains(t, ruby, `describe file("/etc/ssh/sshd_config")`)
	assert.Contains(t, ruby, "it { should exist }")
}

func TestGenerateControlStub_FullControlBlock_NotDoubleWrapped(t *testing.T) {
	// When req.Code already contains a full `control 'ID' do ... end` wrapper
	// (e.g. from `-c controls/` reading whole .rb files), the stub generator
	// must not wrap it again — that produces invalid nested control blocks.
	req := makeRequirement("SV-12345", 0.5)
	code := "control 'SV-12345' do\n  describe file('/etc/passwd') do\n    it { should exist }\n  end\nend\n"
	req.Code = &code
	ruby := GenerateControlStub(req)
	count := strings.Count(ruby, "control 'SV-12345' do")
	assert.Equal(t, 1, count, "expected exactly one `control 'SV-12345' do` line, got %d:\n%s", count, ruby)
}

func TestGenerateControlStub_RenamedControlBlock_RewriteInnerID(t *testing.T) {
	// When upgrade matches a rename (current SV-OLD merges with upstream
	// SV-NEW), the merged requirement adopts the new ID but inherits
	// current's full .rb body — which still wraps with `control 'SV-OLD'`.
	// The stub generator must detect the mismatch and rewrite the wrapper
	// ID to match req.ID so the emitted .rb is valid InSpec (one control
	// per file, named consistently with the requirement).
	req := makeRequirement("SV-268322", 0.5)
	code := "control 'SV-244540' do\n  describe file('/etc/pam.d/system-auth') do\n    its('content') { should_not match(/nullok/) }\n  end\nend\n"
	req.Code = &code
	ruby := GenerateControlStub(req)
	assert.Equal(t, 1, strings.Count(ruby, "control 'SV-268322' do"),
		"expected exactly one `control 'SV-268322' do`, got:\n%s", ruby)
	assert.Equal(t, 0, strings.Count(ruby, "control 'SV-244540' do"),
		"expected zero `control 'SV-244540' do` (old ID should be rewritten), got:\n%s", ruby)
}

func TestGenerateControlStub_StubComment(t *testing.T) {
	req := makeRequirement("SV-014", 0.5)
	ruby := GenerateControlStub(req)
	assert.Regexp(t, `(?i)# TODO|# Stub`, ruby)
}

func TestGenerateControlStub_EscapesDescriptions(t *testing.T) {
	req := makeRequirement("SV-015", 0.5)
	req.Descriptions = []hdf.Description{
		{Label: "default", Data: `it's a "complex" description`},
	}
	ruby := GenerateControlStub(req)
	// Should not have unescaped single quote breaking Ruby
	assert.NotContains(t, ruby, "desc 'it's")
}

func TestGenerateControlStub_TagNumber(t *testing.T) {
	req := makeRequirement("SV-018", 0.5)
	req.Tags = map[string]interface{}{"weight": 10.0}
	ruby := GenerateControlStub(req)
	assert.Contains(t, ruby, "tag weight: 10")
}

func TestGenerateControlStub_WellFormedBlock(t *testing.T) {
	req := makeRequirement("SV-017", 0.5)
	req.Title = ptr("Test Control")
	req.Descriptions = []hdf.Description{
		{Label: "default", Data: "Main description"},
		{Label: "check", Data: "Verify the setting"},
	}
	req.Tags = map[string]interface{}{"nist": []interface{}{"AC-2"}, "severity": "medium"}
	ruby := GenerateControlStub(req)

	assert.True(t, strings.HasPrefix(ruby, "control 'SV-017' do\n"))
	assert.True(t, strings.HasSuffix(ruby, "end\n"))

	titleIdx := strings.Index(ruby, "title")
	descIdx := strings.Index(ruby, "desc '")
	impactIdx := strings.Index(ruby, "impact")
	tagIdx := strings.Index(ruby, "tag ")
	assert.Less(t, titleIdx, descIdx)
	assert.Less(t, descIdx, impactIdx)
	assert.Less(t, impactIdx, tagIdx)
}

// rubyControlDSL stands in for InSpec's control DSL so Ruby can load a
// generated control and report the values it declares.
const rubyControlDSL = `require 'json'
$c = { 'descs' => {}, 'tags' => {} }
def control(id, &blk) $c['id'] = id; instance_eval(&blk) end
def title(t) $c['title'] = t end
def desc(a, b = nil) b.nil? ? $c['descs']['default'] = a : $c['descs'][a] = b end
def impact(i) $c['impact'] = i end
def tag(h) h.each { |k, v| $c['tags'][k.to_s] = v } end
`

// Every string the generator writes into Ruby reaches InSpec unchanged: the
// control id, title, description labels and text, and string and array tags.
func TestGenerateControlStub_RubyReadsEveryStringBack(t *testing.T) {
	req := hdf.BaselineRequirement{
		ID:     "SV-1'x",
		Impact: 0.5,
		Title:  ptr(`it's #{1+1}`),
		Descriptions: []hdf.Description{
			{Label: "default", Data: `it's "a" 1) step`},
			{Label: "it's", Data: "fix\r\nthis \\ (now)\n"},
		},
		Tags: map[string]interface{}{
			"gtitle": `it's #@x`,
			"cci":    []interface{}{"CCI's", `a"b`, `c\d`},
			"nist":   []string{"AC-1 a'b"},
		},
	}
	src := GenerateControlStub(req)
	out := runRuby(t, rubyControlDSL+src+"\nSTDOUT.write(JSON.generate($c))\n")

	var got struct {
		ID     string            `json:"id"`
		Title  string            `json:"title"`
		Descs  map[string]string `json:"descs"`
		Tags   map[string]any    `json:"tags"`
		Impact float64           `json:"impact"`
	}
	require.NoError(t, json.Unmarshal(out, &got), "generated control:\n%s", src)
	assert.Equal(t, req.ID, got.ID)
	assert.Equal(t, *req.Title, got.Title)
	assert.InDelta(t, req.Impact, got.Impact, 0)
	assert.Equal(t, map[string]string{"default": `it's "a" 1) step`, "it's": "fix\r\nthis \\ (now)\n"}, got.Descs)
	assert.Equal(t, map[string]any{
		"gtitle": `it's #@x`,
		"cci":    []any{"CCI's", `a"b`, `c\d`},
		"nist":   []any{"AC-1 a'b"},
	}, got.Tags)
}

// A renamed control's new id is written as a Ruby literal, never spliced raw
// inside the old id's quotes.
func TestGenerateControlStub_RenamedControlBlock_EscapesNewID(t *testing.T) {
	req := makeRequirement(`SV-2'); system('x`, 0.5)
	code := "control 'SV-244540' do\n  describe true do\n    it { should eq true }\n  end\nend\n"
	req.Code = &code
	ruby := GenerateControlStub(req)
	assert.True(t, strings.HasPrefix(ruby, `control "SV-2'); system('x" do`), "got:\n%s", ruby)
	out := runRuby(t, `def control(id) STDOUT.write(id) end`+"\n"+strings.SplitN(ruby, "\n", 2)[0]+" end\n")
	assert.Equal(t, req.ID, string(out))
}
