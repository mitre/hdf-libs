package exportmap_test

import (
	"bytes"
	"crypto/sha512"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	hdftoecs "github.com/mitre/hdf-libs/hdf-converters/v3/converters/hdf-to-ecs/go"
	hdftoocsf "github.com/mitre/hdf-libs/hdf-converters/v3/converters/hdf-to-ocsf/go"
	hdftosplunk "github.com/mitre/hdf-libs/hdf-converters/v3/converters/hdf-to-splunk/go"
	"github.com/mitre/hdf-libs/hdf-converters/v3/shared/go/exportmap"
	hdfutil "github.com/mitre/hdf-libs/hdf-utilities/go/v3"
	validators "github.com/mitre/hdf-libs/hdf-validators/go/v3"
	jsonschema "github.com/santhosh-tekuri/jsonschema/v6"
	"github.com/stretchr/testify/require"
)

func bundleInput(t *testing.T) []byte {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	require.True(t, ok)
	input, err := os.ReadFile(filepath.Join(filepath.Dir(file), "..", "..", "..", "converters", "hdf-to-ecs", "fixtures", "input", "override.json"))
	require.NoError(t, err)
	return input
}

func TestBundlePreservesOriginalBytesAndRequirement(t *testing.T) {
	input := bundleInput(t)
	legacy, err := hdftoecs.ConvertHDFToECS(input, "0.1.0")
	require.NoError(t, err)
	bundle, err := exportmap.BuildExportBundle(input, legacy, "ecs")
	require.NoError(t, err)
	require.Equal(t, input, bundle.Source)
	var event struct {
		HDF struct {
			Source struct {
				Pointer     string          `json:"pointer"`
				Requirement json.RawMessage `json:"requirement"`
			} `json:"source"`
		} `json:"hdf"`
	}
	require.NoError(t, json.Unmarshal(bundle.Events, &event))
	require.Equal(t, "/baselines/0/requirements/0", event.HDF.Source.Pointer)
	var original struct {
		Baselines []struct {
			Requirements []json.RawMessage `json:"requirements"`
		} `json:"baselines"`
	}
	require.NoError(t, json.Unmarshal(input, &original))
	require.Len(t, original.Baselines, 1)
	require.Len(t, original.Baselines[0].Requirements, 1)
	require.JSONEq(t, string(original.Baselines[0].Requirements[0]), string(event.HDF.Source.Requirement))
}

func TestBundleManifestIdentifiesOriginalArtifact(t *testing.T) {
	input := bundleInput(t)
	legacy, err := hdftoecs.ConvertHDFToECS(input, "0.1.0")
	require.NoError(t, err)
	bundle, err := exportmap.BuildExportBundle(input, legacy, "ecs")
	require.NoError(t, err)
	digest := fmt.Sprintf("%x", sha512.Sum512(input))
	require.JSONEq(t, fmt.Sprintf(`{
		"profileVersion":"1.0","outputProfile":"legacy-additive/1","target":"ecs",
		"events":"events.ndjson","artifacts":[{"sourceName":"hdf-results",
		"externalId":"sha512:%s","mediaType":"application/json","href":"source.json",
		"checksum":{"algorithm":"sha512","value":"%s"}}]
	}`, digest, digest), string(bundle.Manifest))
	var event map[string]interface{}
	require.NoError(t, json.Unmarshal(bundle.Events, &event))
	hdf, ok := exportmap.AsMap(event["hdf"])
	require.True(t, ok)
	source, ok := exportmap.AsMap(hdf["source"])
	require.True(t, ok)
	require.Equal(t, "1.0", source["profileVersion"])
	require.Equal(t, "legacy-additive/1", source["outputProfile"])
	artifact, ok := exportmap.AsMap(source["artifact"])
	require.True(t, ok)
	require.Equal(t, "sha512:"+digest, artifact["externalId"])
}

func TestBundleRejectsMalformedUnicode(t *testing.T) {
	input := bundleInput(t)
	legacy, err := hdftoecs.ConvertHDFToECS(input, "0.1.0")
	require.NoError(t, err)
	for _, replacement := range [][]byte{[]byte(`\ud800`), []byte(`\udfff`), {0xff}} {
		t.Run(fmt.Sprintf("%x", replacement), func(t *testing.T) {
			malformed := bytes.Replace(input, []byte("Ensure SSH root login is disabled"), replacement, 1)
			_, err := exportmap.BuildExportBundle(malformed, legacy, "ecs")
			require.Error(t, err)
		})
	}
}

func TestBundleRejectsMissingResultCollections(t *testing.T) {
	for _, input := range []string{`null`, `[]`, `{}`, `{"baselines":null}`, `{"baselines":{}}`} {
		t.Run(input, func(t *testing.T) {
			_, err := exportmap.BuildExportBundle([]byte(input), nil, "ecs")
			require.ErrorContains(t, err, "baselines")
		})
	}
}

func TestBundleRejectsExtraProjections(t *testing.T) {
	input := bundleInput(t)
	legacy, err := hdftoecs.ConvertHDFToECS(input, "0.1.0")
	require.NoError(t, err)
	_, err = exportmap.BuildExportBundle(input, append(bytes.Clone(legacy), legacy...), "ecs")
	require.ErrorContains(t, err, "count")
}

func TestBundleRejectsExistingSourceEnvelope(t *testing.T) {
	input := bundleInput(t)
	legacy, err := hdftoecs.ConvertHDFToECS(input, "0.1.0")
	require.NoError(t, err)
	var event map[string]interface{}
	require.NoError(t, json.Unmarshal(legacy, &event))
	hdf, ok := exportmap.AsMap(event["hdf"])
	require.True(t, ok)
	hdf["source"] = nil
	projection, err := json.Marshal(event)
	require.NoError(t, err)
	_, err = exportmap.BuildExportBundle(input, projection, "ecs")
	require.ErrorContains(t, err, "already")
}

func TestBundleEnforcesConfiguredSizeBeforeDecoding(t *testing.T) {
	hdfutil.SetDefaultMaxInputSize(1)
	t.Cleanup(func() { hdfutil.SetDefaultMaxInputSize(0) })
	_, err := exportmap.BuildExportBundle([]byte("not json"), nil, "ecs")
	require.ErrorContains(t, err, "maximum allowed size")
}

func TestBundleRejectsOverwrittenMalformedUnicode(t *testing.T) {
	input := bundleInput(t)
	legacy, err := hdftoecs.ConvertHDFToECS(input, "0.1.0")
	require.NoError(t, err)
	input = bytes.Replace(input, []byte(`"title": "Ensure SSH`), []byte(`"title": "\ud800", "title": "Ensure SSH`), 1)
	_, err = exportmap.BuildExportBundle(input, legacy, "ecs")
	require.ErrorContains(t, err, "Unicode")
}

func TestBundleTargetAdaptersPreserveProjection(t *testing.T) {
	for _, tc := range []struct {
		target  string
		convert func([]byte, string) ([]byte, error)
		bundle  func([]byte, string) (*exportmap.ExportBundle, error)
		path    []string
	}{
		{"ecs", hdftoecs.ConvertHDFToECS, hdftoecs.ConvertHDFToECSBundle, []string{"hdf", "source"}},
		{"splunk", hdftosplunk.ConvertHDFToSplunk, hdftosplunk.ConvertHDFToSplunkBundle, []string{"event", "hdf", "source"}},
		{"ocsf", hdftoocsf.ConvertHDFToOCSF, hdftoocsf.ConvertHDFToOCSFBundle, []string{"unmapped", "hdf_source"}},
	} {
		t.Run(tc.target, func(t *testing.T) {
			input := bundleInput(t)
			bundle, err := tc.bundle(input, "0.1.0")
			require.NoError(t, err)
			var event map[string]interface{}
			require.NoError(t, json.Unmarshal(bundle.Events, &event))
			parent := event
			for _, key := range tc.path[:len(tc.path)-1] {
				var ok bool
				parent, ok = exportmap.AsMap(parent[key])
				require.True(t, ok)
			}
			key := tc.path[len(tc.path)-1]
			source, ok := exportmap.AsMap(parent[key])
			require.True(t, ok)
			require.Equal(t, "/baselines/0/requirements/0", source["pointer"])
			var original map[string]interface{}
			require.NoError(t, json.Unmarshal(input, &original))
			baselines, ok := exportmap.AsSlice(original["baselines"])
			require.True(t, ok)
			baseline, ok := exportmap.AsMap(baselines[0])
			require.True(t, ok)
			reqs, ok := exportmap.AsSlice(baseline["requirements"])
			require.True(t, ok)
			require.Equal(t, reqs[0], source["requirement"])
			delete(parent, key)
			projection, err := json.Marshal(event)
			require.NoError(t, err)
			legacy, err := tc.convert(input, "0.1.0")
			require.NoError(t, err)
			require.JSONEq(t, string(legacy), string(projection))
			require.Equal(t, input, bundle.Source)
			var manifest map[string]interface{}
			require.NoError(t, json.Unmarshal(bundle.Manifest, &manifest))
			require.Equal(t, tc.target, manifest["target"])
		})
	}
}

func TestBundleSourceResolutionCases(t *testing.T) {
	_, file, _, ok := runtime.Caller(0)
	require.True(t, ok)
	data, err := os.ReadFile(filepath.Join(filepath.Dir(file), "..", "..", "bundle-fixtures", "cases.json"))
	require.NoError(t, err)
	var cases []struct {
		Name  string `json:"name"`
		Edits []struct {
			Document string      `json:"document"`
			Path     []string    `json:"path"`
			Value    interface{} `json:"value"`
			Remove   bool        `json:"remove"`
		} `json:"edits"`
		ArtifactMode string `json:"artifactMode"`
		Error        string `json:"error"`
	}
	require.NoError(t, json.Unmarshal(data, &cases))
	for _, tc := range cases {
		t.Run(tc.Name, func(t *testing.T) {
			input := bundleInput(t)
			bundle, err := hdftoecs.ConvertHDFToECSBundle(input, "0.1.0")
			require.NoError(t, err)
			var event, manifest map[string]interface{}
			require.NoError(t, json.Unmarshal(bundle.Events, &event))
			require.NoError(t, json.Unmarshal(bundle.Manifest, &manifest))
			hdf, ok := exportmap.AsMap(event["hdf"])
			require.True(t, ok)
			envelope, ok := exportmap.AsMap(hdf["source"])
			require.True(t, ok)
			documents := map[string]map[string]interface{}{"envelope": envelope, "manifest": manifest}
			for _, edit := range tc.Edits {
				parent := documents[edit.Document]
				for _, key := range edit.Path[:len(edit.Path)-1] {
					parent, ok = exportmap.AsMap(parent[key])
					require.True(t, ok)
				}
				if edit.Remove {
					delete(parent, edit.Path[len(edit.Path)-1])
				} else {
					parent[edit.Path[len(edit.Path)-1]] = edit.Value
				}
			}
			artifacts := []exportmap.BundleArtifact{{Href: "source.json", Bytes: input}}
			switch tc.ArtifactMode {
			case "missing":
				artifacts = nil
			case "duplicate":
				artifacts = append(artifacts, artifacts[0])
			case "tampered":
				artifacts[0].Bytes = append(bytes.Clone(input), ' ')
			case "duplicate-reference":
				refs, valid := exportmap.AsSlice(manifest["artifacts"])
				require.True(t, valid)
				manifest["artifacts"] = append(refs, refs[0])
			}
			envelopeBytes, err := json.Marshal(envelope)
			require.NoError(t, err)
			manifestBytes, err := json.Marshal(manifest)
			require.NoError(t, err)
			resolved, err := exportmap.ResolveExportSource(envelopeBytes, manifestBytes, artifacts)
			if tc.Error != "" {
				require.ErrorContains(t, err, tc.Error)
				return
			}
			require.NoError(t, err)
			require.Equal(t, input, resolved.Source)
			var original struct {
				Baselines []struct {
					Requirements []json.RawMessage `json:"requirements"`
				} `json:"baselines"`
			}
			require.NoError(t, json.Unmarshal(input, &original))
			require.JSONEq(t, string(original.Baselines[0].Requirements[0]), string(resolved.Requirement))
			var document struct {
				Baselines []json.RawMessage `json:"baselines"`
			}
			require.NoError(t, json.Unmarshal(input, &document))
			require.JSONEq(t, string(document.Baselines[0]), string(resolved.Baseline))
		})
	}
}

func TestBundleSchemaValidatesEmittedValues(t *testing.T) {
	input := bundleInput(t)
	require.True(t, validators.ValidateResults(input).Valid)
	_, file, _, ok := runtime.Caller(0)
	require.True(t, ok)
	compiler := jsonschema.NewCompiler()
	for _, path := range []string{"../../../../hdf-schema/src/schemas/primitives/common.schema.json", "../../export-bundle.schema.json"} {
		data, err := os.ReadFile(filepath.Join(filepath.Dir(file), path))
		require.NoError(t, err)
		var schema map[string]interface{}
		require.NoError(t, json.Unmarshal(data, &schema))
		id, ok := schema["$id"].(string)
		require.True(t, ok)
		require.NoError(t, compiler.AddResource(id, schema))
	}
	manifestSchema, err := compiler.Compile("urn:hdf:siem-export-bundle:1#/$defs/Manifest")
	require.NoError(t, err)
	envelopeSchema, err := compiler.Compile("urn:hdf:siem-export-bundle:1#/$defs/SourceEnvelope")
	require.NoError(t, err)
	for _, convert := range []func([]byte, string) (*exportmap.ExportBundle, error){hdftoecs.ConvertHDFToECSBundle, hdftosplunk.ConvertHDFToSplunkBundle, hdftoocsf.ConvertHDFToOCSFBundle} {
		bundle, err := convert(input, "0.1.0")
		require.NoError(t, err)
		var manifest, event map[string]interface{}
		require.NoError(t, json.Unmarshal(bundle.Manifest, &manifest))
		require.NoError(t, json.Unmarshal(bundle.Events, &event))
		require.NoError(t, manifestSchema.Validate(manifest))
		var parent map[string]interface{}
		var envelope interface{}
		switch manifest["target"] {
		case "ecs":
			parent, _ = exportmap.AsMap(event["hdf"])
			envelope = parent["source"]
		case "splunk":
			parent, _ = exportmap.AsMap(event["event"])
			parent, _ = exportmap.AsMap(parent["hdf"])
			envelope = parent["source"]
		case "ocsf":
			parent, _ = exportmap.AsMap(event["unmapped"])
			envelope = parent["hdf_source"]
		}
		require.NoError(t, envelopeSchema.Validate(envelope))
	}
}

func TestBundleEmptyAssessmentRetainsArtifact(t *testing.T) {
	var document map[string]interface{}
	require.NoError(t, json.Unmarshal(bundleInput(t), &document))
	document["baselines"] = []interface{}{}
	input, err := json.Marshal(document)
	require.NoError(t, err)
	require.True(t, validators.ValidateResults(input).Valid)
	for _, convert := range []func([]byte, string) (*exportmap.ExportBundle, error){hdftoecs.ConvertHDFToECSBundle, hdftosplunk.ConvertHDFToSplunkBundle, hdftoocsf.ConvertHDFToOCSFBundle} {
		bundle, err := convert(input, "0.1.0")
		require.NoError(t, err)
		require.Empty(t, bundle.Events)
		require.Equal(t, input, bundle.Source)
		var manifest struct {
			Artifacts []json.RawMessage `json:"artifacts"`
		}
		require.NoError(t, json.Unmarshal(bundle.Manifest, &manifest))
		require.Len(t, manifest.Artifacts, 1)
	}
}

func TestBundleDuplicateRequirementIDsResolveByOccurrence(t *testing.T) {
	var document map[string]interface{}
	require.NoError(t, json.Unmarshal(bundleInput(t), &document))
	baselines, ok := exportmap.AsSlice(document["baselines"])
	require.True(t, ok)
	baseline, ok := exportmap.AsMap(baselines[0])
	require.True(t, ok)
	reqs, ok := exportmap.AsSlice(baseline["requirements"])
	require.True(t, ok)
	baseline["requirements"] = append(reqs, reqs[0])
	document["baselines"] = append(baselines, baseline)
	input, err := json.Marshal(document)
	require.NoError(t, err)
	require.True(t, validators.ValidateResults(input).Valid)
	bundle, err := hdftoecs.ConvertHDFToECSBundle(input, "0.1.0")
	require.NoError(t, err)
	lines := bytes.Split(bytes.TrimSpace(bundle.Events), []byte{'\n'})
	require.Len(t, lines, 4)
	for i, line := range lines {
		var event struct {
			HDF struct {
				Source json.RawMessage `json:"source"`
			} `json:"hdf"`
		}
		require.NoError(t, json.Unmarshal(line, &event))
		var source struct {
			Pointer string `json:"pointer"`
		}
		require.NoError(t, json.Unmarshal(event.HDF.Source, &source))
		require.Equal(t, fmt.Sprintf("/baselines/%d/requirements/%d", i/2, i%2), source.Pointer)
		resolved, err := exportmap.ResolveExportSource(event.HDF.Source, bundle.Manifest, []exportmap.BundleArtifact{{Href: "source.json", Bytes: input}})
		require.NoError(t, err)
		require.Contains(t, string(resolved.Requirement), `"id":"SV-001"`)
	}
}

func TestBundleNumberTokenIsSignificant(t *testing.T) {
	input := bytes.Replace(bundleInput(t), []byte(`"impact": 0.7`), []byte(`"impact": 0.70`), 1)
	require.True(t, validators.ValidateResults(input).Valid)
	bundle, err := hdftoecs.ConvertHDFToECSBundle(input, "0.1.0")
	require.NoError(t, err)
	var event struct {
		HDF struct {
			Source json.RawMessage `json:"source"`
		} `json:"hdf"`
	}
	require.NoError(t, json.Unmarshal(bundle.Events, &event))
	artifacts := []exportmap.BundleArtifact{{Href: "source.json", Bytes: input}}
	fromEvent, err := exportmap.ResolveExportEvent(bundle.Events, bundle.Manifest, artifacts)
	require.NoError(t, err)
	require.Contains(t, string(fromEvent.Requirement), `"impact":0.70`)
	resolved, err := exportmap.ResolveExportSource(event.HDF.Source, bundle.Manifest, artifacts)
	require.NoError(t, err)
	require.Contains(t, string(resolved.Requirement), `"impact":0.70`)
	changed := bytes.Replace(event.HDF.Source, []byte(`"impact":0.70`), []byte(`"impact":0.7`), 1)
	_, err = exportmap.ResolveExportSource(changed, bundle.Manifest, artifacts)
	require.ErrorContains(t, err, "record mismatch")
}

func TestBundleRejectsMalformedProjectionAndSource(t *testing.T) {
	for _, projection := range []string{"", "null", `{"hdf":null}`, "{\"hdf\":{}}\n{\"hdf\":{}}"} {
		_, err := exportmap.BuildExportBundle(bundleInput(t), []byte(projection), "ecs")
		require.Error(t, err)
	}
	_, err := exportmap.BuildExportBundle(bundleInput(t), nil, "unknown")
	require.ErrorContains(t, err, "target")
	for _, source := range []string{"", "not-json", "{} {}", "\ufeff{}"} {
		_, err = hdftoecs.ConvertHDFToECSBundle([]byte(source), "0.1.0")
		require.Error(t, err)
	}
	_, err = exportmap.ResolveExportSource([]byte("{}"), []byte("{}"), nil)
	require.ErrorContains(t, err, "profile")
	_, err = exportmap.ResolveExportSource([]byte("{"), []byte("{}"), nil)
	require.Error(t, err)
}

func TestBundleLargeSourceString(t *testing.T) {
	var document map[string]interface{}
	require.NoError(t, json.Unmarshal(bundleInput(t), &document))
	baselines, ok := exportmap.AsSlice(document["baselines"])
	require.True(t, ok)
	baseline, ok := exportmap.AsMap(baselines[0])
	require.True(t, ok)
	baseline["extensions"] = map[string]interface{}{"passthrough": map[string]interface{}{"large": strings.Repeat("a", 10*1024*1024)}}
	input, err := json.Marshal(document)
	require.NoError(t, err)
	require.True(t, validators.ValidateResults(input).Valid)
	bundle, err := hdftoecs.ConvertHDFToECSBundle(input, "0.1.0")
	require.NoError(t, err)
	resolved, err := exportmap.ResolveExportEvent(bundle.Events, bundle.Manifest, []exportmap.BundleArtifact{{Href: "source.json", Bytes: bundle.Source}})
	require.NoError(t, err)
	require.Equal(t, input, resolved.Source)
	require.JSONEq(t, string(mustMarshalBundleValue(t, baseline)), string(resolved.Baseline))
}

func mustMarshalBundleValue(t *testing.T, value interface{}) []byte {
	t.Helper()
	encoded, err := json.Marshal(value)
	require.NoError(t, err)
	return encoded
}

func TestBundleReadbackRejectsInvalidEventsAndLocations(t *testing.T) {
	input := bundleInput(t)
	bundle, err := hdftoecs.ConvertHDFToECSBundle(input, "0.1.0")
	require.NoError(t, err)
	artifacts := []exportmap.BundleArtifact{{Href: "source.json", Bytes: input}}
	for _, event := range []string{"not-json", `{}`, `{"hdf":{"source":null}}`} {
		_, err := exportmap.ResolveExportEvent([]byte(event), bundle.Manifest, artifacts)
		require.Error(t, err)
	}
	_, err = exportmap.ResolveExportEvent(bundle.Events, []byte("{"), artifacts)
	require.Error(t, err)
	var manifest map[string]interface{}
	require.NoError(t, json.Unmarshal(bundle.Manifest, &manifest))
	manifest["target"] = "unknown"
	_, err = exportmap.ResolveExportEvent(bundle.Events, mustMarshalBundleValue(t, manifest), artifacts)
	require.ErrorContains(t, err, "target")
	manifest["target"] = "ecs"
	refs, ok := exportmap.AsSlice(manifest["artifacts"])
	require.True(t, ok)
	ref, ok := exportmap.AsMap(refs[0])
	require.True(t, ok)
	delete(ref, "href")
	_, err = exportmap.ResolveExportEvent(bundle.Events, mustMarshalBundleValue(t, manifest), artifacts)
	require.ErrorContains(t, err, "location")
}

func TestBundlePublicAPIsEnforceConfiguredSize(t *testing.T) {
	input := bundleInput(t)
	bundle, err := hdftoecs.ConvertHDFToECSBundle(input, "0.1.0")
	require.NoError(t, err)
	var event struct {
		HDF struct {
			Source json.RawMessage `json:"source"`
		} `json:"hdf"`
	}
	require.NoError(t, json.Unmarshal(bundle.Events, &event))
	require.Less(t, len(event.HDF.Source), len(input)-1)
	require.Less(t, len(bundle.Manifest), len(input)-1)
	hdfutil.SetDefaultMaxInputSize(len(input) - 1)
	t.Cleanup(func() { hdfutil.SetDefaultMaxInputSize(0) })
	_, err = exportmap.ResolveExportSource(event.HDF.Source, bundle.Manifest, []exportmap.BundleArtifact{{Href: "source.json", Bytes: input}})
	require.ErrorContains(t, err, "maximum allowed size")
	for _, convert := range []func([]byte, string) (*exportmap.ExportBundle, error){hdftoecs.ConvertHDFToECSBundle, hdftosplunk.ConvertHDFToSplunkBundle, hdftoocsf.ConvertHDFToOCSFBundle} {
		_, err := convert(input, "0.1.0")
		require.ErrorContains(t, err, "maximum allowed size")
	}
}
