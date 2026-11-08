package exportmap

import (
	"bytes"
	"crypto/sha512"
	"encoding/json"
	"encoding/json/jsontext"
	"fmt"
	"io"
	"regexp"
	"strconv"

	shared "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go"
	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
)

// ExportBundle carries finding events and their original source artifact.
type ExportBundle struct {
	Events   []byte
	Source   []byte
	Manifest []byte
}

// BundleArtifact supplies retained bytes without filesystem or network access.
type BundleArtifact struct {
	Href  string
	Bytes []byte
}

// ResolvedExportSource contains verified source bytes and their selected records.
type ResolvedExportSource struct {
	Source      []byte
	Baseline    []byte
	Requirement []byte
}

// ResolveExportEvent reads the target envelope without rounding JSON numbers.
func ResolveExportEvent(event, manifest []byte, artifacts []BundleArtifact) (*ResolvedExportSource, error) {
	inventory, err := bundleProfile(manifest)
	if err != nil {
		return nil, err
	}
	target := GetStr(inventory, "target")
	if target != "ecs" && target != "splunk" && target != "ocsf" {
		return nil, fmt.Errorf("unsupported bundle target")
	}
	value, err := decodeBundleJSON(event)
	if err != nil {
		return nil, err
	}
	projection, _ := AsMap(value)
	parent, key := bundleEnvelopeParent(projection, target)
	envelope, ok := AsMap(parent[key])
	if !ok {
		return nil, fmt.Errorf("missing source envelope")
	}
	encoded, err := EncodeLine(envelope)
	if err != nil {
		return nil, err
	}
	return ResolveExportSource(encoded, manifest, artifacts)
}

// ResolveExportSource verifies an envelope against its manifest and retained artifacts.
func ResolveExportSource(envelope, manifest []byte, artifacts []BundleArtifact) (*ResolvedExportSource, error) {
	record, err := bundleProfile(envelope)
	if err != nil {
		return nil, err
	}
	inventory, err := bundleProfile(manifest)
	if err != nil {
		return nil, err
	}
	if record["profileVersion"] != inventory["profileVersion"] || record["outputProfile"] != inventory["outputProfile"] {
		return nil, fmt.Errorf("manifest profile mismatch")
	}
	target := GetStr(inventory, "target")
	if target != "ecs" && target != "splunk" && target != "ocsf" {
		return nil, fmt.Errorf("unsupported manifest target")
	}
	if GetStr(inventory, "events") != "events.ndjson" {
		return nil, fmt.Errorf("unsupported manifest events location")
	}
	digest, err := bundleArtifactDigest(record["artifact"])
	if err != nil {
		return nil, err
	}
	references, _ := AsSlice(inventory["artifacts"])
	matches := make([]map[string]interface{}, 0, 1)
	for _, reference := range references {
		candidate, err := bundleArtifactDigest(reference)
		if err != nil {
			return nil, err
		}
		if candidate == digest {
			ref, _ := AsMap(reference)
			matches = append(matches, ref)
		}
	}
	if len(matches) != 1 {
		return nil, fmt.Errorf("missing or ambiguous manifest artifact")
	}
	href := GetStr(matches[0], "href")
	if href == "" {
		return nil, fmt.Errorf("missing artifact location")
	}
	supplied := make([][]byte, 0, 1)
	for _, artifact := range artifacts {
		if artifact.Href == href {
			supplied = append(supplied, artifact.Bytes)
		}
	}
	if len(supplied) != 1 {
		return nil, fmt.Errorf("missing or ambiguous supplied artifact")
	}
	input := supplied[0]
	if err := shared.ValidateJSONSize(input, "siem-bundle", 0); err != nil {
		return nil, err
	}
	if fmt.Sprintf("%x", sha512.Sum512(input)) != digest {
		return nil, fmt.Errorf("artifact checksum mismatch")
	}
	source, err := decodeBundleJSON(input)
	if err != nil {
		return nil, err
	}
	pointer := bundlePointerPattern.FindStringSubmatch(GetStr(record, "pointer"))
	if pointer == nil {
		return nil, fmt.Errorf("invalid requirement pointer")
	}
	bi, biErr := strconv.Atoi(pointer[1])
	ri, riErr := strconv.Atoi(pointer[2])
	document, _ := AsMap(source)
	baselines, _ := AsSlice(document["baselines"])
	if biErr != nil || riErr != nil || bi >= len(baselines) {
		return nil, fmt.Errorf("requirement pointer does not resolve")
	}
	baseline, _ := AsMap(baselines[bi])
	requirements, _ := AsSlice(baseline["requirements"])
	if ri >= len(requirements) {
		return nil, fmt.Errorf("requirement pointer does not resolve")
	}
	requirement, ok := AsMap(requirements[ri])
	if !ok {
		return nil, fmt.Errorf("requirement pointer does not resolve")
	}
	canonicalRecord, err := EncodeLine(requirement)
	if err != nil {
		return nil, err
	}
	carried, err := EncodeLine(record["requirement"])
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(canonicalRecord, carried) {
		return nil, fmt.Errorf("source record mismatch")
	}
	canonicalBaseline, err := EncodeLine(baseline)
	if err != nil {
		return nil, err
	}
	return &ResolvedExportSource{Source: bytes.Clone(input), Baseline: canonicalBaseline, Requirement: canonicalRecord}, nil
}

var (
	bundleVersionPattern = regexp.MustCompile(`^1\.(0|[1-9]\d*)$`)
	bundleDigestPattern  = regexp.MustCompile(`^[a-f0-9]{128}$`)
	bundlePointerPattern = regexp.MustCompile(`^/baselines/(0|[1-9]\d*)/requirements/(0|[1-9]\d*)$`)
)

func bundleProfile(input []byte) (map[string]interface{}, error) {
	value, err := decodeBundleJSON(input)
	if err != nil {
		return nil, err
	}
	object, _ := AsMap(value)
	if !bundleVersionPattern.MatchString(GetStr(object, "profileVersion")) || GetStr(object, "outputProfile") != "legacy-additive/1" {
		return nil, fmt.Errorf("unsupported source profile")
	}
	return object, nil
}

func bundleArtifactDigest(value interface{}) (string, error) {
	artifact, _ := AsMap(value)
	checksum, _ := AsMap(artifact["checksum"])
	digest := GetStr(checksum, "value")
	if GetStr(artifact, "sourceName") != "hdf-results" || GetStr(artifact, "mediaType") != "application/json" ||
		GetStr(checksum, "algorithm") != "sha512" || !bundleDigestPattern.MatchString(digest) || GetStr(artifact, "externalId") != "sha512:"+digest {
		return "", fmt.Errorf("invalid artifact identity")
	}
	return digest, nil
}

func decodeBundleJSON(input []byte) (interface{}, error) {
	if err := shared.ValidateJSONSize(input, "siem-bundle", 0); err != nil {
		return nil, err
	}
	if !jsontext.Value(input).IsValid(jsontext.AllowDuplicateNames(true)) {
		return nil, fmt.Errorf("source must be valid UTF-8 JSON with well-formed Unicode")
	}
	var value interface{}
	decoder := json.NewDecoder(bytes.NewReader(input))
	decoder.UseNumber()
	if err := decoder.Decode(&value); err != nil {
		return nil, fmt.Errorf("decode source: %w", err)
	}
	return value, nil
}

// ProjectExportBundle preserves the source alongside an existing target projection.
func ProjectExportBundle(input []byte, target string, project func([]byte) ([]byte, error)) (*ExportBundle, error) {
	if err := shared.ValidateJSONSize(input, "siem-bundle", 0); err != nil {
		return nil, err
	}
	events, err := project(input)
	if err != nil {
		return nil, err
	}
	return BuildExportBundle(input, events, target)
}

// BuildExportBundle attaches source records to the supplied target projection.
func BuildExportBundle(input, events []byte, target string) (*ExportBundle, error) {
	if err := shared.ValidateJSONSize(input, "siem-bundle", 0); err != nil {
		return nil, err
	}
	if target != "ecs" && target != "splunk" && target != "ocsf" {
		return nil, fmt.Errorf("unsupported bundle target: %s", target)
	}
	digest := fmt.Sprintf("%x", sha512.Sum512(input))
	sourceName, externalID, mediaType := "hdf-results", "sha512:"+digest, "application/json"
	artifact := hdf.ExternalReference{
		SourceName: sourceName, ExternalID: &externalID, MediaType: &mediaType,
		Checksum: &hdf.Checksum{Algorithm: hdf.Sha512, Value: digest},
	}
	source, err := decodeBundleJSON(input)
	if err != nil {
		return nil, err
	}
	document, _ := AsMap(source)
	baselines, ok := AsSlice(document["baselines"])
	if !ok {
		return nil, fmt.Errorf("source must contain a baselines array")
	}
	decoder := json.NewDecoder(bytes.NewReader(events))
	decoder.UseNumber()
	var output bytes.Buffer
	for bi, rawBaseline := range baselines {
		baseline, _ := AsMap(rawBaseline)
		requirements, _ := AsSlice(baseline["requirements"])
		for ri, requirement := range requirements {
			if _, ok := AsMap(requirement); !ok {
				continue
			}
			var event map[string]interface{}
			if err := decoder.Decode(&event); err != nil {
				return nil, fmt.Errorf("decode finding projection: %w", err)
			}
			parent, key := bundleEnvelopeParent(event, target)
			if parent == nil {
				return nil, fmt.Errorf("missing %s finding projection", target)
			}
			if _, exists := parent[key]; exists {
				return nil, fmt.Errorf("projection already contains a source envelope")
			}
			parent[key] = map[string]interface{}{
				"profileVersion": "1.0", "outputProfile": "legacy-additive/1", "artifact": artifact,
				"pointer":     fmt.Sprintf("/baselines/%d/requirements/%d", bi, ri),
				"requirement": requirement,
			}
			line, err := EncodeLine(event)
			if err != nil {
				return nil, err
			}
			output.Write(line)
		}
	}
	var extra interface{}
	if err := decoder.Decode(&extra); err != io.EOF {
		return nil, fmt.Errorf("finding projection count does not match source requirements")
	}
	href := "source.json"
	artifact.Href = &href
	manifest, err := EncodeLine(map[string]interface{}{
		"profileVersion": "1.0", "outputProfile": "legacy-additive/1", "target": target,
		"events": "events.ndjson", "artifacts": []hdf.ExternalReference{artifact},
	})
	if err != nil {
		return nil, err
	}
	return &ExportBundle{Events: output.Bytes(), Source: bytes.Clone(input), Manifest: manifest}, nil
}

func bundleEnvelopeParent(event map[string]interface{}, target string) (map[string]interface{}, string) {
	if target == "ocsf" {
		parent, _ := AsMap(event["unmapped"])
		return parent, "hdf_source"
	}
	if target == "splunk" {
		event, _ = AsMap(event["event"])
	}
	parent, _ := AsMap(event["hdf"])
	return parent, "source"
}
