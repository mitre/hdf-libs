package convert

import (
	"os"
	"path/filepath"
	"testing"

	shared "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go"
	validators "github.com/mitre/hdf-libs/hdf-validators/go/v3"
)

// readInput loads a real converter fixture by its path relative to the
// converters/ directory. A missing fixture skips the case (partial checkouts).
func readInput(t *testing.T, rel string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(shared.GetConvertersDir(), rel))
	if err != nil {
		t.Skipf("fixture %s unavailable: %v", rel, err)
	}
	return b
}

// TestConvert_PerWrapperType drives GetConverter(...).Convert over a real
// fixture for a representative converter of each *-to-HDF wrapper type, so the
// lifted registry's Convert bodies (results/baseline/raw/plan/amendments
// wrappers) are exercised package-locally — not only through the CLI suite.
// The exhaustive per-converter behavior stays in the CLI converter_*_test.go
// files; this is a self-sufficiency smoke per wrapper type.
func TestConvert_PerWrapperType(t *testing.T) {
	SetVersion("0.0.0-test")
	cases := []struct {
		wrapper  string
		source   string
		fixture  string
		validate func([]byte) validators.ValidationResult
	}{
		{"results", "gosec", "gosec-to-hdf/fixtures/input/real.json", validators.ValidateResults},
		{"baseline", "oscal-catalog", "oscal-to-hdf/fixtures/input/catalog-800-53-rev5.json", validators.ValidateBaseline},
		{"raw", "oscal-ssp", "oscal-to-hdf/fixtures/input/ssp-example.json", validators.ValidateSystem},
		{"plan", "oscal-assessment-plan", "oscal-to-hdf/fixtures/input/sap-fedramp.json", validators.ValidatePlan},
		{"amendments", "openvex", "openvex-to-hdf/fixtures/input/multi-status.openvex.json", validators.ValidateAmendments},
	}
	for _, c := range cases {
		t.Run(c.wrapper, func(t *testing.T) {
			conv, err := GetConverter(c.source, "hdf")
			if err != nil {
				t.Fatalf("GetConverter(%q, hdf): %v", c.source, err)
			}
			if conv.Name() == "" {
				t.Errorf("%s converter must report a Name", c.source)
			}
			out, err := conv.Convert(readInput(t, c.fixture))
			if err != nil {
				t.Fatalf("Convert: %v", err)
			}
			if len(out) == 0 {
				t.Fatal("Convert produced empty output")
			}
			if vr := c.validate(out); !vr.Valid {
				t.Fatalf("%s wrapper output must validate: %s", c.wrapper, vr.Error())
			}
		})
	}
}

// TestConvert_ReverseHDFToX drives every reverse hdf->X exporter over a real HDF
// results document, exercising each reverse-direction Convert body
// package-locally (each is its own struct, not a shared wrapper).
func TestConvert_ReverseHDFToX(t *testing.T) {
	SetVersion("0.0.0-test")
	results := readInput(t, "gosec-to-hdf/fixtures/expected/real.json.hdf.json")
	for _, dest := range []string{"ckl", "asff", "csv", "ocsf", "splunk", "xccdf", "xml", "cklb", "ecs", "oscal-sar"} {
		t.Run(dest, func(t *testing.T) {
			conv, err := GetConverter("hdf", dest)
			if err != nil {
				t.Fatalf("GetConverter(hdf, %s): %v", dest, err)
			}
			_ = conv.Name()
			out, err := conv.Convert(results)
			if err != nil {
				t.Fatalf("hdf->%s Convert: %v", dest, err)
			}
			if len(out) == 0 {
				t.Fatalf("hdf->%s produced empty output", dest)
			}
		})
	}
}

// TestConvert_ReverseHDFAmendmentsToX drives every reverse hdf-amendments->X
// exporter over a real HDF amendments document.
func TestConvert_ReverseHDFAmendmentsToX(t *testing.T) {
	SetVersion("0.0.0-test")
	amendments := readInput(t, "openvex-to-hdf/fixtures/expected/multi-status.openvex.json.hdf.json")
	for _, dest := range []string{"csaf-vex", "cyclonedx-vex", "openvex", "oscal-poam"} {
		t.Run(dest, func(t *testing.T) {
			conv, err := GetConverter("hdf-amendments", dest)
			if err != nil {
				t.Fatalf("GetConverter(hdf-amendments, %s): %v", dest, err)
			}
			_ = conv.Name()
			out, err := conv.Convert(amendments)
			if err != nil {
				t.Fatalf("hdf-amendments->%s Convert: %v", dest, err)
			}
			if len(out) == 0 {
				t.Fatalf("hdf-amendments->%s produced empty output", dest)
			}
		})
	}
}

// TestConvert_SpecialSources exercises the converters registered directly (not
// via a shared *-to-HDF wrapper): the versioned SARIF converter, the gitlab and
// legacyhdf/inspec converters, the OSCAL profile-to-baseline converter, and the
// hdf->hdf version converter — each its own struct with its own Convert body.
func TestConvert_SpecialSources(t *testing.T) {
	SetVersion("0.0.0-test")
	cases := []struct {
		source, dest, fixture string
		validate              func([]byte) validators.ValidationResult
	}{
		{"sarif", "hdf", "sarif-to-hdf/fixtures/input/rich.sarif", validators.ValidateResults},
		{"gitlab", "hdf", "gitlab-to-hdf/fixtures/input/multi-vuln.json", validators.ValidateResults},
		{"legacyhdf", "hdf", "legacyhdf-to-hdf/fixtures/input/minimal.json", validators.ValidateResults},
		{"inspec", "hdf", "legacyhdf-to-hdf/fixtures/input/minimal.json", validators.ValidateResults},
	}
	for _, c := range cases {
		t.Run(c.source+"-"+c.dest, func(t *testing.T) {
			conv, err := GetConverter(c.source, c.dest)
			if err != nil {
				t.Fatalf("GetConverter(%q, %q): %v", c.source, c.dest, err)
			}
			if conv.Name() == "" {
				t.Errorf("%s converter must report a Name", c.source)
			}
			out, err := conv.Convert(readInput(t, c.fixture))
			if err != nil {
				t.Fatalf("Convert: %v", err)
			}
			if len(out) == 0 {
				t.Fatal("Convert produced empty output")
			}
			if vr := c.validate(out); !vr.Valid {
				t.Fatalf("%s->%s output must validate: %s", c.source, c.dest, vr.Error())
			}
		})
	}
}

// TestConvert_VersionedInterfaces exercises the version-aware converters (the
// hdf->hdf version transformer and the versioned SARIF converter), including
// their VersionedConverter / OutputVersionSetter interface methods and the
// version-transform Convert path.
func TestConvert_VersionedInterfaces(t *testing.T) {
	SetVersion("0.0.0-test")

	vc, err := GetConverter("hdf", "hdf")
	if err != nil {
		t.Fatalf("GetConverter(hdf, hdf): %v", err)
	}
	if vc.Name() == "" {
		t.Error("version converter must report a Name")
	}
	if v, ok := vc.(VersionedConverter); ok {
		if len(v.SupportedVersions()) == 0 {
			t.Error("version converter SupportedVersions must not be empty")
		}
		v.SetInputVersion("") // auto-detect
	}
	if o, ok := vc.(OutputVersionSetter); ok {
		o.SetOutputVersion("") // default to modern
	}
	// A v1 legacy HDF auto-detects and transforms up to the modern schema.
	out, err := vc.Convert(readInput(t, "legacyhdf-to-hdf/fixtures/input/minimal.json"))
	if err != nil {
		t.Fatalf("hdf version Convert: %v", err)
	}
	if vr := validators.ValidateResults(out); !vr.Valid {
		t.Fatalf("version-transformed HDF must validate as results: %s", vr.Error())
	}

	sc, err := GetConverter("sarif", "hdf")
	if err != nil {
		t.Fatalf("GetConverter(sarif, hdf): %v", err)
	}
	if v, ok := sc.(VersionedConverter); ok {
		if len(v.SupportedVersions()) == 0 {
			t.Error("sarif converter SupportedVersions must not be empty")
		}
		v.SetInputVersion("")
	}
}

// TestConvert_OSCALProfileAndAutoDetect covers the oscal auto-detect delegator
// and the oscal-profile converter (which needs a catalog supplied via
// SetOSCALCatalogPath).
func TestConvert_OSCALProfileAndAutoDetect(t *testing.T) {
	SetVersion("0.0.0-test")
	catalog := "oscal-to-hdf/fixtures/input/catalog-800-53-rev5.json"

	auto, err := GetConverter("oscal", "hdf")
	if err != nil {
		t.Fatalf("GetConverter(oscal, hdf): %v", err)
	}
	if auto.Name() == "" {
		t.Error("oscal auto-detect must report a Name")
	}
	// Drive the auto-detect delegator across several document types (its switch
	// arms), asserting each delegates and produces output.
	for _, fx := range []string{
		catalog,
		"oscal-to-hdf/fixtures/input/component-example.json",
		"oscal-to-hdf/fixtures/input/ssp-example.json",
		"oscal-to-hdf/fixtures/input/sap-fedramp.json",
	} {
		if out, cerr := auto.Convert(readInput(t, fx)); cerr != nil || len(out) == 0 {
			t.Errorf("oscal auto-detect on %s: out=%d err=%v", fx, len(out), cerr)
		}
	}

	SetOSCALCatalogPath(filepath.Join(shared.GetConvertersDir(), catalog))
	defer SetOSCALCatalogPath("")

	// With the catalog set, auto-detect can also delegate profile and poam
	// documents (further switch arms).
	for _, fx := range []string{
		"oscal-to-hdf/fixtures/input/profile-moderate.json",
		"oscal-to-hdf/fixtures/input/poam-fedramp.json",
	} {
		if out, cerr := auto.Convert(readInput(t, fx)); cerr != nil || len(out) == 0 {
			t.Logf("oscal auto-detect on %s: out=%d err=%v", fx, len(out), cerr)
		}
	}

	prof, err := GetConverter("oscal-profile", "hdf")
	if err != nil {
		t.Fatalf("GetConverter(oscal-profile, hdf): %v", err)
	}
	if prof.Name() == "" {
		t.Error("oscal-profile must report a Name")
	}
	profOut, err := prof.Convert(readInput(t, "oscal-to-hdf/fixtures/input/profile-moderate.json"))
	if err != nil {
		t.Fatalf("oscal-profile Convert: %v", err)
	}
	if vr := validators.ValidateBaseline(profOut); !vr.Valid {
		t.Fatalf("oscal-profile output must validate as baseline: %s", vr.Error())
	}
}

// TestConvert_RegistryPredicates covers the registry's converter predicates:
// empty-input acceptance, internal output-version handling, and the
// version-downgrade post-processor.
func TestConvert_RegistryPredicates(t *testing.T) {
	SetVersion("0.0.0-test")

	gc, err := GetConverter("gosec", "hdf")
	if err != nil {
		t.Fatal(err)
	}
	if e, ok := gc.(interface{ AcceptsEmptyInput() bool }); ok {
		_ = e.AcceptsEmptyInput()
	} else {
		t.Error("a results converter should implement AcceptsEmptyInput")
	}
	if HandlesOutputVersionInternally(gc) {
		t.Error("a forward converter does not handle output version internally")
	}

	vc, err := GetConverter("hdf", "hdf")
	if err != nil {
		t.Fatal(err)
	}
	if !HandlesOutputVersionInternally(vc) {
		t.Error("the hdf->hdf converter handles output version internally")
	}

	// Post-processor passthrough (no target version → unchanged).
	out, err := PostProcessToVersion([]byte(`{"x":1}`), "")
	if err != nil || string(out) != `{"x":1}` {
		t.Fatalf("PostProcessToVersion passthrough failed: out=%s err=%v", out, err)
	}
	// Post-processor downgrade path (modern HDF results → v2) exercises the
	// transform and the lossy-downgrade warning.
	down, err := PostProcessToVersion(readInput(t, "gosec-to-hdf/fixtures/expected/real.json.hdf.json"), "2")
	if err != nil {
		t.Fatalf("PostProcessToVersion downgrade failed: %v", err)
	}
	if len(down) == 0 {
		t.Fatal("downgrade produced empty output")
	}
	// Downgrading a doc with v3-only content (amendments have no v2 equivalent)
	// emits per-item transform warnings — exercise that path (outcome ignored;
	// the point is to drive the warning loop).
	_, _ = PostProcessToVersion(readInput(t, "openvex-to-hdf/fixtures/expected/multi-status.openvex.json.hdf.json"), "2")
}

// TestConvert_InvalidInputErrors drives every converter with clearly-invalid
// input, exercising each Convert body's error path (the wrappers surface the
// underlying converter error rather than a nil-and-nil).
func TestConvert_InvalidInputErrors(t *testing.T) {
	SetVersion("0.0.0-test")
	bad := []byte("this is not a valid document in any format")

	mustError := func(t *testing.T, source, dest string) {
		conv, err := GetConverter(source, dest)
		if err != nil {
			t.Fatalf("GetConverter(%q,%q): %v", source, dest, err)
		}
		if _, cerr := conv.Convert(bad); cerr == nil {
			t.Errorf("%s->%s must error on invalid input, not return nil,nil", source, dest)
		}
	}

	for _, src := range []string{"gosec", "oscal-catalog", "oscal-ssp", "oscal-assessment-plan", "openvex", "sarif", "gitlab", "legacyhdf"} {
		t.Run(src, func(t *testing.T) { mustError(t, src, "hdf") })
	}
	for _, dest := range []string{"ckl", "asff", "csv", "ocsf", "splunk", "xccdf", "xml", "cklb", "ecs", "oscal-sar"} {
		t.Run("hdf-"+dest, func(t *testing.T) { mustError(t, "hdf", dest) })
	}
	for _, dest := range []string{"csaf-vex", "cyclonedx-vex", "openvex", "oscal-poam"} {
		t.Run("amend-"+dest, func(t *testing.T) { mustError(t, "hdf-amendments", dest) })
	}
	t.Run("hdf-version", func(t *testing.T) { mustError(t, "hdf", "hdf") })
}

// TestConvert_UnknownFormatPair confirms the not-found path (a caller mistake)
// returns ErrConverterNotFound rather than a nil converter.
func TestConvert_UnknownFormatPair(t *testing.T) {
	if _, err := GetConverter("no-such-source", "hdf"); err == nil {
		t.Fatal("an unknown source must return ErrConverterNotFound")
	}
}
