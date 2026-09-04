package hdfutil

import (
	"maps"
	"math"
	"strings"
	"testing"
)

// FuzzParseCvssVector checks the CVSS entry points on arbitrary input: parsing
// never panics, an "unknown" version always carries an empty metric map,
// parsed metrics survive a render/re-parse round trip, validation agrees with
// its own error list, and computed 3.1/4.0 scores stay in [0, 10] at one
// decimal of precision.
func FuzzParseCvssVector(f *testing.F) {
	seeds := []string{
		"AV:N/AC:L/Au:N/C:C/I:C/A:C",                                                     // legacy 2.0
		"AV:N/AC:M/Au:S/C:P/I:P/A:N/E:POC/RL:OF/RC:C/CDP:LM/TD:H/CR:M",                   // 2.0 with temporal + environmental
		"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",                                   // 3.0
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H/E:F/RL:O/RC:C",                     // 3.1 scope changed + temporal
		"CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N",                                   // 3.1 all-minimal
		"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H",                // 4.0 base
		"CVSS:4.0/AV:L/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N/E:U/CR:L/MSI:S", // 4.0 threat + environmental
		"",
		"CVSS:",
		"CVSS:9.9/AV:N",    // unsupported version
		"CVSS:3.1//AV:N//", // empty segments
		"/AV:N/",
		"AV:", // empty value
		":N",  // empty key
		"noseparators",
		"AV:N/AV:L/AV:P", // duplicate keys keep the last
		"CVSS:3.1/AV:N\x00/AC:L",
		"ＣＶＳＳ:3.1/AV:N", // full-width prefix is not a prefix
		"CVSS:3.1/" + strings.Repeat("AV:N/", 200),
		strings.Repeat("/", 100),
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, s string) {
		version, metrics := ParseCvssVector(s)
		if version == "unknown" && len(metrics) != 0 {
			t.Errorf("ParseCvssVector(%q) version unknown but metrics non-empty: %v", s, metrics)
		}
		for k, v := range metrics {
			if k == "" || strings.ContainsAny(k, ":/") {
				t.Errorf("ParseCvssVector(%q) produced invalid metric key %q", s, k)
			}
			if v == "" || strings.Contains(v, "/") {
				t.Errorf("ParseCvssVector(%q) produced invalid value %q for key %q", s, v, k)
			}
		}
		// Rendering the parse back into vector form and re-parsing must not
		// change the version or any metric.
		segments := []string{"CVSS:" + version}
		for k, v := range metrics {
			segments = append(segments, k+":"+v)
		}
		version2, metrics2 := ParseCvssVector(strings.Join(segments, "/"))
		if version2 != version || !maps.Equal(metrics2, metrics) {
			t.Errorf("round trip: ParseCvssVector(%q) = (%q, %v), re-parsed rendering = (%q, %v)", s, version, metrics, version2, metrics2)
		}

		valid, errs := ValidateCvssVector(s, "")
		if valid != (len(errs) == 0) {
			t.Errorf("ValidateCvssVector(%q) valid=%v disagrees with %d errors", s, valid, len(errs))
		}

		if sc, err := ComputeCvssScore(s); err == nil {
			assertCvssScoreBounds(t, s, sc, "3.1")
			if sc.TemporalScore > sc.BaseScore {
				t.Errorf("ComputeCvssScore(%q) temporal %v exceeds base %v", s, sc.TemporalScore, sc.BaseScore)
			}
			if again, err2 := ComputeCvssScore(s); err2 != nil || again != sc {
				t.Errorf("ComputeCvssScore(%q) not deterministic: %v/%v then %v/%v", s, sc, err, again, err2)
			}
		}
		if sc, err := ComputeCvss40Score(s); err == nil {
			assertCvssScoreBounds(t, s, sc, "4.0")
			if again, err2 := ComputeCvss40Score(s); err2 != nil || again != sc {
				t.Errorf("ComputeCvss40Score(%q) not deterministic: %v/%v then %v/%v", s, sc, err, again, err2)
			}
		}
	})
}

// assertCvssScoreBounds verifies a computed score's version tag and that both
// scores are one-decimal values within [0, 10].
func assertCvssScoreBounds(t *testing.T, input string, sc CvssScore, wantVersion string) {
	t.Helper()
	if sc.Version != wantVersion {
		t.Errorf("score for %q has version %q, want %q", input, sc.Version, wantVersion)
	}
	for _, score := range []float64{sc.BaseScore, sc.TemporalScore} {
		if score < 0 || score > 10 {
			t.Errorf("score for %q out of range [0,10]: %v", input, score)
		}
		if math.Abs(score*10-math.Round(score*10)) > 1e-9 {
			t.Errorf("score for %q not rounded to one decimal: %v", input, score)
		}
	}
}
