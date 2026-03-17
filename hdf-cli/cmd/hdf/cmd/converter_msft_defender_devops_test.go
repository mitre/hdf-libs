package cmd

import "testing"

func TestMsftDefenderDevopsConverter(t *testing.T) {
	runStandardConverterTests(t, converterTestCase{
		Source:         "msft-defender-devops",
		DisplayName:    "Microsoft Defender for DevOps to HDF",
		FixtureDir:     "msft-defender-devops-to-hdf",
		MinimalFixture: "input/minimal.sarif",
		ErrPrefix:      "msft-defender-devops conversion failed",
	})
}

func TestMsftDefenderDevopsAlias(t *testing.T) {
	t.Run("MSDOAliasIsRegistered", func(t *testing.T) {
		converter, err := GetConverter("msdo", "hdf")
		if err != nil {
			t.Fatalf("msdo alias should be registered: %v", err)
		}
		if converter == nil {
			t.Fatal("converter should not be nil")
		}
		if converter.Name() != "Microsoft Defender for DevOps to HDF" {
			t.Errorf("expected display name 'Microsoft Defender for DevOps to HDF', got %q", converter.Name())
		}
	})
}
