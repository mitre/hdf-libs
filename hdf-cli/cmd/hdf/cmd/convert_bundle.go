package cmd

import (
	"fmt"
	"path/filepath"

	hdftoecs "github.com/mitre/hdf-libs/hdf-converters/v3/converters/hdf-to-ecs/go"
	hdftoocsf "github.com/mitre/hdf-libs/hdf-converters/v3/converters/hdf-to-ocsf/go"
	hdftosplunk "github.com/mitre/hdf-libs/hdf-converters/v3/converters/hdf-to-splunk/go"
	"github.com/mitre/hdf-libs/hdf-converters/v3/shared/go/exportmap"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

func runConvertBundle(cmd *cobra.Command, args []string, target, output string, overwrite bool) error {
	if len(args) != 1 || args[0] == "" || args[0] == "-" {
		return fmt.Errorf("--bundle requires exactly one local source file")
	}
	var incompatible string
	cmd.Flags().Visit(func(flag *pflag.Flag) {
		if cmd.InheritedFlags().Lookup(flag.Name) != nil {
			return
		}
		switch flag.Name {
		case "bundle", "to", "output", "overwrite":
		default:
			if incompatible == "" {
				incompatible = flag.Name
			}
		}
	})
	if incompatible != "" {
		return fmt.Errorf("--%s is not supported with --bundle", incompatible)
	}
	if _, err := siemEventFormat(target); err != nil {
		return fmt.Errorf("--to must be ecs, splunk or ocsf: %w", err)
	}
	if output == "" || output == "-" {
		return fmt.Errorf("-o is required: name the archive file to write")
	}
	if isDirectoryOutput(output) {
		return fmt.Errorf("bundle output must be a file")
	}
	if err := refuseArchiveOverInput(output, filepath.Dir(args[0]), args[0], "source document", nil, overwrite); err != nil {
		return err
	}
	source, err := readFromFile(args[0], false)
	if err != nil {
		return fmt.Errorf("read bundle source: %w", err)
	}
	bundle, err := projectSIEMBundle(source, target)
	if err != nil {
		return fmt.Errorf("build %s bundle: %w", target, err)
	}
	inventory, err := siemEvidencePackage(bundle, target)
	if err != nil {
		return err
	}
	return writeArchiveAtomically(output, []bundleEntry{
		{path: "events.ndjson", data: bundle.Events},
		{path: "evidence-package.json", data: inventory},
		{path: "manifest.json", data: bundle.Manifest},
		{path: "source.json", data: bundle.Source},
	}, newArchiveWriter, overwrite)
}

func projectSIEMBundle(source []byte, target string) (*exportmap.ExportBundle, error) {
	switch target {
	case "ecs":
		return hdftoecs.ConvertHDFToECSBundle(source, version)
	case "splunk":
		return hdftosplunk.ConvertHDFToSplunkBundle(source, version)
	case "ocsf":
		return hdftoocsf.ConvertHDFToOCSFBundle(source, version)
	default:
		return nil, fmt.Errorf("unsupported SIEM target %q", target)
	}
}
