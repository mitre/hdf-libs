package cmd

// The converter registry now lives in the cobra-free, importable package
// github.com/mitre/hdf-libs/hdf-converters/v3/registry/convert (ADR-0007 §9,
// §14), so the CLI and the MCP share one populated registry. This file is a
// thin re-export layer: type aliases and function bindings pointing at that
// package — NO registry logic lives here. Importing convreg triggers the
// converters' registration init()s, populating the shared map.

import (
	convreg "github.com/mitre/hdf-libs/hdf-converters/v3/registry/convert"
)

// init bridges the CLI's build-stamped version (root.go, set via ldflags) into
// the registry so converter output carries the right generator version.
func init() { convreg.SetVersion(version) }

// Relocated types — aliased so cmd call sites and tests compile unchanged.
type (
	Converter           = convreg.Converter
	VersionedConverter  = convreg.VersionedConverter
	OutputVersionSetter = convreg.OutputVersionSetter
	EmptyInputAccepting = convreg.EmptyInputAccepting
	FormatPair          = convreg.FormatPair
	ConverterOption     = convreg.ConverterOption
)

// ErrConverterNotFound is re-exported from the lifted registry.
var ErrConverterNotFound = convreg.ErrConverterNotFound

// Relocated functions — bound to the lifted registry (no reimplementation).
var (
	RegisterConverter = convreg.RegisterConverter
	GetConverter      = convreg.GetConverter
	ListConverters    = convreg.ListConverters
	WithEmptyInputOK  = convreg.WithEmptyInputOK
)
