// Package hdf provides types and utilities for working with Heimdall Data Format (HDF) files.
//
// HDF is a standardized format for security assessment results, designed to work with
// compliance tools like Chef InSpec, AWS Security Hub, and more.
//
// This package includes:
//   - HdfResults: Assessment results with findings
//   - HdfBaseline: Baseline/profile definitions without findings
//
// Example usage:
//
//	data, _ := os.ReadFile("results.json")
//	results, err := hdf.UnmarshalHdfResults(data)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	fmt.Printf("Found %d profiles\n", len(results.Profiles))
package hdf

// Re-export from generated files
// The generated types are in hdf_results.go and hdf_baseline.go
