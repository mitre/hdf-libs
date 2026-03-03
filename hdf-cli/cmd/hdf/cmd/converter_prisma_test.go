package cmd

import "testing"

func TestPrismaConverter(t *testing.T) {
	runStandardConverterTests(t, converterTestCase{
		Source:         "prisma",
		DisplayName:    "Prisma Cloud to HDF",
		FixtureDir:     "prisma-to-hdf",
		MinimalFixture: "input/minimal.csv",
		ErrPrefix:      "prisma conversion failed",
		InvalidInput:   "not,a,valid\ncsv,with,wrong,columns",
	})
}
