package cmd

import prisma "github.com/mitre/hdf-libs/hdf-converters/v3/converters/prisma-to-hdf/go"

func init() {
	registerHDFConverter("prisma", "Prisma Cloud to HDF", "prisma", prisma.ConvertPrismaToHDF)
}
