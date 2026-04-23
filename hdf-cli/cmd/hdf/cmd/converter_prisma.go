package cmd

import prisma "github.com/mitre/hdf-libs/hdf-converters/converters/prisma-to-hdf/go"

func init() {
	registerHDFConverter("prisma", "Prisma Cloud to HDF", "prisma", prisma.ConvertPrismaToHDF)
}
