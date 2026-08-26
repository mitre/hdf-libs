package convert

import defectdojo "github.com/mitre/hdf-libs/hdf-converters/v3/converters/defectdojo-to-hdf/go"

func init() {
	registerHDFConverter("defectdojo", "DefectDojo to HDF", "defectdojo", defectdojo.ConvertDefectDojo)
}
