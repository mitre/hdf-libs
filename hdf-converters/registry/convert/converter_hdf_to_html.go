package convert

import (
	hdftohtml "github.com/mitre/hdf-libs/hdf-converters/v3/converters/hdf-to-html/go"
)

type hdfToHTMLConverter struct {
	reportType hdftohtml.ReportType
}

func (c *hdfToHTMLConverter) Name() string {
	return "HDF to HTML"
}

func (c *hdfToHTMLConverter) Convert(input []byte) ([]byte, error) {
	return hdftohtml.ConvertHDFToHTMLWithOptions(input, hdftohtml.Options{ReportType: c.reportType})
}

// ConvertMany renders several results documents as one aggregated report.
func (c *hdfToHTMLConverter) ConvertMany(inputs []NamedInput) ([]byte, error) {
	docs := make([]hdftohtml.Document, len(inputs))
	for i, in := range inputs {
		docs[i] = hdftohtml.Document{Name: in.Name, Data: in.Data}
	}
	return hdftohtml.ConvertHDFDocumentsToHTML(docs, hdftohtml.Options{ReportType: c.reportType})
}

// SetReportType selects the report's level of detail for later conversions.
func (c *hdfToHTMLConverter) SetReportType(reportType string) error {
	parsed, err := hdftohtml.ParseReportType(reportType)
	if err != nil {
		return err
	}
	c.reportType = parsed
	return nil
}

func init() {
	RegisterConverter("hdf", "html", &hdfToHTMLConverter{})
}
