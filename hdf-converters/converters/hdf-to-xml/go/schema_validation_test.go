package hdftoxml

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"testing"

	corpus "github.com/mitre/hdf-libs/hdf-converters/v3/internal/corpus"
)

// NO TARGET SCHEMA EXISTS, and none can. This converter is a generic
// JSON-to-XML serializer of HDF itself, not an exporter to a third-party format,
// so there is no external specification to validate against — the "schema" for
// its output is the HDF schema the input already satisfied.
//
// What remains checkable is well-formedness: output no XML parser can read is
// malformed in the way a schema would catch, and it is reachable, since element
// names are derived from arbitrary HDF keys. A no-op validator would make every
// MustConvert contract pass vacuously.
type xmlWellFormedValidator struct{}

func (xmlWellFormedValidator) Validate(doc []byte) error {
	if len(doc) == 0 {
		return nil
	}
	dec := xml.NewDecoder(bytes.NewReader(doc))
	for {
		_, err := dec.Token()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("output is not well-formed XML: %w", err)
		}
	}
}

// TestConvertHDFToXML_AdversarialCorpus holds this converter to the shared
// corpus contracts, with well-formedness standing in for a target schema.
func TestConvertHDFToXML_AdversarialCorpus(t *testing.T) {
	corpus.RunSchemaCorpus(t, xmlWellFormedValidator{}, corpus.ResultsCorpus(), ConvertHDFToXML)
}
