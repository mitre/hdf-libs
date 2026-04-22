package hdftoxml

import (
	"encoding/json"
	"encoding/xml"
	"fmt"

	shared "github.com/mitre/hdf-libs/hdf-converters/shared/go"
	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go"
)

// ConvertHDFToXML converts HDF JSON to XML format
func ConvertHDFToXML(input []byte) ([]byte, error) {
	if len(input) == 0 {
		return nil, fmt.Errorf("hdf-to-xml: empty input")
	}
	if err := shared.ValidateJSONSize(input, "hdf-to-xml", 0); err != nil {
		return nil, fmt.Errorf("hdf-to-xml: %w", err)
	}

	// Parse HDF JSON
	var hdfData hdf.HDFResults
	if err := json.Unmarshal(input, &hdfData); err != nil {
		return nil, fmt.Errorf("invalid HDF JSON: %w", err)
	}

	// Validate structure
	if hdfData.Baselines == nil {
		return nil, fmt.Errorf("invalid HDF structure: missing baselines field")
	}

	// Transform to XML structure
	xmlData := transformToXMLStructure(&hdfData)

	// Marshal to XML with indentation
	output, err := xml.MarshalIndent(xmlData, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal XML: %w", err)
	}

	// Add XML header
	xmlWithHeader := append([]byte(xml.Header), output...)
	return xmlWithHeader, nil
}

// XMLHDFResults is the XML representation of HDF results
type XMLHDFResults struct {
	XMLName    xml.Name       `xml:"HdfResults"`
	Baselines  XMLBaselines   `xml:"baselines"`
	Targets    *XMLTargets    `xml:"components,omitempty"`
	Statistics *XMLStatistics `xml:"statistics,omitempty"`
	Timestamp  string         `xml:"timestamp,omitempty"`
}

// XMLBaselines wraps baseline array
type XMLBaselines struct {
	Baseline []XMLBaseline `xml:"baseline"`
}

// XMLBaseline represents a baseline in XML
type XMLBaseline struct {
	Name         string           `xml:"name"`
	Version      *string          `xml:"version,omitempty"`
	Title        *string          `xml:"title,omitempty"`
	Integrity    XMLIntegrity     `xml:"integrity"`
	Requirements *XMLRequirements `xml:"requirements,omitempty"`
}

// XMLIntegrity represents an integrity block
type XMLIntegrity struct {
	Algorithm string `xml:"algorithm"`
	Checksum  string `xml:"checksum"`
}

// XMLRequirements wraps requirement array
type XMLRequirements struct {
	Requirement []XMLRequirement `xml:"requirement"`
}

// XMLRequirement represents a requirement in XML
type XMLRequirement struct {
	ID           string           `xml:"id"`
	Title        *string          `xml:"title,omitempty"`
	Descriptions *XMLDescriptions `xml:"descriptions,omitempty"`
	Impact       float64          `xml:"impact"`
	Tags         *XMLTags         `xml:"tags,omitempty"`
	Results      *XMLResults      `xml:"results,omitempty"`
}

// XMLDescriptions wraps description array
type XMLDescriptions struct {
	Description []XMLDescription `xml:"description"`
}

// XMLDescription represents a labeled description
type XMLDescription struct {
	Label string `xml:"label"`
	Data  string `xml:"data"`
}

// XMLTags represents requirement tags with array support
type XMLTags struct {
	NIST  []string               `xml:"nist,omitempty"`
	CCI   []string               `xml:"cci,omitempty"`
	Other map[string]interface{} `xml:",omitempty"`
}

// XMLResults wraps result array
type XMLResults struct {
	Result []XMLResult `xml:"result"`
}

// XMLResult represents a test result
type XMLResult struct {
	Status    string   `xml:"status"`
	CodeDesc  string   `xml:"codeDesc"`
	StartTime string   `xml:"startTime"`
	Message   *string  `xml:"message,omitempty"`
	RunTime   *float64 `xml:"runTime,omitempty"`
}

// XMLTargets wraps target array
type XMLTargets struct {
	Target []XMLTarget `xml:"target"`
}

// XMLTarget represents a target
type XMLTarget struct {
	Name      string  `xml:"name"`
	Type      string  `xml:"type"`
	FQDN      *string `xml:"fqdn,omitempty"`
	IPAddress *string `xml:"ipAddress,omitempty"`
}

// XMLStatistics represents statistics
type XMLStatistics struct {
	Duration *float64 `xml:"duration,omitempty"`
}

// transformToXMLStructure converts HDF data to XML structure
func transformToXMLStructure(hdf *hdf.HDFResults) *XMLHDFResults {
	result := &XMLHDFResults{}

	// Transform baselines
	if len(hdf.Baselines) > 0 {
		result.Baselines.Baseline = make([]XMLBaseline, len(hdf.Baselines))
		for i, baseline := range hdf.Baselines {
			xmlBaseline := XMLBaseline{
				Name:    baseline.Name,
				Version: baseline.Version,
				Title:   baseline.Title,
			}
			if baseline.Integrity != nil {
				if baseline.Integrity.Algorithm != nil {
					xmlBaseline.Integrity.Algorithm = string(*baseline.Integrity.Algorithm)
				}
				if baseline.Integrity.Checksum != nil {
					xmlBaseline.Integrity.Checksum = *baseline.Integrity.Checksum
				}
			}
			result.Baselines.Baseline[i] = xmlBaseline

			// Transform requirements
			if len(baseline.Requirements) > 0 {
				result.Baselines.Baseline[i].Requirements = &XMLRequirements{
					Requirement: make([]XMLRequirement, len(baseline.Requirements)),
				}
				for j, req := range baseline.Requirements {
					result.Baselines.Baseline[i].Requirements.Requirement[j] = transformRequirement(req)
				}
			}
		}
	}

	// Transform components
	if len(hdf.Components) > 0 {
		result.Targets = &XMLTargets{
			Target: make([]XMLTarget, len(hdf.Components)),
		}
		for i, target := range hdf.Components {
			result.Targets.Target[i] = XMLTarget{
				Name:      target.Name,
				Type:      string(target.Type),
				FQDN:      target.FQDN,
				IPAddress: target.IPAddress,
			}
		}
	}

	// Transform statistics
	if hdf.Statistics != nil && hdf.Statistics.Duration != nil {
		result.Statistics = &XMLStatistics{
			Duration: hdf.Statistics.Duration,
		}
	}

	// Add timestamp
	if hdf.Timestamp != nil {
		result.Timestamp = hdf.Timestamp.Format("2006-01-02T15:04:05Z07:00")
	}

	return result
}

// transformRequirement converts a requirement to XML structure
func transformRequirement(req hdf.EvaluatedRequirement) XMLRequirement {
	xmlReq := XMLRequirement{
		ID:     req.ID,
		Title:  req.Title,
		Impact: req.Impact,
	}

	// Transform descriptions
	if len(req.Descriptions) > 0 {
		xmlReq.Descriptions = &XMLDescriptions{
			Description: make([]XMLDescription, len(req.Descriptions)),
		}
		for i, desc := range req.Descriptions {
			xmlReq.Descriptions.Description[i] = XMLDescription{
				Label: desc.Label,
				Data:  desc.Data,
			}
		}
	}

	// Transform tags - extract NIST and CCI as arrays
	if len(req.Tags) > 0 {
		xmlReq.Tags = &XMLTags{}

		// Extract NIST controls
		if nist, ok := req.Tags["nist"].([]interface{}); ok && len(nist) > 0 {
			xmlReq.Tags.NIST = make([]string, len(nist))
			for i, v := range nist {
				xmlReq.Tags.NIST[i] = fmt.Sprint(v)
			}
		}

		// Extract CCI controls
		if cci, ok := req.Tags["cci"].([]interface{}); ok && len(cci) > 0 {
			xmlReq.Tags.CCI = make([]string, len(cci))
			for i, v := range cci {
				xmlReq.Tags.CCI[i] = fmt.Sprint(v)
			}
		}
	}

	// Transform results
	if len(req.Results) > 0 {
		xmlReq.Results = &XMLResults{
			Result: make([]XMLResult, len(req.Results)),
		}
		for i, res := range req.Results {
			xmlReq.Results.Result[i] = XMLResult{
				Status:    string(res.Status),
				CodeDesc:  res.CodeDesc,
				StartTime: res.StartTime.Format("2006-01-02T15:04:05Z07:00"),
				Message:   res.Message,
				RunTime:   res.RunTime,
			}
		}
	}

	return xmlReq
}
