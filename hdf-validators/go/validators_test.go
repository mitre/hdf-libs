package hdfvalidators

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestValidateResults_ValidDocuments(t *testing.T) {
	t.Run("should validate minimal valid HDF results", func(t *testing.T) {
		validResults := []byte(`{
			"baselines": [{
				"name": "Test Baseline",
				"checksum": { "algorithm": "sha256", "value": "abc123" },
				"requirements": [{
					"id": "REQ-001",
					"descriptions": [{ "label": "default", "data": "Test description" }],
					"impact": 0.5,
					"tags": {},
					"results": [{
						"status": "passed",
						"codeDesc": "Test",
						"startTime": "2025-01-01T00:00:00Z"
					}]
				}]
			}],
			"components": [],
			"statistics": {}
		}`)

		result := ValidateResults(validResults)
		assert.True(t, result.Valid, "Should be valid")
		assert.Empty(t, result.Errors)
	})

	t.Run("should validate results with components and statistics", func(t *testing.T) {
		validResults := []byte(`{
			"baselines": [{
				"name": "Test Baseline",
				"checksum": { "algorithm": "sha256", "value": "abc123" },
				"requirements": [{
					"id": "REQ-001",
					"descriptions": [{ "label": "default", "data": "Test" }],
					"impact": 0.5,
					"tags": {},
					"results": [{ "status": "passed", "codeDesc": "OK", "startTime": "2025-01-01T00:00:00Z" }]
				}]
			}],
			"components": [{
				"name": "web-server-01",
				"type": "host"
			}],
			"statistics": {
				"duration": 45.5
			}
		}`)

		result := ValidateResults(validResults)
		if !result.Valid {
			t.Logf("Validation errors: %s", result.Error())
		}
		assert.True(t, result.Valid)
	})
}

func TestValidateResults_InvalidDocuments(t *testing.T) {
	t.Run("should reject results missing baselines field", func(t *testing.T) {
		invalid := []byte(`{
			"components": [],
			"statistics": {}
		}`)

		result := ValidateResults(invalid)
		assert.False(t, result.Valid)
		assert.NotEmpty(t, result.Errors)
		assert.Contains(t, result.Error(), "baselines")
	})

	t.Run("should reject results with invalid baselines type", func(t *testing.T) {
		invalid := []byte(`{
			"baselines": "not an array",
			"components": [],
			"statistics": {}
		}`)

		result := ValidateResults(invalid)
		assert.False(t, result.Valid)
		assert.Contains(t, result.Error(), "baselines")
	})

	t.Run("should reject baseline missing required name field", func(t *testing.T) {
		invalid := []byte(`{
			"baselines": [{
				"checksum": { "algorithm": "sha256", "value": "abc123" },
				"requirements": []
			}],
			"components": [],
			"statistics": {}
		}`)

		result := ValidateResults(invalid)
		assert.False(t, result.Valid)
		assert.Contains(t, result.Error(), "name")
	})

	t.Run("should reject invalid JSON", func(t *testing.T) {
		invalid := []byte(`not valid json`)

		result := ValidateResults(invalid)
		assert.False(t, result.Valid)
		assert.NotEmpty(t, result.Errors)
	})
}

func TestValidateBaseline_ValidDocuments(t *testing.T) {
	t.Run("should validate minimal valid baseline", func(t *testing.T) {
		validBaseline := []byte(`{
			"name": "Test Baseline",
			"title": "Test Baseline Title",
			"version": "1.0.0",
			"checksum": {
				"algorithm": "sha256",
				"value": "abc123"
			},
			"requirements": [{
				"id": "REQ-001",
				"title": "Test Requirement",
				"descriptions": [{ "label": "default", "data": "Description" }],
				"impact": 0.7,
				"tags": {}
			}]
		}`)

		result := ValidateBaseline(validBaseline)
		assert.True(t, result.Valid)
		assert.Empty(t, result.Errors)
	})

	t.Run("should validate baseline with requirements", func(t *testing.T) {
		validBaseline := []byte(`{
			"name": "Test Baseline",
			"title": "Test Title",
			"version": "1.0.0",
			"checksum": { "algorithm": "sha256", "value": "abc123" },
			"requirements": [{
				"id": "REQ-001",
				"title": "Test Requirement",
				"descriptions": [{ "label": "default", "data": "Description" }],
				"impact": 0.7,
				"tags": { "nist": ["AC-1"] }
			}]
		}`)

		result := ValidateBaseline(validBaseline)
		assert.True(t, result.Valid)
	})
}

func TestValidateBaseline_InvalidDocuments(t *testing.T) {
	t.Run("should reject baseline missing name", func(t *testing.T) {
		invalid := []byte(`{
			"title": "Test",
			"version": "1.0.0",
			"checksum": { "algorithm": "sha256", "value": "abc123" },
			"requirements": [{
				"id": "REQ-001",
				"descriptions": [{ "label": "default", "data": "Test" }],
				"impact": 0.5,
				"tags": {}
			}]
		}`)

		result := ValidateBaseline(invalid)
		assert.False(t, result.Valid)
		assert.Contains(t, result.Error(), "name")
	})

	t.Run("should reject baseline missing requirements", func(t *testing.T) {
		invalid := []byte(`{
			"name": "Test",
			"title": "Test",
			"version": "1.0.0"
		}`)

		result := ValidateBaseline(invalid)
		assert.False(t, result.Valid)
		assert.Contains(t, result.Error(), "requirements")
	})
}

func TestValidationResult_ErrorMessage(t *testing.T) {
	t.Run("should format error messages correctly", func(t *testing.T) {
		result := ValidationResult{
			Valid: false,
			Errors: []ValidationError{
				{Field: "baselines", Description: "is required"},
				{Field: "baselines[0].name", Description: "must be a string"},
			},
		}

		msg := result.Error()
		assert.Contains(t, msg, "baselines")
		assert.Contains(t, msg, "name")
	})

	t.Run("should return empty string for valid results", func(t *testing.T) {
		result := ValidationResult{
			Valid:  true,
			Errors: []ValidationError{},
		}

		assert.Empty(t, result.Error())
	})
}

// ---------------------------------------------------------------------------
// CVE-ecosystem primitives (Cvss, Epss, Kev, AffectedPackage, cwe[]).
// Wave 1 of epic hdf-libs-8zn0 / bead hdf-libs-tilc.
//
// These tests exercise the embedded-bundled-schema path: a failure here
// indicates a schema or wiring bug, not a test bug.
// ---------------------------------------------------------------------------

// resultsWith wraps the given Evaluated_Requirement JSON fragment in a
// minimal-valid hdf-results document. The fragment is inserted verbatim as
// extra fields on the requirement object.
func resultsWith(reqFields string) []byte {
	base := `{
		"baselines": [{
			"name": "CVE-Ecosystem Test Baseline",
			"checksum": { "algorithm": "sha256", "value": "abc123" },
			"requirements": [{
				"id": "CVE-2024-12345",
				"descriptions": [{ "label": "default", "data": "Test CVE finding" }],
				"impact": 0.7,
				"tags": {},
				"results": [{ "status": "failed", "codeDesc": "Vulnerable", "startTime": "2026-05-26T00:00:00Z" }]
				REQ_EXTRA
			}]
		}],
		"components": [],
		"statistics": {}
	}`
	extra := ""
	if reqFields != "" {
		extra = "," + reqFields
	}
	return []byte(strings.Replace(base, "REQ_EXTRA", extra, 1))
}

func TestCveEcosystem_Cvss(t *testing.T) {
	t.Run("accepts full Base+Threat+Environmental entry", func(t *testing.T) {
		data := resultsWith(`"cvss": [{
			"version": "3.1",
			"source": "CVE-2024-3094",
			"baseVector": "CVSS:3.1/AV:L/AC:H/PR:H/UI:N/S:U/C:H/I:H/A:H",
			"baseScore": 6.7,
			"baseSeverity": "medium",
			"threatVector": "E:A/RL:O/RC:C",
			"threatScore": 6.5,
			"environmentalVector": "MAV:N/CR:H/IR:H/AR:H",
			"environmentalScore": 9.0,
			"computedScore": 9.0,
			"computedSeverity": "critical"
		}]`)
		result := ValidateResults(data)
		if !result.Valid {
			t.Logf("Unexpected errors: %s", result.Error())
		}
		assert.True(t, result.Valid)
		assert.Empty(t, result.Errors)
	})

	t.Run("accepts multiple CVSS entries on one requirement", func(t *testing.T) {
		data := resultsWith(`"cvss": [
			{"version": "3.1", "source": "CVE-2024-12345", "baseVector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "baseScore": 9.8, "baseSeverity": "critical"},
			{"version": "3.1", "source": "CVE-2024-12346", "baseVector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N", "baseScore": 4.7, "baseSeverity": "medium"},
			{"version": "2.0", "source": "CVE-2014-0160", "baseVector": "AV:N/AC:L/Au:N/C:P/I:N/A:N", "baseScore": 5.0}
		]`)
		result := ValidateResults(data)
		if !result.Valid {
			t.Logf("Unexpected errors: %s", result.Error())
		}
		assert.True(t, result.Valid)
	})

	t.Run("rejects malformed baseVector", func(t *testing.T) {
		data := resultsWith(`"cvss": [{
			"version": "3.1", "source": "CVE-2024-12345",
			"baseVector": "not a vector", "baseScore": 9.8
		}]`)
		result := ValidateResults(data)
		assert.False(t, result.Valid)
		assert.Contains(t, result.Error(), "baseVector")
	})

	t.Run("rejects missing required version field", func(t *testing.T) {
		data := resultsWith(`"cvss": [{
			"source": "CVE-2024-12345",
			"baseVector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
			"baseScore": 9.8
		}]`)
		result := ValidateResults(data)
		assert.False(t, result.Valid)
		assert.Contains(t, result.Error(), "version")
	})

	t.Run("rejects baseScore above 10.0", func(t *testing.T) {
		data := resultsWith(`"cvss": [{
			"version": "3.1",
			"baseVector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
			"baseScore": 12.5
		}]`)
		result := ValidateResults(data)
		assert.False(t, result.Valid)
		assert.Contains(t, result.Error(), "baseScore")
	})
}

func TestCveEcosystem_Epss(t *testing.T) {
	t.Run("accepts full EPSS object", func(t *testing.T) {
		data := resultsWith(`"epss": {"score": 0.97532, "percentile": 0.99987, "date": "2026-05-26"}`)
		result := ValidateResults(data)
		if !result.Valid {
			t.Logf("Unexpected errors: %s", result.Error())
		}
		assert.True(t, result.Valid)
		assert.Empty(t, result.Errors)
	})

	t.Run("rejects EPSS score above 1.0", func(t *testing.T) {
		data := resultsWith(`"epss": {"score": 1.5, "percentile": 0.5, "date": "2026-05-26"}`)
		result := ValidateResults(data)
		assert.False(t, result.Valid)
		assert.Contains(t, result.Error(), "score")
	})

	t.Run("rejects EPSS missing date", func(t *testing.T) {
		data := resultsWith(`"epss": {"score": 0.5, "percentile": 0.5}`)
		result := ValidateResults(data)
		assert.False(t, result.Valid)
		assert.Contains(t, result.Error(), "date")
	})

	t.Run("rejects EPSS percentile above 1.0", func(t *testing.T) {
		data := resultsWith(`"epss": {"score": 0.5, "percentile": 1.01, "date": "2026-05-26"}`)
		result := ValidateResults(data)
		assert.False(t, result.Valid)
		assert.Contains(t, result.Error(), "percentile")
	})
}

func TestCveEcosystem_Kev(t *testing.T) {
	t.Run("accepts inKev:true with dateAdded + dueDate", func(t *testing.T) {
		data := resultsWith(`"kev": {
			"inKev": true,
			"dateAdded": "2026-03-15",
			"dueDate": "2026-04-05",
			"notes": "Active ransomware exploitation observed."
		}`)
		result := ValidateResults(data)
		if !result.Valid {
			t.Logf("Unexpected errors: %s", result.Error())
		}
		assert.True(t, result.Valid)
	})

	t.Run("accepts inKev:false without dates", func(t *testing.T) {
		data := resultsWith(`"kev": {"inKev": false}`)
		result := ValidateResults(data)
		if !result.Valid {
			t.Logf("Unexpected errors: %s", result.Error())
		}
		assert.True(t, result.Valid)
	})

	t.Run("rejects inKev:true with missing dateAdded", func(t *testing.T) {
		data := resultsWith(`"kev": {"inKev": true, "dueDate": "2026-04-05"}`)
		result := ValidateResults(data)
		assert.False(t, result.Valid)
		assert.Contains(t, result.Error(), "dateAdded")
	})

	t.Run("rejects inKev:true with missing dueDate", func(t *testing.T) {
		data := resultsWith(`"kev": {"inKev": true, "dateAdded": "2026-03-15"}`)
		result := ValidateResults(data)
		assert.False(t, result.Valid)
		assert.Contains(t, result.Error(), "dueDate")
	})
}

func TestCveEcosystem_Cwe(t *testing.T) {
	t.Run("accepts three valid CWE IDs", func(t *testing.T) {
		data := resultsWith(`"cwe": ["CWE-79", "CWE-89", "CWE-352"]`)
		result := ValidateResults(data)
		if !result.Valid {
			t.Logf("Unexpected errors: %s", result.Error())
		}
		assert.True(t, result.Valid)
	})

	t.Run("rejects lowercase cwe-79", func(t *testing.T) {
		data := resultsWith(`"cwe": ["cwe-79"]`)
		result := ValidateResults(data)
		assert.False(t, result.Valid)
	})

	t.Run("rejects bare numeric ID", func(t *testing.T) {
		data := resultsWith(`"cwe": ["79"]`)
		result := ValidateResults(data)
		assert.False(t, result.Valid)
	})

	t.Run("rejects CWE-0", func(t *testing.T) {
		data := resultsWith(`"cwe": ["CWE-0"]`)
		result := ValidateResults(data)
		assert.False(t, result.Valid)
	})

	t.Run("rejects CWE-079 (leading zero)", func(t *testing.T) {
		data := resultsWith(`"cwe": ["CWE-079"]`)
		result := ValidateResults(data)
		assert.False(t, result.Valid)
	})
}

func TestCveEcosystem_AffectedPackages(t *testing.T) {
	t.Run("accepts rpm + npm + maven entries", func(t *testing.T) {
		data := resultsWith(`"affectedPackages": [
			{"name": "openssl", "version": "1.1.1k-7.el8_4", "ecosystem": "rpm",
			 "cpe": "cpe:2.3:a:openssl:openssl:1.1.1k:*:*:*:*:*:*:*",
			 "purl": "pkg:rpm/redhat/openssl@1.1.1k-7.el8_4?arch=x86_64",
			 "fixedInVersion": "1.1.1l"},
			{"name": "lodash", "version": "4.17.20", "ecosystem": "npm",
			 "purl": "pkg:npm/lodash@4.17.20", "fixedInVersion": "4.17.21"},
			{"name": "org.apache.logging.log4j:log4j-core", "version": "2.14.1", "ecosystem": "maven",
			 "cpe": "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*",
			 "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
			 "fixedInVersion": "2.17.1"}
		]`)
		result := ValidateResults(data)
		if !result.Valid {
			t.Logf("Unexpected errors: %s", result.Error())
		}
		assert.True(t, result.Valid)
	})

	t.Run("rejects missing required ecosystem field", func(t *testing.T) {
		data := resultsWith(`"affectedPackages": [{"name": "openssl", "version": "1.1.1k"}]`)
		result := ValidateResults(data)
		assert.False(t, result.Valid)
		assert.Contains(t, result.Error(), "ecosystem")
	})

	t.Run("rejects bad CPE prefix", func(t *testing.T) {
		data := resultsWith(`"affectedPackages": [{"name": "openssl", "version": "1.1.1k", "ecosystem": "rpm", "cpe": "openssl:1.0"}]`)
		result := ValidateResults(data)
		assert.False(t, result.Valid)
		assert.Contains(t, result.Error(), "cpe")
	})

	t.Run("rejects bad PURL prefix", func(t *testing.T) {
		data := resultsWith(`"affectedPackages": [{"name": "foo", "version": "1.0", "ecosystem": "npm", "purl": "foo@1.0"}]`)
		result := ValidateResults(data)
		assert.False(t, result.Valid)
		assert.Contains(t, result.Error(), "purl")
	})

	t.Run("accepts uppercase and complex PURL type names", func(t *testing.T) {
		// The pattern mirrors parsePurl's accept-and-warn behavior: type may be
		// uppercase or contain digits / '.' / '+' / '-' per the PURL grammar.
		data := resultsWith(`"affectedPackages": [
			{"name": "lodash", "version": "4.17.20", "ecosystem": "npm", "purl": "pkg:NPM/lodash@4.17.20"},
			{"name": "thing", "version": "1.0", "ecosystem": "generic", "purl": "pkg:docker.io/library/nginx@1.25"}
		]`)
		result := ValidateResults(data)
		if !result.Valid {
			t.Logf("Unexpected errors: %s", result.Error())
		}
		assert.True(t, result.Valid)
	})

	t.Run("rejects unknown ecosystem enum value", func(t *testing.T) {
		data := resultsWith(`"affectedPackages": [{"name": "thing", "version": "1.0", "ecosystem": "snapcraft"}]`)
		result := ValidateResults(data)
		assert.False(t, result.Valid)
		assert.Contains(t, result.Error(), "ecosystem")
	})
}

func TestCveEcosystem_OverrideCvss(t *testing.T) {
	t.Run("accepts Status_Override with attached cvss block", func(t *testing.T) {
		data := resultsWith(`"overrides": [{
			"type": "riskAdjustment",
			"impact": {"value": 0.5},
			"reason": "Environmental exposure reduced — internal VPN only.",
			"appliedBy": {"type": "email", "identifier": "sec@org.gov"},
			"appliedAt": "2026-04-14T10:00:00Z",
			"expiresAt": "2026-10-14T00:00:00Z",
			"cvss": {
				"version": "3.1",
				"source": "CVE-2024-12345",
				"baseVector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
				"baseScore": 9.8,
				"baseSeverity": "critical",
				"environmentalVector": "MAV:A/CR:M/IR:M/AR:M",
				"environmentalScore": 5.0,
				"computedScore": 5.0,
				"computedSeverity": "medium"
			}
		}]`)
		result := ValidateResults(data)
		if !result.Valid {
			t.Logf("Unexpected errors: %s", result.Error())
		}
		assert.True(t, result.Valid)
	})

	t.Run("accepts Standalone_Override in amendments with cvss block", func(t *testing.T) {
		doc := []byte(`{
			"name": "CVE-Ecosystem Amendments",
			"overrides": [{
				"type": "riskAdjustment",
				"requirementId": "CVE-2024-12345",
				"baselineRef": "Test",
				"impact": {"value": 0.5},
				"reason": "Environmental enrichment — internal-only exposure.",
				"appliedBy": {"type": "email", "identifier": "sec@org.gov"},
				"appliedAt": "2026-04-14T10:00:00Z",
				"expiresAt": "2026-10-14T00:00:00Z",
				"cvss": {
					"version": "3.1",
					"source": "CVE-2024-12345",
					"baseVector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
					"baseScore": 9.8,
					"baseSeverity": "critical",
					"environmentalVector": "MAV:A/CR:M/IR:M/AR:M",
					"environmentalScore": 5.0,
					"computedScore": 5.0,
					"computedSeverity": "medium"
				}
			}]
		}`)
		result := ValidateAmendments(doc)
		if !result.Valid {
			t.Logf("Unexpected errors: %s", result.Error())
		}
		assert.True(t, result.Valid)
	})
}

// TestPoamRequiresExpiresAt asserts a POA&M is time-boxed: without an expiresAt
// deadline it lets a failing requirement duck remediation indefinitely, so the
// schema must reject it (bead 2cyd).
func TestPoamRequiresExpiresAt(t *testing.T) {
	poam := func(expiresAt string) []byte {
		return resultsWith(`"poams": [{
			"type": "remediation",
			"explanation": "Patch deployment scheduled pending vendor fix.",
			"appliedBy": { "type": "email", "identifier": "ops@agency.gov" },
			"appliedAt": "2026-01-20T10:00:00Z"` + expiresAt + `
		}]`)
	}

	t.Run("rejects a POA&M without expiresAt", func(t *testing.T) {
		result := ValidateResults(poam(""))
		assert.False(t, result.Valid)
		assert.Contains(t, result.Error(), "expiresAt")
	})

	t.Run("accepts a POA&M with expiresAt", func(t *testing.T) {
		result := ValidateResults(poam(`, "expiresAt": "2099-12-31T00:00:00Z"`))
		if !result.Valid {
			t.Logf("Unexpected errors: %s", result.Error())
		}
		assert.True(t, result.Valid)
	})
}

func TestSetSchemaDir(t *testing.T) {
	t.Run("should allow loading schemas from custom directory", func(t *testing.T) {
		// Store original
		originalDir := GetSchemaDir()
		defer SetSchemaDir(originalDir)

		// Set custom directory
		customDir := "../../hdf-schema/dist/schemas"
		SetSchemaDir(customDir)

		assert.Equal(t, customDir, GetSchemaDir())

		// Should still validate correctly
		validResults := []byte(`{
			"baselines": [{
				"name": "Test",
				"checksum": { "algorithm": "sha256", "value": "abc" },
				"requirements": [{"id": "SV-1", "impact": 0.5, "tags": {}, "descriptions": [{"label": "default", "data": "Test"}], "results": [{"status": "passed", "codeDesc": "Test", "startTime": "2025-01-01T00:00:00Z"}]}]
			}],
			"components": [],
			"statistics": {}
		}`)

		result := ValidateResults(validResults)
		assert.True(t, result.Valid)
	})
}
