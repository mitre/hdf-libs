package legacyhdf

import "encoding/json"

// IsLegacyHDF checks if the given JSON data appears to be HDF v1.0 format.
// It looks for the presence of version, profiles, and platform fields.
func IsLegacyHDF(data []byte) bool {
	var obj map[string]interface{}
	if err := json.Unmarshal(data, &obj); err != nil {
		return false
	}

	// V1.0 has version field (string), profiles (array), and platform (object)
	version, hasVersion := obj["version"]
	if !hasVersion {
		return false
	}
	if _, isString := version.(string); !isString {
		return false
	}

	profiles, hasProfiles := obj["profiles"]
	if !hasProfiles {
		return false
	}
	if _, isArray := profiles.([]interface{}); !isArray {
		return false
	}

	platform, hasPlatform := obj["platform"]
	if !hasPlatform {
		return false
	}
	if _, isObject := platform.(map[string]interface{}); !isObject {
		return false
	}

	return true
}

// IsLegacyHDFFromMap checks if a parsed map appears to be HDF v1.0 format.
func IsLegacyHDFFromMap(obj map[string]interface{}) bool {
	// V1.0 has version field (string), profiles (array), and platform (object)
	version, hasVersion := obj["version"]
	if !hasVersion {
		return false
	}
	if _, isString := version.(string); !isString {
		return false
	}

	profiles, hasProfiles := obj["profiles"]
	if !hasProfiles {
		return false
	}
	if _, isArray := profiles.([]interface{}); !isArray {
		return false
	}

	platform, hasPlatform := obj["platform"]
	if !hasPlatform {
		return false
	}
	if _, isObject := platform.(map[string]interface{}); !isObject {
		return false
	}

	return true
}
