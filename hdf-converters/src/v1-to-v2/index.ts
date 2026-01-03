/**
 * HDF v1.0 to v2.0 converter.
 *
 * Key transformations:
 * - Remove: version field (implicit in v2.0)
 * - Rename: profiles → baselines
 * - Transform: platform (single object) → targets (array)
 */

export interface HDFV1Results {
  version: string;
  platform: {
    name: string;
    release?: string;
    target_id?: string;
  };
  profiles: unknown[];
  statistics: unknown;
  generator?: unknown;
  timestamp?: string;
  [key: string]: unknown;
}

export interface HDFV2Results {
  baselines: unknown[];
  statistics: unknown;
  targets?: unknown[];
  generator?: unknown;
  timestamp?: string;
  id?: string;
  integrity?: unknown;
  runner?: unknown;
  remediation?: unknown;
  extensions?: Record<string, unknown>;
}

/**
 * Convert HDF v1.0 results to v2.0 format.
 *
 * @param v1Data - HDF v1.0 results object
 * @returns HDF v2.0 results object
 *
 * @example
 * ```typescript
 * const v1 = {
 *   version: "1.0.0",
 *   platform: { name: "ubuntu", release: "20.04" },
 *   profiles: [...],
 *   statistics: {...}
 * };
 * const v2 = convertV1ToV2(v1);
 * // v2 = { baselines: [...], targets: [{...}], statistics: {...} }
 * ```
 */
export function convertV1ToV2(v1Data: HDFV1Results): HDFV2Results {
  const v2: HDFV2Results = {
    baselines: v1Data.profiles || [],
    statistics: v1Data.statistics || {},
  };

  // Transform platform to targets array
  if (v1Data.platform) {
    v2.targets = [
      {
        type: 'system',
        id: v1Data.platform.target_id || v1Data.platform.name,
        name: v1Data.platform.name,
        ...(v1Data.platform.release && { release: v1Data.platform.release }),
      },
    ];
  }

  // Copy optional fields
  if (v1Data.generator) {
    v2.generator = v1Data.generator;
  }

  if (v1Data.timestamp) {
    v2.timestamp = v1Data.timestamp;
  }

  // Preserve any extension fields not part of core schema
  const knownV1Fields = new Set(['version', 'platform', 'profiles', 'statistics', 'generator', 'timestamp']);
  const extensionFields: Record<string, unknown> = {};

  for (const [key, value] of Object.entries(v1Data)) {
    if (!knownV1Fields.has(key)) {
      extensionFields[key] = value;
    }
  }

  if (Object.keys(extensionFields).length > 0) {
    v2.extensions = {
      ...extensionFields,
      v1_version: v1Data.version, // Preserve original version for tracking
    };
  }

  return v2;
}

/**
 * Validate that data appears to be HDF v1.0 format.
 *
 * @param data - Unknown data to validate
 * @returns true if data looks like HDF v1.0
 */
export function isHDFV1(data: unknown): data is HDFV1Results {
  if (typeof data !== 'object' || data === null) {
    return false;
  }

  const obj = data as Record<string, unknown>;

  // V1.0 has version field, profiles, and platform
  return (
    typeof obj.version === 'string' &&
    Array.isArray(obj.profiles) &&
    typeof obj.platform === 'object' &&
    obj.platform !== null
  );
}
