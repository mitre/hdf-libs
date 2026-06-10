// Splunk record types — wire-shape mirror of heimdall2's hdf_splunk_schema
// "1.1" contract. snake_case field names are part of the wire format; do
// not rename without coordinating with downstream Splunk consumers.

export interface SplunkData {
  reports: SplunkReport[];
  profiles: SplunkProfile[];
  controls: SplunkControl[];
}

export interface CommonMeta {
  guid: string;
  filename: string;
  filetype: string;
  subtype: string;
  hdf_splunk_schema: string;
}

// ReportMeta is an alias for CommonMeta — heimdall2's per-record meta types
// have type-specific extras; ours don't yet but we keep the name for parity.
export type ReportMeta = CommonMeta;

export interface SplunkReport {
  meta: ReportMeta;
  statistics?: unknown;
  passthrough?: Record<string, unknown>;
  profiles: unknown[];
  platform: Platform;
  version?: string;
}

export interface Platform {
  name: string;
  release: string;
}

export interface ProfileMeta extends CommonMeta {
  is_baseline: boolean;
  profile_sha256: string;
}

export interface SplunkProfile {
  meta: ProfileMeta;
  summary?: string;
  sha256: string;
  controls: unknown[];
  supports: unknown[];
  name: string;
  copyright?: string;
  maintainer?: string;
  copyright_email?: string;
  version?: string;
  license?: string;
  title?: string;
  parent_profile?: string;
  depends: unknown[];
  attributes: unknown[];
  groups: unknown[];
  status?: string;
}

export interface ControlMeta extends CommonMeta {
  status: string;
  profile_sha256: string;
  is_baseline: boolean;
  is_waived: boolean;
  overlay_depth: number;
}

export interface SplunkControl {
  meta: ControlMeta;
  title?: string;
  code: string;
  desc: string;
  descriptions: Record<string, string>;
  id: string;
  impact: number;
  refs: unknown[];
  source_location?: unknown;
  tags: Record<string, unknown>;
  results: unknown[];
}
