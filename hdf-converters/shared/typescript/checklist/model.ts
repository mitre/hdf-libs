/**
 * Format-neutral model for DISA STIG Viewer checklists and the mapping between
 * that model and HDF Results. CKL (XML, STIG Viewer 2.x) and CKLB (JSON, STIG
 * Viewer 3.x) carry the same semantic content in different shapes; this module
 * centralizes the HDF<->checklist mapping shared by the four converter
 * directions. Mirrors hdf-converters/shared/go/checklist.
 */

/** Canonical, format-neutral assessment status (CKL spelling is canonical). */
export enum CheckStatus {
  Open = 'Open',
  NotAFinding = 'NotAFinding',
  NotReviewed = 'Not_Reviewed',
  NotApplicable = 'Not_Applicable',
}

export interface Asset {
  role?: string;
  assetType?: string;
  hostName?: string;
  hostIP?: string;
  hostMAC?: string;
  hostFQDN?: string;
  targetKey?: string;
  marking?: string;
  webOrDatabase?: boolean;
  webDBSite?: string;
  webDBInstance?: string;
  techArea?: string;
  targetComment?: string;
  classification?: string;
}

export interface Vuln {
  vulnNum: string;
  ruleID?: string;
  ruleVer?: string;
  groupID?: string;
  groupTitle?: string;
  severity?: string;
  ruleTitle?: string;
  vulnDiscuss?: string;
  checkContent?: string;
  fixText?: string;
  weight?: string;
  classification?: string;
  ccis: string[];
  legacyIDs?: string[];
  status: CheckStatus;
  findingDetails?: string;
  comments?: string;
  /** Rarely-used STIG_DATA / rule fields preserved for round-trip. */
  extra?: Record<string, string>;
}

export interface Stig {
  stigID?: string;
  title?: string;
  displayName?: string;
  version?: string;
  releaseInfo?: string;
  uuid?: string;
  referenceIdentifier?: string;
  classification?: string;
  vulns: Vuln[];
}

export interface Checklist {
  asset: Asset;
  stigs: Stig[];
  /** Origin format, "ckl" or "cklb". */
  format?: string;
  cklbVersion?: string;
}
