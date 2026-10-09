/**
 * Helper functions for creating valid HDF objects with sensible defaults
 * Type definitions for helpers.js
 */

import type {
  EvaluatedBaseline,
  EvaluatedRequirement,
  RequirementResult,
  Checksum,
  Integrity,
  Description,
  SourceLocation,
  ResultStatus,
  SupportedPlatform,
  RequirementGroup,
  StatusOverride,
  Poam,
  Cvss,
  Reference,
  AffectedPackage,
  Epss,
  Kev,
  OverrideType,
} from '../dist/ts/hdf.js';

export function createMinimalBaseline(
  name: string,
  requirements: EvaluatedRequirement[],
  options?: {
    title?: string;
    version?: string;
    attributes?: Array<Record<string, unknown>>;
    groups?: RequirementGroup[];
    supports?: SupportedPlatform[];
    integrity?: Integrity;
    resultsChecksum?: Checksum;
    originalChecksum?: Checksum;
    status?: string;
    summary?: string;
  }
): EvaluatedBaseline;

export function createRequirement(
  id: string,
  title: string | null | undefined,
  descriptions: Description[],
  impact: number,
  results: RequirementResult[],
  options?: {
    sourceLocation?: SourceLocation;
    tags?: Record<string, unknown>;
    code?: string;
    // Amendment fields
    effectiveStatus?: ResultStatus;
    effectiveImpact?: number;
    disposition?: OverrideType;
    statusOverrides?: StatusOverride[];
    poams?: Poam[];
    // Vulnerability fields
    cwe?: string[];
    cvss?: Cvss[];
    refs?: Reference[];
    affectedPackages?: AffectedPackage[];
    epss?: Epss;
    kev?: Kev;
  }
): EvaluatedRequirement;

export function createDescription(label: string, data: string): Description;

export function createResult(
  status: ResultStatus,
  message?: string,
  options?: {
    codeDesc?: string;
    startTime?: Date;
    runTime?: number;
    backtrace?: string[];
    exception?: string;
    resource?: string;
    resourceId?: string;
  }
): RequirementResult;

export function createEmptyChecksum(): Checksum;

export function createSupportedPlatform(
  platform: string,
  release?: string
): SupportedPlatform;

export function createSourceLocation(ref: string, line: number): SourceLocation;

export function createStatusOverride(
  type: OverrideType | string,
  options?: {
    reason?: string;
    // Looser than the schema's Identity on purpose: `type` is a plain string,
    // not the IdentityType enum. Kept inline because a top-level type in a
    // .d.ts module is implicitly exported and would collide with Identity.
    appliedBy?: { type: string; identifier: string; description?: string };
    appliedAt?: string;
    expiresAt?: string;
    status?: ResultStatus;
    impact?: { value: number };
  }
): StatusOverride;

export function createPoam(
  type: 'remediation' | 'mitigation' | 'riskAcceptance' | 'vendorDependency' | string,
  options?: {
    explanation?: string;
    appliedBy?: { type: string; identifier: string; description?: string };
    appliedAt?: string;
    expiresAt?: string;
    milestones?: Array<Record<string, unknown>>;
  }
): Poam;

export function createCvss(
  version: string,
  options?: Partial<Omit<Cvss, 'version'>>
): Cvss;

export function severityToImpact(severity: null): null;
export function severityToImpact(severity: string | undefined): number;
export function severityToImpact(severity: string | null | undefined): number | null;

export function impactToSeverity(impact: null): null;
export function impactToSeverity(impact: number): string;
export function impactToSeverity(impact: number | null): string | null;

export function computeEffectiveStatus(
  requirement: EvaluatedRequirement
): ResultStatus;
