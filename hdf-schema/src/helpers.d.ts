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
} from '../dist/ts/hdf-results.js';

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
  title: string,
  descriptions: Description[],
  impact: number,
  results: RequirementResult[],
  options?: {
    sourceLocation?: SourceLocation;
    tags?: Record<string, unknown>;
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
  }
): RequirementResult;

export function createEmptyChecksum(): Checksum;

export function createSupportedPlatform(
  platform: string,
  release?: string
): SupportedPlatform;

export function createSourceLocation(ref: string, line: number): SourceLocation;

export function severityToImpact(severity: null): null;
export function severityToImpact(severity: string): number;
export function severityToImpact(severity: string | null): number | null;

export function impactToSeverity(impact: null): null;
export function impactToSeverity(impact: number): string;
export function impactToSeverity(impact: number | null): string | null;

export function computeEffectiveStatus(
  requirement: EvaluatedRequirement
): ResultStatus;
