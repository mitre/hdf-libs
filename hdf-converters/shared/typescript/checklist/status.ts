import { ResultStatus } from '@mitre/hdf-schema';
import { CheckStatus } from './model.js';

function normalizeKey(s: string): string {
  return s.toLowerCase().trim().split('_').join('').split(' ').join('');
}

const STATUS_BY_KEY: Record<string, CheckStatus> = {
  open: CheckStatus.Open,
  notafinding: CheckStatus.NotAFinding,
  notreviewed: CheckStatus.NotReviewed,
  notapplicable: CheckStatus.NotApplicable,
};

/** Map any CKL/CKLB status spelling to the canonical CheckStatus. */
export function parseStatus(s: string | undefined): CheckStatus {
  return STATUS_BY_KEY[normalizeKey(s ?? '')] ?? CheckStatus.NotReviewed;
}

/** CKL (XML) spelling. */
export function statusToCkl(s: CheckStatus): string {
  return s || CheckStatus.NotReviewed;
}

/** CKLB (JSON) snake_case spelling. */
export function statusToCklb(s: CheckStatus): string {
  switch (s) {
    case CheckStatus.Open:
      return 'open';
    case CheckStatus.NotAFinding:
      return 'not_a_finding';
    case CheckStatus.NotApplicable:
      return 'not_applicable';
    default:
      return 'not_reviewed';
  }
}

/** Canonical status -> HDF Result_Status. */
export function statusToHdf(s: CheckStatus): ResultStatus {
  switch (s) {
    case CheckStatus.Open:
      return ResultStatus.Failed;
    case CheckStatus.NotAFinding:
      return ResultStatus.Passed;
    case CheckStatus.NotApplicable:
      return ResultStatus.NotApplicable;
    default:
      return ResultStatus.NotReviewed;
  }
}

/** HDF Result_Status -> canonical status (error -> Open). */
export function statusFromHdf(s: ResultStatus | undefined): CheckStatus {
  switch (s) {
    case ResultStatus.Passed:
      return CheckStatus.NotAFinding;
    case ResultStatus.Failed:
    case ResultStatus.Error:
      return CheckStatus.Open;
    case ResultStatus.NotApplicable:
      return CheckStatus.NotApplicable;
    default:
      return CheckStatus.NotReviewed;
  }
}
