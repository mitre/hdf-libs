import type { HdfBaseline } from '@mitre/hdf-schema';
import type { ProfileMetadata, InSpecProfile } from './types.js';
import type { PreferSide } from './merge.js';

/**
 * A structured record linking an old requirement to a new one.
 */
export interface LinkRecord {
  oldId: string | null;
  newId: string;
  matchMethod: string;
  confidence: number;
  relationship: 'primary' | 'related' | 'no-match';
  srg?: string | null;
  potentialMismatch: boolean;
}

/**
 * Statistics summarizing the delta operation.
 *
 * SAF CLI-compatible counter semantics:
 * - match: confident primary matches (potentialMismatch=false)
 * - posMisMatch: weak primary matches (potentialMismatch=true)
 * - dupMatch: related matches (shares body with a primary)
 * - noMatch: no match found
 *
 * Invariants:
 * - match + posMisMatch + dupMatch = totalMappedControls
 * - totalMappedControls + noMatch = newControlsLength
 */
export interface DeltaStatistics {
  oldControlsLength: number;
  newControlsLength: number;
  totalMappedControls: number;
  match: number;
  posMisMatch: number;
  dupMatch: number;
  noMatch: number;
}

/**
 * Complete result of an upgrade/delta operation.
 */
export interface UpgradeResult {
  baseline: HdfBaseline;
  profile?: InSpecProfile;
  linkRecords: LinkRecord[];
  statistics: DeltaStatistics;
}

/** Backward-compatible alias. */
export type DeltaResult = UpgradeResult;

/**
 * Options for controlling upgrade/delta generation.
 */
export interface UpgradeOptions {
  /** Conflict resolution: "current", "upstream", or undefined (smart merge). */
  prefer?: PreferSide;
  /** Don't preserve old test code (generate stubs for everything). */
  noCode?: boolean;
  /** Output format: "baseline", "inspec", or "both". Default: produce both. */
  outputFormat?: string;
  /** Put all controls in a single controls/controls.rb file. */
  singleFile?: boolean;
  /** Override profile metadata in the generated inspec.yml. */
  metadata?: ProfileMetadata;
  /** InSpec version constraint for inspec.yml. */
  inspecVersion?: string;
}

/** Backward-compatible alias. */
export type DeltaOptions = UpgradeOptions;
