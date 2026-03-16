export type DetailLevel = 'summary' | 'control' | 'full';

export interface RenderOptions {
  /** What detail to show. Default: 'control' */
  detail?: DetailLevel;
  /** Only show requirements matching these states */
  filterStates?: string[];
  /** Only show requirements matching this severity */
  filterSeverity?: string;
  /** Use color codes (for terminal). Default: true */
  color?: boolean;
}
