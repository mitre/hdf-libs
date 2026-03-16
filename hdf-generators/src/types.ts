/**
 * Options for controlling InSpec profile generation.
 */
export interface GeneratorOptions {
  /** Put all controls in a single controls.rb file instead of one file per control. */
  singleFile?: boolean;
  /** Override baseline metadata in the generated inspec.yml. */
  metadata?: ProfileMetadata;
  /** InSpec version constraint for inspec.yml. Default: '~>6.0'. */
  inspecVersion?: string;
}

/**
 * Metadata overrides for the generated inspec.yml.
 */
export interface ProfileMetadata {
  maintainer?: string;
  copyright?: string;
  license?: string;
  version?: string;
}

/**
 * An in-memory InSpec profile. No file I/O — the CLI is responsible for writing.
 */
export interface InSpecProfile {
  /** The inspec.yml content as a YAML string. */
  inspecYml: string;
  /** Map of filename (e.g. 'controls/SV-238196.rb') to Ruby source code. */
  controls: Map<string, string>;
}
