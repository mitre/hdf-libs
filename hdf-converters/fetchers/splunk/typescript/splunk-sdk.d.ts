// Minimal type declarations for splunk-sdk@2.x. The published package ships
// no types and has no @types/splunk-sdk on npm, so we declare only the
// interface surface this fetcher uses. Keep this shim tight — adding to it
// is fine when a new method is genuinely needed; expanding it speculatively
// is not.
//
// Reference: hdf-converters/node_modules/splunk-sdk/lib/service.js

declare module 'splunk-sdk' {
  /** Result of a Service.* call. The SDK normalizes errors into thrown rejections. */
  export interface ServiceResponse {
    status: number;
    headers?: Record<string, string>;
    body?: unknown;
  }

  /**
   * A pre-authenticated Splunk REST client. Caller is responsible for
   * authenticating before passing the Service to library code; this shim
   * does NOT include `login()` because the library never calls it.
   */
  export interface Service {
    /** GET the relative endpoint path. */
    get(path: string, params?: Record<string, unknown>): Promise<ServiceResponse>;
    /** POST to the relative endpoint path. The body is sent as form-encoded params. */
    post(path: string, params?: Record<string, unknown>): Promise<ServiceResponse>;
    /** Convenience: hits /services/server/info. */
    serverInfo(): Promise<ServiceResponse>;
  }

  // Constructor surface for tests that need to instantiate a real Service
  // (production callers do this themselves).
  export const Service: {
    new (...args: unknown[]): Service;
  };
}
