import { describe, it, expect } from 'vitest';
import Ajv2020 from 'ajv/dist/2020.js';
import addFormats from 'ajv-formats';
import commonSchema from '../src/schemas/primitives/common.schema.json';
import platformSchema from '../src/schemas/primitives/platform.schema.json';
import targetSchema from '../src/schemas/primitives/target.schema.json';
import runnerSchema from '../src/schemas/primitives/runner.schema.json';
import statisticsSchema from '../src/schemas/primitives/statistics.schema.json';
import resultSchema from '../src/schemas/primitives/result.schema.json';
import amendmentsSchema from '../src/schemas/primitives/amendments.schema.json';
import extensionsSchema from '../src/schemas/primitives/extensions.schema.json';
import cvssSchema from '../src/schemas/primitives/cvss.schema.json';
import epssSchema from '../src/schemas/primitives/epss.schema.json';
import kevSchema from '../src/schemas/primitives/kev.schema.json';
import affectedPackageSchema from '../src/schemas/primitives/affected-package.schema.json';
import { schemaRef } from './schema-ref';

describe('Primitive Schema Validation', () => {
  const ajv = new Ajv2020({ strict: false, allErrors: true, validateFormats: true });
  addFormats(ajv);

  // Register all schemas so $ref works
  ajv.addSchema(commonSchema);
  ajv.addSchema(platformSchema);
  ajv.addSchema(targetSchema);
  ajv.addSchema(runnerSchema);
  ajv.addSchema(statisticsSchema);
  ajv.addSchema(resultSchema);
  ajv.addSchema(amendmentsSchema);
  ajv.addSchema(extensionsSchema);
  ajv.addSchema(cvssSchema);
  ajv.addSchema(epssSchema);
  ajv.addSchema(kevSchema);
  ajv.addSchema(affectedPackageSchema);

  describe('common.schema.json', () => {
    describe('Requirement_Group', () => {
      const validate = ajv.compile({
        ...schemaRef(commonSchema, 'Requirement_Group'),
      });

      it('should validate a valid Requirement_Group', () => {
        const valid = {
          id: 'controls/ssh.rb',
          title: 'SSH Configuration Controls',
          requirements: ['SV-238196', 'SV-238197', 'SV-238198'],
        };
        expect(validate(valid)).toBe(true);
        expect(validate.errors).toBeNull();
      });

      it('should reject Requirement_Group with explicit null title', () => {
        const invalid = {
          id: 'controls/ssh.rb',
          title: null,
          requirements: ['SV-238196'],
        };
        expect(validate(invalid)).toBe(false);
      });

      it('should reject Requirement_Group missing required id', () => {
        const invalid = {
          title: 'SSH Controls',
          requirements: ['SV-238196'],
        };
        expect(validate(invalid)).toBe(false);
        expect(validate.errors).not.toBeNull();
      });

      it('should reject Requirement_Group missing required requirements array', () => {
        const invalid = {
          id: 'controls/ssh.rb',
          title: 'SSH Controls',
        };
        expect(validate(invalid)).toBe(false);
      });

      it('should reject Requirement_Group with non-string requirements', () => {
        const invalid = {
          id: 'controls/ssh.rb',
          requirements: [123, 456],
        };
        expect(validate(invalid)).toBe(false);
      });
    });

    describe('Identity', () => {
      const validate = ajv.compile({
        ...schemaRef(commonSchema, 'Identity'),
      });

      it('should accept the agent identity type (AI-agent provenance)', () => {
        const valid = { type: 'agent', identifier: 'cve-enrichment-bot/v0.4.2' };
        expect(validate(valid)).toBe(true);
        expect(validate.errors).toBeNull();
      });

      it('should still accept the existing system type', () => {
        expect(validate({ type: 'system', identifier: 'scanner-01' })).toBe(true);
      });

      it('should reject an unknown identity type (agent is the value, not ai-agent)', () => {
        expect(validate({ type: 'ai-agent', identifier: 'x' })).toBe(false);
      });
    });

    describe('Requirement_Core', () => {
      const validate = ajv.compile({
        ...schemaRef(commonSchema, 'Requirement_Core'),
      });

      it('should validate empty object (all fields optional)', () => {
        expect(validate({})).toBe(true);
      });

      it('should validate v3.1.x-style requirement with no classification fields', () => {
        const valid = {
          id: 'SV-238196',
          title: 'The Ubuntu OS must enforce password complexity',
          impact: 0.5,
          tags: { nist: ['IA-5'], severity: 'medium' },
          descriptions: [{ label: 'default', data: 'desc' }],
          code: 'control "SV-238196" do; end',
        };
        expect(validate(valid)).toBe(true);
      });

      describe('controlType (v3.2 classification field)', () => {
        it.each(['policy', 'procedure', 'technical', 'management', 'operational'])(
          'should accept controlType=%s',
          (value: string) => {
            expect(validate({ id: 'C-1', controlType: value })).toBe(true);
          },
        );

        it('should reject unknown controlType', () => {
          expect(validate({ id: 'C-1', controlType: 'invented' })).toBe(false);
        });

        it('should reject explicit null controlType', () => {
          expect(validate({ id: 'C-1', controlType: null })).toBe(false);
        });

        it('should accept omitted controlType', () => {
          expect(validate({ id: 'C-1' })).toBe(true);
        });
      });

      describe('verificationMethod (v3.2 classification field)', () => {
        it.each(['automated', 'manual-by-design', 'manual-pending-automation', 'hybrid'])(
          'should accept verificationMethod=%s',
          (value: string) => {
            expect(validate({ id: 'C-1', verificationMethod: value })).toBe(true);
          },
        );

        it('should reject unknown verificationMethod', () => {
          expect(validate({ id: 'C-1', verificationMethod: 'magic' })).toBe(false);
        });

        it('should reject explicit null verificationMethod', () => {
          expect(validate({ id: 'C-1', verificationMethod: null })).toBe(false);
        });

        it('should reject legacy snake_case manual_pending_automation (hyphen form is canonical)', () => {
          expect(validate({ id: 'C-1', verificationMethod: 'manual_pending_automation' })).toBe(false);
        });

        it('should accept omitted verificationMethod', () => {
          expect(validate({ id: 'C-1' })).toBe(true);
        });
      });

      describe('applicability (v3.2 classification field)', () => {
        it.each(['required', 'optional', 'advisory'])(
          'should accept applicability=%s',
          (value: string) => {
            expect(validate({ id: 'C-1', applicability: value })).toBe(true);
          },
        );

        it('should reject unknown applicability', () => {
          expect(validate({ id: 'C-1', applicability: 'mandatory' })).toBe(false);
        });

        it('should reject explicit null applicability', () => {
          expect(validate({ id: 'C-1', applicability: null })).toBe(false);
        });

        it('should accept omitted applicability', () => {
          expect(validate({ id: 'C-1' })).toBe(true);
        });
      });

      it('should validate Requirement_Core with all three classification fields populated', () => {
        const valid = {
          id: 'AC-3',
          title: 'Access Enforcement',
          impact: 0.7,
          tags: { nist: ['AC-3'] },
          descriptions: [{ label: 'default', data: 'Enforce approved authorizations.' }],
          code: 'control "AC-3" do; end',
          controlType: 'technical',
          verificationMethod: 'automated',
          applicability: 'required',
        };
        expect(validate(valid)).toBe(true);
      });
    });

    describe('Dependency', () => {
      const validate = ajv.compile({
        ...schemaRef(commonSchema, 'Dependency'),
      });

      it('should validate a valid Dependency with git URL', () => {
        const valid = {
          name: 'ubuntu-22.04-stig-baseline',
          git: 'https://github.com/my-org/ubuntu-22.04-stig-baseline.git',
          branch: 'main',
          status: 'loaded',
        };
        expect(validate(valid)).toBe(true);
      });

      it('should validate an empty Dependency (no required fields)', () => {
        const valid = {};
        expect(validate(valid)).toBe(true);
      });

      it('should reject Dependency with explicit null fields', () => {
        const invalid = {
          name: null,
          url: null,
          status: null,
        };
        expect(validate(invalid)).toBe(false);
      });
    });

    describe('Reference', () => {
      const validate = ajv.compile({
        ...schemaRef(commonSchema, 'Reference'),
      });

      it('should validate Reference with ref string', () => {
        const valid = { ref: 'NIST SP 800-53 Rev 5' };
        expect(validate(valid)).toBe(true);
      });

      it('should validate Reference with url', () => {
        const valid = { url: 'https://nvd.nist.gov/800-53' };
        expect(validate(valid)).toBe(true);
      });

      it('should validate Reference with uri', () => {
        const valid = { uri: 'urn:isbn:0451450523' };
        expect(validate(valid)).toBe(true);
      });

      it('should validate Reference with ref array', () => {
        const valid = {
          ref: [
            { title: 'NIST 800-53', section: 'AC-2' },
            { title: 'CIS Benchmark', section: '5.1' },
          ],
        };
        expect(validate(valid)).toBe(true);
      });

      it('should reject Reference with no recognized field', () => {
        const invalid = { other: 'something' };
        expect(validate(invalid)).toBe(false);
      });
    });

    describe('Source_Location', () => {
      const validate = ajv.compile({
        ...schemaRef(commonSchema, 'Source_Location'),
      });

      it('should validate a valid Source_Location', () => {
        const valid = {
          ref: 'controls/ssh.rb',
          line: 42,
        };
        expect(validate(valid)).toBe(true);
      });

      it('should reject Source_Location with explicit null values', () => {
        const invalid = {
          ref: null,
          line: null,
        };
        expect(validate(invalid)).toBe(false);
      });

      it('should validate empty Source_Location', () => {
        const valid = {};
        expect(validate(valid)).toBe(true);
      });
    });

    describe('Supported_Platform', () => {
      const validate = ajv.compile({
        ...schemaRef(commonSchema, 'Supported_Platform'),
      });

      it('should validate a valid Supported_Platform', () => {
        const valid = {
          'platformFamily': 'redhat',
          'platformName': 'centos',
          release: '8',
        };
        expect(validate(valid)).toBe(true);
      });

      it('should validate Supported_Platform with platform field', () => {
        const valid = {
          platform: 'aws',
        };
        expect(validate(valid)).toBe(true);
      });

      it('should validate empty Supported_Platform', () => {
        const valid = {};
        expect(validate(valid)).toBe(true);
      });

    });

    describe('Identity', () => {
      const validate = ajv.compile({
        ...schemaRef(commonSchema, 'Identity'),
      });

      it('should validate identity with email', () => {
        const valid = {
          identifier: 'user@example.com',
          type: 'email',
        };
        expect(validate(valid)).toBe(true);
      });

      it('should validate identity with system identifier', () => {
        const valid = {
          identifier: 'automated-scanner-01',
          type: 'system',
        };
        expect(validate(valid)).toBe(true);
      });

      it('should validate identity with username type', () => {
        const valid = {
          identifier: 'jdoe',
          type: 'username',
        };
        expect(validate(valid)).toBe(true);
      });

      it('should validate identity with other type and description', () => {
        const valid = {
          identifier: 'custom-id-12345',
          type: 'other',
          description: 'Custom identity system identifier',
        };
        expect(validate(valid)).toBe(true);
      });

      it('should reject identity with explicit null description', () => {
        const invalid = {
          identifier: 'user@example.com',
          type: 'email',
          description: null,
        };
        expect(validate(invalid)).toBe(false);
      });

      it('should reject identity missing required identifier', () => {
        const invalid = {
          type: 'email',
        };
        expect(validate(invalid)).toBe(false);
      });

      it('should reject identity missing required type', () => {
        const invalid = {
          identifier: 'user@example.com',
        };
        expect(validate(invalid)).toBe(false);
      });

      it('should reject identity with invalid type', () => {
        const invalid = {
          identifier: 'test',
          type: 'invalid_type',
        };
        expect(validate(invalid)).toBe(false);
      });
    });

    describe('Verification_Method', () => {
      const validate = ajv.compile({
        ...schemaRef(commonSchema, 'Verification_Method'),
      });

      it('should validate verification method with JWK public key', () => {
        const valid = {
          type: 'JsonWebKey2020',
          controller: 'did:example:123456789abcdefghi',
          publicKeyJwk: {
            kty: 'RSA',
            n: 'xGOr-H7A...',
            e: 'AQAB',
          },
        };
        expect(validate(valid)).toBe(true);
      });

      it('should validate verification method with PEM public key', () => {
        const valid = {
          type: 'RsaVerificationKey2018',
          controller: 'https://example.com/issuer/keys/1',
          publicKeyPem: '-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkq...\n-----END PUBLIC KEY-----',
        };
        expect(validate(valid)).toBe(true);
      });

      it('should validate verification method with Base58 public key', () => {
        const valid = {
          type: 'Ed25519VerificationKey2020',
          controller: 'did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH',
          publicKeyBase58: 'H3C2AVvLMv6gmMNam3uVAjZpfkcJCwDwnZn6z3wXmqPV',
        };
        expect(validate(valid)).toBe(true);
      });

      it('should validate verification method with multiple key formats', () => {
        const valid = {
          type: 'JsonWebKey2020',
          controller: 'https://example.com/keys/1',
          publicKeyJwk: {
            kty: 'EC',
            crv: 'P-256',
            x: 'WKn-ZIGevcwGIyyrzFoZNBdaq9_TsqzGl96oc0CWuis',
            y: 'y77t-RvAHRKTsSGdIYUfweuOvwrvDD-Q3Hv5J0fSKbE',
          },
          publicKeyPem: '-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----',
        };
        expect(validate(valid)).toBe(true);
      });

      it('should reject verification method with explicit null optional fields', () => {
        const invalid = {
          type: 'JsonWebKey2020',
          controller: 'did:example:123',
          publicKeyJwk: null,
          publicKeyPem: null,
          publicKeyBase58: null,
        };
        expect(validate(invalid)).toBe(false);
      });

      it('should reject verification method missing required type', () => {
        const invalid = {
          controller: 'did:example:123',
          publicKeyJwk: { kty: 'RSA' },
        };
        expect(validate(invalid)).toBe(false);
      });

      it('should reject verification method missing required controller', () => {
        const invalid = {
          type: 'JsonWebKey2020',
          publicKeyJwk: { kty: 'RSA' },
        };
        expect(validate(invalid)).toBe(false);
      });

      it('should reject verification method with extra unevaluated properties', () => {
        const invalid = {
          type: 'JsonWebKey2020',
          controller: 'did:example:123',
          publicKeyJwk: { kty: 'RSA' },
          extraField: 'not allowed',
        };
        expect(validate(invalid)).toBe(false);
      });
    });

    describe('Signature', () => {
      const validate = ajv.compile({
        ...schemaRef(commonSchema, 'Signature'),
      });

      it('should validate complete signature with all required fields', () => {
        const valid = {
          type: 'JsonWebSignature2020',
          created: '2025-12-07T15:30:00Z',
          creator: {
            identifier: 'security-team@example.com',
            type: 'email',
          },
          signatureValue: 'eyJhbGciOiJSUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..mPyJAGC4VPTxSt0cHKw',
          proofPurpose: 'attestation',
          verificationMethod: {
            type: 'JsonWebKey2020',
            controller: 'https://example.com/keys/1',
            publicKeyJwk: {
              kty: 'RSA',
              n: 'xGOr-H7A...',
              e: 'AQAB',
            },
          },
        };
        expect(validate(valid)).toBe(true);
      });

      it('should validate signature with RSA verification key', () => {
        const valid = {
          type: 'RsaSignature2018',
          created: '2025-12-07T15:30:00Z',
          creator: {
            identifier: 'yubikey-serial-12345678',
            type: 'system',
            description: 'YubiKey 5C NFC',
          },
          signatureValue: 'base64-encoded-signature-data',
          proofPurpose: 'authentication',
          verificationMethod: {
            type: 'RsaVerificationKey2018',
            controller: 'did:example:org:security',
            publicKeyPem: '-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxGOr...\n-----END PUBLIC KEY-----',
          },
        };
        expect(validate(valid)).toBe(true);
      });

      it('should validate signature with Ed25519 key', () => {
        const valid = {
          type: 'Ed25519Signature2020',
          created: '2025-12-07T15:30:00Z',
          creator: {
            identifier: 'gpg-key-fingerprint-ABCD1234',
            type: 'other',
            description: 'GPG key on hardware token',
          },
          signatureValue: 'base58-encoded-signature',
          proofPurpose: 'assertionMethod',
          verificationMethod: {
            type: 'Ed25519VerificationKey2020',
            controller: 'did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH',
            publicKeyBase58: 'H3C2AVvLMv6gmMNam3uVAjZpfkcJCwDwnZn6z3wXmqPV',
          },
        };
        expect(validate(valid)).toBe(true);
      });

      it('should validate signature with optional nonce', () => {
        const valid = {
          type: 'JsonWebSignature2020',
          created: '2025-12-07T15:30:00Z',
          creator: {
            identifier: 'automated-scanner',
            type: 'system',
          },
          signatureValue: 'signature-data',
          proofPurpose: 'attestation',
          verificationMethod: {
            type: 'JsonWebKey2020',
            controller: 'https://scanner.example.com',
            publicKeyJwk: { kty: 'EC', crv: 'P-256', x: '...', y: '...' },
          },
          nonce: 'random-nonce-12345678',
        };
        expect(validate(valid)).toBe(true);
      });

      it('should validate signature with optional challenge', () => {
        const valid = {
          type: 'JsonWebSignature2020',
          created: '2025-12-07T15:30:00Z',
          creator: {
            identifier: 'auditor@example.com',
            type: 'email',
          },
          signatureValue: 'signature-data',
          proofPurpose: 'authentication',
          verificationMethod: {
            type: 'JsonWebKey2020',
            controller: 'https://example.com/keys/1',
            publicKeyJwk: { kty: 'RSA' },
          },
          challenge: 'challenge-from-verifier-xyz789',
        };
        expect(validate(valid)).toBe(true);
      });

      it('should validate signature with domain restriction', () => {
        const valid = {
          type: 'JsonWebSignature2020',
          created: '2025-12-07T15:30:00Z',
          creator: {
            identifier: 'admin@corp.example.com',
            type: 'email',
          },
          signatureValue: 'signature-data',
          proofPurpose: 'attestation',
          verificationMethod: {
            type: 'JsonWebKey2020',
            controller: 'https://corp.example.com/keys/1',
            publicKeyJwk: { kty: 'RSA' },
          },
          domain: 'corp.example.com',
        };
        expect(validate(valid)).toBe(true);
      });

      it('should reject signature with explicit null optional fields', () => {
        const invalid = {
          type: 'JsonWebSignature2020',
          created: '2025-12-07T15:30:00Z',
          creator: {
            identifier: 'user@example.com',
            type: 'email',
          },
          signatureValue: 'signature-data',
          proofPurpose: 'attestation',
          verificationMethod: {
            type: 'JsonWebKey2020',
            controller: 'https://example.com/keys/1',
            publicKeyJwk: { kty: 'RSA' },
          },
          nonce: null,
          challenge: null,
          domain: null,
        };
        expect(validate(invalid)).toBe(false);
      });

      it('should reject signature missing required type', () => {
        const invalid = {
          created: '2025-12-07T15:30:00Z',
          creator: { identifier: 'user@example.com', type: 'email' },
          signatureValue: 'sig',
          proofPurpose: 'attestation',
          verificationMethod: { type: 'JsonWebKey2020', controller: 'https://example.com' },
        };
        expect(validate(invalid)).toBe(false);
      });

      it('should reject signature missing required created timestamp', () => {
        const invalid = {
          type: 'JsonWebSignature2020',
          creator: { identifier: 'user@example.com', type: 'email' },
          signatureValue: 'sig',
          proofPurpose: 'attestation',
          verificationMethod: { type: 'JsonWebKey2020', controller: 'https://example.com' },
        };
        expect(validate(invalid)).toBe(false);
      });

      it('should reject signature missing required creator', () => {
        const invalid = {
          type: 'JsonWebSignature2020',
          created: '2025-12-07T15:30:00Z',
          signatureValue: 'sig',
          proofPurpose: 'attestation',
          verificationMethod: { type: 'JsonWebKey2020', controller: 'https://example.com' },
        };
        expect(validate(invalid)).toBe(false);
      });

      it('should reject signature missing required signatureValue', () => {
        const invalid = {
          type: 'JsonWebSignature2020',
          created: '2025-12-07T15:30:00Z',
          creator: { identifier: 'user@example.com', type: 'email' },
          proofPurpose: 'attestation',
          verificationMethod: { type: 'JsonWebKey2020', controller: 'https://example.com' },
        };
        expect(validate(invalid)).toBe(false);
      });

      it('should reject signature missing required proofPurpose', () => {
        const invalid = {
          type: 'JsonWebSignature2020',
          created: '2025-12-07T15:30:00Z',
          creator: { identifier: 'user@example.com', type: 'email' },
          signatureValue: 'sig',
          verificationMethod: { type: 'JsonWebKey2020', controller: 'https://example.com' },
        };
        expect(validate(invalid)).toBe(false);
      });

      it('should reject signature missing required verificationMethod', () => {
        const invalid = {
          type: 'JsonWebSignature2020',
          created: '2025-12-07T15:30:00Z',
          creator: { identifier: 'user@example.com', type: 'email' },
          signatureValue: 'sig',
          proofPurpose: 'attestation',
        };
        expect(validate(invalid)).toBe(false);
      });

      it('should reject signature with invalid created timestamp format', () => {
        const invalid = {
          type: 'JsonWebSignature2020',
          created: 'not-a-valid-timestamp',
          creator: { identifier: 'user@example.com', type: 'email' },
          signatureValue: 'sig',
          proofPurpose: 'attestation',
          verificationMethod: { type: 'JsonWebKey2020', controller: 'https://example.com' },
        };
        expect(validate(invalid)).toBe(false);
      });

      it('should reject signature with extra unevaluated properties', () => {
        const invalid = {
          type: 'JsonWebSignature2020',
          created: '2025-12-07T15:30:00Z',
          creator: { identifier: 'user@example.com', type: 'email' },
          signatureValue: 'sig',
          proofPurpose: 'attestation',
          verificationMethod: { type: 'JsonWebKey2020', controller: 'https://example.com', publicKeyJwk: { kty: 'RSA' } },
          extraField: 'not allowed',
        };
        expect(validate(invalid)).toBe(false);
      });
    });

    describe('Evidence', () => {
      const validate = ajv.compile({
        ...schemaRef(commonSchema, 'Evidence'),
      });

      it('should validate screenshot evidence with all fields', () => {
        const valid = {
          type: 'screenshot',
          data: 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==',
          description: 'Screenshot showing compliant configuration',
          mimeType: 'image/png',
          encoding: 'base64',
          size: 1024,
          capturedAt: '2025-12-07T15:30:00Z',
          capturedBy: {
            identifier: 'auditor@example.com',
            type: 'email',
          },
        };
        expect(validate(valid)).toBe(true);
      });

      it('should validate code evidence', () => {
        const valid = {
          type: 'code',
          data: 'const config = { secure: true };',
          description: 'Security configuration code',
          mimeType: 'text/javascript',
          encoding: 'utf-8',
        };
        expect(validate(valid)).toBe(true);
      });

      it('should validate log evidence', () => {
        const valid = {
          type: 'log',
          data: '[2025-12-07 15:30:00] INFO: Security scan completed successfully',
          description: 'Scan completion log',
        };
        expect(validate(valid)).toBe(true);
      });

      it('should validate url evidence', () => {
        const valid = {
          type: 'url',
          data: 'https://github.com/org/repo/blob/main/security-config.yaml',
          description: 'Link to security configuration file',
        };
        expect(validate(valid)).toBe(true);
      });

      it('should validate file evidence', () => {
        const valid = {
          type: 'file',
          data: 'base64-encoded-file-content',
          description: 'Configuration file',
          mimeType: 'application/yaml',
          encoding: 'base64',
          size: 2048,
        };
        expect(validate(valid)).toBe(true);
      });

      it('should validate other evidence type', () => {
        const valid = {
          type: 'other',
          data: 'Custom evidence data',
          description: 'Custom evidence type for specialized use case',
        };
        expect(validate(valid)).toBe(true);
      });

      it('should validate minimal evidence (required fields only)', () => {
        const valid = {
          type: 'screenshot',
          data: 'base64-image-data',
        };
        expect(validate(valid)).toBe(true);
      });

      it('should reject evidence with explicit null optional fields', () => {
        const invalid = {
          type: 'log',
          data: 'log content',
          description: null,
          mimeType: null,
          encoding: null,
          size: null,
          capturedAt: null,
          capturedBy: null,
        };
        expect(validate(invalid)).toBe(false);
      });

      it('should reject evidence missing required type', () => {
        const invalid = {
          data: 'some data',
        };
        expect(validate(invalid)).toBe(false);
      });

      it('should reject evidence missing required data', () => {
        const invalid = {
          type: 'screenshot',
        };
        expect(validate(invalid)).toBe(false);
      });

      it('should reject evidence with invalid type', () => {
        const invalid = {
          type: 'invalid_type',
          data: 'some data',
        };
        expect(validate(invalid)).toBe(false);
      });

      it('should reject evidence with invalid capturedAt format', () => {
        const invalid = {
          type: 'screenshot',
          data: 'base64-data',
          capturedAt: 'not-a-valid-date',
        };
        expect(validate(invalid)).toBe(false);
      });

      it('should reject evidence with extra unevaluated properties', () => {
        const invalid = {
          type: 'screenshot',
          data: 'base64-data',
          extraField: 'not allowed',
        };
        expect(validate(invalid)).toBe(false);
      });
    });

    describe('Milestone', () => {
      const validate = ajv.compile({
        ...schemaRef(commonSchema, 'Milestone'),
      });

      it('should validate minimal pending milestone', () => {
        const valid = {
          description: 'Test patch in staging environment',
          estimatedCompletion: '2025-12-15T00:00:00Z',
          status: 'pending',
        };
        expect(validate(valid)).toBe(true);
      });

      it('should validate in-progress milestone', () => {
        const valid = {
          description: 'Deploy security patch to production',
          estimatedCompletion: '2025-01-10T00:00:00Z',
          status: 'inProgress',
        };
        expect(validate(valid)).toBe(true);
      });

      it('should validate completed milestone with all fields', () => {
        const valid = {
          description: 'Implement network segmentation',
          estimatedCompletion: '2025-01-01T00:00:00Z',
          status: 'completed',
          completedAt: '2025-01-05T14:30:00Z',
          completedBy: {
            identifier: 'ops-team@example.com',
            type: 'email',
          },
        };
        expect(validate(valid)).toBe(true);
      });

      it('should reject completed milestone with explicit null completedBy', () => {
        const invalid = {
          description: 'Review compliance status',
          estimatedCompletion: '2025-01-01T00:00:00Z',
          status: 'completed',
          completedAt: '2025-01-02T10:00:00Z',
          completedBy: null,
        };
        expect(validate(invalid)).toBe(false);
      });

      it('should reject milestone missing required description', () => {
        const invalid = {
          estimatedCompletion: '2025-01-01T00:00:00Z',
          status: 'pending',
        };
        expect(validate(invalid)).toBe(false);
      });

      it('should reject milestone missing required estimatedCompletion', () => {
        const invalid = {
          description: 'Test milestone',
          status: 'pending',
        };
        expect(validate(invalid)).toBe(false);
      });

      it('should reject milestone missing required status', () => {
        const invalid = {
          description: 'Test milestone',
          estimatedCompletion: '2025-01-01T00:00:00Z',
        };
        expect(validate(invalid)).toBe(false);
      });

      it('should reject milestone with invalid status', () => {
        const invalid = {
          description: 'Test milestone',
          estimatedCompletion: '2025-01-01T00:00:00Z',
          status: 'cancelled', // invalid - not in enum
        };
        expect(validate(invalid)).toBe(false);
      });

      it('should reject milestone with extra unevaluated properties', () => {
        const invalid = {
          description: 'Test milestone',
          estimatedCompletion: '2025-01-01T00:00:00Z',
          status: 'pending',
          extraField: 'not allowed',
        };
        expect(validate(invalid)).toBe(false);
      });
    });
  });

  describe('platform.schema.json', () => {
    describe('Platform', () => {
      const validate = ajv.compile({
        ...schemaRef(platformSchema, 'Platform'),
      });

      it('should validate a valid Platform', () => {
        const valid = {
          name: 'ubuntu',
          release: '20.04',
        };
        expect(validate(valid)).toBe(true);
      });

      it('should validate Platform with targetId', () => {
        const valid = {
          name: 'windows',
          release: '10',
          targetId: '21H2',
        };
        expect(validate(valid)).toBe(true);
      });

      it('should reject Platform with explicit null targetId', () => {
        const invalid = {
          name: 'ubuntu',
          release: '20.04',
          targetId: null,
        };
        expect(validate(invalid)).toBe(false);
      });

      it('should reject Platform missing required name', () => {
        const invalid = {
          release: '20.04',
        };
        expect(validate(invalid)).toBe(false);
      });

      it('should reject Platform missing required release', () => {
        const invalid = {
          name: 'ubuntu',
        };
        expect(validate(invalid)).toBe(false);
      });
    });
  });

  describe('target.schema.json', () => {
    const validate = ajv.compile({
      ...schemaRef(targetSchema, 'Target'),
    });

    describe('Host_Target', () => {
      it('should validate a valid host target', () => {
        const valid = {
          type: 'host',
          name: 'web-server-01',
          fqdn: 'web-server-01.example.com',
          ipAddress: '192.168.1.100',
          osName: 'Ubuntu',
          osVersion: '22.04',
        };
        expect(validate(valid)).toBe(true);
      });

      it('should validate minimal host target', () => {
        const valid = {
          type: 'host',
          name: 'server',
        };
        expect(validate(valid)).toBe(true);
      });
    });

    describe('Container_Image_Target', () => {
      it('should validate a valid container image target', () => {
        const valid = {
          type: 'containerImage',
          name: 'nginx:1.25',
          registry: 'docker.io',
          repository: 'library/nginx',
          tag: '1.25',
          digest: 'sha256:' + 'a'.repeat(64),
        };
        expect(validate(valid)).toBe(true);
      });

      it('should validate minimal container image target', () => {
        const valid = {
          type: 'containerImage',
          name: 'my-image',
        };
        expect(validate(valid)).toBe(true);
      });
    });

    describe('Container_Instance_Target', () => {
      it('should validate a valid container instance target', () => {
        const valid = {
          type: 'containerInstance',
          name: 'nginx-abc123',
          containerId: 'abc123def456',
          image: 'nginx:1.25',
          runtime: 'containerd',
        };
        expect(validate(valid)).toBe(true);
      });
    });

    describe('Container_Platform_Target', () => {
      it('should validate a valid container platform target', () => {
        const valid = {
          type: 'containerPlatform',
          name: 'production-cluster',
          platformType: 'kubernetes',
          clusterName: 'prod-k8s',
          namespace: 'default',
          version: '1.28',
        };
        expect(validate(valid)).toBe(true);
      });
    });

    describe('Cloud_Account_Target', () => {
      it('should validate a valid AWS account target', () => {
        const valid = {
          type: 'cloudAccount',
          name: 'Production AWS',
          provider: 'aws',
          accountId: '123456789012',
          region: 'us-east-1',
        };
        expect(validate(valid)).toBe(true);
      });

      it('should validate Azure subscription target', () => {
        const valid = {
          type: 'cloudAccount',
          name: 'Azure Production',
          provider: 'azure',
          accountId: 'subscription-uuid',
        };
        expect(validate(valid)).toBe(true);
      });

      it('should reject invalid provider', () => {
        const invalid = {
          type: 'cloudAccount',
          name: 'Unknown Cloud',
          provider: 'invalid_provider',
        };
        expect(validate(invalid)).toBe(false);
      });
    });

    describe('Cloud_Resource_Target', () => {
      it('should validate a valid cloud resource target', () => {
        const valid = {
          type: 'cloudResource',
          name: 'web-server-ec2',
          provider: 'aws',
          resourceType: 'ec2:instance',
          resourceId: 'i-1234567890abcdef0',
          arn: 'arn:aws:ec2:us-east-1:123456789012:instance/i-1234567890abcdef0',
          region: 'us-east-1',
        };
        expect(validate(valid)).toBe(true);
      });
    });

    describe('Repository_Target', () => {
      it('should validate a valid repository target', () => {
        const valid = {
          type: 'repository',
          name: 'my-app',
          url: 'https://github.com/org/my-app',
          branch: 'main',
          commit: 'abc123def456789',
        };
        expect(validate(valid)).toBe(true);
      });
    });

    describe('Application_Target', () => {
      it('should validate a valid application target', () => {
        const valid = {
          type: 'application',
          name: 'Customer Portal',
          url: 'https://portal.example.com',
          version: '2.5.0',
          environment: 'production',
        };
        expect(validate(valid)).toBe(true);
      });
    });

    describe('Artifact_Target', () => {
      it('should validate a valid artifact target', () => {
        const valid = {
          type: 'artifact',
          name: 'lodash',
          packageManager: 'npm',
          packageName: 'lodash',
          version: '4.17.21',
          checksum: 'sha256:abc123',
        };
        expect(validate(valid)).toBe(true);
      });
    });

    describe('Network_Target', () => {
      it('should validate a valid network target', () => {
        const valid = {
          type: 'network',
          name: 'Corporate LAN',
          cidr: '10.0.0.0/8',
          gateway: '10.0.0.1',
        };
        expect(validate(valid)).toBe(true);
      });
    });

    describe('Database_Target', () => {
      it('should validate a valid database target', () => {
        const valid = {
          type: 'database',
          name: 'Production PostgreSQL',
          engine: 'postgresql',
          version: '15.2',
          host: 'db.example.com',
          port: 5432,
        };
        expect(validate(valid)).toBe(true);
      });
    });

    describe('Target discriminator validation', () => {
      it('should reject target with invalid type', () => {
        const invalid = {
          type: 'invalid_type',
          name: 'something',
        };
        expect(validate(invalid)).toBe(false);
      });

      it('should reject target missing type', () => {
        const invalid = {
          name: 'something',
        };
        expect(validate(invalid)).toBe(false);
      });

      it('should reject target missing name', () => {
        const invalid = {
          type: 'host',
        };
        expect(validate(invalid)).toBe(false);
      });
    });
  });

  describe('runner.schema.json', () => {
    const validate = ajv.compile({
      ...schemaRef(runnerSchema, 'Runner'),
    });

    it('should validate a minimal runner with only name', () => {
      const valid = {
        name: 'ubuntu',
      };
      expect(validate(valid)).toBe(true);
    });

    it('should validate a full runner with all fields', () => {
      const valid = {
        name: 'ubuntu',
        release: '20.04',
        architecture: 'x86_64',
        hostname: 'ci-runner-01',
      };
      expect(validate(valid)).toBe(true);
    });

    it('should validate runner with release only', () => {
      const valid = {
        name: 'macos',
        release: '13.2',
      };
      expect(validate(valid)).toBe(true);
    });

    it('should validate runner with architecture', () => {
      const valid = {
        name: 'ubuntu',
        architecture: 'arm64',
      };
      expect(validate(valid)).toBe(true);
    });

    it('should reject runner missing required name', () => {
      const invalid = {
        release: '20.04',
        architecture: 'x86_64',
      };
      expect(validate(invalid)).toBe(false);
    });

    it('should validate runner with operator (automated system)', () => {
      const valid = {
        name: 'ubuntu',
        release: '20.04',
        operator: {
          identifier: 'jenkins-ci-pipeline',
          type: 'system',
        },
      };
      expect(validate(valid)).toBe(true);
    });

    it('should validate runner with operator (human)', () => {
      const valid = {
        name: 'ubuntu',
        operator: {
          identifier: 'jdoe@example.com',
          type: 'email',
        },
      };
      expect(validate(valid)).toBe(true);
    });

    it('should validate runner with operator (simple manual assessment)', () => {
      const valid = {
        name: 'manual',
        operator: {
          identifier: 'John Doe - Manual DISA Checklist Review',
          type: 'simple',
          description: 'Human auditor completing DISA checklist by hand',
        },
      };
      expect(validate(valid)).toBe(true);
    });

    it('should validate runner without operator field', () => {
      const valid = {
        name: 'ubuntu',
        release: '20.04',
      };
      expect(validate(valid)).toBe(true);
    });

    it('should validate runner with containerImage', () => {
      const valid = {
        name: 'docker',
        containerImage: 'inspec/inspec:latest',
      };
      expect(validate(valid)).toBe(true);
    });

    it('should validate runner with containerId', () => {
      const valid = {
        name: 'docker',
        containerImage: 'inspec/inspec:5.22.3',
        containerId: 'a1b2c3d4e5f6',
      };
      expect(validate(valid)).toBe(true);
    });

    it('should validate runner with full container details', () => {
      const valid = {
        name: 'kubernetes-pod',
        containerImage: 'ghcr.io/my-org/security-scanner:v2.1.0',
        containerId: 'security-scan-job-xyz123',
        hostname: 'k8s-node-worker-03',
        architecture: 'arm64',
        operator: {
          identifier: 'github-actions-ci',
          type: 'system',
        },
      };
      expect(validate(valid)).toBe(true);
    });

    it('should validate containerId without containerImage', () => {
      const valid = {
        name: 'docker',
        containerId: 'running-container-123',
      };
      expect(validate(valid)).toBe(true);
    });
  });

  describe('statistics.schema.json', () => {
    describe('Statistic_Block', () => {
      const validate = ajv.compile({
        ...schemaRef(statisticsSchema, 'Statistic_Block'),
      });

      it('should validate a valid Statistic_Block', () => {
        const valid = { total: 42 };
        expect(validate(valid)).toBe(true);
      });

      it('should reject Statistic_Block missing required total', () => {
        const invalid = {};
        expect(validate(invalid)).toBe(false);
      });

      it('should reject Statistic_Block with non-number total', () => {
        const invalid = { total: 'forty-two' };
        expect(validate(invalid)).toBe(false);
      });
    });

    describe('Statistic_Hash', () => {
      const validate = ajv.compile({
        ...schemaRef(statisticsSchema, 'Statistic_Hash'),
      });

      it('should validate a full Statistic_Hash', () => {
        const valid = {
          passed: { total: 10 },
          failed: { total: 2 },
          notApplicable: { total: 5 },
          notReviewed: { total: 3 },
          error: { total: 0 },
        };
        expect(validate(valid)).toBe(true);
      });

      it('should reject Statistic_Hash with explicit null values', () => {
        const invalid = {
          passed: { total: 10 },
          failed: null,
          notApplicable: null,
          notReviewed: null,
          error: null,
        };
        expect(validate(invalid)).toBe(false);
      });

      it('should validate empty Statistic_Hash', () => {
        const valid = {};
        expect(validate(valid)).toBe(true);
      });

      it('should validate partial Statistic_Hash', () => {
        const valid = {
          passed: { total: 15 },
          failed: { total: 3 },
        };
        expect(validate(valid)).toBe(true);
      });

      it('should reject deprecated skipped field', () => {
        const invalid = {
          passed: { total: 10 },
          skipped: { total: 5 },
        };
        expect(validate(invalid)).toBe(false);
        expect(validate.errors).toBeDefined();
      });
    });

    describe('Statistics', () => {
      const validate = ajv.compile({
        ...schemaRef(statisticsSchema, 'Statistics'),
      });

      it('should validate a full Statistics object', () => {
        const valid = {
          duration: 45.5,
          requirements: {
            passed: { total: 50 },
            failed: { total: 5 },
            notApplicable: { total: 10 },
            notReviewed: { total: 2 },
            error: { total: 1 },
          },
        };
        expect(validate(valid)).toBe(true);
      });

      it('should validate Statistics with only duration', () => {
        const valid = {
          duration: 30.0,
        };
        expect(validate(valid)).toBe(true);
      });

      it('should reject Statistics with explicit null duration', () => {
        const invalid = {
          duration: null,
          requirements: {
            passed: { total: 10 },
          },
        };
        expect(validate(invalid)).toBe(false);
      });

      it('should reject Statistics with explicit null requirements', () => {
        const invalid = {
          duration: 15.5,
          requirements: null,
        };
        expect(validate(invalid)).toBe(false);
      });

      it('should validate empty Statistics', () => {
        const valid = {};
        expect(validate(valid)).toBe(true);
      });
    });
  });

  describe('result.schema.json', () => {
    describe('Result_Status', () => {
      const validate = ajv.compile({
        ...schemaRef(resultSchema, 'Result_Status'),
      });

      it('should validate "passed" status', () => {
        expect(validate('passed')).toBe(true);
      });

      it('should validate "failed" status', () => {
        expect(validate('failed')).toBe(true);
      });

      it('should validate "notApplicable" status', () => {
        expect(validate('notApplicable')).toBe(true);
      });

      it('should validate "notReviewed" status', () => {
        expect(validate('notReviewed')).toBe(true);
      });

      it('should validate "error" status', () => {
        expect(validate('error')).toBe(true);
      });

      it('should reject skipped status', () => {
        expect(validate('skipped')).toBe(false);
      });

      it('should reject invalid status', () => {
        expect(validate('unknown')).toBe(false);
      });
    });

    describe('Requirement_Result', () => {
      const validate = ajv.compile({
        ...schemaRef(resultSchema, 'Requirement_Result'),
      });

      it('should validate a full Requirement_Result', () => {
        const valid = {
          status: 'passed',
          codeDesc: 'File /etc/passwd should exist',
          runTime: 0.005,
          startTime: '2025-01-15T10:30:00Z',
          resource: 'file',
          resourceId: '/etc/passwd',
        };
        expect(validate(valid)).toBe(true);
      });

      it('should reject Requirement_Result without status', () => {
        const invalid = {
          codeDesc: 'Test description',
          startTime: '2025-01-15T10:30:00Z',
        };
        expect(validate(invalid)).toBe(false);
        expect(validate.errors).toMatchObject([
          expect.objectContaining({
            message: expect.stringMatching(/required|missing/i),
            params: expect.objectContaining({ missingProperty: 'status' }),
          }),
        ]);
      });

      it('should validate minimal Requirement_Result', () => {
        const valid = {
          status: 'passed',
          codeDesc: 'Test description',
          startTime: '2025-01-15T10:30:00Z',
        };
        expect(validate(valid)).toBe(true);
      });

      it('should validate Requirement_Result with failed status and message', () => {
        const valid = {
          status: 'failed',
          codeDesc: 'File /etc/secure should have mode 0600',
          startTime: '2025-01-15T10:30:00Z',
          message: 'expected mode to be 0600, got 0644',
        };
        expect(validate(valid)).toBe(true);
      });

      it('should validate Requirement_Result with notReviewed status and message', () => {
        const valid = {
          status: 'notReviewed',
          codeDesc: 'Manual verification required',
          startTime: '2025-01-15T10:30:00Z',
          message: 'This check requires manual verification by an auditor',
        };
        expect(validate(valid)).toBe(true);
      });

      it('should validate Requirement_Result with notApplicable status and message', () => {
        const valid = {
          status: 'notApplicable',
          codeDesc: 'Check for GNOME desktop configuration',
          startTime: '2025-01-15T10:30:00Z',
          message: 'GNOME desktop is not installed, this requirement does not apply',
        };
        expect(validate(valid)).toBe(true);
      });

      it('should validate Requirement_Result with error and backtrace', () => {
        const valid = {
          status: 'error',
          codeDesc: 'Check failed to execute',
          startTime: '2025-01-15T10:30:00Z',
          exception: 'RuntimeError',
          backtrace: ['line1', 'line2', 'line3'],
        };
        expect(validate(valid)).toBe(true);
      });

      it('should reject Requirement_Result missing required codeDesc', () => {
        const invalid = {
          status: 'passed',
          startTime: '2025-01-15T10:30:00Z',
        };
        expect(validate(invalid)).toBe(false);
      });

      it('should reject Requirement_Result missing required startTime', () => {
        const invalid = {
          status: 'passed',
          codeDesc: 'Test description',
        };
        expect(validate(invalid)).toBe(false);
      });

      it('should reject invalid startTime format (date only)', () => {
        const invalid = {
          status: 'passed',
          codeDesc: 'Test description',
          startTime: '2025-01-15',
        };
        expect(validate(invalid)).toBe(false);
      });

      it('should reject invalid startTime format (plain text)', () => {
        const invalid = {
          status: 'passed',
          codeDesc: 'Test description',
          startTime: 'January 15, 2025 at 10:30 AM',
        };
        expect(validate(invalid)).toBe(false);
      });

      it('should reject startTime without timezone', () => {
        const invalid = {
          status: 'passed',
          codeDesc: 'Test description',
          startTime: '2025-01-15T10:30:00',
        };
        expect(validate(invalid)).toBe(false);
      });

      it('should accept startTime with timezone offset', () => {
        const valid = {
          status: 'passed',
          codeDesc: 'Test description',
          startTime: '2025-01-15T10:30:00-05:00',
        };
        expect(validate(valid)).toBe(true);
      });

      it('should accept startTime with milliseconds', () => {
        const valid = {
          status: 'passed',
          codeDesc: 'Test description',
          startTime: '2025-01-15T10:30:00.123Z',
        };
        expect(validate(valid)).toBe(true);
      });
    });

    describe('Requirement_Description', () => {
      const validate = ajv.compile({
        ...schemaRef(resultSchema, 'Requirement_Description'),
      });

      it('should validate a valid Requirement_Description', () => {
        const valid = {
          label: 'fix',
          data: 'Configure the SSH daemon to use only FIPS-approved ciphers.',
        };
        expect(validate(valid)).toBe(true);
      });

      it('should validate check description', () => {
        const valid = {
          label: 'check',
          data: 'Verify the SSH daemon is configured to use FIPS-approved ciphers.',
        };
        expect(validate(valid)).toBe(true);
      });

      it('should reject Requirement_Description missing label', () => {
        const invalid = {
          data: 'Some description text',
        };
        expect(validate(invalid)).toBe(false);
      });

      it('should reject Requirement_Description missing data', () => {
        const invalid = {
          label: 'fix',
        };
        expect(validate(invalid)).toBe(false);
      });
    });
  });

  describe('extensions.schema.json', () => {
    describe('Status_Override', () => {
      const validate = ajv.compile({
        ...schemaRef(extensionsSchema, 'Status_Override'),
      });

      it('should validate a waiver status override with all required fields', () => {
        const valid = {
          type: 'waiver',
          status: 'notApplicable',
          reason: 'Risk accepted by ISSO pending system upgrade',
          appliedBy: {
            identifier: 'isso@example.com',
            type: 'simple',
          },
          appliedAt: '2025-12-05T20:30:00Z',
          expiresAt: '2026-12-05T20:30:00Z',
        };
        expect(validate(valid)).toBe(true);
      });

      it('should validate an attestation status override with all required fields', () => {
        const valid = {
          type: 'attestation',
          status: 'passed',
          reason: 'Manually verified by security team during audit',
          appliedBy: {
            identifier: 'security-team@example.com',
            type: 'simple',
          },
          appliedAt: '2025-12-05T15:30:00Z',
          expiresAt: '2026-12-05T15:30:00Z',
        };
        expect(validate(valid)).toBe(true);
      });

      it('should validate status override with all valid status values (including error)', () => {
        const statuses = ['passed', 'failed', 'notApplicable', 'notReviewed', 'error'];
        statuses.forEach(status => {
          const valid = {
            type: 'attestation',
            status,
            reason: 'Test override',
            appliedBy: {
            identifier: 'test@example.com',
            type: 'simple',
          },
            appliedAt: '2025-12-05T20:30:00Z',
            expiresAt: '2026-12-05T20:30:00Z',
          };
          expect(validate(valid)).toBe(true);
        });
      });

      it('should reject status override missing expiresAt (no permanent overrides)', () => {
        const invalid = {
          type: 'waiver',
          status: 'notApplicable',
          reason: 'Test',
          appliedBy: {
            identifier: 'test@example.com',
            type: 'simple',
          },
          appliedAt: '2025-12-05T20:30:00Z',
          // missing: expiresAt
        };
        expect(validate(invalid)).toBe(false);
      });

      it('should reject status override with null expiresAt (no permanent overrides)', () => {
        const invalid = {
          type: 'waiver',
          status: 'notApplicable',
          reason: 'Test',
          appliedBy: {
            identifier: 'test@example.com',
            type: 'simple',
          },
          appliedAt: '2025-12-05T20:30:00Z',
          expiresAt: null,
        };
        expect(validate(invalid)).toBe(false);
      });

      it('should reject status override missing required fields', () => {
        const invalid = {
          type: 'waiver',
          // missing: status, reason, appliedBy, appliedAt, expiresAt
        };
        expect(validate(invalid)).toBe(false);
      });

      it('should reject status override with invalid type', () => {
        const invalid = {
          type: 'invalid_type', // not a valid override type
          status: 'failed',
          reason: 'Test',
          appliedBy: {
            identifier: 'test@example.com',
            type: 'simple',
          },
          appliedAt: '2025-12-05T20:30:00Z',
          expiresAt: '2026-12-05T20:30:00Z',
        };
        expect(validate(invalid)).toBe(false);
      });

      it('should reject override with invalid status', () => {
        const invalid = {
          type: 'waiver',
          status: 'skipped', // invalid - skipped was removed
          reason: 'Test',
          appliedBy: {
            identifier: 'test@example.com',
            type: 'simple',
          },
          appliedAt: '2025-12-05T20:30:00Z',
          expiresAt: '2026-12-05T20:30:00Z',
        };
        expect(validate(invalid)).toBe(false);
      });

      it('should validate override with evidence array', () => {
        const valid = {
          type: 'attestation',
          status: 'passed',
          reason: 'Manually verified configuration is compliant',
          appliedBy: {
            identifier: 'security-team@example.com',
            type: 'simple',
          },
          appliedAt: '2025-12-07T15:30:00Z',
          expiresAt: '2026-12-07T15:30:00Z',
          evidence: [
            {
              type: 'screenshot',
              data: 'base64-encoded-screenshot',
              description: 'Screenshot showing compliant configuration',
            },
          ],
        };
        expect(validate(valid)).toBe(true);
      });

      it('should validate attestation override with multiple evidence items', () => {
        const valid = {
          type: 'attestation',
          status: 'passed',
          reason: 'Manual verification with documented evidence',
          appliedBy: {
            identifier: 'auditor@example.com',
            type: 'simple',
          },
          appliedAt: '2025-12-07T15:30:00Z',
          expiresAt: '2026-12-07T15:30:00Z',
          evidence: [
            {
              type: 'screenshot',
              data: 'base64-screenshot-data',
              description: 'Configuration interface screenshot',
              mimeType: 'image/png',
              encoding: 'base64',
              size: 2048,
              capturedAt: '2025-12-07T15:30:00Z',
              capturedBy: {
                identifier: 'auditor@example.com',
                type: 'email',
              },
            },
            {
              type: 'code',
              data: 'config { security_enabled = true }',
              description: 'Configuration file snippet',
              mimeType: 'text/plain',
            },
            {
              type: 'url',
              data: 'https://wiki.example.com/security-audit-2025-12-07',
              description: 'Link to audit documentation',
            },
          ],
        };
        expect(validate(valid)).toBe(true);
      });

      it('should reject override with explicit null evidence', () => {
        const invalid = {
          type: 'waiver',
          status: 'notApplicable',
          reason: 'Control not applicable to this system',
          appliedBy: {
            identifier: 'isso@example.com',
            type: 'simple',
          },
          appliedAt: '2025-12-07T15:30:00Z',
          expiresAt: '2026-12-07T15:30:00Z',
          evidence: null,
        };
        expect(validate(invalid)).toBe(false);
      });

      it('should validate override with empty evidence array', () => {
        const valid = {
          type: 'attestation',
          status: 'passed',
          reason: 'Verified but no evidence captured',
          appliedBy: {
            identifier: 'auditor@example.com',
            type: 'simple',
          },
          appliedAt: '2025-12-07T15:30:00Z',
          expiresAt: '2026-12-07T15:30:00Z',
          evidence: [],
        };
        expect(validate(valid)).toBe(true);
      });

      it('should validate override with digital signature object', () => {
        const valid = {
          type: 'waiver',
          status: 'notApplicable',
          reason: 'Risk accepted by CISO',
          appliedBy: {
            identifier: 'ciso@example.com',
            type: 'simple',
          },
          appliedAt: '2025-12-07T15:30:00Z',
          expiresAt: '2027-12-07T15:30:00Z',
          signature: {
            type: 'JsonWebSignature2020',
            created: '2025-12-07T15:30:00Z',
            creator: {
              identifier: 'ciso@example.com',
              type: 'email',
            },
            signatureValue: 'eyJhbGciOiJSUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..sig',
            proofPurpose: 'attestation',
            verificationMethod: {
              type: 'JsonWebKey2020',
              controller: 'https://example.com/ciso/keys/1',
              publicKeyJwk: {
                kty: 'RSA',
                n: 'xGOr-H7A...',
                e: 'AQAB',
              },
            },
          },
        };
        expect(validate(valid)).toBe(true);
      });

      it('should validate override with Yubikey hardware signature', () => {
        const valid = {
          type: 'attestation',
          status: 'passed',
          reason: 'Manually verified with hardware token',
          appliedBy: {
            identifier: 'security-auditor@example.com',
            type: 'simple',
          },
          appliedAt: '2025-12-07T15:30:00Z',
          expiresAt: '2026-12-07T15:30:00Z',
          signature: {
            type: 'RsaSignature2018',
            created: '2025-12-07T15:30:00Z',
            creator: {
              identifier: 'yubikey-serial-87654321',
              type: 'system',
              description: 'YubiKey 5 NFC - Security Team',
            },
            signatureValue: 'base64-encoded-signature-from-yubikey',
            proofPurpose: 'authentication',
            verificationMethod: {
              type: 'RsaVerificationKey2018',
              controller: 'https://pki.example.com/yubikey/87654321',
              publicKeyPem: '-----BEGIN PUBLIC KEY-----\nMIIBIjAN...\n-----END PUBLIC KEY-----',
            },
          },
        };
        expect(validate(valid)).toBe(true);
      });

      it('should validate override with GPG signature', () => {
        const valid = {
          type: 'waiver',
          status: 'notApplicable',
          reason: 'Exception granted by security team',
          appliedBy: {
            identifier: 'gpg:ABCD1234EFGH5678',
            type: 'simple',
          },
          appliedAt: '2025-12-07T15:30:00Z',
          expiresAt: '2026-12-07T15:30:00Z',
          signature: {
            type: 'Ed25519Signature2020',
            created: '2025-12-07T15:30:00Z',
            creator: {
              identifier: 'ABCD1234EFGH5678',
              type: 'other',
              description: 'GPG key fingerprint',
            },
            signatureValue: 'base58-gpg-signature',
            proofPurpose: 'attestation',
            verificationMethod: {
              type: 'Ed25519VerificationKey2020',
              controller: 'gpg:ABCD1234EFGH5678',
              publicKeyBase58: 'H3C2AVvLMv6gmMNam3uVAjZpfkcJCwDwnZn6z3wXmqPV',
            },
          },
        };
        expect(validate(valid)).toBe(true);
      });

      it('should validate override with signature containing nonce for replay protection', () => {
        const valid = {
          type: 'attestation',
          status: 'passed',
          reason: 'Verified in secure environment',
          appliedBy: {
            identifier: 'security-team@example.com',
            type: 'simple',
          },
          appliedAt: '2025-12-07T15:30:00Z',
          expiresAt: '2026-12-07T15:30:00Z',
          signature: {
            type: 'JsonWebSignature2020',
            created: '2025-12-07T15:30:00Z',
            creator: {
              identifier: 'security-team@example.com',
              type: 'email',
            },
            signatureValue: 'signature-data',
            proofPurpose: 'attestation',
            verificationMethod: {
              type: 'JsonWebKey2020',
              controller: 'https://example.com/keys/1',
              publicKeyJwk: { kty: 'RSA' },
            },
            nonce: 'random-nonce-abc123xyz789',
            domain: 'example.com',
          },
        };
        expect(validate(valid)).toBe(true);
      });

      it('should reject override with explicit null signature (backward compatibility)', () => {
        const invalid = {
          type: 'waiver',
          status: 'notApplicable',
          reason: 'Not applicable to this system',
          appliedBy: {
            identifier: 'isso@example.com',
            type: 'simple',
          },
          appliedAt: '2025-12-07T15:30:00Z',
          expiresAt: '2026-12-07T15:30:00Z',
          signature: null,
        };
        expect(validate(invalid)).toBe(false);
      });

      it('should validate override with appliedBy as Identity object', () => {
        const valid = {
          type: 'waiver',
          status: 'notApplicable',
          reason: 'Risk accepted by ISSO',
          appliedBy: {
            identifier: 'isso@example.com',
            type: 'email',
            description: 'Information System Security Officer',
          },
          appliedAt: '2025-12-07T15:30:00Z',
          expiresAt: '2026-12-07T15:30:00Z',
        };
        expect(validate(valid)).toBe(true);
      });

      it('should validate override with appliedBy as simple string', () => {
        const valid = {
          type: 'attestation',
          status: 'passed',
          reason: 'Manually verified',
          appliedBy: {
            identifier: 'auditor@example.com',
            type: 'simple',
          },
          appliedAt: '2025-12-07T15:30:00Z',
          expiresAt: '2026-12-07T15:30:00Z',
        };
        expect(validate(valid)).toBe(true);
      });

      it('should validate override with previousChecksum (for amendment chain)', () => {
        const valid = {
          type: 'waiver',
          status: 'notApplicable',
          reason: 'Risk accepted',
          appliedBy: {
            identifier: 'isso@example.com',
            type: 'simple',
          },
          appliedAt: '2025-12-07T16:00:00Z',
          expiresAt: '2026-12-07T16:00:00Z',
          previousChecksum: {
            algorithm: 'sha256',
            value: 'abc123def456...',
          },
        };
        expect(validate(valid)).toBe(true);
      });

      it('should reject override with explicit null previousChecksum (first amendment)', () => {
        const invalid = {
          type: 'waiver',
          status: 'notApplicable',
          reason: 'First override, no previous amendment',
          appliedBy: {
            identifier: 'isso@example.com',
            type: 'simple',
          },
          appliedAt: '2025-12-07T16:00:00Z',
          expiresAt: '2026-12-07T16:00:00Z',
          previousChecksum: null,
        };
        expect(validate(invalid)).toBe(false);
      });
    });

    describe('Generator', () => {
      const validate = ajv.compile({
        ...schemaRef(extensionsSchema, 'Generator'),
      });

      it('should validate a valid Generator', () => {
        const valid = {
          name: 'Chef InSpec',
          version: '5.22.3',
        };
        expect(validate(valid)).toBe(true);
      });

      it('should validate Generator with different tool', () => {
        const valid = {
          name: 'Heimdall',
          version: '2.10.0',
        };
        expect(validate(valid)).toBe(true);
      });

      it('should reject Generator missing required name', () => {
        const invalid = {
          version: '1.0.0',
        };
        expect(validate(invalid)).toBe(false);
      });

      it('should reject Generator missing required version', () => {
        const invalid = {
          name: 'SomeTool',
        };
        expect(validate(invalid)).toBe(false);
      });
    });

    describe('POAM', () => {
      const validate = ajv.compile({
        ...schemaRef(extensionsSchema, 'POAM'),
      });

      it('should validate minimal remediation POAM', () => {
        const valid = {
          type: 'remediation',
          explanation: 'Security patch scheduled for deployment to production environment',
          appliedBy: {
            identifier: 'ops-team@example.com',
            type: 'simple',
          },
          appliedAt: '2025-12-01T10:00:00Z',
          expiresAt: '2099-12-31T00:00:00Z',
        };
        expect(validate(valid)).toBe(true);
      });

      it('should validate mitigation POAM with milestones', () => {
        const valid = {
          type: 'mitigation',
          explanation: 'Implemented network segmentation as compensating control while awaiting vendor patch',
          appliedBy: {
            identifier: 'network-team@example.com',
            type: 'simple',
          },
          appliedAt: '2025-12-01T10:00:00Z',
          expiresAt: '2099-12-31T00:00:00Z',
          milestones: [
            {
              description: 'Configure firewall rules to isolate affected system',
              estimatedCompletion: '2025-12-05T00:00:00Z',
              status: 'completed',
              completedAt: '2025-12-04T14:30:00Z',
              completedBy: {
                identifier: 'network-admin@example.com',
                type: 'email',
              },
            },
            {
              description: 'Deploy vendor patch when available',
              estimatedCompletion: '2026-01-15T00:00:00Z',
              status: 'pending',
            },
          ],
        };
        expect(validate(valid)).toBe(true);
      });

      it('should validate riskAcceptance POAM with signature', () => {
        const valid = {
          type: 'riskAcceptance',
          explanation: 'Risk formally accepted by CISO pending system decommission in Q2',
          appliedBy: {
            identifier: 'ciso@example.com',
            type: 'simple',
          },
          appliedAt: '2025-12-07T10:00:00Z',
          expiresAt: '2026-06-30T00:00:00Z',
          signature: {
            type: 'JsonWebSignature2020',
            created: '2025-12-07T10:00:00Z',
            creator: {
              identifier: 'ciso@example.com',
              type: 'email',
            },
            signatureValue: 'base64-signature-value',
            proofPurpose: 'attestation',
            verificationMethod: {
              type: 'JsonWebKey2020',
              controller: 'did:example:ciso',
              publicKeyJwk: {
                kty: 'RSA',
                n: 'exampleKey',
              },
            },
          },
        };
        expect(validate(valid)).toBe(true);
      });

      it('should validate POAM with evidence array', () => {
        const valid = {
          type: 'mitigation',
          explanation: 'Compensating controls implemented - network segmentation and enhanced monitoring',
          appliedBy: {
            identifier: 'security-team@example.com',
            type: 'simple',
          },
          appliedAt: '2025-12-07T10:00:00Z',
          expiresAt: '2099-12-31T00:00:00Z',
          evidence: [
            {
              type: 'file',
              data: 'base64-firewall-rules',
              description: 'Firewall configuration showing network segmentation',
              mimeType: 'text/plain',
            },
            {
              type: 'screenshot',
              data: 'base64-screenshot',
              description: 'SIEM dashboard showing enhanced monitoring',
              mimeType: 'image/png',
            },
          ],
        };
        expect(validate(valid)).toBe(true);
      });

      it('should validate POAM with expiresAt', () => {
        const valid = {
          type: 'remediation',
          explanation: 'Patch deployment requires change control approval',
          appliedBy: {
            identifier: 'ops@example.com',
            type: 'simple',
          },
          appliedAt: '2025-12-01T10:00:00Z',
          expiresAt: '2025-12-31T00:00:00Z',
        };
        expect(validate(valid)).toBe(true);
      });

      it('should reject POAM with explicit null expiresAt', () => {
        const invalid = {
          type: 'remediation',
          explanation: 'Long-term remediation effort with no fixed deadline',
          appliedBy: {
            identifier: 'ops@example.com',
            type: 'simple',
          },
          appliedAt: '2025-12-01T10:00:00Z',
          expiresAt: null,
        };
        expect(validate(invalid)).toBe(false);
      });

      it('should reject POAM with explicit null milestones', () => {
        const invalid = {
          type: 'remediation',
          explanation: 'Simple remediation with no milestone tracking',
          appliedBy: {
            identifier: 'ops@example.com',
            type: 'simple',
          },
          appliedAt: '2025-12-01T10:00:00Z',
          milestones: null,
        };
        expect(validate(invalid)).toBe(false);
      });

      it('should reject POAM missing required explanation', () => {
        const invalid = {
          type: 'remediation',
          appliedBy: {
            identifier: 'ops@example.com',
            type: 'simple',
          },
          appliedAt: '2025-12-01T10:00:00Z',
        };
        expect(validate(invalid)).toBe(false);
      });

      it('should reject POAM missing required appliedBy', () => {
        const invalid = {
          type: 'remediation',
          explanation: 'Test',
          appliedAt: '2025-12-01T10:00:00Z',
        };
        expect(validate(invalid)).toBe(false);
      });

      it('should reject POAM missing required appliedAt', () => {
        const invalid = {
          type: 'remediation',
          explanation: 'Test',
          appliedBy: {
            identifier: 'ops@example.com',
            type: 'simple',
          },
        };
        expect(validate(invalid)).toBe(false);
      });

      it('should reject POAM with invalid type', () => {
        const invalid = {
          type: 'exception', // invalid - not a POAM type
          explanation: 'Test',
          appliedBy: {
            identifier: 'ops@example.com',
            type: 'simple',
          },
          appliedAt: '2025-12-01T10:00:00Z',
        };
        expect(validate(invalid)).toBe(false);
      });

      it('should reject POAM with extra unevaluated properties', () => {
        const invalid = {
          type: 'remediation',
          explanation: 'Test',
          appliedBy: {
            identifier: 'ops@example.com',
            type: 'simple',
          },
          appliedAt: '2025-12-01T10:00:00Z',
          extraField: 'not allowed',
        };
        expect(validate(invalid)).toBe(false);
      });

      it('should validate POAM with previousChecksum (for amendment chain)', () => {
        const valid = {
          type: 'remediation',
          explanation: 'Second POAM, referencing previous mitigation',
          appliedBy: {
            identifier: 'ops@example.com',
            type: 'simple',
          },
          appliedAt: '2025-12-07T16:00:00Z',
          expiresAt: '2099-12-31T00:00:00Z',
          previousChecksum: {
            algorithm: 'sha256',
            value: 'xyz789abc012...',
          },
        };
        expect(validate(valid)).toBe(true);
      });

      it('should reject POAM with explicit null previousChecksum (first amendment)', () => {
        const invalid = {
          type: 'remediation',
          explanation: 'First POAM, no previous amendment',
          appliedBy: {
            identifier: 'ops@example.com',
            type: 'simple',
          },
          appliedAt: '2025-12-07T16:00:00Z',
          previousChecksum: null,
        };
        expect(validate(invalid)).toBe(false);
      });
    });

    describe('Integrity', () => {
      const validate = ajv.compile({
        ...schemaRef(extensionsSchema, 'Integrity'),
      });

      it('should validate Integrity with sha256', () => {
        const valid = {
          algorithm: 'sha256',
          checksum: 'abc123def456789...',
        };
        expect(validate(valid)).toBe(true);
      });

      it('should validate Integrity with sha512 and signature', () => {
        const valid = {
          algorithm: 'sha512',
          checksum: 'abc123def456789...',
          signature: 'base64-encoded-signature',
          signedBy: 'security-team@example.com',
        };
        expect(validate(valid)).toBe(true);
      });

      it('should reject Integrity with explicit null optional fields', () => {
        const invalid = {
          algorithm: 'sha384',
          checksum: 'abc123...',
          signature: null,
          signedBy: null,
        };
        expect(validate(invalid)).toBe(false);
      });

      it('should validate empty Integrity', () => {
        const valid = {};
        expect(validate(valid)).toBe(true);
      });

      it('should reject Integrity with invalid algorithm', () => {
        const invalid = {
          algorithm: 'md5',
          checksum: 'abc123',
        };
        expect(validate(invalid)).toBe(false);
      });

      it('should reject Integrity with algorithm but no checksum', () => {
        const invalid = {
          algorithm: 'sha256',
        };
        expect(validate(invalid)).toBe(false);
      });

      it('should reject Integrity with checksum but no algorithm', () => {
        const invalid = {
          checksum: 'abc123def456',
        };
        expect(validate(invalid)).toBe(false);
      });
    });
  });

  describe('Date-Time Format Validation', () => {
    describe('Milestone timestamps', () => {
      const validate = ajv.compile({
        ...schemaRef(commonSchema, 'Milestone'),
      });

      it('should accept valid ISO 8601 date-time for estimatedCompletion', () => {
        const valid = {
          description: 'Fix critical vulnerability',
          estimatedCompletion: '2025-12-15T14:30:00Z',
          status: 'pending',
        };
        expect(validate(valid)).toBe(true);
      });

      it('should accept ISO 8601 with timezone offset', () => {
        const valid = {
          description: 'Deploy patch',
          estimatedCompletion: '2025-12-15T14:30:00-05:00',
          status: 'pending',
        };
        expect(validate(valid)).toBe(true);
      });

      it('should accept ISO 8601 with milliseconds', () => {
        const valid = {
          description: 'Complete testing',
          estimatedCompletion: '2025-12-15T14:30:00.123Z',
          status: 'completed',
          completedAt: '2025-12-14T10:00:00.456Z',
        };
        expect(validate(valid)).toBe(true);
      });

      it('should reject invalid date-time format for estimatedCompletion', () => {
        const invalid = {
          description: 'Fix vulnerability',
          estimatedCompletion: '2025-12-15',
          status: 'pending',
        };
        expect(validate(invalid)).toBe(false);
      });

      it('should reject plain text date', () => {
        const invalid = {
          description: 'Deploy update',
          estimatedCompletion: 'December 15, 2025',
          status: 'pending',
        };
        expect(validate(invalid)).toBe(false);
      });

      it('should reject timestamp without timezone', () => {
        const invalid = {
          description: 'Test fix',
          estimatedCompletion: '2025-12-15T14:30:00',
          status: 'pending',
        };
        expect(validate(invalid)).toBe(false);
      });

      it('should reject invalid completedAt format', () => {
        const invalid = {
          description: 'Complete milestone',
          estimatedCompletion: '2025-12-15T14:30:00Z',
          status: 'completed',
          completedAt: '12/14/2025',
        };
        expect(validate(invalid)).toBe(false);
      });
    });

    describe('Status_Override timestamps', () => {
      const validate = ajv.compile({
        ...schemaRef(extensionsSchema, 'Status_Override'),
      });

      it('should accept valid ISO 8601 timestamps', () => {
        const valid = {
          type: 'waiver',
          status: 'passed',
          reason: 'Compensating controls in place',
          appliedBy: { identifier: 'john.doe@example.com', type: 'email' },
          appliedAt: '2025-12-14T10:00:00Z',
          expiresAt: '2026-12-14T10:00:00Z',
        };
        expect(validate(valid)).toBe(true);
      });

      it('should reject invalid appliedAt format', () => {
        const invalid = {
          type: 'waiver',
          status: 'passed',
          reason: 'Approved',
          appliedBy: { identifier: 'admin', type: 'username' },
          appliedAt: 'yesterday',
          expiresAt: '2026-12-14T10:00:00Z',
        };
        expect(validate(invalid)).toBe(false);
      });

      it('should reject invalid expiresAt format', () => {
        const invalid = {
          type: 'attestation',
          status: 'passed',
          reason: 'Manual verification',
          appliedBy: { identifier: 'admin', type: 'username' },
          appliedAt: '2025-12-14T10:00:00Z',
          expiresAt: '12/14/2026',
        };
        expect(validate(invalid)).toBe(false);
      });
    });

    describe('POAM timestamps', () => {
      const validate = ajv.compile({
        ...schemaRef(extensionsSchema, 'POAM'),
      });

      it('should accept valid ISO 8601 timestamps', () => {
        const valid = {
          type: 'remediation',
          explanation: 'Deploy security patch to fix CVE-2025-12345',
          appliedBy: { identifier: 'security.team@example.com', type: 'email' },
          appliedAt: '2025-12-14T10:00:00Z',
          expiresAt: '2099-12-31T00:00:00Z',
        };
        expect(validate(valid)).toBe(true);
      });

      it('should accept nullable expiresAt with valid format', () => {
        const valid = {
          type: 'mitigation',
          explanation: 'Implement compensating controls until patch is available',
          appliedBy: { identifier: 'admin', type: 'username' },
          appliedAt: '2025-12-14T10:00:00Z',
          expiresAt: '2026-06-14T10:00:00Z',
        };
        expect(validate(valid)).toBe(true);
      });

      it('should reject explicit null expiresAt', () => {
        const invalid = {
          type: 'riskAcceptance',
          explanation: 'Accept low-risk finding based on CISO decision',
          appliedBy: { identifier: 'ciso', type: 'username' },
          appliedAt: '2025-12-14T10:00:00Z',
          expiresAt: null,
        };
        expect(validate(invalid)).toBe(false);
      });

      it('should reject invalid appliedAt format', () => {
        const invalid = {
          type: 'remediation',
          explanation: 'Fix critical security issue',
          appliedBy: { identifier: 'dev', type: 'username' },
          appliedAt: 'not-a-date',
          expiresAt: null,
        };
        expect(validate(invalid)).toBe(false);
      });

      it('should reject invalid expiresAt format when provided', () => {
        const invalid = {
          type: 'remediation',
          explanation: 'Deploy security fix to all production servers',
          appliedBy: { identifier: 'ops', type: 'username' },
          appliedAt: '2025-12-14T10:00:00Z',
          expiresAt: 'sometime next year',
        };
        expect(validate(invalid)).toBe(false);
      });
    });

    describe('Signature created timestamp', () => {
      const validate = ajv.compile({
        ...schemaRef(commonSchema, 'Signature'),
      });

      it('should accept valid ISO 8601 created timestamp', () => {
        const valid = {
          type: 'JsonWebSignature2020',
          created: '2025-12-14T10:00:00Z',
          creator: { identifier: 'signer@example.com', type: 'email' },
          signatureValue: 'base64-signature-value',
          proofPurpose: 'attestation',
          verificationMethod: {
            type: 'JsonWebKey2020',
            controller: 'did:example:123',
            publicKeyJwk: { kty: 'RSA', n: 'abc', e: 'AQAB' },
          },
        };
        expect(validate(valid)).toBe(true);
      });

      it('should reject invalid created timestamp format', () => {
        const invalid = {
          type: 'JsonWebSignature2020',
          created: '2025-12-14',
          creator: { identifier: 'signer@example.com', type: 'email' },
          signatureValue: 'sig-value',
          proofPurpose: 'attestation',
          verificationMethod: {
            type: 'JsonWebKey2020',
            controller: 'did:example:123',
            publicKeyJwk: { kty: 'RSA', n: 'abc', e: 'AQAB' },
          },
        };
        expect(validate(invalid)).toBe(false);
      });
    });

    describe('Evidence capturedAt timestamp', () => {
      const validate = ajv.compile({
        ...schemaRef(commonSchema, 'Evidence'),
      });

      it('should accept valid ISO 8601 capturedAt timestamp', () => {
        const valid = {
          type: 'screenshot',
          data: 'base64-encoded-image',
          capturedAt: '2025-12-14T10:30:00Z',
        };
        expect(validate(valid)).toBe(true);
      });

      it('should reject explicit null capturedAt', () => {
        const invalid = {
          type: 'screenshot',
          data: 'base64-data',
          capturedAt: null,
        };
        expect(validate(invalid)).toBe(false);
      });

      it('should reject invalid capturedAt format', () => {
        const invalid = {
          type: 'screenshot',
          data: 'base64-data',
          capturedAt: 'today at noon',
        };
        expect(validate(invalid)).toBe(false);
      });
    });
  });

  describe('Array and Numeric Constraints', () => {
    // Note: results and descriptions arrays are in hdf-results.schema.json (Evaluated_Requirement)
    // Those tests are in hdf-results.test.ts

    describe('Statistics numeric constraints', () => {
      const validate = ajv.compile({
        ...schemaRef(statisticsSchema, 'Statistics'),
      });

      it('should accept valid statistics with positive duration', () => {
        const valid = {
          duration: 123.45,
        };
        expect(validate(valid)).toBe(true);
      });

      it('should accept duration of zero', () => {
        const valid = {
          duration: 0,
        };
        expect(validate(valid)).toBe(true);
      });

      it('should reject negative duration', () => {
        const invalid = {
          duration: -10.5,
        };
        expect(validate(invalid)).toBe(false);
        expect(validate.errors).toContainEqual(
          expect.objectContaining({
            keyword: 'minimum',
          })
        );
      });

      it('should accept integer total count', () => {
        const valid = {
          duration: 1.0,
          requirements: {
            passed: { total: 50 },
          },
        };
        expect(validate(valid)).toBe(true);
      });

      it('should reject negative total count', () => {
        const invalid = {
          duration: 1.0,
          requirements: {
            passed: { total: -5 },
          },
        };
        expect(validate(invalid)).toBe(false);
      });

      it('should reject non-integer total count', () => {
        const invalid = {
          duration: 1.0,
          requirements: {
            passed: { total: 50.5 },
          },
        };
        expect(validate(invalid)).toBe(false);
        expect(validate.errors).toContainEqual(
          expect.objectContaining({
            keyword: 'type',
          })
        );
      });
    });

    describe('Requirement_Result runTime constraint', () => {
      const validate = ajv.compile({
        ...schemaRef(resultSchema, 'Requirement_Result'),
      });

      it('should accept positive runTime', () => {
        const valid = {
          status: 'passed',
          codeDesc: 'Test check',
          startTime: '2025-01-15T10:00:00Z',
          runTime: 1.234,
        };
        expect(validate(valid)).toBe(true);
      });

      it('should accept zero runTime', () => {
        const valid = {
          status: 'passed',
          codeDesc: 'Test check',
          startTime: '2025-01-15T10:00:00Z',
          runTime: 0,
        };
        expect(validate(valid)).toBe(true);
      });

      it('should reject negative runTime', () => {
        const invalid = {
          status: 'passed',
          codeDesc: 'Test check',
          startTime: '2025-01-15T10:00:00Z',
          runTime: -5.0,
        };
        expect(validate(invalid)).toBe(false);
        expect(validate.errors).toContainEqual(
          expect.objectContaining({
            keyword: 'minimum',
          })
        );
      });
    });

    describe('Database_Target port constraint', () => {
      const validate = ajv.compile({
        ...schemaRef(targetSchema, 'Database_Target'),
      });

      it('should accept valid port number', () => {
        const valid = {
          type: 'database',
          name: 'prod-db',
          engine: 'postgresql',
          port: 5432,
        };
        expect(validate(valid)).toBe(true);
      });

      it('should accept minimum valid port (1)', () => {
        const valid = {
          type: 'database',
          name: 'test-db',
          engine: 'mysql',
          port: 1,
        };
        expect(validate(valid)).toBe(true);
      });

      it('should accept maximum valid port (65535)', () => {
        const valid = {
          type: 'database',
          name: 'mongo-db',
          engine: 'mongodb',
          port: 65535,
        };
        expect(validate(valid)).toBe(true);
      });

      it('should reject port 0', () => {
        const invalid = {
          type: 'database',
          name: 'invalid-db',
          engine: 'postgresql',
          port: 0,
        };
        expect(validate(invalid)).toBe(false);
        expect(validate.errors).toContainEqual(
          expect.objectContaining({
            keyword: 'minimum',
          })
        );
      });

      it('should reject port above 65535', () => {
        const invalid = {
          type: 'database',
          name: 'invalid-db',
          engine: 'postgresql',
          port: 70000,
        };
        expect(validate(invalid)).toBe(false);
        expect(validate.errors).toContainEqual(
          expect.objectContaining({
            keyword: 'maximum',
          })
        );
      });
    });
  });

  describe('Format Pattern Validation', () => {
    describe('Container digest patterns', () => {
      const validate = ajv.compile({
        ...schemaRef(targetSchema, 'Container_Image_Target'),
      });

      it('should accept valid sha256 digest', () => {
        const valid = {
          type: 'containerImage',
          name: 'nginx',
          digest: 'sha256:' + 'a'.repeat(64),
        };
        expect(validate(valid)).toBe(true);
      });

      it('should accept valid sha512 digest', () => {
        const valid = {
          type: 'containerImage',
          name: 'nginx',
          digest: 'sha512:' + 'b'.repeat(128),
        };
        expect(validate(valid)).toBe(true);
      });

      it('should accept valid blake3 digest', () => {
        const valid = {
          type: 'containerImage',
          name: 'nginx',
          digest: 'blake3:' + 'c'.repeat(64),
        };
        expect(validate(valid)).toBe(true);
      });

      it('should reject digest with invalid algorithm', () => {
        const invalid = {
          type: 'containerImage',
          name: 'nginx',
          digest: 'md5:' + 'a'.repeat(32),
        };
        expect(validate(invalid)).toBe(false);
        expect(validate.errors).toContainEqual(
          expect.objectContaining({
            keyword: 'pattern',
          })
        );
      });

      it('should reject digest with wrong hash length for sha256', () => {
        const invalid = {
          type: 'containerImage',
          name: 'nginx',
          digest: 'sha256:' + 'a'.repeat(32), // Too short
        };
        expect(validate(invalid)).toBe(false);
      });

      it('should reject digest with uppercase hex chars', () => {
        const invalid = {
          type: 'containerImage',
          name: 'nginx',
          digest: 'sha256:' + 'A'.repeat(64), // Uppercase not allowed per OCI spec
        };
        expect(validate(invalid)).toBe(false);
      });
    });

    describe('MAC address pattern', () => {
      const validate = ajv.compile({
        ...schemaRef(targetSchema, 'Host_Target'),
      });

      it('should accept valid MAC address (uppercase)', () => {
        const valid = {
          type: 'host',
          name: 'server-01',
          hostname: 'server-01',
          macAddress: '00:1A:2B:3C:4D:5E',
        };
        expect(validate(valid)).toBe(true);
      });

      it('should accept valid MAC address (mixed case)', () => {
        const valid = {
          type: 'host',
          name: 'server-02',
          hostname: 'server-02',
          macAddress: 'aA:bB:cC:dD:eE:fF',
        };
        expect(validate(valid)).toBe(true);
      });

      it('should reject MAC address with invalid format (hyphens)', () => {
        const invalid = {
          type: 'host',
          name: 'server-03',
          hostname: 'server-03',
          macAddress: '00-1A-2B-3C-4D-5E',
        };
        expect(validate(invalid)).toBe(false);
      });

      it('should reject MAC address with wrong length', () => {
        const invalid = {
          type: 'host',
          name: 'server-04',
          hostname: 'server-04',
          macAddress: '00:1A:2B:3C:4D',
        };
        expect(validate(invalid)).toBe(false);
      });

      it('should reject MAC address with invalid hex characters', () => {
        const invalid = {
          type: 'host',
          name: 'server-05',
          hostname: 'server-05',
          macAddress: '00:1G:2B:3C:4D:5E',
        };
        expect(validate(invalid)).toBe(false);
      });
    });

    describe('IP address format', () => {
      const validate = ajv.compile({
        ...schemaRef(targetSchema, 'Host_Target'),
      });

      it('should accept valid IPv4 address', () => {
        const valid = {
          type: 'host',
          name: 'web-server',
          hostname: 'web-server.example.com',
          ipAddress: '192.168.1.100',
        };
        expect(validate(valid)).toBe(true);
      });

      it('should accept valid IPv6 address', () => {
        const valid = {
          type: 'host',
          name: 'db-server',
          hostname: 'db-server.example.com',
          ipAddress: '2001:0db8:85a3:0000:0000:8a2e:0370:7334',
        };
        expect(validate(valid)).toBe(true);
      });

      it('should accept compressed IPv6 address', () => {
        const valid = {
          type: 'host',
          name: 'app-server',
          hostname: 'app-server.example.com',
          ipAddress: '2001:db8::1',
        };
        expect(validate(valid)).toBe(true);
      });

      it('should reject invalid IP address', () => {
        const invalid = {
          type: 'host',
          name: 'bad-server',
          hostname: 'bad-server.example.com',
          ipAddress: '999.999.999.999',
        };
        expect(validate(invalid)).toBe(false);
      });

      it('should reject malformed IP address', () => {
        const invalid = {
          type: 'host',
          name: 'invalid-server',
          hostname: 'invalid-server.example.com',
          ipAddress: 'not-an-ip',
        };
        expect(validate(invalid)).toBe(false);
      });
    });

    describe('Git URI format', () => {
      const validate = ajv.compile({
        ...schemaRef(commonSchema, 'Dependency'),
      });

      it('should accept valid HTTPS git URL', () => {
        const valid = {
          name: 'baseline-dependency',
          git: 'https://github.com/user/repo.git',
        };
        expect(validate(valid)).toBe(true);
      });

      it('should accept valid SSH git URL', () => {
        const valid = {
          name: 'baseline-dependency',
          git: 'ssh://git@github.com:user/repo.git',
        };
        expect(validate(valid)).toBe(true);
      });

      it('should reject invalid URI', () => {
        const invalid = {
          name: 'baseline-dependency',
          git: 'not a valid uri',
        };
        expect(validate(invalid)).toBe(false);
        expect(validate.errors).toContainEqual(
          expect.objectContaining({
            keyword: 'format',
            params: { format: 'uri' },
          })
        );
      });
    });

    describe('Reference URL/URI format validation', () => {
      const validateUrl = ajv.compile({
        type: 'object',
        required: ['url'],
        properties: {
          url: {
            type: 'string',
            format: 'uri',
          },
        },
      });

      const validateUri = ajv.compile({
        type: 'object',
        required: ['uri'],
        properties: {
          uri: {
            type: 'string',
            format: 'uri',
          },
        },
      });

      it('should accept valid HTTPS URL', () => {
        expect(validateUrl({ url: 'https://example.com/doc' })).toBe(true);
      });

      it('should accept valid HTTP URL', () => {
        expect(validateUrl({ url: 'http://example.com/page.html' })).toBe(true);
      });

      it('should reject invalid URL', () => {
        expect(validateUrl({ url: 'not a url' })).toBe(false);
        expect(validateUrl.errors).toContainEqual(
          expect.objectContaining({
            keyword: 'format',
            params: { format: 'uri' },
          })
        );
      });

      it('should accept valid URI', () => {
        expect(validateUri({ uri: 'https://standards.org/doc#section-3' })).toBe(true);
      });

      it('should reject invalid URI', () => {
        expect(validateUri({ uri: 'invalid uri' })).toBe(false);
        expect(validateUri.errors).toContainEqual(
          expect.objectContaining({
            keyword: 'format',
            params: { format: 'uri' },
          })
        );
      });
    });

    describe('Dependency url format validation', () => {
      const validate = ajv.compile({
        ...schemaRef(commonSchema, 'Dependency'),
      });

      it('should accept valid HTTP URL', () => {
        const valid = {
          name: 'dependency',
          url: 'http://example.com/resource',
        };
        expect(validate(valid)).toBe(true);
      });

      it('should accept relative URL reference', () => {
        const valid = {
          name: 'dependency',
          url: '../relative/path',
        };
        expect(validate(valid)).toBe(true);
      });

      it('should reject invalid URL format', () => {
        const invalid = {
          name: 'dependency',
          url: 'not a valid url',
        };
        expect(validate(invalid)).toBe(false);
        expect(validate.errors).toContainEqual(
          expect.objectContaining({
            keyword: 'format',
          })
        );
      });
    });

    describe('Remediation uri format validation', () => {
      const validate = ajv.compile({
        ...schemaRef(commonSchema, 'Remediation'),
      });

      it('should accept valid HTTPS URI', () => {
        const valid = {
          uri: 'https://github.com/org/ansible-playbooks',
        };
        expect(validate(valid)).toBe(true);
      });

      it('should accept valid file URI', () => {
        const valid = {
          uri: 'file:///opt/remediation/scripts',
        };
        expect(validate(valid)).toBe(true);
      });

      it('should reject invalid URI', () => {
        const invalid = {
          uri: 'not a uri',
        };
        expect(validate(invalid)).toBe(false);
        expect(validate.errors).toContainEqual(
          expect.objectContaining({
            keyword: 'format',
            params: { format: 'uri' },
          })
        );
      });
    });

    describe('Host_Target fqdn format validation', () => {
      const validate = ajv.compile({
        ...schemaRef(targetSchema, 'Host_Target'),
      });

      it('should accept valid FQDN', () => {
        const valid = {
          type: 'host',
          name: 'web-server',
          fqdn: 'web01.example.com',
        };
        expect(validate(valid)).toBe(true);
      });

      it('should accept valid subdomain FQDN', () => {
        const valid = {
          type: 'host',
          name: 'api-server',
          fqdn: 'api.prod.example.com',
        };
        expect(validate(valid)).toBe(true);
      });

      it('should reject invalid hostname', () => {
        const invalid = {
          type: 'host',
          name: 'bad-host',
          fqdn: 'not a valid hostname!',
        };
        expect(validate(invalid)).toBe(false);
        expect(validate.errors).toContainEqual(
          expect.objectContaining({
            keyword: 'format',
            params: { format: 'hostname' },
          })
        );
      });
    });

    describe('Repository_Target url format validation', () => {
      const validate = ajv.compile({
        ...schemaRef(targetSchema, 'Repository_Target'),
      });

      it('should accept valid HTTPS repository URL', () => {
        const valid = {
          type: 'repository',
          name: 'source-code',
          url: 'https://github.com/org/repo',
        };
        expect(validate(valid)).toBe(true);
      });

      it('should accept valid SSH repository URL', () => {
        const valid = {
          type: 'repository',
          name: 'source-code',
          url: 'ssh://git@gitlab.com/org/repo.git',
        };
        expect(validate(valid)).toBe(true);
      });

      it('should reject invalid repository URL', () => {
        const invalid = {
          type: 'repository',
          name: 'source-code',
          url: 'not a url',
        };
        expect(validate(invalid)).toBe(false);
        expect(validate.errors).toContainEqual(
          expect.objectContaining({
            keyword: 'format',
            params: { format: 'uri' },
          })
        );
      });
    });

    describe('Application_Target url format validation', () => {
      const validate = ajv.compile({
        ...schemaRef(targetSchema, 'Application_Target'),
      });

      it('should accept valid HTTPS application URL', () => {
        const valid = {
          type: 'application',
          name: 'web-app',
          url: 'https://app.example.com',
        };
        expect(validate(valid)).toBe(true);
      });

      it('should accept valid HTTP application URL with port', () => {
        const valid = {
          type: 'application',
          name: 'api',
          url: 'http://localhost:8080/api',
        };
        expect(validate(valid)).toBe(true);
      });

      it('should reject invalid application URL', () => {
        const invalid = {
          type: 'application',
          name: 'app',
          url: 'not a valid url',
        };
        expect(validate(invalid)).toBe(false);
        expect(validate.errors).toContainEqual(
          expect.objectContaining({
            keyword: 'format',
            params: { format: 'uri' },
          })
        );
      });
    });
  });
  describe('cvss.schema.json', () => {
    describe('Cvss', () => {
      const validate = ajv.compile({
        ...schemaRef(cvssSchema, 'Cvss'),
      });

      describe('valid Cvss objects', () => {
        it('should validate Base-only vendor-supplied CVSS 3.1', () => {
          const valid = {
            version: '3.1',
            source: 'CVE-2024-12345',
            baseVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
            baseScore: 7.5,
            baseSeverity: 'high',
          };
          expect(validate(valid)).toBe(true);
          expect(validate.errors).toBeNull();
        });

        it('should validate minimal Cvss with only required fields', () => {
          const valid = {
            version: '3.1',
            baseVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
            baseScore: 7.5,
          };
          expect(validate(valid)).toBe(true);
        });

        it('should validate Base + Threat (consumer added Exploit Maturity)', () => {
          const valid = {
            version: '3.1',
            source: 'CVE-2023-44487',
            baseVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H',
            baseScore: 7.5,
            baseSeverity: 'high',
            threatVector: 'E:U/RL:O/RC:C',
            threatScore: 5.5,
          };
          expect(validate(valid)).toBe(true);
        });

        it('should validate Base + Environmental (consumer Modified Base + Security Requirements)', () => {
          const valid = {
            version: '3.1',
            source: 'CVE-2024-3094',
            baseVector: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H',
            baseScore: 8.1,
            baseSeverity: 'high',
            environmentalVector: 'MAV:N/CR:H/IR:H/AR:H',
            environmentalScore: 6.8,
          };
          expect(validate(valid)).toBe(true);
        });

        it('should validate Full v4 with Base + Threat + Environmental + Supplemental + computed', () => {
          const valid = {
            version: '4.0',
            source: 'CVE-2024-21762',
            baseVector: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N',
            baseScore: 9.8,
            baseSeverity: 'critical',
            threatVector: 'E:A',
            threatScore: 9.3,
            environmentalVector: 'MAV:N/CR:H/IR:H/AR:H',
            environmentalScore: 9.5,
            supplementalVector: 'S:P/AU:N/V:C/RE:M',
            computedScore: 4.2,
            computedSeverity: 'medium',
          };
          expect(validate(valid)).toBe(true);
        });

        it('should validate v2 legacy CVSS 2.0', () => {
          const valid = {
            version: '2.0',
            source: 'CVE-2014-0160',
            baseVector: 'AV:N/AC:L/Au:N/C:P/I:N/A:N',
            baseScore: 5.0,
            baseSeverity: 'medium',
          };
          expect(validate(valid)).toBe(true);
        });

        it('should validate CVSS 3.0 vector', () => {
          const valid = {
            version: '3.0',
            baseVector: 'CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
            baseScore: 9.8,
          };
          expect(validate(valid)).toBe(true);
        });

        it('should accept all baseSeverity enum values', () => {
          const severities = ['none', 'low', 'medium', 'high', 'critical'];
          severities.forEach((sev) => {
            const valid = {
              version: '3.1',
              baseVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
              baseScore: 5.0,
              baseSeverity: sev,
            };
            expect(validate(valid)).toBe(true);
          });
        });

        it('should accept all computedSeverity enum values', () => {
          const severities = ['none', 'low', 'medium', 'high', 'critical'];
          severities.forEach((sev) => {
            const valid = {
              version: '3.1',
              baseVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
              baseScore: 5.0,
              computedSeverity: sev,
            };
            expect(validate(valid)).toBe(true);
          });
        });

        it('should accept boundary scores 0.0 and 10.0', () => {
          const lowEnd = {
            version: '3.1',
            baseVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N',
            baseScore: 0.0,
          };
          const highEnd = {
            version: '3.1',
            baseVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
            baseScore: 10.0,
          };
          expect(validate(lowEnd)).toBe(true);
          expect(validate(highEnd)).toBe(true);
        });
      });

      describe('invalid Cvss objects', () => {
        it('should accept Cvss without baseVector (vendor-final-score case)', () => {
          // Some vendor tools (Twistlock/Prisma Cloud) emit a final score
          // without the vector that derived it. The schema makes baseVector
          // optional so this data is captured structurally rather than lost.
          const valid = {
            version: '3.1',
            baseScore: 7.5,
            baseSeverity: 'high',
            source: 'CVE-2024-12345',
          };
          expect(validate(valid)).toBe(true);
        });

        it('should reject Cvss missing required version', () => {
          const invalid = {
            baseVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
            baseScore: 7.5,
          };
          expect(validate(invalid)).toBe(false);
        });

        it('should accept Cvss with baseVector but no baseScore', () => {
          // baseScore is optional — a Cvss instance may carry only a vector.
          const valid = {
            version: '3.1',
            baseVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
          };
          expect(validate(valid)).toBe(true);
        });

        it('should accept consumer-enrichment Cvss (environmental only, no base)', () => {
          // A riskAdjustment override carries consumer deltas with no base —
          // base belongs to the finding, merged at apply time.
          const valid = {
            version: '3.1',
            source: 'CVE-2021-44228',
            environmentalVector: 'MAV:A/CR:H/IR:M/AR:L',
            computedScore: 5.2,
            computedSeverity: 'medium',
          };
          expect(validate(valid)).toBe(true);
        });

        it('should reject content-free Cvss (version only, no metric/score)', () => {
          // The anyOf guardrail requires at least one substantive field.
          const invalid = { version: '3.1' };
          expect(validate(invalid)).toBe(false);
        });

        it('should reject Cvss with only a severity band (no score/vector)', () => {
          // baseSeverity alone is not a substantive CVSS metric per the anyOf.
          const invalid = { version: '3.1', baseSeverity: 'high' };
          expect(validate(invalid)).toBe(false);
        });

        it('should reject baseScore out of range (above 10.0)', () => {
          const invalid = {
            version: '3.1',
            baseVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
            baseScore: 15.0,
          };
          expect(validate(invalid)).toBe(false);
        });

        it('should reject baseScore out of range (below 0.0)', () => {
          const invalid = {
            version: '3.1',
            baseVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
            baseScore: -1.0,
          };
          expect(validate(invalid)).toBe(false);
        });

        it('should reject threatScore out of range', () => {
          const invalid = {
            version: '3.1',
            baseVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
            baseScore: 7.5,
            threatScore: 11.0,
          };
          expect(validate(invalid)).toBe(false);
        });

        it('should reject environmentalScore out of range', () => {
          const invalid = {
            version: '3.1',
            baseVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
            baseScore: 7.5,
            environmentalScore: 99.0,
          };
          expect(validate(invalid)).toBe(false);
        });

        it('should reject computedScore out of range', () => {
          const invalid = {
            version: '3.1',
            baseVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
            baseScore: 7.5,
            computedScore: -0.5,
          };
          expect(validate(invalid)).toBe(false);
        });

        it('should reject bad version enum value', () => {
          const invalid = {
            version: '5.0',
            baseVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
            baseScore: 7.5,
          };
          expect(validate(invalid)).toBe(false);
        });

        it('should reject malformed baseVector ("not a vector")', () => {
          const invalid = {
            version: '3.1',
            baseVector: 'not a vector',
            baseScore: 7.5,
          };
          expect(validate(invalid)).toBe(false);
        });

        it('should reject malformed threatVector', () => {
          const invalid = {
            version: '3.1',
            baseVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
            baseScore: 7.5,
            threatVector: 'this is not a vector!',
          };
          expect(validate(invalid)).toBe(false);
        });

        it('should reject malformed environmentalVector', () => {
          const invalid = {
            version: '3.1',
            baseVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
            baseScore: 7.5,
            environmentalVector: '???',
          };
          expect(validate(invalid)).toBe(false);
        });

        it('should reject malformed supplementalVector', () => {
          const invalid = {
            version: '3.1',
            baseVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
            baseScore: 7.5,
            supplementalVector: 'lower case junk',
          };
          expect(validate(invalid)).toBe(false);
        });

        it('should reject bad baseSeverity enum value', () => {
          const invalid = {
            version: '3.1',
            baseVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
            baseScore: 7.5,
            baseSeverity: 'extreme',
          };
          expect(validate(invalid)).toBe(false);
        });

        it('should reject bad computedSeverity enum value', () => {
          const invalid = {
            version: '3.1',
            baseVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
            baseScore: 7.5,
            computedSeverity: 'urgent',
          };
          expect(validate(invalid)).toBe(false);
        });

        it('should reject Cvss with explicit null required field', () => {
          const invalid = {
            version: '3.1',
            baseVector: null,
            baseScore: 7.5,
          };
          expect(validate(invalid)).toBe(false);
        });

        it('should reject Cvss with extra unevaluated properties', () => {
          const invalid = {
            version: '3.1',
            baseVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
            baseScore: 7.5,
            extraField: 'not allowed',
          };
          expect(validate(invalid)).toBe(false);
        });
      });

      describe('schema examples', () => {
        const examples = (cvssSchema as { $defs: { Cvss: { examples?: unknown[] } } }).$defs.Cvss
          .examples;

        it('should have at least 5 examples', () => {
          expect(examples).toBeDefined();
          expect(Array.isArray(examples)).toBe(true);
          expect((examples as unknown[]).length).toBeGreaterThanOrEqual(5);
        });

        it('every example should be valid against the Cvss schema', () => {
          (examples as Record<string, unknown>[]).forEach((ex, idx) => {
            // Strip $comment before validation (it's documentation, not data)
            const data = { ...ex };
            delete data.$comment;
            const ok = validate(data);
            if (!ok) {
              throw new Error(
                `Example ${idx} failed validation: ${JSON.stringify(validate.errors)}`,
              );
            }
            expect(ok).toBe(true);
          });
        });

        it('every example should have a $comment field documenting it', () => {
          (examples as Record<string, unknown>[]).forEach((ex, idx) => {
            expect(ex.$comment, `example ${idx} missing $comment`).toBeDefined();
            expect(typeof ex.$comment).toBe('string');
          });
        });
      });
    });
  });
  describe('epss.schema.json', () => {
    describe('Epss', () => {
      const validate = ajv.compile({
        ...schemaRef(epssSchema, 'Epss'),
      });

      it('should validate a full Epss object', () => {
        const valid = {
          score: 0.045,
          percentile: 0.92,
          date: '2026-05-26',
        };
        expect(validate(valid)).toBe(true);
        expect(validate.errors).toBeNull();
      });

      it('should validate Epss with very high score (log4shell-style)', () => {
        const valid = {
          score: 0.97532,
          percentile: 0.99987,
          date: '2026-05-26',
        };
        expect(validate(valid)).toBe(true);
      });

      it('should validate Epss with score at lower bound 0.0', () => {
        const valid = {
          score: 0.0,
          percentile: 0.0,
          date: '2026-05-26',
        };
        expect(validate(valid)).toBe(true);
      });

      it('should validate Epss with score at upper bound 1.0', () => {
        const valid = {
          score: 1.0,
          percentile: 1.0,
          date: '2026-05-26',
        };
        expect(validate(valid)).toBe(true);
      });

      it('should reject Epss missing required score', () => {
        const invalid = {
          percentile: 0.92,
          date: '2026-05-26',
        };
        expect(validate(invalid)).toBe(false);
        expect(validate.errors).toMatchObject([
          expect.objectContaining({
            params: expect.objectContaining({ missingProperty: 'score' }),
          }),
        ]);
      });

      it('should reject Epss missing required percentile', () => {
        const invalid = {
          score: 0.045,
          date: '2026-05-26',
        };
        expect(validate(invalid)).toBe(false);
        expect(validate.errors).toMatchObject([
          expect.objectContaining({
            params: expect.objectContaining({ missingProperty: 'percentile' }),
          }),
        ]);
      });

      it('should reject Epss missing required date', () => {
        const invalid = {
          score: 0.045,
          percentile: 0.92,
        };
        expect(validate(invalid)).toBe(false);
        expect(validate.errors).toMatchObject([
          expect.objectContaining({
            params: expect.objectContaining({ missingProperty: 'date' }),
          }),
        ]);
      });

      it('should reject Epss with score above 1.0', () => {
        const invalid = {
          score: 1.5,
          percentile: 0.92,
          date: '2026-05-26',
        };
        expect(validate(invalid)).toBe(false);
      });

      it('should reject Epss with negative score', () => {
        const invalid = {
          score: -0.1,
          percentile: 0.92,
          date: '2026-05-26',
        };
        expect(validate(invalid)).toBe(false);
      });

      it('should reject Epss with percentile above 1.0', () => {
        const invalid = {
          score: 0.045,
          percentile: 1.01,
          date: '2026-05-26',
        };
        expect(validate(invalid)).toBe(false);
      });

      it('should reject Epss with negative percentile', () => {
        const invalid = {
          score: 0.045,
          percentile: -0.01,
          date: '2026-05-26',
        };
        expect(validate(invalid)).toBe(false);
      });

      it('should reject Epss with malformed date (slash separator)', () => {
        const invalid = {
          score: 0.045,
          percentile: 0.92,
          date: '2026/05/26',
        };
        expect(validate(invalid)).toBe(false);
      });

      it('should reject Epss with malformed date (date-time instead of date)', () => {
        const invalid = {
          score: 0.045,
          percentile: 0.92,
          date: '2026-05-26T10:30:00Z',
        };
        expect(validate(invalid)).toBe(false);
      });

      it('should reject Epss with non-numeric score', () => {
        const invalid = {
          score: '0.045',
          percentile: 0.92,
          date: '2026-05-26',
        };
        expect(validate(invalid)).toBe(false);
      });

      it('should reject Epss with extra unevaluated properties', () => {
        const invalid = {
          score: 0.045,
          percentile: 0.92,
          date: '2026-05-26',
          model: 'epss-v3',
        };
        expect(validate(invalid)).toBe(false);
      });

      it('should reject Epss with explicit null fields', () => {
        const invalid = {
          score: null,
          percentile: null,
          date: null,
        };
        expect(validate(invalid)).toBe(false);
      });
    });
  });
  describe('kev.schema.json', () => {
    describe('Kev', () => {
      const validate = ajv.compile({
        ...schemaRef(kevSchema, 'Kev'),
      });

      it('should validate inKev=true with required dateAdded and dueDate', () => {
        const valid = {
          inKev: true,
          dateAdded: '2026-03-15',
          dueDate: '2026-04-05',
        };
        expect(validate(valid)).toBe(true);
      });

      it('should validate inKev=true with optional notes', () => {
        const valid = {
          inKev: true,
          dateAdded: '2026-03-15',
          dueDate: '2026-04-05',
          notes: 'Active ransomware exploitation observed in the wild.',
        };
        expect(validate(valid)).toBe(true);
      });

      it('should validate inKev=false with no dates (dates only required when inKev=true)', () => {
        const valid = {
          inKev: false,
        };
        expect(validate(valid)).toBe(true);
      });

      it('should validate inKev=false with dates present (dates optional but allowed)', () => {
        const valid = {
          inKev: false,
          dateAdded: '2026-03-15',
          dueDate: '2026-04-05',
        };
        expect(validate(valid)).toBe(true);
      });

      it('should reject Kev missing required inKev', () => {
        const invalid = {
          dateAdded: '2026-03-15',
          dueDate: '2026-04-05',
        };
        expect(validate(invalid)).toBe(false);
      });

      it('should reject Kev with inKev=true missing dateAdded', () => {
        const invalid = {
          inKev: true,
          dueDate: '2026-04-05',
        };
        expect(validate(invalid)).toBe(false);
      });

      it('should reject Kev with inKev=true missing dueDate', () => {
        const invalid = {
          inKev: true,
          dateAdded: '2026-03-15',
        };
        expect(validate(invalid)).toBe(false);
      });

      it('should reject Kev with inKev=true missing both dates', () => {
        const invalid = {
          inKev: true,
        };
        expect(validate(invalid)).toBe(false);
      });

      it('should reject Kev with malformed dateAdded', () => {
        const invalid = {
          inKev: true,
          dateAdded: 'not-a-date',
          dueDate: '2026-04-05',
        };
        expect(validate(invalid)).toBe(false);
      });

      it('should reject Kev with malformed dueDate', () => {
        const invalid = {
          inKev: true,
          dateAdded: '2026-03-15',
          dueDate: '03/15/2026',
        };
        expect(validate(invalid)).toBe(false);
      });

      it('should reject Kev with date-time instead of date for dateAdded', () => {
        const invalid = {
          inKev: true,
          dateAdded: '2026-03-15T00:00:00Z',
          dueDate: '2026-04-05',
        };
        expect(validate(invalid)).toBe(false);
      });

      it('should reject Kev with non-boolean inKev', () => {
        const invalid = {
          inKev: 'true',
          dateAdded: '2026-03-15',
          dueDate: '2026-04-05',
        };
        expect(validate(invalid)).toBe(false);
      });

      it('should reject Kev with explicit null notes', () => {
        const invalid = {
          inKev: true,
          dateAdded: '2026-03-15',
          dueDate: '2026-04-05',
          notes: null,
        };
        expect(validate(invalid)).toBe(false);
      });

      it('should reject Kev with extra unevaluated properties', () => {
        const invalid = {
          inKev: true,
          dateAdded: '2026-03-15',
          dueDate: '2026-04-05',
          extraField: 'not allowed',
        };
        expect(validate(invalid)).toBe(false);
      });

      it('should accept Kev where dueDate is before dateAdded (CISA occasionally adjusts dates)', () => {
        const valid = {
          inKev: true,
          dateAdded: '2026-04-05',
          dueDate: '2026-03-15',
        };
        expect(validate(valid)).toBe(true);
      });
    });
  });

  describe('CWE ID array pattern (for Evaluated_Requirement.cwe)', () => {
    // Tests the JSON Schema fragment that will be used for cwe[] on Evaluated_Requirement.
    // The integration into hdf-results.schema.json happens later; here we validate the
    // pattern in isolation so the wire-up is straightforward.
    const cweArraySchema = {
      type: 'array',
      items: {
        type: 'string',
        pattern: '^CWE-\\d+$',
      },
    };
    const validate = ajv.compile(cweArraySchema);

    it('should accept a valid CWE ID array', () => {
      expect(validate(['CWE-79', 'CWE-89', 'CWE-352'])).toBe(true);
    });

    it('should accept a single-element CWE array', () => {
      expect(validate(['CWE-79'])).toBe(true);
    });

    it('should accept an empty array', () => {
      expect(validate([])).toBe(true);
    });

    it('should accept very large CWE numbers', () => {
      expect(validate(['CWE-1234567'])).toBe(true);
    });

    it('should reject lowercase cwe prefix', () => {
      expect(validate(['cwe-79'])).toBe(false);
    });

    it('should reject mixed-case Cwe prefix', () => {
      expect(validate(['Cwe-79'])).toBe(false);
    });

    it('should reject non-numeric CWE suffix', () => {
      expect(validate(['CWE-abc'])).toBe(false);
    });

    it('should reject CWE id with no number', () => {
      expect(validate(['CWE-'])).toBe(false);
    });

    it('should reject bare numeric string with no CWE- prefix', () => {
      expect(validate(['79'])).toBe(false);
    });

    it('should reject CWE id with trailing space', () => {
      expect(validate(['CWE-79 '])).toBe(false);
    });

    it('should reject CWE id with leading space', () => {
      expect(validate([' CWE-79'])).toBe(false);
    });

    it('should reject CWE id with leading zeros stripped form (acceptable but ensure plain digits)', () => {
      // Plain digits are required; we still accept leading zeros since pattern is just \d+.
      expect(validate(['CWE-079'])).toBe(true);
    });

    it('should reject array containing one invalid entry among valid ones', () => {
      expect(validate(['CWE-79', 'cwe-89'])).toBe(false);
    });

    it('should reject non-string entries', () => {
      expect(validate([79])).toBe(false);
    });

    it('should reject CWE id with extra punctuation', () => {
      expect(validate(['CWE-79.1'])).toBe(false);
    });
  });
  describe('affected-package.schema.json', () => {
    describe('Affected_Package', () => {
      const validate = ajv.compile({
        ...schemaRef(affectedPackageSchema, 'Affected_Package'),
      });

      it('should validate minimal Affected_Package (name + version + ecosystem only)', () => {
        const valid = {
          name: 'requests',
          version: '2.28.1',
          ecosystem: 'pypi',
        };
        expect(validate(valid)).toBe(true);
        expect(validate.errors).toBeNull();
      });

      it('should validate full Affected_Package with CPE, PURL, and fixedInVersion', () => {
        const valid = {
          name: 'openssl',
          version: '1.1.1k-7.el8_4',
          ecosystem: 'rpm',
          cpe: 'cpe:2.3:a:openssl:openssl:1.1.1k:*:*:*:*:*:*:*',
          purl: 'pkg:rpm/redhat/openssl@1.1.1k-7.el8_4?arch=x86_64',
          fixedInVersion: '1.1.1l',
        };
        expect(validate(valid)).toBe(true);
        expect(validate.errors).toBeNull();
      });

      it('should validate Affected_Package with PURL but no CPE (common in npm world)', () => {
        const valid = {
          name: 'lodash',
          version: '4.17.20',
          ecosystem: 'npm',
          purl: 'pkg:npm/lodash@4.17.20',
        };
        expect(validate(valid)).toBe(true);
      });

      it('should validate Affected_Package with hardware CPE part type (cpe:2.3:h)', () => {
        const valid = {
          name: 'cisco-firmware',
          version: '15.2',
          ecosystem: 'generic',
          cpe: 'cpe:2.3:h:cisco:catalyst:15.2:*:*:*:*:*:*:*',
        };
        expect(validate(valid)).toBe(true);
      });

      it('should validate Affected_Package with OS CPE part type (cpe:2.3:o)', () => {
        const valid = {
          name: 'linux_kernel',
          version: '5.10.0',
          ecosystem: 'generic',
          cpe: 'cpe:2.3:o:linux:linux_kernel:5.10.0:*:*:*:*:*:*:*',
        };
        expect(validate(valid)).toBe(true);
      });

      it.each(['npm', 'pypi', 'rpm', 'deb', 'maven', 'gem', 'nuget', 'go', 'cargo', 'generic'])(
        'should accept ecosystem=%s',
        (value: string) => {
          expect(validate({ name: 'pkg', version: '1.0', ecosystem: value })).toBe(true);
        },
      );

      it('should reject Affected_Package with no identifier at all (empty object)', () => {
        expect(validate({})).toBe(false);
        expect(validate.errors).toEqual(
          expect.arrayContaining([
            expect.objectContaining({ keyword: 'anyOf' }),
          ]),
        );
      });

      it('should reject Affected_Package with name only (no version, no ecosystem, no purl, no cpe)', () => {
        expect(validate({ name: 'openssl' })).toBe(false);
      });

      it('should reject Affected_Package with name + version but no ecosystem (and no purl/cpe fallback)', () => {
        expect(validate({ name: 'openssl', version: '1.1.1k' })).toBe(false);
      });

      it('should accept Affected_Package with purl alone (anyOf branch 2 — purl encodes name/version/ecosystem)', () => {
        expect(validate({ purl: 'pkg:npm/lodash@4.17.20' })).toBe(true);
      });

      it('should accept Affected_Package with cpe alone (anyOf branch 3 — cpe encodes vendor/product/version)', () => {
        expect(
          validate({ cpe: 'cpe:2.3:a:openssl:openssl:1.1.1k:*:*:*:*:*:*:*' }),
        ).toBe(true);
      });

      it('should reject Affected_Package with unknown ecosystem', () => {
        const invalid = {
          name: 'pkg',
          version: '1.0',
          ecosystem: 'cocoapods',
        };
        expect(validate(invalid)).toBe(false);
      });

      it('should reject Affected_Package with explicit null ecosystem', () => {
        const invalid = {
          name: 'pkg',
          version: '1.0',
          ecosystem: null,
        };
        expect(validate(invalid)).toBe(false);
      });

      it('should reject malformed CPE (truncated, missing part-type letter)', () => {
        const invalid = {
          name: 'openssl',
          version: '1.1.1k',
          ecosystem: 'rpm',
          cpe: 'cpe:2.3',
        };
        expect(validate(invalid)).toBe(false);
      });

      it('should reject malformed CPE (wrong CPE version)', () => {
        const invalid = {
          name: 'openssl',
          version: '1.1.1k',
          ecosystem: 'rpm',
          cpe: 'cpe:2.2:a:openssl:openssl:1.1.1k:*:*:*:*:*:*:*',
        };
        expect(validate(invalid)).toBe(false);
      });

      it('should reject malformed CPE (invalid part-type letter)', () => {
        const invalid = {
          name: 'openssl',
          version: '1.1.1k',
          ecosystem: 'rpm',
          cpe: 'cpe:2.3:x:openssl:openssl:1.1.1k:*:*:*:*:*:*:*',
        };
        expect(validate(invalid)).toBe(false);
      });

      it('should reject malformed PURL (no pkg: scheme)', () => {
        const invalid = {
          name: 'openssl',
          version: '1.1.1k',
          ecosystem: 'rpm',
          purl: 'openssl@1.0',
        };
        expect(validate(invalid)).toBe(false);
      });

      it('should reject malformed PURL (pkg: scheme but no type)', () => {
        const invalid = {
          name: 'openssl',
          version: '1.1.1k',
          ecosystem: 'rpm',
          purl: 'pkg:',
        };
        expect(validate(invalid)).toBe(false);
      });

      it('should reject Affected_Package with extra unevaluated properties', () => {
        const invalid = {
          name: 'pkg',
          version: '1.0',
          ecosystem: 'npm',
          extraField: 'not allowed',
        };
        expect(validate(invalid)).toBe(false);
      });

      it('should reject Affected_Package with explicit null optional fields', () => {
        const invalid = {
          name: 'pkg',
          version: '1.0',
          ecosystem: 'npm',
          cpe: null,
          purl: null,
          fixedInVersion: null,
        };
        expect(validate(invalid)).toBe(false);
      });

      it('should validate maven ecosystem with full identifiers and fixedInVersion (patch path)', () => {
        const valid = {
          name: 'org.apache.logging.log4j:log4j-core',
          version: '2.14.1',
          ecosystem: 'maven',
          cpe: 'cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*',
          purl: 'pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1',
          fixedInVersion: '2.17.1',
        };
        expect(validate(valid)).toBe(true);
      });
    });
  });
});
