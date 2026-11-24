import { execFileSync } from 'node:child_process';
import { describe, it, expect } from 'vitest';
import { generateControlStub } from '../src/control-stub.js';
import { makeRequirement, desc } from './helpers.js';

describe('generateControlStub', () => {
  it('generates a minimal control with id, impact, and default description', () => {
    const req = makeRequirement({ id: 'SV-001' });
    const ruby = generateControlStub(req);
    expect(ruby).toContain("control 'SV-001' do");
    expect(ruby).toContain('impact 0.5');
    expect(ruby).toContain('Test requirement');
    expect(ruby).toMatch(/end\n$/);
  });

  it('includes title when present', () => {
    const req = makeRequirement({ id: 'SV-002', title: 'My Title' });
    const ruby = generateControlStub(req);
    expect(ruby).toContain("title 'My Title'");
  });

  it('renders impact 0.0 as 0.0 not 0', () => {
    const req = makeRequirement({ id: 'SV-003', impact: 0.0 });
    const ruby = generateControlStub(req);
    expect(ruby).toContain('impact 0.0');
    expect(ruby).not.toMatch(/impact 0[^.]/);
  });

  it('renders impact 1.0 as a number', () => {
    const req = makeRequirement({ id: 'SV-004', impact: 1.0 });
    const ruby = generateControlStub(req);
    expect(ruby).toContain('impact 1.0');
  });

  it('renders impact 0.7 without trailing zero issues', () => {
    const req = makeRequirement({ id: 'SV-005', impact: 0.7 });
    const ruby = generateControlStub(req);
    expect(ruby).toContain('impact 0.7');
  });

  it('emits desc for the default description', () => {
    const req = makeRequirement({
      id: 'SV-006',
      descriptions: [desc('default', 'The main description')],
    });
    const ruby = generateControlStub(req);
    expect(ruby).toContain("desc 'The main description'");
  });

  it('emits labeled desc for non-default descriptions', () => {
    const req = makeRequirement({
      id: 'SV-007',
      descriptions: [
        desc('default', 'Main desc'),
        desc('check', 'Check this thing'),
        desc('fix', 'Fix this thing'),
      ],
    });
    const ruby = generateControlStub(req);
    expect(ruby).toContain("desc 'check'");
    expect(ruby).toContain("'Check this thing'");
    expect(ruby).toContain("desc 'fix'");
    expect(ruby).toContain("'Fix this thing'");
  });

  it('skips duplicate default label in descs', () => {
    const req = makeRequirement({
      id: 'SV-008',
      descriptions: [
        desc('default', 'Main desc'),
        desc('default', 'Main desc'),
      ],
    });
    const ruby = generateControlStub(req);
    // Should only have one `desc` line (not `desc 'default', ...`)
    const descMatches = ruby.match(/^\s+desc /gm);
    expect(descMatches).toHaveLength(1);
  });

  it('renders tag arrays with Ruby array syntax', () => {
    const req = makeRequirement({
      id: 'SV-009',
      tags: {
        cci: ['CCI-000068', 'CCI-000197'],
        nist: ['AC-17 (2)', 'IA-5 (1)'],
      },
    });
    const ruby = generateControlStub(req);
    expect(ruby).toContain("tag cci: ['CCI-000068', 'CCI-000197']");
    expect(ruby).toContain("tag nist: ['AC-17 (2)', 'IA-5 (1)']");
  });

  it('renders tag strings with proper quoting', () => {
    const req = makeRequirement({
      id: 'SV-010',
      tags: { severity: 'medium' },
    });
    const ruby = generateControlStub(req);
    expect(ruby).toContain("tag severity: 'medium'");
  });

  it('renders tag nil values', () => {
    const req = makeRequirement({
      id: 'SV-011',
      tags: { severity: null },
    });
    const ruby = generateControlStub(req);
    expect(ruby).toContain('tag severity: nil');
  });

  it('renders tag boolean values', () => {
    const req = makeRequirement({
      id: 'SV-012',
      tags: { documentable: false },
    });
    const ruby = generateControlStub(req);
    expect(ruby).toContain('tag documentable: false');
  });

  it('includes existing code in control body', () => {
    const req = makeRequirement({
      id: 'SV-013',
      code: '  describe file("/etc/ssh/sshd_config") do\n    it { should exist }\n  end',
    });
    const ruby = generateControlStub(req);
    expect(ruby).toContain('describe file("/etc/ssh/sshd_config")');
    expect(ruby).toContain('it { should exist }');
  });

  it('does not double-wrap code that is already a full control block', () => {
    // When code already contains a full `control 'ID' do ... end` wrapper
    // (e.g. from `-c controls/` reading whole .rb files), the stub generator
    // must not wrap it again — that produces invalid nested control blocks.
    const req = makeRequirement({
      id: 'SV-12345',
      code: "control 'SV-12345' do\n  describe file('/etc/passwd') do\n    it { should exist }\n  end\nend\n",
    });
    const ruby = generateControlStub(req);
    const matches = ruby.match(/control 'SV-12345' do/g) || [];
    expect(matches.length).toBe(1);
  });

  it('rewrites the inner control ID when renamed by an upgrade match', () => {
    // When upgrade matches a rename (current SV-OLD merges with upstream
    // SV-NEW), the merged requirement adopts the new ID but inherits
    // current's full .rb body — which still wraps with `control 'SV-OLD'`.
    // The stub generator must rewrite the wrapper ID to match req.id.
    const req = makeRequirement({
      id: 'SV-268322',
      code: "control 'SV-244540' do\n  describe file('/etc/pam.d/system-auth') do\n    its('content') { should_not match(/nullok/) }\n  end\nend\n",
    });
    const ruby = generateControlStub(req);
    expect((ruby.match(/control 'SV-268322' do/g) || []).length).toBe(1);
    expect((ruby.match(/control 'SV-244540' do/g) || []).length).toBe(0);
  });

  it('adds stub comment when no code is provided', () => {
    const req = makeRequirement({ id: 'SV-014' });
    const ruby = generateControlStub(req);
    expect(ruby).toMatch(/# TODO|# Stub/i);
  });

  it('escapes special characters in descriptions', () => {
    const req = makeRequirement({
      id: 'SV-015',
      descriptions: [desc('default', "it's a \"complex\" description")],
    });
    const ruby = generateControlStub(req);
    expect(ruby).toContain(`  desc %q(it's a "complex" description)\n`);
  });

  it('handles severity tag in tags', () => {
    const req = makeRequirement({
      id: 'SV-016',
      severity: 'high' as any,
      tags: { severity: 'high', gtitle: 'Group Title' },
    });
    const ruby = generateControlStub(req);
    expect(ruby).toContain("tag severity: 'high'");
    expect(ruby).toContain("tag gtitle: 'Group Title'");
  });

  it('renders tag with numeric value', () => {
    const req = makeRequirement({
      id: 'SV-018',
      tags: { weight: 10.0 },
    });
    const ruby = generateControlStub(req);
    expect(ruby).toContain('tag weight: 10');
  });

  it('renders tag with object value as JSON', () => {
    const req = makeRequirement({
      id: 'SV-019',
      tags: { cis_controls: [{ '8': ['6.1', '6.2'] }] } as any,
    });
    const ruby = generateControlStub(req);
    expect(ruby).toContain('tag cis_controls:');
  });

  it('generates well-formed Ruby control block', () => {
    const req = makeRequirement({
      id: 'SV-017',
      title: 'Test Control',
      impact: 0.5,
      descriptions: [
        desc('default', 'Main description'),
        desc('check', 'Verify the setting'),
      ],
      tags: { nist: ['AC-2'], severity: 'medium' },
    });
    const ruby = generateControlStub(req);

    // Verify structure: control ... do ... end
    expect(ruby).toMatch(/^control 'SV-017' do\n/);
    expect(ruby).toMatch(/\nend\n$/);

    // Verify ordering: title, desc, impact, tags, code
    const titleIdx = ruby.indexOf('title');
    const descIdx = ruby.indexOf("desc '");
    const impactIdx = ruby.indexOf('impact');
    const tagIdx = ruby.indexOf('tag ');
    expect(titleIdx).toBeLessThan(descIdx);
    expect(descIdx).toBeLessThan(impactIdx);
    expect(impactIdx).toBeLessThan(tagIdx);
  });
  // A renamed control's new id is written as a Ruby literal, never spliced raw
  // inside the old id's quotes.
  it('escapes a renamed control id', () => {
    const req = makeRequirement({
      id: "SV-2'); system('x",
      code: "control 'SV-244540' do\n  describe true do\n    it { should eq true }\n  end\nend\n",
    });
    const ruby = generateControlStub(req);
    expect(ruby.startsWith(`control "SV-2'); system('x" do`)).toBe(true);
    if (hasRuby()) {
      const out = execFileSync('ruby', ['-'], { input: `def control(id) STDOUT.write(id) end\n${ruby.split('\n')[0]} end\n` });
      expect(out.toString('utf-8')).toBe(req.id);
    }
  });

  // Every string the generator writes into Ruby reaches InSpec unchanged. Ruby
  // loads the control under a stand-in for InSpec's DSL and reports the values.
  it.skipIf(!hasRuby())('has every string read back unchanged by Ruby', () => {
    const req = makeRequirement({
      id: "SV-1'x",
      title: "it's #{1+1}",
      descriptions: [desc('default', 'it\'s "a" 1) step'), desc("it's", 'fix\r\nthis \\ (now)\n')],
      tags: { gtitle: "it's #@x", cci: ["CCI's", 'a"b', 'c\\d'], nist: ["AC-1 a'b"] },
    });
    const src = generateControlStub(req);
    const out = execFileSync('ruby', ['-'], { input: `${RUBY_CONTROL_DSL}${src}\nSTDOUT.write(JSON.generate($c))\n` });
    expect(JSON.parse(out.toString('utf-8'))).toEqual({
      id: "SV-1'x",
      title: "it's #{1+1}",
      descs: { default: 'it\'s "a" 1) step', "it's": 'fix\r\nthis \\ (now)\n' },
      impact: 0.5,
      tags: { gtitle: "it's #@x", cci: ["CCI's", 'a"b', 'c\\d'], nist: ["AC-1 a'b"] },
    });
  });
});

// A stand-in for InSpec's control DSL; the Go suite uses the same one.
const RUBY_CONTROL_DSL = `require 'json'
$c = { 'descs' => {}, 'tags' => {} }
def control(id, &blk) $c['id'] = id; instance_eval(&blk) end
def title(t) $c['title'] = t end
def desc(a, b = nil) b.nil? ? $c['descs']['default'] = a : $c['descs'][a] = b end
def impact(i) $c['impact'] = i end
def tag(h) h.each { |k, v| $c['tags'][k.to_s] = v } end
`;

function hasRuby(): boolean {
  try {
    execFileSync('ruby', ['-v'], { stdio: 'ignore' });
    return true;
  } catch {
    return false;
  }
}
