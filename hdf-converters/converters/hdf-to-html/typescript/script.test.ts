import { describe, it, expect } from 'vitest';
import { SCRIPT } from './assets.js';

/**
 * The report's inline script, run against a stand-in for the few DOM calls it
 * makes. It is the same text in both languages, so this covers the Go output
 * too. What a browser does with the markup is not tested here; that the script
 * runs under the report's own security policy was checked in Chrome.
 */

type Listener = () => void;

class El {
  attrs = new Map<string, string>();
  classes = new Set<string>();
  listeners = new Map<string, Listener[]>();
  textContent = '';
  value = '';
  hidden = false;
  open = false;
  /** Requirements inside a group. */
  members: El[] = [];
  /** The one disclosure inside a requirement's article. */
  panel: El | null = null;
  summary: { textContent: string } | null = null;

  classList = { add: (name: string) => void this.classes.add(name) };

  getAttribute(name: string): string | null {
    return this.attrs.get(name) ?? null;
  }
  setAttribute(name: string, value: string): void {
    this.attrs.set(name, value);
  }
  removeAttribute(name: string): void {
    this.attrs.delete(name);
  }
  addEventListener(event: string, listener: Listener): void {
    this.listeners.set(event, [...(this.listeners.get(event) ?? []), listener]);
  }
  fire(event: string): void {
    for (const listener of this.listeners.get(event) ?? []) listener();
  }
  querySelector(selector: string): unknown {
    if (selector === 'summary') return this.summary;
    if (selector === 'details') return this.panel;
    if (selector === 'article.requirement:not([hidden])') return this.members.find((m) => !m.hidden) ?? null;
    throw new Error(`unexpected selector ${selector}`);
  }
}

interface World {
  root: El;
  toggle: El;
  win: El;
  box: El | null;
  shown: El;
  expand: El;
  collapse: El;
  buttons: El[];
  reqs: El[];
  groups: El[];
  storage: Map<string, string>;
}

// A requirement is an article carrying the status and holding one disclosure.
function requirement(status: string, summary: string): El {
  const el = new El();
  el.setAttribute('data-status', status);
  el.summary = { textContent: summary };
  el.panel = new El();
  return el;
}

/** The disclosure inside a requirement, which is what opens and closes. */
function panelOf(req: El): El {
  return req.panel!;
}

function run(options: { systemDark?: boolean; stored?: string; storageFails?: boolean; executive?: boolean } = {}): World {
  const root = new El();
  const toggle = new El();
  const win = new El();
  const shown = new El();
  const expand = new El();
  const collapse = new El();
  const box = options.executive ? null : new El();
  const storage = new Map<string, string>();
  if (options.stored) storage.set('hdf-report-theme', options.stored);

  const reqs = options.executive
    ? []
    : [requirement('passed', 'Passed V-1 Low Banner AC-8'), requirement('failed', 'Failed V-2 High Root login IA-2'), requirement('failed', 'Failed V-3 Low Audit AU-2')];
  const groups = options.executive ? [] : [new El(), new El()];
  if (!options.executive) {
    groups[0]!.members = [reqs[0]!];
    groups[1]!.members = [reqs[1]!, reqs[2]!];
  }
  const buttons = ['all', 'passed', 'failed'].map((status) => {
    const b = new El();
    b.setAttribute('data-status', status);
    return b;
  });

  const ids: Record<string, El | null> = {
    'theme-toggle': toggle,
    'filter-text': box,
    'filter-count': shown,
    'expand-all': expand,
    'collapse-all': collapse,
  };
  const document = {
    documentElement: root,
    getElementById: (id: string) => ids[id] ?? null,
    querySelectorAll: (selector: string) => {
      if (selector === 'article.requirement') return reqs;
      if (selector === '#results details.group') return groups;
      if (selector === 'button.filter') return buttons;
      if (selector === 'details') return [...groups, ...reqs.map(panelOf)];
      throw new Error(`unexpected selector ${selector}`);
    },
  };
  const window = {
    matchMedia: () => ({ matches: options.systemDark === true }),
    addEventListener: (event: string, listener: Listener) => win.addEventListener(event, listener),
    get localStorage() {
      if (options.storageFails) throw new Error('storage is unavailable');
      return {
        getItem: (key: string) => storage.get(key) ?? null,
        setItem: (key: string, value: string) => void storage.set(key, value),
      };
    },
  };

  new Function('document', 'window', SCRIPT)(document, window);
  return { root, toggle, win, box, shown, expand, collapse, buttons, reqs, groups, storage };
}

describe('report script: theme', () => {
  it('starts from the system setting and names the switch for what it will do', () => {
    const light = run();
    expect(light.toggle.textContent).toBe('Dark mode');
    expect(light.toggle.getAttribute('aria-label')).toBe('Switch to dark mode');
    expect(light.root.getAttribute('data-theme')).toBeNull();
    expect(light.root.classes.has('js')).toBe(true);

    const dark = run({ systemDark: true });
    expect(dark.toggle.textContent).toBe('Light mode');
    expect(dark.toggle.getAttribute('aria-label')).toBe('Switch to light mode');
  });

  it('switches on click, overriding the system setting, and remembers the choice', () => {
    const w = run({ systemDark: true });
    w.toggle.fire('click');
    expect(w.root.getAttribute('data-theme')).toBe('light');
    expect(w.toggle.textContent).toBe('Dark mode');
    expect(w.storage.get('hdf-report-theme')).toBe('light');

    w.toggle.fire('click');
    expect(w.root.getAttribute('data-theme')).toBe('dark');
    expect(w.toggle.textContent).toBe('Light mode');
    expect(w.storage.get('hdf-report-theme')).toBe('dark');
  });

  it('applies a remembered choice, and ignores a stored value that is not one', () => {
    expect(run({ stored: 'dark' }).root.getAttribute('data-theme')).toBe('dark');
    expect(run({ systemDark: true, stored: 'light' }).toggle.textContent).toBe('Dark mode');
    expect(run({ stored: 'sepia' }).root.getAttribute('data-theme')).toBeNull();
  });

  it('still switches when storage is unavailable', () => {
    const w = run({ storageFails: true });
    w.toggle.fire('click');
    expect(w.root.getAttribute('data-theme')).toBe('dark');
    expect(w.toggle.textContent).toBe('Light mode');
  });

  it('works in the executive report, which has no results filter', () => {
    const w = run({ executive: true });
    w.toggle.fire('click');
    expect(w.root.getAttribute('data-theme')).toBe('dark');
    expect(w.shown.textContent).toBe('');
  });

  it('prints everything in the light palette and restores the screen afterwards', () => {
    const chosen = run({ stored: 'dark' });
    chosen.win.fire('beforeprint');
    expect(chosen.root.getAttribute('data-theme')).toBe('light');
    expect([...chosen.groups, ...chosen.reqs.map(panelOf)].every((d) => d.open)).toBe(true);
    chosen.win.fire('afterprint');
    expect(chosen.root.getAttribute('data-theme')).toBe('dark');

    const unchosen = run({ systemDark: true });
    unchosen.win.fire('beforeprint');
    expect(unchosen.root.getAttribute('data-theme')).toBe('light');
    unchosen.win.fire('afterprint');
    expect(unchosen.root.getAttribute('data-theme')).toBeNull();
  });
});

describe('report script: results filter', () => {
  it('shows everything at first and says so', () => {
    const w = run();
    expect(w.shown.textContent).toBe('3 of 3 requirements shown');
    expect(w.reqs.every((r) => !r.hidden)).toBe(true);
    expect(w.groups.every((g) => !g.hidden && !g.open)).toBe(true);
  });

  it('filters by status, hiding groups with no match and opening the rest', () => {
    const w = run();
    w.buttons[2]!.fire('click');
    expect(w.reqs.map((r) => r.hidden)).toEqual([true, false, false]);
    expect(w.shown.textContent).toBe('2 of 3 requirements shown');
    expect(w.groups.map((g) => g.hidden)).toEqual([true, false]);
    expect(w.groups[1]!.open).toBe(true);
    expect(w.buttons.map((b) => b.getAttribute('aria-pressed'))).toEqual(['false', 'false', 'true']);

    w.buttons[0]!.fire('click');
    expect(w.reqs.every((r) => !r.hidden)).toBe(true);
    expect(w.groups.every((g) => !g.hidden)).toBe(true);
  });

  it('filters by text in the summary, case-insensitively, together with status', () => {
    const w = run();
    w.box!.value = '  LOW ';
    w.box!.fire('input');
    expect(w.reqs.map((r) => r.hidden)).toEqual([false, true, false]);

    w.buttons[2]!.fire('click');
    expect(w.reqs.map((r) => r.hidden)).toEqual([true, true, false]);
    expect(w.shown.textContent).toBe('1 of 3 requirements shown');
  });

  it('expands and collapses what is showing, and leaves what is hidden alone', () => {
    const w = run();
    w.buttons[1]!.fire('click');
    w.expand.fire('click');
    expect(w.reqs.map((r) => panelOf(r).open)).toEqual([true, false, false]);
    expect(w.groups[0]!.open).toBe(true);

    w.collapse.fire('click');
    expect(w.reqs.every((r) => !panelOf(r).open)).toBe(true);
    expect(w.groups[0]!.open).toBe(false);
  });
});
