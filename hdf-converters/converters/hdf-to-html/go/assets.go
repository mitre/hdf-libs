package hdftohtml

// The stylesheet and script are static: no document text ever reaches them. They
// are byte-identical to the TypeScript peer's assets.ts, which the goldens pin.

// scriptHash is the CSP source expression for script; a test recomputes it. The
// policy admits this one script and nothing else, so text that slipped past
// escaping still could not run.
const scriptHash = "sha256-qSWp8qyciIXtWkgoJwmOHQStFaBr4NYbGB5EAv9iNPg="

const stylesheet = `:root {
  color-scheme: light;
  --bg: #f3f5f8; --surface: #ffffff; --surface-2: #eef3f8; --ink: #16212d; --muted: #4a5968; --line: #d0d7de; --control-line: #66747f;
  --brand-1: #003a61; --brand-2: #005288; --on-brand: #ffffff; --accent: #005288; --on-accent: #ffffff; --focus: #0066a8; --track: #dbe4ec;
  --code-bg: #0f1b28; --code-ink: #e6edf3; --shadow: 0 1px 2px rgba(15, 23, 42, 0.06), 0 8px 24px rgba(15, 23, 42, 0.07);
  --s-passed: #2e7d32; --s-passed-on: #ffffff; --t-passed: #e8f5e9; --t-passed-on: #1b5e20;
  --s-failed: #c62828; --s-failed-on: #ffffff; --t-failed: #ffebee; --t-failed-on: #8e1616;
  --s-not-applicable: #0277bd; --s-not-applicable-on: #ffffff; --t-not-applicable: #e1f5fe; --t-not-applicable-on: #01497c;
  --s-not-reviewed: #b45300; --s-not-reviewed-on: #ffffff; --t-not-reviewed: #fff3e0; --t-not-reviewed-on: #7a3600;
  --s-error: #3f51b5; --s-error-on: #ffffff; --t-error: #e8eaf6; --t-error-on: #1a237e;
  --s-unknown: #5c6670; --s-unknown-on: #ffffff; --t-unknown: #e9edf1; --t-unknown-on: #16212d;
  --s-critical: #c62828; --s-critical-on: #ffffff; --t-critical: #ffebee; --t-critical-on: #8e1616;
  --s-high: #bf360c; --s-high-on: #ffffff; --t-high: #fbe9e7; --t-high-on: #8a2607;
  --s-medium: #b45300; --s-medium-on: #ffffff; --t-medium: #fff3e0; --t-medium-on: #7a3600;
  --s-low: #806600; --s-low-on: #ffffff; --t-low: #fffde7; --t-low-on: #5c4a00;
  --s-none: #0277bd; --s-none-on: #ffffff; --t-none: #e1f5fe; --t-none-on: #01497c;
}
@media (prefers-color-scheme: dark) {
  :root:not([data-theme="light"]) {
    color-scheme: dark;
    --bg: #0a131d; --surface: #111e2b; --surface-2: #1a2b3d; --ink: #e8edf2; --muted: #b9c5d1; --line: #2c4056; --control-line: #8fa3b7;
    --brand-1: #00263f; --brand-2: #005288; --on-brand: #ffffff; --accent: #70c7f4; --on-accent: #06202f; --focus: #70c7f4; --track: #2c4056;
    --code-bg: #060d15; --code-ink: #e6edf3; --shadow: 0 1px 2px rgba(0, 0, 0, 0.4), 0 8px 24px rgba(0, 0, 0, 0.35);
    --s-passed: #4cb04f; --s-passed-on: #06200a; --t-passed: #12301a; --t-passed-on: #b9e4bb;
    --s-failed: #ef7a70; --s-failed-on: #2b0603; --t-failed: #3d1614; --t-failed-on: #ffc9c4;
    --s-not-applicable: #03a9f4; --s-not-applicable-on: #02202e; --t-not-applicable: #0c3048; --t-not-applicable-on: #b3e5fc;
    --s-not-reviewed: #fe9900; --s-not-reviewed-on: #2e1b00; --t-not-reviewed: #3d2a0a; --t-not-reviewed-on: #ffe0b2;
    --s-error: #9fa8da; --s-error-on: #10153d; --t-error: #262c58; --t-error-on: #dfe2f5;
    --s-unknown: #aab6c2; --s-unknown-on: #101820; --t-unknown: #26374a; --t-unknown-on: #e8edf2;
    --s-critical: #ef7a70; --s-critical-on: #2b0603; --t-critical: #3d1614; --t-critical-on: #ffc9c4;
    --s-high: #ff8a65; --s-high-on: #2e0d02; --t-high: #3f1d12; --t-high-on: #ffccbc;
    --s-medium: #ff9800; --s-medium-on: #2e1b00; --t-medium: #3d2a0a; --t-medium-on: #ffe0b2;
    --s-low: #ffeb3b; --s-low-on: #2b2600; --t-low: #3a3508; --t-low-on: #fff59d;
    --s-none: #03a9f4; --s-none-on: #02202e; --t-none: #0c3048; --t-none-on: #b3e5fc;
  }
}
:root[data-theme="dark"] {
  color-scheme: dark;
  --bg: #0a131d; --surface: #111e2b; --surface-2: #1a2b3d; --ink: #e8edf2; --muted: #b9c5d1; --line: #2c4056; --control-line: #8fa3b7;
  --brand-1: #00263f; --brand-2: #005288; --on-brand: #ffffff; --accent: #70c7f4; --on-accent: #06202f; --focus: #70c7f4; --track: #2c4056;
  --code-bg: #060d15; --code-ink: #e6edf3; --shadow: 0 1px 2px rgba(0, 0, 0, 0.4), 0 8px 24px rgba(0, 0, 0, 0.35);
  --s-passed: #4cb04f; --s-passed-on: #06200a; --t-passed: #12301a; --t-passed-on: #b9e4bb;
  --s-failed: #ef7a70; --s-failed-on: #2b0603; --t-failed: #3d1614; --t-failed-on: #ffc9c4;
  --s-not-applicable: #03a9f4; --s-not-applicable-on: #02202e; --t-not-applicable: #0c3048; --t-not-applicable-on: #b3e5fc;
  --s-not-reviewed: #fe9900; --s-not-reviewed-on: #2e1b00; --t-not-reviewed: #3d2a0a; --t-not-reviewed-on: #ffe0b2;
  --s-error: #9fa8da; --s-error-on: #10153d; --t-error: #262c58; --t-error-on: #dfe2f5;
  --s-unknown: #aab6c2; --s-unknown-on: #101820; --t-unknown: #26374a; --t-unknown-on: #e8edf2;
  --s-critical: #ef7a70; --s-critical-on: #2b0603; --t-critical: #3d1614; --t-critical-on: #ffc9c4;
  --s-high: #ff8a65; --s-high-on: #2e0d02; --t-high: #3f1d12; --t-high-on: #ffccbc;
  --s-medium: #ff9800; --s-medium-on: #2e1b00; --t-medium: #3d2a0a; --t-medium-on: #ffe0b2;
  --s-low: #ffeb3b; --s-low-on: #2b2600; --t-low: #3a3508; --t-low-on: #fff59d;
  --s-none: #03a9f4; --s-none-on: #02202e; --t-none: #0c3048; --t-none-on: #b3e5fc;
}
.c-passed { --c: var(--s-passed); --c-on: var(--s-passed-on); --t: var(--t-passed); --t-on: var(--t-passed-on); }
.c-failed { --c: var(--s-failed); --c-on: var(--s-failed-on); --t: var(--t-failed); --t-on: var(--t-failed-on); }
.c-not-applicable { --c: var(--s-not-applicable); --c-on: var(--s-not-applicable-on); --t: var(--t-not-applicable); --t-on: var(--t-not-applicable-on); }
.c-not-reviewed { --c: var(--s-not-reviewed); --c-on: var(--s-not-reviewed-on); --t: var(--t-not-reviewed); --t-on: var(--t-not-reviewed-on); }
.c-error { --c: var(--s-error); --c-on: var(--s-error-on); --t: var(--t-error); --t-on: var(--t-error-on); }
.c-unknown { --c: var(--s-unknown); --c-on: var(--s-unknown-on); --t: var(--t-unknown); --t-on: var(--t-unknown-on); }
.c-critical { --c: var(--s-critical); --c-on: var(--s-critical-on); --t: var(--t-critical); --t-on: var(--t-critical-on); }
.c-high { --c: var(--s-high); --c-on: var(--s-high-on); --t: var(--t-high); --t-on: var(--t-high-on); }
.c-medium { --c: var(--s-medium); --c-on: var(--s-medium-on); --t: var(--t-medium); --t-on: var(--t-medium-on); }
.c-low { --c: var(--s-low); --c-on: var(--s-low-on); --t: var(--t-low); --t-on: var(--t-low-on); }
.c-none { --c: var(--s-none); --c-on: var(--s-none-on); --t: var(--t-none); --t-on: var(--t-none-on); }
* { box-sizing: border-box; }
html { scroll-padding-top: 5rem; }
body { font-family: system-ui, -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; font-size: 1rem; line-height: 1.5; color: var(--ink); background: var(--bg); margin: 0; }
[hidden] { display: none !important; }
:focus-visible { outline: 3px solid var(--focus); outline-offset: 2px; border-radius: 4px; }
.vh { position: absolute; width: 1px; height: 1px; margin: -1px; padding: 0; overflow: hidden; clip-path: inset(50%); white-space: nowrap; border: 0; }
.skip { position: absolute; left: 0.75rem; top: -4rem; z-index: 20; background: var(--surface); color: var(--ink); padding: 0.5rem 0.9rem; border-radius: 8px; border: 2px solid var(--focus); font-weight: 600; }
.skip:focus { top: 0.6rem; }
.topbar { position: sticky; top: 0; z-index: 10; display: flex; flex-wrap: wrap; align-items: center; gap: 0.4rem 1.25rem; background: linear-gradient(100deg, var(--brand-1), var(--brand-2)); color: var(--on-brand); padding: 0.85rem 1.75rem; box-shadow: 0 4px 18px rgba(15, 23, 42, 0.28); }
.topbar .brand { font-size: 1.2rem; font-weight: 700; letter-spacing: -0.01em; margin: 0; }
.topbar .report-type { font-size: 0.8rem; font-weight: 600; border: 1px solid var(--on-brand); border-radius: 999px; padding: 0.1rem 0.7rem; }
.topbar nav { display: flex; flex-wrap: wrap; gap: 0.25rem; margin-left: auto; }
.topbar a { color: var(--on-brand); text-decoration: none; font-size: 0.9rem; font-weight: 600; padding: 0.3rem 0.75rem; border-radius: 999px; }
.topbar a:hover { text-decoration: underline; }
.topbar a:focus-visible, .topbar button:focus-visible { outline-color: var(--on-brand); }
.theme-toggle { display: none; font: inherit; font-size: 0.85rem; font-weight: 600; min-height: 2rem; padding: 0.2rem 0.85rem; border: 1px solid var(--on-brand); border-radius: 999px; background: transparent; color: var(--on-brand); cursor: pointer; }
.js .theme-toggle { display: inline-flex; align-items: center; }
.theme-toggle:hover { background: rgba(0, 0, 0, 0.3); }
main { max-width: 84rem; margin: 0 auto; padding: 1.5rem 1.75rem 3.5rem; }
.card { background: var(--surface); border: 1px solid var(--line); border-radius: 16px; padding: 1.35rem 1.5rem 1.5rem; margin: 0 0 1.5rem; box-shadow: var(--shadow); }
h2 { font-size: 1.3rem; letter-spacing: -0.01em; margin: 0 0 0.85rem; }
h3 { font-size: 1.02rem; margin: 0 0 0.7rem; }
h4, h5 { font-size: 0.78rem; margin: 1.2rem 0 0.45rem; color: var(--muted); text-transform: uppercase; letter-spacing: 0.07em; }
a { color: var(--accent); }
p { margin: 0.4rem 0; }
.as-of, .empty, .formula { color: var(--muted); font-size: 0.88rem; }
details.fold { margin: 0.6rem 0; border: 1px solid var(--line); border-radius: 12px; background: var(--surface); }
details.fold > summary { display: flex; align-items: center; gap: 0.6rem; cursor: pointer; padding: 0.55rem 0.9rem 0.55rem 2.1rem; position: relative; list-style: none; border-radius: 12px; }
details.fold > summary::-webkit-details-marker { display: none; }
details.fold > summary::before { content: ""; position: absolute; left: 0.9rem; top: 50%; width: 0.5rem; height: 0.5rem; border-right: 2px solid var(--muted); border-bottom: 2px solid var(--muted); transform: translateY(-60%) rotate(-45deg); }
details.fold[open] > summary::before { transform: translateY(-70%) rotate(45deg); }
details.fold > summary:hover { background: var(--surface-2); }
details.fold[open] > summary { border-bottom: 1px solid var(--line); border-radius: 12px 12px 0 0; background: var(--surface-2); }
details.fold > summary > h3, details.fold > summary > h4, details.fold > summary > h5 { display: inline; margin: 0; min-width: 0; overflow-wrap: anywhere; }
details.fold > summary > .count { flex: none; }
details.fold > summary > h4, details.fold > summary > h5 { color: var(--ink); }
.fold-body { padding: 0.75rem 0.9rem 0.9rem; }
.fold-body > :first-child { margin-top: 0; }
.count { display: inline-block; min-width: 1.6rem; text-align: center; font-size: 0.75rem; font-weight: 700; border-radius: 999px; padding: 0.05rem 0.5rem; background: var(--t-unknown); color: var(--t-unknown-on); }
.to-top { margin: 0.9rem 0 0; font-size: 0.85rem; text-align: right; }
.to-top a, .page-top { font-weight: 600; }
.page-top { position: fixed; right: 1rem; bottom: 1rem; z-index: 9; padding: 0.4rem 0.9rem; border-radius: 999px; background: var(--accent); color: var(--on-accent); text-decoration: none; box-shadow: var(--shadow); }
.page-top:hover { text-decoration: underline; }
.dashboard { display: grid; grid-template-columns: minmax(0, 2fr) minmax(0, 1.25fr) minmax(0, 1fr); gap: 1rem; margin: 1rem 0 1.25rem; }
.facts { display: grid; grid-template-columns: repeat(auto-fit, minmax(20rem, 1fr)); gap: 0.75rem; align-items: start; }
.facts > details.fold, .components > details.fold { margin: 0; background: var(--surface-2); }
.panel { border: 1px solid var(--line); border-radius: 14px; padding: 1rem 1.1rem 1.15rem; background: var(--surface-2); display: flex; flex-direction: column; }
.stats { list-style: none; margin: 0; padding: 0; display: grid; grid-template-columns: repeat(auto-fit, minmax(8.5rem, 1fr)); gap: 0.6rem; }
.stat { display: flex; flex-direction: column; gap: 0.1rem; border-radius: 12px; padding: 0.65rem 0.8rem 0.7rem; background: var(--t); color: var(--t-on); border-left: 6px solid var(--c); }
.stat .num { font-size: 1.9rem; font-weight: 800; line-height: 1.1; font-variant-numeric: tabular-nums; }
.stat .lbl { font-weight: 700; font-size: 0.92rem; }
.stat .sub { font-size: 0.78rem; }
.stat-total { background: none; color: var(--ink); border: 1px dashed var(--control-line); border-left: 6px solid var(--s-unknown); }
.bar { display: flex; gap: 2px; height: 0.8rem; border-radius: 999px; overflow: hidden; background: var(--track); margin-top: auto; }
.stats + .bar { margin-top: 1rem; }
.seg { flex: var(--n) 0 0; background: var(--c); }
.compliance { text-align: center; align-items: center; }
.compliance h3 { align-self: flex-start; }
.gauge { --ring: var(--s-failed); width: 10.5rem; height: 10.5rem; margin: 0.25rem auto 0.7rem; border-radius: 50%; display: grid; place-items: center; background: conic-gradient(var(--ring) calc(var(--pct) * 1%), var(--track) 0); }
.gauge .pct { width: 8.1rem; height: 8.1rem; border-radius: 50%; background: var(--surface-2); display: grid; place-items: center; font-size: 1.75rem; font-weight: 800; font-variant-numeric: tabular-nums; }
.compliance-high .gauge { --ring: var(--s-passed); }
.compliance-medium .gauge { --ring: var(--s-not-reviewed); }
.level { font-weight: 700; display: inline-block; border-radius: 999px; padding: 0.1rem 0.85rem; background: var(--t-failed); color: var(--t-failed-on); }
.compliance-high .level { background: var(--t-passed); color: var(--t-passed-on); }
.compliance-medium .level { background: var(--t-not-reviewed); color: var(--t-not-reviewed-on); }
dl { display: grid; grid-template-columns: max-content 1fr; gap: 0.3rem 1.25rem; margin: 0.5rem 0; }
dt { font-weight: 600; color: var(--muted); }
dd { margin: 0; overflow-wrap: anywhere; }
.table-wrap { overflow-x: auto; border: 1px solid var(--line); border-radius: 12px; margin: 0.5rem 0; }
table { border-collapse: collapse; width: 100%; font-size: 0.9rem; }
caption { text-align: left; font-weight: 700; padding: 0.6rem 0.8rem; background: var(--surface-2); border-bottom: 1px solid var(--line); }
th, td { border-bottom: 1px solid var(--line); padding: 0.5rem 0.8rem; text-align: left; vertical-align: top; }
tbody tr:last-child > *, tfoot tr:last-child > * { border-bottom: 0; }
thead th { background: var(--surface-2); font-size: 0.78rem; text-transform: uppercase; letter-spacing: 0.05em; color: var(--muted); }
tfoot th, tfoot td { font-weight: 700; background: var(--surface-2); border-top: 2px solid var(--line); }
td.text { white-space: pre-wrap; overflow-wrap: anywhere; }
table.summary td, table.summary thead th:not(:first-child) { text-align: right; font-variant-numeric: tabular-nums; }
table.details th { width: 11.5rem; background: var(--surface-2); color: var(--muted); font-weight: 600; }
.components { display: grid; grid-template-columns: repeat(auto-fit, minmax(21rem, 1fr)); gap: 0.75rem; align-items: start; }
.component .type { font-weight: 600; font-size: 0.75rem; border-radius: 999px; padding: 0.05rem 0.6rem; background: var(--accent); color: var(--on-accent); }
.chips { list-style: none; display: flex; flex-wrap: wrap; gap: 0.4rem; margin: 0.25rem 0 0; padding: 0; }
.chips li { display: inline-flex; border: 1px solid var(--control-line); border-radius: 8px; overflow: hidden; font-size: 0.82rem; background: var(--surface); }
.chips .k { background: var(--t-unknown); color: var(--t-unknown-on); padding: 0.15rem 0.5rem; font-weight: 700; }
.chips .v { padding: 0.15rem 0.55rem; overflow-wrap: anywhere; }
.toolbar { display: none; flex-wrap: wrap; align-items: center; gap: 0.6rem 0.75rem; margin: 0 0 1.1rem; padding: 0.75rem; border: 1px solid var(--line); border-radius: 12px; background: var(--surface-2); }
.js .toolbar { display: flex; }
.toolbar input { flex: 1 1 16rem; font: inherit; color: var(--ink); background: var(--surface); padding: 0.45rem 0.75rem; border: 1px solid var(--control-line); border-radius: 8px; min-height: 2.25rem; }
.toolbar input::placeholder { color: var(--muted); opacity: 1; }
.toolbar button { font: inherit; font-size: 0.86rem; font-weight: 600; min-height: 2.25rem; padding: 0.3rem 0.85rem; border: 1px solid var(--control-line); border-radius: 999px; background: var(--surface); color: var(--ink); cursor: pointer; }
.toolbar button:hover { background: var(--t-unknown); }
.toolbar button[aria-pressed="true"] { background: var(--accent); border-color: var(--accent); color: var(--on-accent); }
.filters { display: flex; flex-wrap: wrap; gap: 0.35rem; }
.shown { color: var(--muted); font-size: 0.86rem; margin-left: auto; }
details.fold.source { border-left: 5px solid var(--accent); }
details.fold.source > summary > h3, details.fold.baseline > summary > h3, details.fold.baseline > summary > h4 { font-size: 1.02rem; text-transform: none; letter-spacing: 0; color: var(--ink); }
details.requirement[open] > summary { position: sticky; top: 3.4rem; z-index: 5; }
.req-head, details.requirement > summary { display: grid; grid-template-columns: 9rem minmax(6rem, 11rem) 6.5rem minmax(10rem, 2fr) minmax(8rem, 1.4fr); gap: 0.85rem; align-items: center; }
.req-head { padding: 0.4rem 2.6rem 0.4rem 1.1rem; font-size: 0.74rem; font-weight: 700; color: var(--muted); text-transform: uppercase; letter-spacing: 0.06em; }
details.requirement { border: 1px solid var(--line); border-left: 6px solid var(--c); border-radius: 12px; margin: 0.5rem 0; background: var(--surface); }
details.requirement > summary { cursor: pointer; padding: 0.7rem 2.6rem 0.7rem 0.95rem; list-style: none; position: relative; border-radius: 0 11px 11px 0; }
details.requirement > summary::-webkit-details-marker { display: none; }
details.requirement > summary::after { content: ""; position: absolute; right: 1.1rem; top: 50%; width: 0.55rem; height: 0.55rem; border-right: 2px solid var(--muted); border-bottom: 2px solid var(--muted); transform: translateY(-70%) rotate(45deg); }
details.requirement[open] > summary::after { transform: translateY(-30%) rotate(225deg); }
details.requirement > summary:hover { background: var(--surface-2); }
details.requirement > summary:focus-visible { outline-offset: -3px; }
details.requirement[open] > summary { border-bottom: 1px solid var(--line); background: var(--surface-2); border-radius: 0 11px 0 0; }
.req-body { padding: 0.9rem 1.1rem 1.1rem; }
.location { display: flex; flex-wrap: wrap; align-items: center; gap: 0.6rem; margin: 0 0 0.6rem; padding: 0.5rem 0.75rem; border: 1px solid var(--line); border-left: 4px solid var(--accent); border-radius: 8px; background: var(--surface-2); }
.location .k, .sub .k { font-size: 0.74rem; font-weight: 700; text-transform: uppercase; letter-spacing: 0.06em; color: var(--muted); }
code { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 0.88rem; overflow-wrap: anywhere; }
.sub { display: block; margin-top: 0.35rem; font-size: 0.85rem; }
.baseline > dl { margin-bottom: 0.75rem; }
.tag.enriched { background: var(--accent); border-color: var(--accent); color: var(--on-accent); }
details.doc { margin-top: 0.5rem; }
details.doc > summary { cursor: pointer; font-weight: 600; font-size: 0.85rem; width: fit-content; }
details.doc > pre { white-space: pre-wrap; }
section.card > h3 { margin-top: 1.25rem; }
.req-id { font-weight: 700; overflow-wrap: anywhere; }
.req-title { overflow-wrap: anywhere; }
.tags { display: flex; flex-wrap: wrap; gap: 0.3rem; }
.tag { font-size: 0.75rem; font-weight: 600; border: 1px solid var(--control-line); border-radius: 999px; padding: 0.05rem 0.55rem; background: var(--surface); white-space: nowrap; }
.status, .sev { display: inline-flex; align-items: center; gap: 0.4rem; border-radius: 999px; padding: 0.15rem 0.7rem; font-size: 0.8rem; font-weight: 700; white-space: nowrap; width: fit-content; }
.status { color: var(--c-on); background: var(--c); }
.sev { background: var(--t); color: var(--t-on); }
.sev::before { content: ""; width: 0.6rem; height: 0.6rem; border-radius: 50%; background: var(--c); }
pre { margin: 0.25rem 0 0.5rem; white-space: pre-wrap; overflow-wrap: anywhere; font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 0.85rem; }
pre.prose { font-family: inherit; font-size: 0.92rem; margin: 0; }
.req-body > pre.prose { margin-bottom: 0.25rem; }
pre.code { background: var(--code-bg); color: var(--code-ink); border-radius: 12px; padding: 0.85rem 1rem; }
@media (prefers-reduced-motion: no-preference) { html { scroll-behavior: smooth; } }
@media (forced-colors: active) { .status, .sev, .tag, .stat, .seg, .gauge, .level, .component .type { border: 1px solid; forced-color-adjust: auto; } }
@media (max-width: 68rem) { .dashboard { grid-template-columns: 1fr 1fr; } .dashboard .panel:first-child { grid-column: 1 / -1; } }
@media (max-width: 60rem) { .topbar { position: static; } details.requirement[open] > summary { top: 0; } .req-head { display: none; } details.requirement > summary { grid-template-columns: 1fr 1fr; } .req-title, .tags { grid-column: 1 / -1; } }
@media (max-width: 40rem) { .dashboard { grid-template-columns: 1fr; } main { padding: 1rem 0.85rem 2.5rem; } .card { padding: 1rem; border-radius: 12px; } .topbar { padding: 0.75rem 1rem; } dl { grid-template-columns: 1fr; gap: 0 0; } dd { margin-bottom: 0.4rem; } }
@media print { .topbar { position: static; box-shadow: none; } .skip, .toolbar, .theme-toggle, .page-top, .to-top { display: none !important; } body { background: #ffffff; } main { max-width: none; padding: 0; } .card { box-shadow: none; } details.requirement { break-inside: avoid; } * { -webkit-print-color-adjust: exact; print-color-adjust: exact; } }
`

const script = `(function () {
  'use strict';
  var slice = Array.prototype.slice;
  var root = document.documentElement;
  var themeKey = 'hdf-report-theme';

  function all(selector) {
    return slice.call(document.querySelectorAll(selector));
  }

  // Theme: the reader's choice wins over the system setting and is remembered.
  var toggle = document.getElementById('theme-toggle');

  function systemDark() {
    return window.matchMedia('(prefers-color-scheme: dark)').matches;
  }

  function currentTheme() {
    var chosen = root.getAttribute('data-theme');
    if (chosen === 'dark' || chosen === 'light') {
      return chosen;
    }
    return systemDark() ? 'dark' : 'light';
  }

  function showTheme() {
    var dark = currentTheme() === 'dark';
    toggle.textContent = dark ? 'Light mode' : 'Dark mode';
    toggle.setAttribute('aria-label', dark ? 'Switch to light mode' : 'Switch to dark mode');
  }

  function remember(theme) {
    try {
      window.localStorage.setItem(themeKey, theme);
    } catch (ignore) {
      return;
    }
  }

  function recall() {
    try {
      return window.localStorage.getItem(themeKey);
    } catch (ignore) {
      return null;
    }
  }

  var saved = recall();
  if (saved === 'dark' || saved === 'light') {
    root.setAttribute('data-theme', saved);
  }
  toggle.addEventListener('click', function () {
    var next = currentTheme() === 'dark' ? 'light' : 'dark';
    root.setAttribute('data-theme', next);
    remember(next);
    showTheme();
  });
  showTheme();

  // Print the whole report, in the light palette, whatever is open on screen.
  var beforePrint = null;
  window.addEventListener('beforeprint', function () {
    beforePrint = root.getAttribute('data-theme');
    root.setAttribute('data-theme', 'light');
    all('details').forEach(function (d) {
      d.open = true;
    });
  });
  window.addEventListener('afterprint', function () {
    if (beforePrint === null) {
      root.removeAttribute('data-theme');
    } else {
      root.setAttribute('data-theme', beforePrint);
    }
  });

  root.classList.add('js');

  // Results filter: only the reports that list requirements carry it.
  var box = document.getElementById('filter-text');
  if (box === null) {
    return;
  }
  var reqs = all('details.requirement');
  var groups = all('#results details.group');
  var shown = document.getElementById('filter-count');
  var buttons = all('button.filter');
  var status = 'all';

  function matches(d, query) {
    if (status !== 'all') {
      if (d.getAttribute('data-status') !== status) {
        return false;
      }
    }
    if (query === '') {
      return true;
    }
    return d.querySelector('summary').textContent.toLowerCase().indexOf(query) !== -1;
  }

  function apply() {
    var query = box.value.trim().toLowerCase();
    var filtering = query !== '' || status !== 'all';
    var visible = 0;
    reqs.forEach(function (d) {
      var ok = matches(d, query);
      d.hidden = !ok;
      if (ok) {
        visible += 1;
      }
    });
    // A filter is no use if its matches sit inside closed groups.
    groups.forEach(function (g) {
      var any = g.querySelector('details.requirement:not([hidden])') !== null;
      g.hidden = filtering ? !any : false;
      if (filtering) {
        g.open = any;
      }
    });
    shown.textContent = visible + ' of ' + reqs.length + ' requirements shown';
  }

  function setOpen(open) {
    groups.forEach(function (g) {
      if (!g.hidden) {
        g.open = open;
      }
    });
    reqs.forEach(function (d) {
      if (!d.hidden) {
        d.open = open;
      }
    });
  }

  buttons.forEach(function (b) {
    b.addEventListener('click', function () {
      status = b.getAttribute('data-status');
      buttons.forEach(function (other) {
        other.setAttribute('aria-pressed', other === b ? 'true' : 'false');
      });
      apply();
    });
  });
  box.addEventListener('input', apply);
  document.getElementById('expand-all').addEventListener('click', function () {
    setOpen(true);
  });
  document.getElementById('collapse-all').addEventListener('click', function () {
    setOpen(false);
  });
  apply();
})();
`
