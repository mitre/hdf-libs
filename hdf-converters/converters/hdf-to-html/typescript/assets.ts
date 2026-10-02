/**
 * The stylesheet and script are static: no document text ever reaches them.
 * They are byte-identical to the Go peer's assets.go, which the goldens pin.
 */

/**
 * The CSP source expression for SCRIPT; a test recomputes it. The policy admits
 * this one script and nothing else, so text that slipped past escaping still
 * could not run.
 */
export const SCRIPT_HASH = "sha256-qSWp8qyciIXtWkgoJwmOHQStFaBr4NYbGB5EAv9iNPg=";

export const STYLESHEET =
  ":root {\n" +
  "  color-scheme: light;\n" +
  "  --bg: #f3f5f8; --surface: #ffffff; --surface-2: #eef3f8; --ink: #16212d; --muted: #4a5968; --line: #d0d7de; --control-line: #66747f;\n" +
  "  --brand-1: #003a61; --brand-2: #005288; --on-brand: #ffffff; --accent: #005288; --on-accent: #ffffff; --focus: #0066a8; --track: #dbe4ec;\n" +
  "  --code-bg: #0f1b28; --code-ink: #e6edf3; --shadow: 0 1px 2px rgba(15, 23, 42, 0.06), 0 8px 24px rgba(15, 23, 42, 0.07);\n" +
  "  --s-passed: #2e7d32; --s-passed-on: #ffffff; --t-passed: #e8f5e9; --t-passed-on: #1b5e20;\n" +
  "  --s-failed: #c62828; --s-failed-on: #ffffff; --t-failed: #ffebee; --t-failed-on: #8e1616;\n" +
  "  --s-not-applicable: #0277bd; --s-not-applicable-on: #ffffff; --t-not-applicable: #e1f5fe; --t-not-applicable-on: #01497c;\n" +
  "  --s-not-reviewed: #b45300; --s-not-reviewed-on: #ffffff; --t-not-reviewed: #fff3e0; --t-not-reviewed-on: #7a3600;\n" +
  "  --s-error: #3f51b5; --s-error-on: #ffffff; --t-error: #e8eaf6; --t-error-on: #1a237e;\n" +
  "  --s-unknown: #5c6670; --s-unknown-on: #ffffff; --t-unknown: #e9edf1; --t-unknown-on: #16212d;\n" +
  "  --s-critical: #c62828; --s-critical-on: #ffffff; --t-critical: #ffebee; --t-critical-on: #8e1616;\n" +
  "  --s-high: #bf360c; --s-high-on: #ffffff; --t-high: #fbe9e7; --t-high-on: #8a2607;\n" +
  "  --s-medium: #b45300; --s-medium-on: #ffffff; --t-medium: #fff3e0; --t-medium-on: #7a3600;\n" +
  "  --s-low: #806600; --s-low-on: #ffffff; --t-low: #fffde7; --t-low-on: #5c4a00;\n" +
  "  --s-none: #0277bd; --s-none-on: #ffffff; --t-none: #e1f5fe; --t-none-on: #01497c;\n" +
  "}\n" +
  "@media (prefers-color-scheme: dark) {\n" +
  "  :root:not([data-theme=\"light\"]) {\n" +
  "    color-scheme: dark;\n" +
  "    --bg: #0a131d; --surface: #111e2b; --surface-2: #1a2b3d; --ink: #e8edf2; --muted: #b9c5d1; --line: #2c4056; --control-line: #8fa3b7;\n" +
  "    --brand-1: #00263f; --brand-2: #005288; --on-brand: #ffffff; --accent: #70c7f4; --on-accent: #06202f; --focus: #70c7f4; --track: #2c4056;\n" +
  "    --code-bg: #060d15; --code-ink: #e6edf3; --shadow: 0 1px 2px rgba(0, 0, 0, 0.4), 0 8px 24px rgba(0, 0, 0, 0.35);\n" +
  "    --s-passed: #4cb04f; --s-passed-on: #06200a; --t-passed: #12301a; --t-passed-on: #b9e4bb;\n" +
  "    --s-failed: #ef7a70; --s-failed-on: #2b0603; --t-failed: #3d1614; --t-failed-on: #ffc9c4;\n" +
  "    --s-not-applicable: #03a9f4; --s-not-applicable-on: #02202e; --t-not-applicable: #0c3048; --t-not-applicable-on: #b3e5fc;\n" +
  "    --s-not-reviewed: #fe9900; --s-not-reviewed-on: #2e1b00; --t-not-reviewed: #3d2a0a; --t-not-reviewed-on: #ffe0b2;\n" +
  "    --s-error: #9fa8da; --s-error-on: #10153d; --t-error: #262c58; --t-error-on: #dfe2f5;\n" +
  "    --s-unknown: #aab6c2; --s-unknown-on: #101820; --t-unknown: #26374a; --t-unknown-on: #e8edf2;\n" +
  "    --s-critical: #ef7a70; --s-critical-on: #2b0603; --t-critical: #3d1614; --t-critical-on: #ffc9c4;\n" +
  "    --s-high: #ff8a65; --s-high-on: #2e0d02; --t-high: #3f1d12; --t-high-on: #ffccbc;\n" +
  "    --s-medium: #ff9800; --s-medium-on: #2e1b00; --t-medium: #3d2a0a; --t-medium-on: #ffe0b2;\n" +
  "    --s-low: #ffeb3b; --s-low-on: #2b2600; --t-low: #3a3508; --t-low-on: #fff59d;\n" +
  "    --s-none: #03a9f4; --s-none-on: #02202e; --t-none: #0c3048; --t-none-on: #b3e5fc;\n" +
  "  }\n" +
  "}\n" +
  ":root[data-theme=\"dark\"] {\n" +
  "  color-scheme: dark;\n" +
  "  --bg: #0a131d; --surface: #111e2b; --surface-2: #1a2b3d; --ink: #e8edf2; --muted: #b9c5d1; --line: #2c4056; --control-line: #8fa3b7;\n" +
  "  --brand-1: #00263f; --brand-2: #005288; --on-brand: #ffffff; --accent: #70c7f4; --on-accent: #06202f; --focus: #70c7f4; --track: #2c4056;\n" +
  "  --code-bg: #060d15; --code-ink: #e6edf3; --shadow: 0 1px 2px rgba(0, 0, 0, 0.4), 0 8px 24px rgba(0, 0, 0, 0.35);\n" +
  "  --s-passed: #4cb04f; --s-passed-on: #06200a; --t-passed: #12301a; --t-passed-on: #b9e4bb;\n" +
  "  --s-failed: #ef7a70; --s-failed-on: #2b0603; --t-failed: #3d1614; --t-failed-on: #ffc9c4;\n" +
  "  --s-not-applicable: #03a9f4; --s-not-applicable-on: #02202e; --t-not-applicable: #0c3048; --t-not-applicable-on: #b3e5fc;\n" +
  "  --s-not-reviewed: #fe9900; --s-not-reviewed-on: #2e1b00; --t-not-reviewed: #3d2a0a; --t-not-reviewed-on: #ffe0b2;\n" +
  "  --s-error: #9fa8da; --s-error-on: #10153d; --t-error: #262c58; --t-error-on: #dfe2f5;\n" +
  "  --s-unknown: #aab6c2; --s-unknown-on: #101820; --t-unknown: #26374a; --t-unknown-on: #e8edf2;\n" +
  "  --s-critical: #ef7a70; --s-critical-on: #2b0603; --t-critical: #3d1614; --t-critical-on: #ffc9c4;\n" +
  "  --s-high: #ff8a65; --s-high-on: #2e0d02; --t-high: #3f1d12; --t-high-on: #ffccbc;\n" +
  "  --s-medium: #ff9800; --s-medium-on: #2e1b00; --t-medium: #3d2a0a; --t-medium-on: #ffe0b2;\n" +
  "  --s-low: #ffeb3b; --s-low-on: #2b2600; --t-low: #3a3508; --t-low-on: #fff59d;\n" +
  "  --s-none: #03a9f4; --s-none-on: #02202e; --t-none: #0c3048; --t-none-on: #b3e5fc;\n" +
  "}\n" +
  ".c-passed { --c: var(--s-passed); --c-on: var(--s-passed-on); --t: var(--t-passed); --t-on: var(--t-passed-on); }\n" +
  ".c-failed { --c: var(--s-failed); --c-on: var(--s-failed-on); --t: var(--t-failed); --t-on: var(--t-failed-on); }\n" +
  ".c-not-applicable { --c: var(--s-not-applicable); --c-on: var(--s-not-applicable-on); --t: var(--t-not-applicable); --t-on: var(--t-not-applicable-on); }\n" +
  ".c-not-reviewed { --c: var(--s-not-reviewed); --c-on: var(--s-not-reviewed-on); --t: var(--t-not-reviewed); --t-on: var(--t-not-reviewed-on); }\n" +
  ".c-error { --c: var(--s-error); --c-on: var(--s-error-on); --t: var(--t-error); --t-on: var(--t-error-on); }\n" +
  ".c-unknown { --c: var(--s-unknown); --c-on: var(--s-unknown-on); --t: var(--t-unknown); --t-on: var(--t-unknown-on); }\n" +
  ".c-critical { --c: var(--s-critical); --c-on: var(--s-critical-on); --t: var(--t-critical); --t-on: var(--t-critical-on); }\n" +
  ".c-high { --c: var(--s-high); --c-on: var(--s-high-on); --t: var(--t-high); --t-on: var(--t-high-on); }\n" +
  ".c-medium { --c: var(--s-medium); --c-on: var(--s-medium-on); --t: var(--t-medium); --t-on: var(--t-medium-on); }\n" +
  ".c-low { --c: var(--s-low); --c-on: var(--s-low-on); --t: var(--t-low); --t-on: var(--t-low-on); }\n" +
  ".c-none { --c: var(--s-none); --c-on: var(--s-none-on); --t: var(--t-none); --t-on: var(--t-none-on); }\n" +
  "* { box-sizing: border-box; }\n" +
  "html { scroll-padding-top: 5rem; }\n" +
  "body { font-family: system-ui, -apple-system, \"Segoe UI\", Roboto, Helvetica, Arial, sans-serif; font-size: 1rem; line-height: 1.5; color: var(--ink); background: var(--bg); margin: 0; }\n" +
  "[hidden] { display: none !important; }\n" +
  ":focus-visible { outline: 3px solid var(--focus); outline-offset: 2px; border-radius: 4px; }\n" +
  ".vh { position: absolute; width: 1px; height: 1px; margin: -1px; padding: 0; overflow: hidden; clip-path: inset(50%); white-space: nowrap; border: 0; }\n" +
  ".skip { position: absolute; left: 0.75rem; top: -4rem; z-index: 20; background: var(--surface); color: var(--ink); padding: 0.5rem 0.9rem; border-radius: 8px; border: 2px solid var(--focus); font-weight: 600; }\n" +
  ".skip:focus { top: 0.6rem; }\n" +
  ".topbar { position: sticky; top: 0; z-index: 10; display: flex; flex-wrap: wrap; align-items: center; gap: 0.4rem 1.25rem; background: linear-gradient(100deg, var(--brand-1), var(--brand-2)); color: var(--on-brand); padding: 0.85rem 1.75rem; box-shadow: 0 4px 18px rgba(15, 23, 42, 0.28); }\n" +
  ".topbar .brand { font-size: 1.2rem; font-weight: 700; letter-spacing: -0.01em; margin: 0; }\n" +
  ".topbar .report-type { font-size: 0.8rem; font-weight: 600; border: 1px solid var(--on-brand); border-radius: 999px; padding: 0.1rem 0.7rem; }\n" +
  ".topbar nav { display: flex; flex-wrap: wrap; gap: 0.25rem; margin-left: auto; }\n" +
  ".topbar a { color: var(--on-brand); text-decoration: none; font-size: 0.9rem; font-weight: 600; padding: 0.3rem 0.75rem; border-radius: 999px; }\n" +
  ".topbar a:hover { text-decoration: underline; }\n" +
  ".topbar a:focus-visible, .topbar button:focus-visible { outline-color: var(--on-brand); }\n" +
  ".theme-toggle { display: none; font: inherit; font-size: 0.85rem; font-weight: 600; min-height: 2rem; padding: 0.2rem 0.85rem; border: 1px solid var(--on-brand); border-radius: 999px; background: transparent; color: var(--on-brand); cursor: pointer; }\n" +
  ".js .theme-toggle { display: inline-flex; align-items: center; }\n" +
  ".theme-toggle:hover { background: rgba(0, 0, 0, 0.3); }\n" +
  "main { max-width: 84rem; margin: 0 auto; padding: 1.5rem 1.75rem 3.5rem; }\n" +
  ".card { background: var(--surface); border: 1px solid var(--line); border-radius: 16px; padding: 1.35rem 1.5rem 1.5rem; margin: 0 0 1.5rem; box-shadow: var(--shadow); }\n" +
  "h2 { font-size: 1.3rem; letter-spacing: -0.01em; margin: 0 0 0.85rem; }\n" +
  "h3 { font-size: 1.02rem; margin: 0 0 0.7rem; }\n" +
  "h4, h5 { font-size: 0.78rem; margin: 1.2rem 0 0.45rem; color: var(--muted); text-transform: uppercase; letter-spacing: 0.07em; }\n" +
  "a { color: var(--accent); }\n" +
  "p { margin: 0.4rem 0; }\n" +
  ".as-of, .empty, .formula { color: var(--muted); font-size: 0.88rem; }\n" +
  "details.fold { margin: 0.6rem 0; border: 1px solid var(--line); border-radius: 12px; background: var(--surface); }\n" +
  "details.fold > summary { display: flex; align-items: center; gap: 0.6rem; cursor: pointer; padding: 0.55rem 0.9rem 0.55rem 2.1rem; position: relative; list-style: none; border-radius: 12px; }\n" +
  "details.fold > summary::-webkit-details-marker { display: none; }\n" +
  "details.fold > summary::before { content: \"\"; position: absolute; left: 0.9rem; top: 50%; width: 0.5rem; height: 0.5rem; border-right: 2px solid var(--muted); border-bottom: 2px solid var(--muted); transform: translateY(-60%) rotate(-45deg); }\n" +
  "details.fold[open] > summary::before { transform: translateY(-70%) rotate(45deg); }\n" +
  "details.fold > summary:hover { background: var(--surface-2); }\n" +
  "details.fold[open] > summary { border-bottom: 1px solid var(--line); border-radius: 12px 12px 0 0; background: var(--surface-2); }\n" +
  "details.fold > summary > h3, details.fold > summary > h4, details.fold > summary > h5 { display: inline; margin: 0; min-width: 0; overflow-wrap: anywhere; }\n" +
  "details.fold > summary > .count { flex: none; }\n" +
  "details.fold > summary > h4, details.fold > summary > h5 { color: var(--ink); }\n" +
  ".fold-body { padding: 0.75rem 0.9rem 0.9rem; }\n" +
  ".fold-body > :first-child { margin-top: 0; }\n" +
  ".count { display: inline-block; min-width: 1.6rem; text-align: center; font-size: 0.75rem; font-weight: 700; border-radius: 999px; padding: 0.05rem 0.5rem; background: var(--t-unknown); color: var(--t-unknown-on); }\n" +
  ".to-top { margin: 0.9rem 0 0; font-size: 0.85rem; text-align: right; }\n" +
  ".to-top a, .page-top { font-weight: 600; }\n" +
  ".page-top { position: fixed; right: 1rem; bottom: 1rem; z-index: 9; padding: 0.4rem 0.9rem; border-radius: 999px; background: var(--accent); color: var(--on-accent); text-decoration: none; box-shadow: var(--shadow); }\n" +
  ".page-top:hover { text-decoration: underline; }\n" +
  ".dashboard { display: grid; grid-template-columns: minmax(0, 2fr) minmax(0, 1.25fr) minmax(0, 1fr); gap: 1rem; margin: 1rem 0 1.25rem; }\n" +
  ".facts { display: grid; grid-template-columns: repeat(auto-fit, minmax(20rem, 1fr)); gap: 0.75rem; align-items: start; }\n" +
  ".facts > details.fold, .components > details.fold { margin: 0; background: var(--surface-2); }\n" +
  ".panel { border: 1px solid var(--line); border-radius: 14px; padding: 1rem 1.1rem 1.15rem; background: var(--surface-2); display: flex; flex-direction: column; }\n" +
  ".stats { list-style: none; margin: 0; padding: 0; display: grid; grid-template-columns: repeat(auto-fit, minmax(8.5rem, 1fr)); gap: 0.6rem; }\n" +
  ".stat { display: flex; flex-direction: column; gap: 0.1rem; border-radius: 12px; padding: 0.65rem 0.8rem 0.7rem; background: var(--t); color: var(--t-on); border-left: 6px solid var(--c); }\n" +
  ".stat .num { font-size: 1.9rem; font-weight: 800; line-height: 1.1; font-variant-numeric: tabular-nums; }\n" +
  ".stat .lbl { font-weight: 700; font-size: 0.92rem; }\n" +
  ".stat .sub { font-size: 0.78rem; }\n" +
  ".stat-total { background: none; color: var(--ink); border: 1px dashed var(--control-line); border-left: 6px solid var(--s-unknown); }\n" +
  ".bar { display: flex; gap: 2px; height: 0.8rem; border-radius: 999px; overflow: hidden; background: var(--track); margin-top: auto; }\n" +
  ".stats + .bar { margin-top: 1rem; }\n" +
  ".seg { flex: var(--n) 0 0; background: var(--c); }\n" +
  ".compliance { text-align: center; align-items: center; }\n" +
  ".compliance h3 { align-self: flex-start; }\n" +
  ".gauge { --ring: var(--s-failed); width: 10.5rem; height: 10.5rem; margin: 0.25rem auto 0.7rem; border-radius: 50%; display: grid; place-items: center; background: conic-gradient(var(--ring) calc(var(--pct) * 1%), var(--track) 0); }\n" +
  ".gauge .pct { width: 8.1rem; height: 8.1rem; border-radius: 50%; background: var(--surface-2); display: grid; place-items: center; font-size: 1.75rem; font-weight: 800; font-variant-numeric: tabular-nums; }\n" +
  ".compliance-high .gauge { --ring: var(--s-passed); }\n" +
  ".compliance-medium .gauge { --ring: var(--s-not-reviewed); }\n" +
  ".level { font-weight: 700; display: inline-block; border-radius: 999px; padding: 0.1rem 0.85rem; background: var(--t-failed); color: var(--t-failed-on); }\n" +
  ".compliance-high .level { background: var(--t-passed); color: var(--t-passed-on); }\n" +
  ".compliance-medium .level { background: var(--t-not-reviewed); color: var(--t-not-reviewed-on); }\n" +
  "dl { display: grid; grid-template-columns: max-content 1fr; gap: 0.3rem 1.25rem; margin: 0.5rem 0; }\n" +
  "dt { font-weight: 600; color: var(--muted); }\n" +
  "dd { margin: 0; overflow-wrap: anywhere; }\n" +
  ".table-wrap { overflow-x: auto; border: 1px solid var(--line); border-radius: 12px; margin: 0.5rem 0; }\n" +
  "table { border-collapse: collapse; width: 100%; font-size: 0.9rem; }\n" +
  "caption { text-align: left; font-weight: 700; padding: 0.6rem 0.8rem; background: var(--surface-2); border-bottom: 1px solid var(--line); }\n" +
  "th, td { border-bottom: 1px solid var(--line); padding: 0.5rem 0.8rem; text-align: left; vertical-align: top; }\n" +
  "tbody tr:last-child > *, tfoot tr:last-child > * { border-bottom: 0; }\n" +
  "thead th { background: var(--surface-2); font-size: 0.78rem; text-transform: uppercase; letter-spacing: 0.05em; color: var(--muted); }\n" +
  "tfoot th, tfoot td { font-weight: 700; background: var(--surface-2); border-top: 2px solid var(--line); }\n" +
  "td.text { white-space: pre-wrap; overflow-wrap: anywhere; }\n" +
  "table.summary td, table.summary thead th:not(:first-child) { text-align: right; font-variant-numeric: tabular-nums; }\n" +
  "table.details th { width: 11.5rem; background: var(--surface-2); color: var(--muted); font-weight: 600; }\n" +
  ".components { display: grid; grid-template-columns: repeat(auto-fit, minmax(21rem, 1fr)); gap: 0.75rem; align-items: start; }\n" +
  ".component .type { font-weight: 600; font-size: 0.75rem; border-radius: 999px; padding: 0.05rem 0.6rem; background: var(--accent); color: var(--on-accent); }\n" +
  ".chips { list-style: none; display: flex; flex-wrap: wrap; gap: 0.4rem; margin: 0.25rem 0 0; padding: 0; }\n" +
  ".chips li { display: inline-flex; border: 1px solid var(--control-line); border-radius: 8px; overflow: hidden; font-size: 0.82rem; background: var(--surface); }\n" +
  ".chips .k { background: var(--t-unknown); color: var(--t-unknown-on); padding: 0.15rem 0.5rem; font-weight: 700; }\n" +
  ".chips .v { padding: 0.15rem 0.55rem; overflow-wrap: anywhere; }\n" +
  ".toolbar { display: none; flex-wrap: wrap; align-items: center; gap: 0.6rem 0.75rem; margin: 0 0 1.1rem; padding: 0.75rem; border: 1px solid var(--line); border-radius: 12px; background: var(--surface-2); }\n" +
  ".js .toolbar { display: flex; }\n" +
  ".toolbar input { flex: 1 1 16rem; font: inherit; color: var(--ink); background: var(--surface); padding: 0.45rem 0.75rem; border: 1px solid var(--control-line); border-radius: 8px; min-height: 2.25rem; }\n" +
  ".toolbar input::placeholder { color: var(--muted); opacity: 1; }\n" +
  ".toolbar button { font: inherit; font-size: 0.86rem; font-weight: 600; min-height: 2.25rem; padding: 0.3rem 0.85rem; border: 1px solid var(--control-line); border-radius: 999px; background: var(--surface); color: var(--ink); cursor: pointer; }\n" +
  ".toolbar button:hover { background: var(--t-unknown); }\n" +
  ".toolbar button[aria-pressed=\"true\"] { background: var(--accent); border-color: var(--accent); color: var(--on-accent); }\n" +
  ".filters { display: flex; flex-wrap: wrap; gap: 0.35rem; }\n" +
  ".shown { color: var(--muted); font-size: 0.86rem; margin-left: auto; }\n" +
  "details.fold.source { border-left: 5px solid var(--accent); }\n" +
  "details.fold.source > summary > h3, details.fold.baseline > summary > h3, details.fold.baseline > summary > h4 { font-size: 1.02rem; text-transform: none; letter-spacing: 0; color: var(--ink); }\n" +
  "details.requirement[open] > summary { position: sticky; top: 3.4rem; z-index: 5; }\n" +
  ".req-head, details.requirement > summary { display: grid; grid-template-columns: 9rem minmax(6rem, 11rem) 6.5rem minmax(10rem, 2fr) minmax(8rem, 1.4fr); gap: 0.85rem; align-items: center; }\n" +
  ".req-head { padding: 0.4rem 2.6rem 0.4rem 1.1rem; font-size: 0.74rem; font-weight: 700; color: var(--muted); text-transform: uppercase; letter-spacing: 0.06em; }\n" +
  "details.requirement { border: 1px solid var(--line); border-left: 6px solid var(--c); border-radius: 12px; margin: 0.5rem 0; background: var(--surface); }\n" +
  "details.requirement > summary { cursor: pointer; padding: 0.7rem 2.6rem 0.7rem 0.95rem; list-style: none; position: relative; border-radius: 0 11px 11px 0; }\n" +
  "details.requirement > summary::-webkit-details-marker { display: none; }\n" +
  "details.requirement > summary::after { content: \"\"; position: absolute; right: 1.1rem; top: 50%; width: 0.55rem; height: 0.55rem; border-right: 2px solid var(--muted); border-bottom: 2px solid var(--muted); transform: translateY(-70%) rotate(45deg); }\n" +
  "details.requirement[open] > summary::after { transform: translateY(-30%) rotate(225deg); }\n" +
  "details.requirement > summary:hover { background: var(--surface-2); }\n" +
  "details.requirement > summary:focus-visible { outline-offset: -3px; }\n" +
  "details.requirement[open] > summary { border-bottom: 1px solid var(--line); background: var(--surface-2); border-radius: 0 11px 0 0; }\n" +
  ".req-body { padding: 0.9rem 1.1rem 1.1rem; }\n" +
  ".location { display: flex; flex-wrap: wrap; align-items: center; gap: 0.6rem; margin: 0 0 0.6rem; padding: 0.5rem 0.75rem; border: 1px solid var(--line); border-left: 4px solid var(--accent); border-radius: 8px; background: var(--surface-2); }\n" +
  ".location .k, .sub .k { font-size: 0.74rem; font-weight: 700; text-transform: uppercase; letter-spacing: 0.06em; color: var(--muted); }\n" +
  "code { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 0.88rem; overflow-wrap: anywhere; }\n" +
  ".sub { display: block; margin-top: 0.35rem; font-size: 0.85rem; }\n" +
  ".baseline > dl { margin-bottom: 0.75rem; }\n" +
  ".tag.enriched { background: var(--accent); border-color: var(--accent); color: var(--on-accent); }\n" +
  "details.doc { margin-top: 0.5rem; }\n" +
  "details.doc > summary { cursor: pointer; font-weight: 600; font-size: 0.85rem; width: fit-content; }\n" +
  "details.doc > pre { white-space: pre-wrap; }\n" +
  "section.card > h3 { margin-top: 1.25rem; }\n" +
  ".req-id { font-weight: 700; overflow-wrap: anywhere; }\n" +
  ".req-title { overflow-wrap: anywhere; }\n" +
  ".tags { display: flex; flex-wrap: wrap; gap: 0.3rem; }\n" +
  ".tag { font-size: 0.75rem; font-weight: 600; border: 1px solid var(--control-line); border-radius: 999px; padding: 0.05rem 0.55rem; background: var(--surface); white-space: nowrap; }\n" +
  ".status, .sev { display: inline-flex; align-items: center; gap: 0.4rem; border-radius: 999px; padding: 0.15rem 0.7rem; font-size: 0.8rem; font-weight: 700; white-space: nowrap; width: fit-content; }\n" +
  ".status { color: var(--c-on); background: var(--c); }\n" +
  ".sev { background: var(--t); color: var(--t-on); }\n" +
  ".sev::before { content: \"\"; width: 0.6rem; height: 0.6rem; border-radius: 50%; background: var(--c); }\n" +
  "pre { margin: 0.25rem 0 0.5rem; white-space: pre-wrap; overflow-wrap: anywhere; font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 0.85rem; }\n" +
  "pre.prose { font-family: inherit; font-size: 0.92rem; margin: 0; }\n" +
  ".req-body > pre.prose { margin-bottom: 0.25rem; }\n" +
  "pre.code { background: var(--code-bg); color: var(--code-ink); border-radius: 12px; padding: 0.85rem 1rem; }\n" +
  "@media (prefers-reduced-motion: no-preference) { html { scroll-behavior: smooth; } }\n" +
  "@media (forced-colors: active) { .status, .sev, .tag, .stat, .seg, .gauge, .level, .component .type { border: 1px solid; forced-color-adjust: auto; } }\n" +
  "@media (max-width: 68rem) { .dashboard { grid-template-columns: 1fr 1fr; } .dashboard .panel:first-child { grid-column: 1 / -1; } }\n" +
  "@media (max-width: 60rem) { .topbar { position: static; } details.requirement[open] > summary { top: 0; } .req-head { display: none; } details.requirement > summary { grid-template-columns: 1fr 1fr; } .req-title, .tags { grid-column: 1 / -1; } }\n" +
  "@media (max-width: 40rem) { .dashboard { grid-template-columns: 1fr; } main { padding: 1rem 0.85rem 2.5rem; } .card { padding: 1rem; border-radius: 12px; } .topbar { padding: 0.75rem 1rem; } dl { grid-template-columns: 1fr; gap: 0 0; } dd { margin-bottom: 0.4rem; } }\n" +
  "@media print { .topbar { position: static; box-shadow: none; } .skip, .toolbar, .theme-toggle, .page-top, .to-top { display: none !important; } body { background: #ffffff; } main { max-width: none; padding: 0; } .card { box-shadow: none; } details.requirement { break-inside: avoid; } * { -webkit-print-color-adjust: exact; print-color-adjust: exact; } }\n";

export const SCRIPT =
  "(function () {\n" +
  "  'use strict';\n" +
  "  var slice = Array.prototype.slice;\n" +
  "  var root = document.documentElement;\n" +
  "  var themeKey = 'hdf-report-theme';\n" +
  "\n" +
  "  function all(selector) {\n" +
  "    return slice.call(document.querySelectorAll(selector));\n" +
  "  }\n" +
  "\n" +
  "  // Theme: the reader's choice wins over the system setting and is remembered.\n" +
  "  var toggle = document.getElementById('theme-toggle');\n" +
  "\n" +
  "  function systemDark() {\n" +
  "    return window.matchMedia('(prefers-color-scheme: dark)').matches;\n" +
  "  }\n" +
  "\n" +
  "  function currentTheme() {\n" +
  "    var chosen = root.getAttribute('data-theme');\n" +
  "    if (chosen === 'dark' || chosen === 'light') {\n" +
  "      return chosen;\n" +
  "    }\n" +
  "    return systemDark() ? 'dark' : 'light';\n" +
  "  }\n" +
  "\n" +
  "  function showTheme() {\n" +
  "    var dark = currentTheme() === 'dark';\n" +
  "    toggle.textContent = dark ? 'Light mode' : 'Dark mode';\n" +
  "    toggle.setAttribute('aria-label', dark ? 'Switch to light mode' : 'Switch to dark mode');\n" +
  "  }\n" +
  "\n" +
  "  function remember(theme) {\n" +
  "    try {\n" +
  "      window.localStorage.setItem(themeKey, theme);\n" +
  "    } catch (ignore) {\n" +
  "      return;\n" +
  "    }\n" +
  "  }\n" +
  "\n" +
  "  function recall() {\n" +
  "    try {\n" +
  "      return window.localStorage.getItem(themeKey);\n" +
  "    } catch (ignore) {\n" +
  "      return null;\n" +
  "    }\n" +
  "  }\n" +
  "\n" +
  "  var saved = recall();\n" +
  "  if (saved === 'dark' || saved === 'light') {\n" +
  "    root.setAttribute('data-theme', saved);\n" +
  "  }\n" +
  "  toggle.addEventListener('click', function () {\n" +
  "    var next = currentTheme() === 'dark' ? 'light' : 'dark';\n" +
  "    root.setAttribute('data-theme', next);\n" +
  "    remember(next);\n" +
  "    showTheme();\n" +
  "  });\n" +
  "  showTheme();\n" +
  "\n" +
  "  // Print the whole report, in the light palette, whatever is open on screen.\n" +
  "  var beforePrint = null;\n" +
  "  window.addEventListener('beforeprint', function () {\n" +
  "    beforePrint = root.getAttribute('data-theme');\n" +
  "    root.setAttribute('data-theme', 'light');\n" +
  "    all('details').forEach(function (d) {\n" +
  "      d.open = true;\n" +
  "    });\n" +
  "  });\n" +
  "  window.addEventListener('afterprint', function () {\n" +
  "    if (beforePrint === null) {\n" +
  "      root.removeAttribute('data-theme');\n" +
  "    } else {\n" +
  "      root.setAttribute('data-theme', beforePrint);\n" +
  "    }\n" +
  "  });\n" +
  "\n" +
  "  root.classList.add('js');\n" +
  "\n" +
  "  // Results filter: only the reports that list requirements carry it.\n" +
  "  var box = document.getElementById('filter-text');\n" +
  "  if (box === null) {\n" +
  "    return;\n" +
  "  }\n" +
  "  var reqs = all('details.requirement');\n" +
  "  var groups = all('#results details.group');\n" +
  "  var shown = document.getElementById('filter-count');\n" +
  "  var buttons = all('button.filter');\n" +
  "  var status = 'all';\n" +
  "\n" +
  "  function matches(d, query) {\n" +
  "    if (status !== 'all') {\n" +
  "      if (d.getAttribute('data-status') !== status) {\n" +
  "        return false;\n" +
  "      }\n" +
  "    }\n" +
  "    if (query === '') {\n" +
  "      return true;\n" +
  "    }\n" +
  "    return d.querySelector('summary').textContent.toLowerCase().indexOf(query) !== -1;\n" +
  "  }\n" +
  "\n" +
  "  function apply() {\n" +
  "    var query = box.value.trim().toLowerCase();\n" +
  "    var filtering = query !== '' || status !== 'all';\n" +
  "    var visible = 0;\n" +
  "    reqs.forEach(function (d) {\n" +
  "      var ok = matches(d, query);\n" +
  "      d.hidden = !ok;\n" +
  "      if (ok) {\n" +
  "        visible += 1;\n" +
  "      }\n" +
  "    });\n" +
  "    // A filter is no use if its matches sit inside closed groups.\n" +
  "    groups.forEach(function (g) {\n" +
  "      var any = g.querySelector('details.requirement:not([hidden])') !== null;\n" +
  "      g.hidden = filtering ? !any : false;\n" +
  "      if (filtering) {\n" +
  "        g.open = any;\n" +
  "      }\n" +
  "    });\n" +
  "    shown.textContent = visible + ' of ' + reqs.length + ' requirements shown';\n" +
  "  }\n" +
  "\n" +
  "  function setOpen(open) {\n" +
  "    groups.forEach(function (g) {\n" +
  "      if (!g.hidden) {\n" +
  "        g.open = open;\n" +
  "      }\n" +
  "    });\n" +
  "    reqs.forEach(function (d) {\n" +
  "      if (!d.hidden) {\n" +
  "        d.open = open;\n" +
  "      }\n" +
  "    });\n" +
  "  }\n" +
  "\n" +
  "  buttons.forEach(function (b) {\n" +
  "    b.addEventListener('click', function () {\n" +
  "      status = b.getAttribute('data-status');\n" +
  "      buttons.forEach(function (other) {\n" +
  "        other.setAttribute('aria-pressed', other === b ? 'true' : 'false');\n" +
  "      });\n" +
  "      apply();\n" +
  "    });\n" +
  "  });\n" +
  "  box.addEventListener('input', apply);\n" +
  "  document.getElementById('expand-all').addEventListener('click', function () {\n" +
  "    setOpen(true);\n" +
  "  });\n" +
  "  document.getElementById('collapse-all').addEventListener('click', function () {\n" +
  "    setOpen(false);\n" +
  "  });\n" +
  "  apply();\n" +
  "})();\n";
