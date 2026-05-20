# `hdf generate upgrade`

Upgrade an HDF Baseline — or a full InSpec profile — using a newer release of
its underlying security baseline document. `upgrade` matches your requirements
against the new version, then merges them: the new guidance supplies updated
titles, descriptions, and metadata, while your test code and local
customizations are preserved.

```
hdf generate upgrade <current> <upstream> [flags]
```

- **`<current>`** — what you have now: an InSpec profile directory, or an
  HDF Results / HDF Baseline / InSpec JSON / XCCDF file.
- **`<upstream>`** — the new guidance: typically a freshly released XCCDF
  benchmark, or another HDF Baseline.

`delta` is an alias for `upgrade`, to reflect the historical delta capability
in the SAF CLI.

## Requirements

Upgrading an InSpec **profile directory** requires `cinc-auditor` or `inspec`
on your `PATH` — `upgrade` uses it to read the profile. File inputs need no
external tools.

## Update an InSpec profile in place

The common case: you maintain an InSpec profile and a new STIG release just
dropped. Point `upgrade` at the profile directory and the new XCCDF:

```
hdf generate upgrade ./my-stig-profile/ ./new-stig-xccdf.xml
```

This updates `controls/*.rb` in place — merged metadata, your test code intact
— removes controls the new release dropped, and leaves `inspec.yml` untouched.
A summary (`baseline.json`, `delta.json`, `delta.md`) is written to
`./my-stig-profile/.upgrade/`.

## Review the upgrade before applying it

Pass `-o` to write a fresh, upgraded copy and leave the original untouched —
useful for diffing the result before you commit it:

```
hdf generate upgrade ./my-stig-profile/ ./new-stig-xccdf.xml -o ./upgraded/
```

## Keep controls the new release dropped

By default, controls absent from the new guidance are removed. To keep them —
for example, custom controls you authored outside the STIG — add
`--keep-unmatched`:

```
hdf generate upgrade ./my-stig-profile/ ./new-stig-xccdf.xml --keep-unmatched
```

## Upgrade a baseline without an InSpec profile

When `<current>` is a file, `upgrade` produces an HDF Baseline. With no `-o` it
prints to stdout, so you can pipe it:

```
hdf generate upgrade old-baseline.json new-stig-xccdf.xml > upgraded.json
```

Add `-o <dir>` to write `baseline.json` to a directory instead, or
`--report-dir <dir>` to also save the `delta.json` / `delta.md` reports.

To turn the resulting baseline into an InSpec profile, follow up with
`hdf generate inspec-profile`.

## Resolve conflicts your way

When your customizations and the new guidance disagree on a field, `--prefer`
controls the outcome:

```
hdf generate upgrade ./my-stig-profile/ ./new.xml --prefer current
```

- *(default)* — new guidance wins on metadata; your code is kept.
- `--prefer current` — your values win on every conflict.
- `--prefer upstream` — take the new guidance verbatim.

## How upgrade matches controls

`upgrade` does not pair controls by ID, because IDs cannot be assumed to be
stable between releases of a security baseline document in many cases. For
example, STIG control IDs (`SV-NNNNN`) are reassigned between releases, so an
ID-based comparison would report a renamed control as one deletion plus one
addition — and drop your test code along with it.

Instead it matches by *meaning*, in two tiers:

- **SRG match.** Every STIG control implements a requirement from a Security
  Requirements Guide (SRG), recorded in its `gtitle` tag. Controls on both
  sides that implement the same SRG requirement are paired directly — the
  clean, unambiguous case.

- **CCI Jaccard tiebreak.** When several controls share one SRG requirement,
  an SRG match alone is ambiguous. `upgrade` then scores each candidate by how
  much their CCI (Control Correlation Identifier) sets overlap — the Jaccard
  similarity, intersection over union — together with title similarity, and
  picks the strongest match.

Further fallback strategies handle cross-vendor cases, such as matching a
control to its equivalent on another platform by title similarity.

Because matching is meaning-based, `upgrade` follows a control across an ID
change instead of losing it. The `delta.md` report records which method
matched each control, so you can review any pairing you want to double-check.

## Flags

| Flag | Purpose |
|---|---|
| `-o, --output-dir` | Write output here instead of in place (profile dir) or stdout (file input). |
| `--report-dir` | Where to write `delta.json` / `delta.md`. Defaults to `.upgrade/` for profile inputs. |
| `--keep-unmatched` | Keep controls absent from the new guidance instead of dropping them. |
| `--prefer` | Conflict resolution: `current` or `upstream`. |
| `--no-code` | Don't carry your existing test code forward. |
| `-T, --id-type` | XCCDF ID field to use: `rule`, `group`, `cis`, `version`. |

Run `hdf generate upgrade --help` for the full flag reference.
