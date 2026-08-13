# Tools reference

This document covers every script in the project except
`generate_stc_map.py`, which has its own page:
[`docs/stc-map-tool.md`](stc-map-tool.md). Every command and its output
shown below was run against the real catalog, not written from memory.

## `validate_sources.py`

Confirms every MITRE technique and tactic ID referenced in
`data_sources.json` is correctly namespaced, actually exists in
`mitre_reference.json`, sits at the expected nesting depth, and that
each source's listed tactics and techniques are mutually consistent.
Run this before committing any change to `data_sources.json`.

```
usage: validate_sources.py [-h] [--sources SOURCES] [--reference REFERENCE]

  --sources SOURCES     Path to the source catalog to validate
                         (default: data_sources.json)
  --reference REFERENCE Path to the MITRE reference file to validate
                         against (default: mitre_reference.json)
```

Exits `0` and prints `PASSED` on success. Exits `1` if it finds
integrity errors. Exits `2` if a file is missing or isn't valid JSON.

## `coverage_gap_report.py`

Reports MITRE ATT&CK coverage broken down by domain and tactic: what's
covered, what's explicitly out of scope, and what genuine gaps remain.
Also performs two integrity checks on `out_of_scope_techniques.json`
itself: that every ID in it actually exists in the reference data, and
that nothing is both covered by a source and marked out of scope at
the same time (a sign the out-of-scope entry is stale).

```
usage: coverage_gap_report.py [-h] [--sources SOURCES] [--reference REFERENCE]
                               [--out-of-scope OUT_OF_SCOPE]
                               [--domain {all,enterprise-attack,mobile-attack,ics-attack}]
                               [--detail] [--status]

  --sources SOURCES      Path to the source catalog (default: data_sources.json)
  --reference REFERENCE  Path to the MITRE reference file
                          (default: mitre_reference.json)
  --out-of-scope PATH    Path to the out-of-scope registry
                          (default: out_of_scope_techniques.json)
  --domain {...}         Restrict the report to one MITRE ATT&CK domain
                          (default: all)
  --detail               List every gap technique, not just counts
  --status               Also print a breakdown of sources by their
                          status field. Combine with --detail to list
                          the actual sources in each status.
```

`--status` example output:

```
=== Source status breakdown ===
  collected         0  (0.0%)
  planned           0  (0.0%)
  not_collected     0  (0.0%)
  unknown         152  (100.0%)
  Total sources: 152
```

If a source has a status value outside the four expected ones, the
report flags it explicitly rather than silently grouping or dropping
it:

```
  [!] 1 source(s) with an unrecognized status value: ['bogus_value']
```

## `ingest_mitre_stix.py`

Builds `mitre_reference.json` from local MITRE ATT&CK STIX bundle
files. Use this when MITRE publishes a new ATT&CK version, after
downloading the new bundles with `fetch_reference.sh`.

```
usage: ingest_mitre_stix.py [-h] [--enterprise ENTERPRISE] [--mobile MOBILE]
                             [--ics ICS] [-o OUTPUT]

  --enterprise PATH  Path to local enterprise-attack.json
  --mobile PATH      Path to local mobile-attack.json
  --ics PATH         Path to local ics-attack.json
  -o, --output PATH  Path to write the generated reference file to
                     (default: mitre_reference.json)
```

At least one of `--enterprise`, `--mobile`, or `--ics` is required.
Running the script with none of them produces a clear error rather
than an empty or broken output file:

```
Error: provide at least one of --enterprise / --mobile / --ics pointing at a locally downloaded STIX bundle.
Download from, e.g.: https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json
```

You don't need to pass all three every time, but be aware this is a
full overwrite, not a merge: the output file contains only the domains
you actually pass in that run. Running with just `--mobile` against an
existing `mitre_reference.json` that also had enterprise and ICS data
replaces the whole file with mobile-only data - it does not leave the
other two domains as they were. Pass all three domains you want
represented in the output every time you run this.

## `fetch_reference.sh`

Downloads the current MITRE ATT&CK STIX bundles for all three domains
from the official `mitre-attack/attack-stix-data` repository into
`./mitre_stix_data/`, then prints the `ingest_mitre_stix.py` command to
build `mitre_reference.json` from them. Takes no arguments. Requires
network access to `raw.githubusercontent.com`.

```
$ ./fetch_reference.sh --help
Usage: fetch_reference.sh

Downloads the current MITRE ATT&CK STIX bundles (Enterprise, Mobile,
and ICS) from the official mitre-attack/attack-stix-data repository
into ./mitre_stix_data/, then prints the ingest_mitre_stix.py command
to build mitre_reference.json from them.

Takes no arguments. Requires network access to raw.githubusercontent.com.
```

Running `--help` prints this and exits without downloading anything.

## `test_ingest_mitre.py`

Exercises `ingest_mitre_stix.py`'s STIX-parsing logic against a
hand-built fixture, checking it correctly handles the field shapes
MITRE's own STIX format documentation describes: namespacing,
sub-technique detection, tactic linkage, and a fallback path for
objects missing the expected `mitre-attack` source name. Takes no
arguments; run it directly:

```bash
python3 test_ingest_mitre.py
```

This confirms the parser logic is correct for the shapes it was
built against. It does not confirm the real, current MITRE dataset
matches this fixture exactly — that requires running
`ingest_mitre_stix.py` against a real downloaded bundle (via
`fetch_reference.sh`) and comparing the resulting counts against
[attack.mitre.org/resources/updates](https://attack.mitre.org/resources/updates/).

## `test_validate_sources.py`

Exercises `validate_sources.py`'s checks against a set of hand-built
fixture entries — a valid entry, an unnamespaced ID, an ID that
doesn't exist in the reference, a technique nested at the wrong depth,
a technique/tactic mismatch, and a `broad_spectrum` entry (which is
exempt from the normal tactic/technique requirements by design) —
confirming each one is flagged (or correctly not flagged) as expected.
Takes no arguments; run it directly:

```bash
python3 test_validate_sources.py
```
