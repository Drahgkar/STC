# data_sources.json schema

This document describes the structure of `data_sources.json`, field by
field. Every example below is copied from the real catalog, not
invented.

## Overall shape

The file has one top-level key, `log_warehouse`, containing a nested
structure four levels deep:

```
log_warehouse
  └── <platform>
        └── <service>
              └── <log source>
                    └── { mitre_tactics, mitre_techniques, siem_labels, status, ... }
```

## Platform

A platform is a product, vendor, or environment. Examples in the
current catalog: `windows`, `aws`, `paloalto_panos`,
`mobile_threat_defense`.

Platform names are lowercase, with underscores instead of spaces. This
is a raw identifier, not a display label. The mind map tool converts it
to a readable form (`paloalto_panos` becomes "Palo Alto PAN-OS") when
rendering, without changing the underlying key.

## Service

A service is a component or subsystem within a platform. Under
`windows`, for example, services include `endpoint_os`, `dns_server`,
and `active_directory`. A platform can have as few as one service or
more than a dozen.

## Log source

A log source is a specific, distinct log or event stream — the actual
thing you'd turn on or query. Under `windows/endpoint_os`, log sources
include `sysmon`, `security`, and `powershell`. This is the level every
technique mapping attaches to.

## Fields on a log source

Here's a real entry, `windows/endpoint_os/sysmon`, with its technique
list shortened for readability:

```json
{
  "mitre_tactics": ["enterprise-attack:TA0001", "..."],
  "mitre_techniques": ["enterprise-attack:T1001", "..."],
  "siem_labels": {
    "google_secops": "win:sysmon:operational",
    "splunk_sourcetype": null,
    "elastic_ecs_dataset": null,
    "sentinel_table": null,
    "wazuh_rule_group": null
  },
  "status": "unknown"
}
```

### `mitre_tactics`

An array of MITRE ATT&CK tactic IDs this source's techniques touch.
Each ID is namespaced by domain: `enterprise-attack:TA0001`,
`mobile-attack:TA0027`, or `ics-attack:TA0108`. This array is derived
from `mitre_techniques` — it's the set of tactics those techniques
belong to, not an independent claim.

### `mitre_techniques`

An array of MITRE ATT&CK technique IDs this source provides evidence
for, namespaced by domain the same way as tactics:
`enterprise-attack:T1055`, `enterprise-attack:T1055.001` for a
sub-technique, `mobile-attack:T1417`, `ics-attack:T0883`.

Every ID in this array must resolve against `mitre_reference.json`.
`validate_sources.py` checks this and fails on any ID that doesn't
exist, whether from a typo or a retired technique.

### `siem_labels`

An object with five fixed keys: `google_secops`, `splunk_sourcetype`,
`elastic_ecs_dataset`, `sentinel_table`, and `wazuh_rule_group`. Each
holds the field or label you'd use to query this source in that SIEM,
or `null` if that mapping hasn't been verified yet.

**Every entry starts with all five values set to `null`.** This
catalog ships with `siem_labels` intentionally blank across all 152
entries and 760 values — not partially filled in, not defaulted to one
SIEM over another. Don't guess a plausible-looking field name for a
SIEM you haven't actually verified against — an incorrect label is
worse than an honest `null`, since it looks authoritative and isn't.
Fill in a value only once you've confirmed it against that SIEM's real
documentation or your own working query.

Here's an illustrative example of what a fully-mapped entry looks
like once verified across all five SIEMs, for the Windows Sysmon
operational log (`windows/endpoint_os/sysmon`). This is **not** the
current state of that entry in `data_sources.json` — every entry ships
blank, as stated above — it's shown here purely to demonstrate the
shape a completed mapping takes:

```json
{
  "google_secops": "win:sysmon:operational",
  "splunk_sourcetype": "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
  "elastic_ecs_dataset": "logs-windows.sysmon_operational-*",
  "sentinel_table": "Microsoft-Windows-Sysmon/Operational",
  "wazuh_rule_group": "Microsoft-Windows-Sysmon/Operational"
}
```

Note that Sysmon's Splunk sourcetype differs by platform — the value
above is for Windows specifically. The separate `linux/endpoint_os/sysmon_linux`
entry would use `sysmon:linux` instead, not the Windows value shown
here.

#### Adding or removing a SIEM

The five keys above are not enforced by `validate_sources.py` — it
doesn't check that `siem_labels` has exactly these keys, or reject
extra ones. That means the schema itself doesn't stop you from adding
a sixth key to an entry, but doing so without also updating the
tooling below will leave that key silently unused everywhere except
the raw JSON:

1. **The flyout display table.** `generate_stc_map.py` has a hardcoded
   `labelNames` object (in the JavaScript inside `generate_html()`)
   that maps each of the five keys to the display name shown in the
   mind map's hover flyout. A new key needs an entry here, or it never
   appears in the UI at all.
2. **The `google_secops` special case.** Unlike the other four keys,
   `google_secops` gets a second, distinct use: `generate_stc_map.py`
   reads it directly (`secops_label = siem_labels.get("google_secops")`)
   to build the `[label]` suffix shown directly in the tree's log
   source labels, not just in the flyout. If you're replacing which
   SIEM gets this treatment, this is the specific line to change - it
   won't happen automatically just by editing the schema.
3. **Every existing entry.** Adding a new key to the schema doesn't
   retroactively add it to the 152 entries already in
   `data_sources.json`. For consistency, add the new key (as `null`,
   until verified) to every existing entry, not just new ones.
4. **This document.** Update the key list above.

Removing a key follows the same list in reverse - check whether any
entry actually populates it (a `grep` for the key name across
`data_sources.json` will show you), and confirm nothing outside the
schema depends on it the way `google_secops` does before deleting it.

### `status`

One of four values: `"collected"`, `"planned"`, `"not_collected"`, or
`"unknown"`. This field describes whether a source is actually
deployed and collecting, in a specific environment.

As shipped, every entry in this catalog has `status: "unknown"`. This
catalog documents what a source is technically capable of providing,
not any one organization's actual deployment. If you adopt this
catalog for your own environment, update `status` to reflect what you
genuinely collect. That's what makes the field useful.

To see a breakdown of how many sources currently have each status
value, run `python3 coverage_gap_report.py --status`. Add `--detail`
to list the individual sources in each status rather than just the
counts. See [`docs/tools-reference.md`](tools-reference.md) for the
full flag reference.

### `broad_spectrum` and `broad_spectrum_reason` (optional)

Some log sources use dynamic, vendor-driven technique tagging rather
than a fixed list STC enumerates directly — a source like this sets
`"broad_spectrum": true`. `broad_spectrum_reason` explains why, in
plain language specific to that source. Here's a real example, from
`ossec_hids/ossec_manager/ossec_alerts`:

```json
{
  "broad_spectrum": true,
  "broad_spectrum_reason": "The base/default OSSEC ruleset does not ship with MITRE ATT&CK mapping..."
}
```

Note that `broad_spectrum` doesn't always mean "more capable than a
fixed list." In this example, it means the opposite: the reasoning
explains that a fixed technique list would overstate the tool's actual
out-of-the-box capability, and the flag exists to make that limitation
explicit rather than imply broader coverage than the tool provides
without extra configuration. Read the specific `broad_spectrum_reason`
for each entry rather than assuming what the flag means.

## Related files

- **`mitre_reference.json`** holds the MITRE ATT&CK data every
  technique and tactic ID is checked against. See
  `python3 ingest_mitre_stix.py --help` for how it's built.
- **`out_of_scope_techniques.json`** is a flat object mapping a
  technique ID to a written reason it's excluded from coverage, such
  as `"enterprise-attack:T1027.003": "Steganography - requires deep
  content/statistical analysis of files to detect hidden data, not
  observable via typical event logging"`.
- **`research_needed.json`** is a list of open questions, each with a
  `source`, `flagged_reason`, `what_to_verify`, and `status` field. A
  resolved item also has a `resolution` field explaining what was
  found.
