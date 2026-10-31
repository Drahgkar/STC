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
    "google_secops": "WINDOWS_SYSMON",
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

**A value is set only once it's verified.** Don't guess a
plausible-looking field name for a SIEM you haven't actually verified
against — an incorrect label is worse than an honest `null`, since it
looks authoritative and isn't. Fill in a value only once you've
confirmed it against that SIEM's real documentation or your own
working query.

**A vendor with several products means the current one.** When a
source names a vendor that sells several products or collection paths
(Ping Identity, Proofpoint, Mimecast, Claroty), STC assumes the
vendor's current product or connector. The source's resolved
`research_needed.json` entry names the assumption, so you can change
the value if your environment uses a different product.

`google_secops` holds the source's **ingestion label**: the log type
that selects the Google SecOps parser, such as `WINEVTLOG` or
`WINDOWS_SYSMON`. Search it as `metadata.log_type`. Several sources can
share a label; the Windows Security, System, and Application logs all
ingest as `WINEVTLOG`. Values come from Google's
[Supported log types and default parsers](https://docs.cloud.google.com/chronicle/docs/ingestion/parser-list/supported-default-parsers)
list, using these rules:

- **A parser for the product wins.** If Google has a parser for the
  source's product, use its label, even when the parser's doc page
  doesn't name that specific log.
- **Syslog falls back to `NIX_SYSTEM`.** Linux logs that arrive over
  syslog with no parser of their own use `NIX_SYSTEM`, the same label
  as the syslog source.
- **Two candidate parsers means `null`.** When more than one parser
  fits and the docs don't settle it, leave the value `null` until
  someone picks.

Where a label rests on a rule rather than on the parser's doc page,
the matching `research_needed.json` entry is marked resolved and says
so. Google SecOps labels are set for 116 of 152 sources. Each source
left `null` has an unresolved `research_needed.json` entry naming the
candidate parsers and what's left to verify.

`elastic_ecs_dataset` holds the source's **data stream dataset**: the
`data_stream.dataset` of the Elastic integration that collects it,
such as `system.security` or `windows.sysmon_operational`. Search it as
`event.dataset`. It's the dataset name only, not an index pattern like
`logs-windows.sysmon_operational-*`. Values come from the
[Elastic Package Registry](https://epr.elastic.co/search), which lists
each integration's data streams, using these rules:

- **A data stream that names the log wins.** For example, the Windows
  Security log uses `system.security`.
- **A product's single generic stream covers all its logs.** When an
  integration has one logs stream for the whole product, such as
  `panw.panos`, every log from that product uses it.
- **Syslog falls back to `system.syslog`.** Linux logs that arrive
  over syslog with no stream of their own use `system.syslog`.
- **Two candidate streams means `null`.** When more than one stream or
  integration fits, or one source spans several streams (Zeek has one
  per log), leave the value `null` until someone picks.

Elastic datasets are set for 83 of 152 sources. As with Google SecOps,
each source left `null` has an unresolved `research_needed.json` entry,
and each label that rests on a rule or a beta integration has a
resolved entry that says so.

`sentinel_table` holds the **Log Analytics table** the source lands in
when Microsoft Sentinel collects it, such as `SecurityEvent` or
`CommonSecurityLog`. Search it by using the table name as the first
line of a KQL query. Values come from Microsoft's
[tables and connectors reference](https://learn.microsoft.com/en-us/azure/sentinel/sentinel-tables-connectors-reference)
and the connector definitions in the
[Azure-Sentinel repository](https://github.com/Azure/Azure-Sentinel),
using these rules:

- **The product's Sentinel connector wins.** If Sentinel has a data
  connector for the product, use the table it writes. For example, the
  Windows Security log uses `SecurityEvent` through the Windows
  Security Events via AMA connector.
- **Deprecated device connectors keep their table.** Many CEF and
  syslog device connectors are marked deprecated. Microsoft documents
  collecting those devices with the generic CEF via AMA or Syslog via
  AMA connector instead, which writes the same `CommonSecurityLog` or
  `Syslog` table.
- **No connector means the Azure Monitor Agent default.** Windows
  event log channels go to `Event`, and syslog messages go to `Syslog`.
  Text log files go to a table the analyst names, so those stay `null`.
- **Two candidate tables means `null`.** When more than one connector
  or table fits, or one source spans several tables, leave the value
  `null` until someone picks.

Sentinel tables are set for 93 of 152 sources. Each source left `null`
has an unresolved `research_needed.json` entry, and each label that
rests on a rule has a resolved entry that says so.

`splunk_sourcetype` holds the **source type** the source is indexed
under, such as `XmlWinEventLog` or `pan:traffic`. Search it as
`sourcetype=`. It's the source type only, not the `source` field,
which for Windows event logs names the channel (for example,
`XmlWinEventLog:Security`). Values come from the documentation of the
Splunk add-ons on [Splunkbase](https://splunkbase.splunk.com/), most
of which Splunk publishes at `splunk.github.io/splunk-add-on-for-<product>`,
using these rules, in order:

- **The product's Splunk-supported add-on wins.** For example, the
  Okta System Log uses `OktaIM2:log` from the Splunk Add-on for Okta
  Identity Cloud.
- **Windows event log channels use `XmlWinEventLog`.** Since version
  6.0.0, the Splunk Add-on for Microsoft Windows renders event log
  inputs as XML by default, for any channel. The exception is a channel
  that a product add-on names its own source type for, such as Hyper-V.
- **Splunk Connect for Syslog covers syslog devices.** When no
  Splunk-supported add-on exists, use the source type that
  [Splunk Connect for Syslog](https://github.com/splunk/splunk-connect-for-syslog)
  documents for the product, such as `pan:traffic` or `fgt_traffic`.
- **A vendor-built add-on counts when the vendor documents it.** An
  add-on built by the product's vendor counts if the vendor's own docs
  name the source type. Community-built add-ons don't count.
- **Pretrained source types cover the rest.** Splunk's
  [pretrained source types](https://help.splunk.com/en/data-management/onboard-data-to-splunk-enterprise/get-data-in/10.6/configure-source-types/list-of-pretrained-source-types)
  name some logs directly, such as `cups_access` and `asterisk_cdr`.
  Linux logs that arrive over syslog with no source type of their own
  use `syslog`.
- **A product's single source type covers all its logs.** When the
  add-on has one source type for the whole product, such as
  `cisco:asa`, every log from that product uses it. When an add-on
  offers several formats of the same log, use the one for the
  product's default format, such as `apache:access:combined`.
- **Two candidate source types means `null`.** When more than one
  add-on or source type fits, or one source spans several source types
  (Zeek has one per log), leave the value `null` until someone picks.

Splunk source types are set for 84 of 152 sources. As with the other
SIEMs, each source left `null` has an unresolved `research_needed.json`
entry, and each label that rests on a rule has a resolved entry that
says so.

`wazuh_rule_group` holds the **rule group** that Wazuh 4.x tags the
source's alerts with, such as `windows_security` or `sysmon`. Search
it as `rule.groups`. A rule carries several groups; this is the most
specific one that names the product or log, not a shared group like
`windows` that other sources also carry. Values come from the rule
and decoder files in the
[Wazuh 4.14.9 ruleset](https://github.com/wazuh/wazuh/tree/v4.14.9/ruleset),
using these rules:

- **The product's rule file wins.** If a rule file targets the
  product or log, use its group. For example, the Windows Security log
  uses `windows_security` from `0580-win-security_rules.xml`, and
  CloudTrail uses `aws_cloudtrail`.
- **A product's single rule file covers all its logs.** When one rule
  file covers the whole product, such as `paloalto` or `gcp`, its
  grouping rule tags every decoded event from that product, so every
  log from the product uses it.
- **Other Windows event channels use `windows`.** Every event from
  the eventchannel decoder gets the `windows` group, so a channel with
  no rule file of its own, such as Task Scheduler, uses that.
- **Syslog falls back to `syslog`.** Linux logs that arrive over
  syslog with no decoder or rule file of their own use `syslog`.
- **Two candidate groups means `null`.** When more than one rule file
  fits, or a rule file exists but its decoder doesn't match the log
  (Wazuh's VMware decoders expect ESX-era program names), leave the
  value `null` until someone picks.

Wazuh 5.x drops rule groups in favor of integrations and Sigma
`logsource` fields, so these values target 4.x only. Wazuh rule groups
are set for 70 of 152 sources, with the same `research_needed.json`
entries as the other SIEMs.

Here's an example of a fully-mapped entry, for the Windows Sysmon
operational log (`windows/endpoint_os/sysmon`), as set in
`data_sources.json`:

```json
{
  "google_secops": "WINDOWS_SYSMON",
  "splunk_sourcetype": "XmlWinEventLog",
  "elastic_ecs_dataset": "windows.sysmon_operational",
  "sentinel_table": "Event",
  "wazuh_rule_group": "sysmon"
}
```

Several Windows logs share these values, the same way they share
`WINEVTLOG`. Splunk's
[Sysmon add-on](https://splunk.github.io/splunk-add-on-for-microsoft-sysmon/Sourcetypes/)
uses the `XmlWinEventLog` source type for every XML event channel; the
event's `source` field names the channel. Windows event logs collected
by the Azure Monitor Agent go to the
[`Event` table](https://learn.microsoft.com/en-us/azure/azure-monitor/vm/data-collection-windows-events).
Wazuh 4.x tags its Sysmon rules with the `windows` and `sysmon` groups,
which you search as `rule.groups`.

Note that Sysmon's Splunk sourcetype differs by platform — the value
above is for Windows specifically. The separate `linux/endpoint_os/sysmon_linux`
entry uses `sysmon:linux`, from the
[Splunk Add-on for Sysmon for Linux](https://docs.splunk.com/Documentation/AddOns/released/NixSysmon/Sourcetypes).

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
