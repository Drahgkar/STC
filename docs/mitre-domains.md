# MITRE ATT&CK domains

STC covers all three MITRE ATT&CK domains: Enterprise, Mobile, and
ICS. This document summarizes each domain's scope and the catalog's
current coverage. Run `python3 coverage_gap_report.py` for live numbers;
the figures below reflect the catalog at the time of writing.

## Enterprise

697 techniques, covering conventional IT environments: endpoints,
identity, network infrastructure, cloud platforms, and the applications
running on them.

**Coverage: 574 of 706 techniques (100% of in-scope).** 132 techniques
are marked out of scope, and none remain open.

Enterprise is the most conventionally documented domain. Most mappings
here rely on direct vendor documentation without the platform-specific
caveats Mobile and ICS require. See
[`coverage-methodology.md`](coverage-methodology.md) for what
"in scope" means and how out-of-scope determinations get made.

## Mobile

124 techniques, covering iOS and Android. A meaningful share of Mobile
techniques describe behavior internal to a malicious app's own process
— clipboard access, on-device input capture, and similar — which
generally isn't observable from outside that app without deep runtime
instrumentation this catalog didn't find a verified source for. Most of
this domain's out-of-scope entries reflect that limitation specifically,
not a gap in research effort.

**Coverage: 67 of 125 techniques (98.5% of in-scope).** 57 techniques
are marked out of scope. 1 remains open, in Initial Access.

Mobile coverage in this catalog comes from four source categories, each
with a different evidence model:

- **Mobile Device Management** (Intune, Jamf Pro, Workspace ONE):
  administrative and policy-change events — enrollment, compliance
  status, remote wipe — not deep on-device behavior.
- **Mobile Threat Defense** (Lookout, Zimperium, Microsoft Defender for
  Mobile): network and phishing protection, confirmed on both iOS and
  Android, plus malware scanning, confirmed as Android-only. See
  [`coverage-methodology.md`](coverage-methodology.md) for why these
  are tracked separately rather than combined.
- **Mobile forensic extraction** (Cellebrite UFED): post-incident,
  on-demand device extraction. This is a fundamentally different
  evidence model from the other three — there's no continuous log
  stream, only what an investigator can retrieve after connecting to a
  specific device.
- **Android Enterprise's native `SecurityLog` API**: OS-level security
  events — app-start activity, failed unlock attempts, ADB commands
  over USB — available only on enterprise-managed Android devices, with
  no equivalent found for iOS.

## ICS

97 techniques, covering industrial control systems: PLCs, HMI and
SCADA systems, engineering workstations, and the network protocols
connecting them.

**Coverage: 87 of 104 techniques (98.9% of in-scope).** 16 techniques
are marked out of scope. 1 remains open, in Execution.

ICS coverage follows the Purdue Model's separation of control-system
levels, described in detail in
[`coverage-methodology.md`](coverage-methodology.md). In short: Level
0–1 devices (PLCs, RTUs) are covered through passive network
monitoring, since most can't run an agent at all. Level 2–3 systems
(engineering workstations, HMI/SCADA servers) are covered through
native Windows Event Log auditing by default, with agent-based tools
treated as a separately flagged, conditional capability rather than an
assumption.

Several of this domain's out-of-scope techniques describe
process-state outcomes — "Loss of View," "Denial of Control," and
similar — that an analyst infers by correlating other technique-level
evidence, rather than something with an independent log signature of
its own.

## Keeping this current

`mitre_reference.json` reflects a specific snapshot of MITRE's ATT&CK
data. When MITRE publishes a new version, rebuild it with
`ingest_mitre_stix.py`, then run `validate_sources.py` to catch any
technique ID in `data_sources.json` that a version change retired or
restructured.
