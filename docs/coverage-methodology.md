# Coverage methodology

This document explains how a technique earns a place in
`data_sources.json`, why some techniques are marked out of scope
instead, and the domain-specific considerations that shaped those
decisions.

## The evidence standard

A technique maps to a log source only when there's a specific,
checkable reason to believe that source actually provides evidence for
it. Acceptable evidence includes a vendor's official documentation, a
named event ID or log field, or independent confirmation from more
than one credible source.

Two consequences follow from this standard.

First, similarity between products isn't evidence. Two products in the
same category can behave differently, so a mapping confirmed for one
vendor's product doesn't transfer to a similar product from another
vendor without separate verification.

Second, an unverified claim doesn't get silently dropped. It goes into
`research_needed.json`, with the specific question that would need to
be answered to resolve it. A tracked open question is more useful than
a mapping asserted without evidence.

## What "out of scope" means

A technique in `out_of_scope_techniques.json` isn't a gap. It's a
technique this catalog has deliberately concluded no log source can
provide evidence for, with a written reason specific to that technique.

Common reasons a technique ends up here:

- **The technique describes something inherently unobservable.** An
  attacker's own passive network sniffing, for example, produces no
  log trace on the victim's systems by definition.
- **The technique requires content analysis a log entry can't
  capture.** Detecting steganography in a file requires examining the
  file's actual bytes, not the fact that a file event occurred.
- **The technique happens entirely upstream of the environment being
  monitored.** Hardware or software supply chain compromise during
  manufacturing occurs before any device is deployed and generating
  logs.
- **The technique is a process-state outcome, not a discrete event.**
  Several MITRE ATT&CK Impact-tactic techniques (in the ICS domain
  especially) describe an emergent consequence — "Loss of View," for
  example — that an analyst infers by correlating other technique-level
  evidence, rather than something with its own independent log
  signature.

## Domain-specific considerations

### Mobile: iOS and Android aren't equivalent

Mobile Threat Defense products don't provide the same capability on
both platforms. Microsoft's own documentation for Microsoft Defender
for Mobile lists malware scanning as Android-only, reflecting a real
architectural difference: iOS's stricter app sandboxing prevents
third-party security apps from scanning other installed apps the way
Android permits. Where this catalog credits a Mobile Threat Defense
source with malware-scanning coverage, that mapping is scoped to
Android specifically, not applied to both platforms uniformly.

### ICS: what's actually deployable matters more than what's possible

Industrial environments follow the Purdue Model, which separates
control-system levels by function and, in practice, by how they can be
monitored.

Level 0–1 devices — PLCs, RTUs, sensors — are frequently
resource-constrained, run proprietary firmware, and have no capacity to
run a monitoring agent at all. Evidence for techniques at this level
comes from passive network monitoring, watching the actual industrial
protocol traffic, not from the device itself.

Level 2–3 systems — engineering workstations, HMI and SCADA servers —
often run Windows, but that doesn't mean every Windows monitoring
capability applies to them by default. Verified guidance from vendors
in this space (Nozomi Networks, among others) states that OT/ICS
devices are often certified by their manufacturer for a specific
configuration, and installing a third-party agent can invalidate that
certification. This catalog treats native Windows Event Log auditing
as the default assumption for these systems, since it requires only a
policy change, and treats agent-based tools like Sysmon as a
separately flagged, conditional capability that depends on the specific
deployment having been validated by the vendor.

### Enterprise: the largest and most conventionally documented domain

Enterprise sources generally have the most direct vendor documentation
available, and the evidence standard above applies without the
domain-specific caveats that Mobile and ICS require.

## Coverage numbers in context

Run `python3 coverage_gap_report.py` for current numbers. A domain's
coverage percentage is calculated against its in-scope technique
count — total techniques minus those in
`out_of_scope_techniques.json` — not against the domain's full
technique count. This is deliberate: a domain with many legitimately
unobservable techniques should not be penalized in its coverage
percentage for techniques no log source could ever provide.
